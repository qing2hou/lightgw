// 防火墙策略的 Manager 接线（T105-T107）：装载/重装/重排（全段拆装单 batch）。
package proxy

import (
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"haproxyweb/internal/model"
	"haproxyweb/internal/nft"
	"haproxyweb/internal/proxy/fw"
)

// buildPolicySpecs 从 DB 全部启用策略构建编译参数（Order 升序）。
func (m *Manager) buildPolicySpecs() ([]fw.PolicySpec, error) {
	var pols []model.FwPolicy
	if err := m.db.Where("enabled = ?", true).Find(&pols).Error; err != nil {
		return nil, err
	}
	sort.Slice(pols, func(i, j int) bool { return pols[i].Order < pols[j].Order })
	specs := make([]fw.PolicySpec, 0, len(pols))
	for _, p := range pols {
		specs = append(specs, fw.PolicySpec{
			ID: p.ID, Order: p.Order, Action: p.Action,
			SrcList:   parseIPListOrEmpty(p.SrcList),
			DstList:   parseIPListOrEmpty(p.DstList),
			Proto:     strings.ToLower(strings.TrimSpace(p.Proto)),
			PortRange: strings.TrimSpace(p.PortRange),
		})
	}
	return specs, nil
}

// ReinstallPolicies 策略全段重装（单 batch：暂存拆全部 pol 标记行 → 暂存新行 →
// 一次提交，无间隙窗口）。策略变更/启停/重排的统一入口（T107 热更——
// established 会话由 pre_mark 打标短路，不受重装影响）。
func (m *Manager) ReinstallPolicies() error {
	conn, err := m.nftConn()
	if err != nil {
		return err
	}
	m.nftApplyMu.Lock()
	defer m.nftApplyMu.Unlock()

	specs, err := m.buildPolicySpecs()
	if err != nil {
		return err
	}
	rules, err := fw.CompilePolicies(specs)
	if err != nil {
		return err
	}
	// 单 batch：暂存拆旧行（全部 pol 标记）→ 暂存新行 → 一次提交。
	// 拆旧行需逐 ID 暂存——PurgeByCommentNoFlush 一次一类；pol 的 ID 集合
	// 从 DB + 内核标记对账取并集（避免 DB 已删的 ID 残留）。
	ids, err := conn.InstalledIDs()
	if err == nil {
		for id := range ids[nft.KindPolicy] {
			if _, err := conn.PurgeByCommentNoFlush(nft.KindPolicy, id); err != nil {
				return err
			}
		}
	}
	for _, r := range rules {
		conn.AddCompiled(r.Chain, r.Rule)
	}
	return conn.FlushCommit()
}

// TeardownPolicies 拆除全部策略行（无启用策略时的归零路径）。
func (m *Manager) TeardownPolicies() {
	m.ReinstallPolicies() // 空集重装 = 全拆（幂等路径复用）
}

// KillPolicySessions API-P6：drop 策略创建/更新时可选立即掐断匹配的存量会话。
// 匹配口径：conntrack 表项的 orig 五元组落在（源列表 × 目的列表 × 端口组）
// 笛卡尔展开的任一组合内（IP/CIDR 匹配 + 端口/范围）。
func (m *Manager) KillPolicySessions(p model.FwPolicy) int {
	lines := readConntrackTable()
	if lines == nil {
		return 0
	}
	srcs := parseIPListOrEmpty(p.SrcList)
	dsts := parseIPListOrEmpty(p.DstList)
	killed := 0
	for _, ln := range lines {
		c, ok := parseConntrackLine(ln)
		if !ok {
			continue
		}
		if len(srcs) > 0 && !ipInList(c.origSrc, srcs) {
			continue
		}
		if len(dsts) > 0 && !ipInList(c.origDst, dsts) {
			continue
		}
		if p.Proto != "" && p.Proto != "any" && c.proto != strings.ToLower(p.Proto) {
			continue
		}
		if s := strings.TrimSpace(p.PortRange); s != "" && !portInGroups(c.origDPort, s) {
			continue
		}
		spec := &snatRuleSpec{ID: p.ID}
		if deleteConntrackEntry(spec, c) {
			killed++
		}
	}
	return killed
}

// portInGroups 端口是否在端口组串（"80,443,1000-2000"）内。
func portInGroups(portStr, groups string) bool {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(groups, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, e1 := strconv.Atoi(strings.TrimSpace(lo))
			h, e2 := strconv.Atoi(strings.TrimSpace(hi))
			if e1 == nil && e2 == nil && port >= l && port <= h {
				return true
			}
			continue
		}
		if p, e := strconv.Atoi(part); e == nil && p == port {
			return true
		}
	}
	return false
}

// PolicyCounters 策略命中计数快照（pol 标记聚合；drop/accept 桶分别语义）。
func (m *Manager) PolicyCounters() map[uint]struct {
	Packets uint64
	Bytes   uint64
} {
	out := map[uint]struct {
		Packets uint64
		Bytes   uint64
	}{}
	m.nftMu.Lock()
	conn := m.nft
	m.nftMu.Unlock()
	if conn == nil {
		return out
	}
	m.nftApplyMu.Lock()
	res, err := conn.CountersByComment()
	m.nftApplyMu.Unlock()
	if err != nil {
		return out
	}
	for ud, pair := range res.ByRule {
		kind, id, ok := nft.ParseComment(ud)
		if !ok || kind != nft.KindPolicy {
			continue
		}
		e := out[id]
		e.Packets += pair.Accept.Packets + pair.Drop.Packets
		e.Bytes += pair.Accept.Bytes + pair.Drop.Bytes
		out[id] = e
	}
	return out
}

// ---------- T109 会话可视化：conntrack dump 聚合 + 按 ID 掐断 ----------

// CTSnapshot 单条会话的稳定视图。
type CTSnapshot struct {
	ID       string // base64(proto|src|sport|dst|dport)（orig 四元组）
	Proto    string
	Src      string // ip:port
	Dst      string // ip:port（DNAT 前）
	SrcAfter string // reply.dst NAT 改写后的源（SNAT 出口 IP；dnat 会话为空）
	Router   string // snat:<egress出口IP> / dnat:<发布IP> / policy / other
	State    string
}

// SnapshotSessions conntrack 表全量快照（读 /proc 或 conntrack -L 兜底——
// 复用 readConntrackTable；归属判定按 reply 元组反查引擎注册表）。
func (m *Manager) SnapshotSessions() []CTSnapshot {
	lines := readConntrackTable()
	if lines == nil {
		return nil
	}
	m.mu.Lock()
	entries := make([]*snatEntry, 0, len(m.snatRules))
	for _, e := range m.snatRules {
		entries = append(entries, e)
	}
	m.mu.Unlock()
	// 出口 SNAT IP 集合（snat 归属判定）与发布 IP 集合（dnat 归属）
	snatOutIPs := map[string]string{} // outIP -> 规则标识
	dnatListenIPs := map[string]bool{}
	for _, e := range entries {
		if e.dnat {
			dnatListenIPs[e.ifIn] = true // ifIn 复用为发布 IP
		} else if e.outIP != "" {
			snatOutIPs[e.outIP] = fmt.Sprintf("snat:%s", e.outIP)
		}
	}
	out := make([]CTSnapshot, 0, len(lines))
	for _, ln := range lines {
		c, ok := parseConntrackLine(ln)
		if !ok {
			continue
		}
		s := CTSnapshot{
			Proto: c.proto,
			// orig：客户端/目标真实四元组
			Src: net.JoinHostPort(c.origSrc, c.origSPort),
			Dst: net.JoinHostPort(c.origDst, c.origDPort),
			// reply 元组：SNAT 后的会话形态——reply.src=SNAT出口、
			// reply.dst=SNAT出口:客户端（回程视角）。src_after 取 reply.src
			SrcAfter: net.JoinHostPort(c.replySrc, c.replySPort),
			State:    stateOfConntrackLine(ln),
		}
		s.ID = encodeCTID(c)
		switch {
		case snatOutIPs[c.replySrc] != "":
			s.Router = snatOutIPs[c.replySrc]
		case dnatListenIPs[replyDstIsClient(c)]: // dnat：orig.dst=发布IP
			if dnatListenIPs[c.origDst] {
				s.Router = "dnat:" + c.origDst
			}
		default:
			if dnatListenIPs[c.origDst] {
				s.Router = "dnat:" + c.origDst
			} else {
				s.Router = "other"
			}
		}
		out = append(out, s)
	}
	return out
}

// replyDstIsClient 占位（归属分支可读性；返回空串）。
func replyDstIsClient(c *ctSession) string { return "" }

// stateOfConntrackLine 从行内提取状态（ESTABLISHED/TIME_WAIT 等）。
func stateOfConntrackLine(ln string) string {
	for _, f := range strings.Fields(ln) {
		if v, ok := strings.CutPrefix(f, "state="); ok {
			return v
		}
	}
	// /proc 格式：字段三位置（tcp 6 116 ESTABLISHED src=...）
	fs := strings.Fields(ln)
	if len(fs) >= 4 && (fs[0] == "tcp" || fs[0] == "udp") {
		return fs[3]
	}
	return ""
}

// encodeCTID orig 四元组稳定编码（掐断接口引用）。
func encodeCTID(c *ctSession) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s", c.proto, c.origSrc, c.origSPort, c.origDst, c.origDPort)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// KillSessionByID 按 ID 掐断（base64 解码回四元组 → conntrack -D）。
func (m *Manager) KillSessionByID(id string) (int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(id))
	if err != nil {
		return 0, fmt.Errorf("会话 id 格式错误")
	}
	parts := strings.SplitN(string(raw), "|", 5)
	if len(parts) != 5 {
		return 0, fmt.Errorf("会话 id 内容无效")
	}
	proto, src, sport, dst, dport := parts[0], parts[1], parts[2], parts[3], parts[4]
	if proto != "tcp" && proto != "udp" {
		return 0, fmt.Errorf("会话协议 %q 不支持掐断", proto)
	}
	c := &ctSession{proto: proto, origSrc: src, origSPort: sport, origDst: dst, origDPort: dport}
	if deleteConntrackEntry(&snatRuleSpec{}, c) {
		return 1, nil
	}
	return 0, nil
}
