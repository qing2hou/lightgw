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

// ReinstallPolicies 策略段全量重装（评审 #1 修正：**与默认拒绝尾行同 batch 重建**，
// 保证 fwd 链序恒为 [规则放行行…, 策略行…, deny 尾行]——AddCompiled 只有链尾
// 追加，若只重装 pol 段，旧 deny 行会留在 pol 行之前，策略行被 deny 短路全部失效）。
// 单 batch：暂存拆（pol 全标记 + deny 全标记）→ 暂存装（pol 行 → deny 行）→ 提交。
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
	// 暂存拆旧（失败 fail-fast——评审 #15：静默跳过会双份叠加+序错乱）
	ids, err := conn.InstalledIDs()
	if err != nil {
		return err
	}
	for id := range ids[nft.KindPolicy] {
		if _, err := conn.PurgeByCommentNoFlush(nft.KindPolicy, id); err != nil {
			return err
		}
	}
	if _, err := conn.PurgeByCommentNoFlush(nft.KindDefaultDeny, 0); err != nil {
		return err
	}
	// 暂存装：pol 行在前、deny 尾行在后（序就是链评估序）
	for _, r := range rules {
		conn.AddCompiled(r.Chain, r.Rule)
	}
	m.appendDefaultDenyNoFlush(conn)
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
		// 评审 #14：本机自营连接护栏——orig 与 reply 双侧目标都是本机会话
		// （管理面/后端连接）不掐断，防 any/any 空集策略削掉管理面
		if m.isLocalSession(c) {
			continue
		}
		if len(srcs) > 0 && !ipInList(c.origSrc, srcs) {
			continue
		}
		// 评审 #13：dst 维度同时接受 orig.dst（真实目标）与 reply.src
		// （dnat 会话的 reply 源=后端 IP——策略行在 fwd 匹配的是 DNAT 后目的）
		if len(dsts) > 0 && !ipInList(c.origDst, dsts) && !ipInList(c.replySrc, dsts) {
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
			// NAT 后源（DEFECT-3 修正）：conntrack 的 reply tuple[::-1]——
			// reply.src 是对端服务器、reply.dst 才是本机 SNAT 后的源。
			// NAT 后源:port = reply.dst:reply.dport
			SrcAfter: net.JoinHostPort(c.replyDst, c.replyDPort),
			State:    stateOfConntrackLine(ln),
		}
		s.ID = encodeCTID(c)
		// 归属判定（DEFECT-3 修正）：
		//   snat：reply.dst = SNAT 出口 IP（回程目的地即被改写的源）；
		//   dnat：orig.dst = 发布 IP
		switch {
		case snatOutIPs[c.replyDst] != "":
			s.Router = snatOutIPs[c.replyDst]
		case dnatListenIPs[c.origDst]:
			s.Router = "dnat:" + c.origDst
		default:
			s.Router = "other"
		}
		out = append(out, s)
	}
	return out
}

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

// KillSessionByID 按 ID 掐断一条会话。
//
// 会话有两类，掐断手段不同：
//
//  1. **端口映射（tcp/udp，用户态转发）**：进程里有一对真实 socket，
//     conntrack 只是它们在核内的影子。只删 conntrack 表项无效——
//     copyTCP/copyFast 协程照常搬数据，内核立刻重建条目（实测：掐断后
//     传输速率不变）。必须按 orig 四元组找到 session 并强制关闭连接。
//
//  2. **SNAT 穿越（纯内核转发）**：没有用户态 socket，删 conntrack 表项
//     即断流，这是原有行为。
//
// 实现顺序：先试用户态会话（命中即真断），再回落 conntrack -D。
// 两类都做，覆盖"用户态会话已结束但 conntrack 表项仍在 TIME_WAIT"的情况。
func (m *Manager) KillSessionByID(id string) (int, error) {
	trimmed := strings.TrimSpace(id)
	// 进程内会话（端口映射）的 id 形如 "u:<ruleID>:<srcIP>:<srcPort>"。
	// 这类会话不经过 conntrack，必须走用户态强制关闭路径。
	if rest, ok := strings.CutPrefix(trimmed, "u:"); ok {
		parts := strings.SplitN(rest, ":", 3)
		if len(parts) != 3 {
			return 0, fmt.Errorf("会话 id 内容无效")
		}
		srcIP, sportStr := parts[1], parts[2]
		sp, err := strconv.Atoi(sportStr)
		if err != nil {
			return 0, fmt.Errorf("会话 id 内容无效")
		}
		if m.killUserSessionBySrc(srcIP, sp) {
			return 1, nil
		}
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(trimmed)
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

	killed := 0
	// ① 用户态会话：按 orig 四元组精确定位并强制断开。
	//    入向段的 orig 就是「客户端 → 网关监听口」，与 encodeCTID 的编码一致。
	if sp, err := strconv.Atoi(sport); err == nil {
		if dp, err := strconv.Atoi(dport); err == nil {
			if m.killUserSession(proto, src, sp, dst, dp) {
				killed++
			}
		}
	}

	// ② conntrack 表项（SNAT 会话的唯一手段；端口映射顺带清影子条目）
	c := &ctSession{proto: proto, origSrc: src, origSPort: sport, origDst: dst, origDPort: dport}
	if deleteConntrackEntry(&snatRuleSpec{}, c) {
		if killed == 0 {
			killed = 1
		}
	}
	return killed, nil
}

// killUserSession 按入向段四元组找到用户态会话并强制断开，返回是否命中。
//
// 匹配键（四个都要相等）：
//
//	proto、客户端 IP、客户端端口、监听 IP、监听端口
//
// 注意 UDP 会话的 srcIP/srcPort 记录的是**客户端**地址（与 TCP 一致），
// 所以同一套匹配逻辑对两种协议都成立。
// killUserSessionBySrc 按「客户端 IP + 客户端端口」找到进程内会话并强制断开。
//
// 用于会话表里 "u:" 前缀的 id（端口映射会话，不经过 conntrack）。
// 客户端 IP+端口在一条连接的生命周期内唯一，足以定位。
func (m *Manager) killUserSessionBySrc(srcIP string, srcPort int) bool {
	var hit *session
	m.sessions.Range(func(_, v any) bool {
		s, ok := v.(*session)
		if !ok {
			return true
		}
		if s.srcIP == srcIP && s.srcPort == srcPort {
			hit = s
			return false
		}
		return true
	})
	if hit == nil {
		return false
	}
	if !hit.forceClose() {
		return false
	}
	logf("规则[%s#%d] 会话已掐断（用户态）: %s:%d", hit.rule.Name, hit.rule.ID, srcIP, srcPort)
	return true
}

func (m *Manager) killUserSession(proto, srcIP string, srcPort int, listenIP string, listenPort int) bool {
	var hit *session
	m.sessions.Range(func(_, v any) bool {
		s, ok := v.(*session)
		if !ok {
			return true
		}
		if s.rule.Protocol != proto {
			return true
		}
		if s.srcIP != srcIP || s.srcPort != srcPort {
			return true
		}
		if s.listenIP != listenIP || s.listenPort != listenPort {
			return true
		}
		hit = s
		return false // 命中即停
	})
	if hit == nil {
		return false
	}
	// forceClose 内部 Close 两个连接；会话的收尾（removeSession / 流量日志）
	// 由 copy 协程的自然退出路径完成，这里不重复做。
	if !hit.forceClose() {
		return false
	}
	logf("规则[%s#%d] 会话已掐断: %s %s:%d → %s:%d",
		hit.rule.Name, hit.rule.ID, proto, srcIP, srcPort, listenIP, listenPort)
	return true
}

// isLocalSession 本机自营会话判定（orig/reply 目标侧均落在本机地址上——
// 管理面 Web/API、DB、后端探测连接；防策略掐断误杀管理面，评审 #14）。
func (m *Manager) isLocalSession(c *ctSession) bool {
	local := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				local[ipn.IP.String()] = true
			}
		}
	}
	// 会话的"目标侧"：orig.dst（客户端视角目标）与 reply.dst（服务端视角回程目标）。
	// 双侧都是本机 = 本机发起且本机接收的自营连接
	return local[c.origDst] && local[c.replyDst]
}
