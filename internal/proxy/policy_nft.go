// 防火墙策略的 Manager 接线（T105-T107）：装载/重装/重排（全段拆装单 batch）。
package proxy

import (
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
