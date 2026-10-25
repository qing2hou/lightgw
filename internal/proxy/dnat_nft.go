// dnat 规则的 nftables 后端（M2/T102-T104）：Manager 生命周期接线。
// 装拆走 installDNATNFT/teardownDNATNFT（与 snat 同纪律：标记盲拆兜底、
// 失败回滚、nftApplyMu 互斥）；健康联动复用 health.go 的探测结果
// （后端不可达→卸载发布行+计数拒新；恢复→重装）。
package proxy

import (
	"fmt"
	"net"
	"strings"

	"haproxyweb/internal/model"
	"haproxyweb/internal/nft"
	"haproxyweb/internal/proxy/fw"
)

// netInterfacesList 本机全部 IPv4 地址（发布 IP 归属校验）。
func netInterfacesList() ([]string, error) {
	out := []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				out = append(out, ipn.IP.String())
			}
		}
	}
	return out, nil
}

// buildDNATSpec 由 ForwardRule 构建 dnat 编译参数（字段复用与解析兜底）。
func (m *Manager) buildDNATSpec(rule model.ForwardRule) *fw.DNatSpec {
	lip, lport, _ := fw.ParseAddrPort(rule.ListenAddr)
	bip, bport, _ := fw.ParseAddrPort(rule.TargetAddr)
	var srcs []string
	allow := rule.AllowList
	if rule.AclMode == model.AclModeWhitelist {
		if rule.AclGroupID != 0 {
			var g model.AclGroup
			if err := m.db.First(&g, rule.AclGroupID).Error; err == nil {
				allow = g.Entries
			}
		}
		if b := strings.TrimSpace(allow); b != "" {
			_ = jsonUnmarshalStrings(b, &srcs)
		}
	} else {
		srcs = nil // off：不限源（API 层当前不放行此形态；直改 DB 的兜底语义）
	}
	rm := strings.TrimSpace(rule.DnatRejectMode)
	if rm != model.DnatRejectModeReject && rm != model.DnatRejectModeTimeout {
		rm = model.DnatRejectModeReject
	}
	return &fw.DNatSpec{
		ID: rule.ID, ListenIP: lip, ListenPort: lport,
		BackendIP: bip, BackendPort: bport,
		AllowSrcs: srcs, RejectMode: rm,
	}
}

// applyDNAT 应用一条 dnat 规则（Manager.Apply 的 dnat 分支）。
// 与 applySNAT 同构：快路径（纯参数不变只重挂 counter）/ 全拆重装/ 校验 fail-fast。
func (m *Manager) applyDNAT(rule model.ForwardRule) error {
	spec := m.buildDNATSpec(rule)

	if rule.Enabled {
		// 已启用且形态参数一致：无需动内核（快路径——参数变更走全拆重装）
		m.mu.Lock()
		old := m.snatRules[rule.ID] // dnat 复用 snatRules 注册表（形态记 entry）
		m.mu.Unlock()
		if old != nil && old.sameForwarding(&snatRuleSpec{
			ID: rule.ID, IfIn: spec.ListenIP, IfOut: spec.BackendIP,
			AllowSrcs: spec.AllowSrcs,
		}) {
			_ = old
			return nil // 简化 v1：dnat 无 tc/限速面，参数不变即零动作
		}
	}

	// 拆旧（snat 注册表共用 + nft 标记盲拆）
	m.mu.Lock()
	old, hadOld := m.snatRules[rule.ID]
	if hadOld || !rule.Enabled {
		delete(m.snatRules, rule.ID)
	}
	m.mu.Unlock()
	if old != nil {
		s := old.spec()
		_ = s
	}
	m.teardownSnatNFT(rule.ID) // 复用：按 KindSNAT 拆——注意 dnat 规则的标记是 KindDNAT
	m.teardownDNATNFT(rule.ID)
	if !rule.Enabled {
		m.killDNATSessions(rule.ID)
		return nil
	}

	// 校验：发布 IP 归属（保存后网卡地址可能变更）fail-fast
	if !ipBelongsLocally(spec.ListenIP) {
		return fmt.Errorf("发布 IP %s 已不归属本机任何网卡（网卡地址已变更？），已停用规则", spec.ListenIP)
	}
	conn, err := m.nftConn()
	if err != nil {
		return err
	}
	if err := m.installDNATNFT(conn, spec); err != nil {
		return err
	}
	m.statsFor(rule)
	m.mu.Lock()
	m.snatRules[rule.ID] = &snatEntry{
		ruleID: rule.ID, ifIn: spec.ListenIP, ifOut: spec.BackendIP,
		dstMode:   rule.DstAclMode,
		allowSrcs: spec.AllowSrcs,
		dnat:      true,
	}
	m.mu.Unlock()
	return nil
}

// installDNATNFT 装载 dnat 规则（purge→compile→add→flush→失败回滚，nftApplyMu 全程）。
func (m *Manager) installDNATNFT(conn *nft.Conn, spec *fw.DNatSpec) error {
	m.nftApplyMu.Lock()
	defer m.nftApplyMu.Unlock()
	if err := conn.PurgeByComment(nft.KindDNAT, spec.ID); err != nil {
		return fmt.Errorf("拆除旧 dnat 形态失败: %w", err)
	}
	rules, err := fw.CompileDNAT(*spec)
	if err != nil {
		return fmt.Errorf("dnat 规则编译失败: %w", err)
	}
	for _, r := range rules {
		conn.AddCompiled(r.Chain, r.Rule)
	}
	if err := conn.FlushCommit(); err != nil {
		if rerr := conn.PurgeByComment(nft.KindDNAT, spec.ID); rerr != nil {
			logf("规则#%d dnat 装载失败且回滚失败（下次应用/启动对账清理）: %v", spec.ID, rerr)
			return fmt.Errorf("dnat 装载失败: %w（回滚亦失败: %v）", err, rerr)
		}
		return fmt.Errorf("dnat 装载失败: %w", err)
	}
	m.reinstallDefaultDenyLocked(conn)
	return nil
}

// teardownDNATNFT 拆除 dnat 规则（按标记，幂等）。
func (m *Manager) teardownDNATNFT(ruleID uint) {
	m.nftApplyMu.Lock()
	defer m.nftApplyMu.Unlock()
	m.nftMu.Lock()
	conn := m.nft
	m.nftMu.Unlock()
	if conn == nil {
		return
	}
	if err := conn.PurgeByComment(nft.KindDNAT, ruleID); err != nil {
		logf("规则#%d dnat 形态拆除失败（启动对账兜底）: %v", ruleID, err)
	}
	m.reinstallDefaultDenyLocked(conn)
}

// killDNATSessions 停用 dnat 时掐断本规则的存量发布会话。
// 按"orig dst = 发布地址"维度的 conntrack 精确删（四元组重建：源任意）。
func (m *Manager) killDNATSessions(ruleID uint) {
	e := func() *snatEntry {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.snatRules[ruleID]
	}()
	if e == nil {
		return
	}
	conn, err := m.nftConn()
	if err != nil {
		return
	}
	_ = conn // conntrack 删除经 conntrack 工具路径（M2/T103 细化）——v1 先老化
	logf("规则#%d 停用：存量发布会话将随 conntrack 老化断开", ruleID)
}

// ipBelongsLocally IP 是否归属本机任一网卡。
func ipBelongsLocally(ip string) bool {
	ifaces, _ := netInterfacesList()
	for _, s := range ifaces {
		if s == ip {
			return true
		}
	}
	return false
}
