// snat 规则的 nftables 后端（T004：替换 iptables exec 形态，语义等价）。
// 引擎层 internal/nft + 编译层 internal/proxy/fw；本文件是 Manager 接线面。
package proxy

import (
	"fmt"

	"haproxyweb/internal/nft"
	"haproxyweb/internal/proxy/fw"
)

// nftConn 引擎连接（Manager 持有；懒加载——无 snat/dnat 规则的部署零开销）。
// 线程安全：google/nftables.Conn 自带锁。
func (m *Manager) nftConn() (*nft.Conn, error) {
	m.nftMu.Lock()
	defer m.nftMu.Unlock()
	if m.nft == nil {
		c, err := nft.Dial()
		if err != nil {
			return nil, err
		}
		// 表与链幂等建立 + 宿主探测 + 锚点
		if err := c.EnsureTable(); err != nil {
			_ = c.CloseLasting()
			return nil, fmt.Errorf("建立 nftables 基础表失败: %w", err)
		}
		prof, err := c.DetectHost()
		if err != nil {
			_ = c.CloseLasting()
			return nil, err
		}
		if prof.LegacyIPTables && prof.ForwardPolicyDrop {
			_ = c.CloseLasting()
			return nil, &nft.LegacyConflictError{Profile: prof}
		}
		if err := c.EnsureAnchor(prof); err != nil {
			_ = c.CloseLasting()
			return nil, err
		}
		m.nft = c
		profSnapshot := prof
		m.nftHostProfile = &profSnapshot
	}
	return m.nft, nil
}

// installSnatNFT 经 nft 引擎安装一条 snat 规则（fw 编译 + 标记盲拆兜底 + 装载）。
func (m *Manager) installSnatNFT(spec *snatRuleSpec) error {
	conn, err := m.nftConn()
	if err != nil {
		return err
	}
	// 幂等：先按标记盲拆旧形态（热升级/脏状态兜底）
	if err := conn.PurgeByComment(nft.KindSNAT, spec.ID); err != nil {
		return fmt.Errorf("拆除旧规则形态失败: %w", err)
	}
	fwSpec := fw.Spec{
		ID: spec.ID, IfIn: spec.IfIn, IfOut: spec.IfOut, OutIP: spec.OutIP,
		AllowSrcs: spec.AllowSrcs, DstMode: spec.DstAclMode,
		DstAllow: spec.DstAllow, DstDeny: spec.DstDeny,
		EgGw: spec.EgressGw,
	}
	rules, err := fw.CompileSNAT(fwSpec)
	if err != nil {
		return fmt.Errorf("规则编译失败: %w", err)
	}
	for _, r := range rules {
		conn.AddCompiled(r.Chain, r.Rule)
	}
	if err := conn.FlushCommit(); err != nil {
		// 半装防御：失败即盲拆本规则标记（宁可断新、不可脏规则）
		_ = conn.PurgeByComment(nft.KindSNAT, spec.ID)
		return fmt.Errorf("nftables 装载失败: %w", err)
	}
	return nil
}

// teardownSnatNFT 拆除一条 snat 规则的全部 nft 形态（按标记，幂等）。
func (m *Manager) teardownSnatNFT(ruleID uint) {
	m.nftMu.Lock()
	conn := m.nft
	m.nftMu.Unlock()
	if conn == nil {
		return
	}
	if err := conn.PurgeByComment(nft.KindSNAT, ruleID); err != nil {
		logf("规则#%d nft 形态拆除失败（启动对账将兜底清理）: %v", ruleID, err)
	}
}
