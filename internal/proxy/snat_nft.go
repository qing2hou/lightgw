// snat 规则的 nftables 后端（T004：替换 iptables exec 形态，语义等价）。
// 引擎层 internal/nft + 编译层 internal/proxy/fw；本文件是 Manager 接线面。
package proxy

import (
	"fmt"

	"haproxyweb/internal/model"
	"haproxyweb/internal/nft"
	"haproxyweb/internal/proxy/fw"
)

// nftConn 引擎连接（Manager 持有；懒加载——无 snat/dnat 规则的部署零开销）。
// 连接生命周期：nftMu 保护指针发布；装载互斥由 nftApplyMu 独立承担
// （ Miner 锁原则：purge-then-add 全序列必须串行，否则并发 Apply 会
// 交叉出双份同标记规则——评审 M9）。
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
			// 冲突即弃（评审 S3：不留已建的空表——装入即弃也是残留）
			_ = c.DropTable()
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
// 装载互斥（评审 M9）：purge→compile→add→flush 全序列持 nftApplyMu——
// 防并发 Apply 的 purge/add 交叉产生同标记双份。
func (m *Manager) installSnatNFT(spec *snatRuleSpec) error {
	conn, err := m.nftConn()
	if err != nil {
		return err
	}
	m.nftApplyMu.Lock()
	defer m.nftApplyMu.Unlock()

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
		// 半装防御：失败即盲拆本规则标记（宁可断新、不可脏规则）。
		// 回滚自身失败必须留痕（评审 M7：静默=半装残留不可观测）
		if rerr := conn.PurgeByComment(nft.KindSNAT, spec.ID); rerr != nil {
			logf("规则#%d nft 装载失败且回滚失败（可能残留半装形态，下次应用/启动对账将清理）: %v", spec.ID, rerr)
			return fmt.Errorf("nftables 装载失败: %w（回滚亦失败: %v）", err, rerr)
		}
		return fmt.Errorf("nftables 装载失败: %w", err)
	}
	// 默认拒绝尾行重装（入口集随启用规则集变化——全局一条，多规则共享）
	m.reinstallDefaultDenyLocked(conn)
	return nil
}

// teardownSnatNFT 拆除一条 snat 规则的全部 nft 形态（按标记，幂等）+
// 默认拒绝尾行重算。停用/删除/协议切换统一入口。
func (m *Manager) teardownSnatNFT(ruleID uint) {
	m.nftApplyMu.Lock()
	defer m.nftApplyMu.Unlock()
	m.nftMu.Lock()
	conn := m.nft
	m.nftMu.Unlock()
	if conn == nil {
		return
	}
	if err := conn.PurgeByComment(nft.KindSNAT, ruleID); err != nil {
		logf("规则#%d nft 形态拆除失败（启动对账将兜底清理）: %v", ruleID, err)
	}
	m.reinstallDefaultDenyLocked(conn)
}

// reinstallDefaultDenyLocked 默认拒绝尾行重装（调用方持 nftApplyMu）。
// 入口集 = 当前 DB 启用 snat 规则的入口网卡去重集；空集时拆除尾行
// （vanilla 语义回到全通——与"有规则才有管辖区"一致）。
func (m *Manager) reinstallDefaultDenyLocked(conn *nft.Conn) {
	var rules []model.ForwardRule
	if err := m.db.Where("protocol IN ? AND enabled = ?", []string{"snat", "dnat"}, true).Find(&rules).Error; err != nil {
		// 复审 N5：DB 读失败时保留在位尾行（拆了装不回=漏拒绝——不保守方向）
		logf("默认拒绝尾行重算跳过（DB 读取失败，保留在位形态）: %v", err)
		return
	}
	seen := map[string]bool{}
	ifaces := make([]string, 0, len(rules))
	dnatBackends := make([]string, 0, len(rules))
	denied := false
	for _, r := range rules {
		if r.Protocol == model.ProtocolDNAT {
			// dnat：辖区=后端 IP；白名单语义恒真（API 强制），发布行必然依赖兜底拒绝
			if bip, _, ok := splitHostPortOK(r.TargetAddr); ok {
				if !seen["b:"+bip] {
					seen["b:"+bip] = true
					dnatBackends = append(dnatBackends, bip)
				}
			}
			denied = true
			continue
		}
		if !seen[r.ListenAddr] {
			seen[r.ListenAddr] = true
			ifaces = append(ifaces, r.ListenAddr)
		}
		// 复审 N5：目标白名单也依赖兜底拒绝（白名单外全拒）——与源白名单、
		// 目标黑名单同属"指定就不通"语义族
		if r.AclMode == model.AclModeWhitelist ||
			(r.DstAclMode == model.AclModeWhitelist && len(parseIPListOrEmpty(r.DstAllowList)) > 0) ||
			(r.DstAclMode == model.AclModeBlacklist && len(parseIPListOrEmpty(r.DstDenyList)) > 0) {
			denied = true
		}
	}
	// N6：拆除与新增同一 netlink batch（无间隙窗口）。暂存删除 → 暂存新增 →
	// 一次提交；无 denied 时只提交删除（幂等归零）。
	if _, err := conn.PurgeByCommentNoFlush(nft.KindDefaultDeny, 0); err != nil {
		logf("默认拒绝尾行拆除暂存失败: %v", err)
		return
	}
	if denied {
		for _, r := range fw.CompileDefaultDenyEx(0, ifaces, dnatBackends) {
			conn.AddCompiled(r.Chain, r.Rule)
		}
	}
	if err := conn.FlushCommit(); err != nil {
		logf("默认拒绝尾行装载失败（白名单外流量将由宿主 policy 兜底或放行）: %v", err)
	}
}

// appendDefaultDenyNoFlush 默认拒绝尾行的集计算 + 暂存追加（不提交、不拆旧——
// 调用方在同 batch 中控制顺序：先暂存拆旧，再追加本函数的行，最后 FlushCommit）。
// deny 行必须保持在 fwd 链尾（fwd 链追加序 = 评估序；deny 是终结行，
// 排在其他行前面会把后续行全部短路——评审 #1）。
func (m *Manager) appendDefaultDenyNoFlush(conn *nft.Conn) {
	var rules []model.ForwardRule
	if err := m.db.Where("protocol IN ? AND enabled = ?", []string{"snat", "dnat"}, true).Find(&rules).Error; err != nil {
		return // DB 读失败：不动 deny 形态（保守——拆了装不回=漏拒绝）
	}
	seen := map[string]bool{}
	ifaces := make([]string, 0, len(rules))
	dnatBackends := make([]string, 0, len(rules))
	denied := false
	for _, r := range rules {
		if r.Protocol == model.ProtocolDNAT {
			if bip, _, ok := splitHostPortOK(r.TargetAddr); ok && !seen["b:"+bip] {
				seen["b:"+bip] = true
				dnatBackends = append(dnatBackends, bip)
			}
			denied = true
			continue
		}
		if !seen[r.ListenAddr] {
			seen[r.ListenAddr] = true
			ifaces = append(ifaces, r.ListenAddr)
		}
		if r.AclMode == model.AclModeWhitelist ||
			(r.DstAclMode == model.AclModeWhitelist && len(parseIPListOrEmpty(r.DstAllowList)) > 0) ||
			(r.DstAclMode == model.AclModeBlacklist && len(parseIPListOrEmpty(r.DstDenyList)) > 0) {
			denied = true
		}
	}
	if !denied {
		return
	}
	for _, r := range fw.CompileDefaultDenyEx(0, ifaces, dnatBackends) {
		conn.AddCompiled(r.Chain, r.Rule)
	}
}

// migrateLegacyIPTables 启动迁移（T006）：经 netlink 拆除全部旧 haweb-sn:
// iptables 形态。连接失败（无权限/无内核 nftables）返回错误由调用方降级。
func (m *Manager) migrateLegacyIPTables() (int, error) {
	conn, err := m.nftConn()
	if err != nil {
		return 0, err
	}
	return conn.PurgeLegacyIPTables()
}

// purgeOrphanNFTRules nft 形态启动对账：haweb 表内 haweb-nft:snat:<id> 标记
// 规则、DB 无对应启用 snat 规则的，按标记拆除（进程崩溃残留归零）。
func (m *Manager) purgeOrphanNFTRules() {
	conn, err := m.nftConn()
	if err != nil {
		logf("[snat] nft 启动对账跳过（引擎连接不可用）: %v", err)
		return
	}
	m.nftApplyMu.Lock()
	defer m.nftApplyMu.Unlock()
	installed, err := conn.InstalledIDs()
	if err != nil {
		logf("[snat] nft 启动对账读取失败: %v", err)
		return
	}
	if len(installed) == 0 {
		return
	}
	live := map[uint]bool{}
	var rules []model.ForwardRule
	m.db.Where("protocol IN ? AND enabled = ?", []string{"snat", "dnat"}, true).Find(&rules)
	for _, r := range rules {
		live[r.ID] = true
	}
	var purged []uint
	// 评审 #7：两个 kind 都对账（dnat 孤儿残留=发布地址流量被永久改写到
	// 已删除的后端）
	for _, kind := range []string{nft.KindSNAT, nft.KindDNAT} {
		for id := range installed[kind] {
			if live[id] {
				continue
			}
			if err := conn.PurgeByComment(kind, id); err == nil {
				purged = append(purged, id)
			}
		}
	}
	if len(purged) > 0 {
		logf("[snat] nft 启动对账：已拆除 %d 条孤儿规则: %v", len(purged), purged)
	}
	m.reinstallDefaultDenyLocked(conn)
}

// teardownEgressRouteNFT netlink 版策略路由拆除（M6：替代 exec ip 兜底；
// 语义沿承——只删 lookup 本表的规则，绝不盲删 pref 槽）。失败降级旧 exec 路径。
func (m *Manager) teardownEgressRouteNFT(rtTable int) {
	if rtTable == 0 {
		return
	}
	conn, err := m.nftConn()
	if err != nil {
		return // 引擎不可用——调用方的 exec 兜底路径继续
	}
	if err := conn.TearEgressRoute(rtTable, nil); err != nil {
		logf("策略路由表 %d netlink 拆除失败: %v", rtTable, err)
	}
}

// countersFromNFT 从 nft counter 快照聚合单规则计数（M5/N1/N2/三轮定案）。
// 单计数点口径：Accept = fwd 放行行（③④）之和（fwd hook 每 Derby 包计一次，
// 与旧 tc 单点量纲一致；srcnat 行不加 counter——NAT 链仅每连接首包求值）；
// Drop = 本规则 ② 黑名单行。全局默认拒绝（deny:0）不进 per-rule——N 条规则
// 不可 N 倍重复计（全局面走 CountersByCommentResult.DenyDeny）。
func countersFromNFT(res *nft.CountersByCommentResult, ruleID uint, allowSrcs []string) *snatCounters {
	pair, ok := res.ByRule[nft.Comment(nft.KindSNAT, ruleID)]
	if !ok {
		return nil
	}
	return &snatCounters{
		PktsAccept: int64(pair.Accept.Packets), BytesAccept: int64(pair.Accept.Bytes),
		PktsDrop: int64(pair.Drop.Packets), BytesDrop: int64(pair.Drop.Bytes),
	}
}

// ReadSnatCountersNFT API 摘要用的规则计数快照（三轮复审建议 3：nft 优先，
// 不可读降级 exec 旧口径，两者皆不可读返回 nil——调用方展示 unknown）。
// 与 pollSnatCounters 同源（CountersByComment），持 nftApplyMu 防会话交错。
func (m *Manager) ReadSnatCountersNFT(ruleID uint, ifIn string, allowSrcs []string) *snatCounters {
	m.nftMu.Lock()
	conn := m.nft
	m.nftMu.Unlock()
	if conn != nil {
		m.nftApplyMu.Lock()
		res, err := conn.CountersByComment()
		m.nftApplyMu.Unlock()
		if err == nil {
			if c := countersFromNFT(res, ruleID, allowSrcs); c != nil {
				return c
			}
			return &snatCounters{} // 引擎在位但读不到（未启用）——零值语义
		}
	}
	// 降级：老机器 exec 口径
	return ReadSnatCounters(ruleID, ifIn, allowSrcs)
}

// splitHostPortOK "IP:port" → (ip, port, ok)。
func splitHostPortOK(s string) (string, int, bool) {
	ip, port, err := fw.ParseAddrPort(s)
	if err != nil {
		return "", 0, false
	}
	return ip, port, true
}
