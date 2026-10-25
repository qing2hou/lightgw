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
	m.db.Where("protocol = ? AND enabled = ?", "snat", true).Find(&rules)
	seen := map[string]bool{}
	ifaces := make([]string, 0, len(rules))
	denied := false
	for _, r := range rules {
		if !seen[r.ListenAddr] {
			seen[r.ListenAddr] = true
			ifaces = append(ifaces, r.ListenAddr)
		}
		if r.AclMode == model.AclModeWhitelist ||
			(r.DstAclMode == model.AclModeBlacklist && parseIPListOrEmpty(r.DstDenyList) != nil) {
			denied = true
		}
	}
	// 先拆旧尾行（幂等；deny 标记只能在默认拒绝行上——非 deny 标记行不碰）
	if err := conn.PurgeByComment(nft.KindDefaultDeny, 0); err != nil {
		logf("默认拒绝尾行拆除失败: %v", err)
		return
	}
	if !denied {
		return // 无"指定就不通"语义的规则——默认拒绝不适用（off 全放行）
	}
	for _, r := range fw.CompileDefaultDeny(0, ifaces) {
		conn.AddCompiled(r.Chain, r.Rule)
	}
	if err := conn.FlushCommit(); err != nil {
		logf("默认拒绝尾行装载失败（白名单外流量将由宿主 policy 兜底或放行）: %v", err)
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
	m.db.Where("protocol = ? AND enabled = ?", "snat", true).Find(&rules)
	for _, r := range rules {
		live[r.ID] = true
	}
	ids := installed[nft.KindSNAT]
	var purged []uint
	for id := range ids {
		if live[id] {
			continue
		}
		if err := conn.PurgeByComment(nft.KindSNAT, id); err == nil {
			purged = append(purged, id)
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

// countersFromNFT 从 nft counter 快照聚合单规则计数（M5：pollSnatCounters 的
// netlink 数据源；无 iptables/tc 二进制环境唯一可用口径）。
// 口径：ACCEPT 计数 = 全部放行行（fwd ③④）+ SNAT 行 counter 之和的 max——
// 同一包同时命中 fwd 放行与 srcnat 改写两条行会双计，取 max 保持与旧口径
// （tc 单计数点）量纲一致；DROP 计数 = ②黑名单行 + 默认拒绝行中归属本规则
// 入口网卡的部分不可分——v1 归入全局 deny counter（列入已知边界）。
func countersFromNFT(counted map[string]nft.CounterSnapshot, ruleID uint, allowSrcs []string) *snatCounters {
	target := nft.Comment(nft.KindSNAT, ruleID)
	accMax, drop := nft.CounterSnapshot{}, nft.CounterSnapshot{}
	have := false
	for ud, ctr := range counted {
		if ud != target {
			continue
		}
		have = true
		// 区分放行/拒绝行：聚合阶段不解析表达式——按"counter 值较大集合"归并
		// 会导致口径漂移。此处按行聚合目标：ACCEPT 桶先无条件求和，
		// 调用方差分逻辑依赖行语义——P4 复审时以 CountersByComment 的
		// verdict 维度扩展为准（M5 简化实现，单桶求和）。
		accMax.Bytes += ctr.Bytes
		accMax.Packets += ctr.Packets
	}
	if !have {
		return nil
	}
	// 兜底 DROP（默认拒绝行全局聚合，ruleID=0 标记——不属于单规则）
	deny := counted[nft.Comment(nft.KindDefaultDeny, 0)]
	drop = deny
	return &snatCounters{
		PktsAccept: int64(accMax.Packets), BytesAccept: int64(accMax.Bytes),
		PktsDrop: int64(drop.Packets), BytesDrop: int64(drop.Bytes),
	}
}
