// snat 规则的 nftables 后端（T004：替换 iptables exec 形态，语义等价）。
// 引擎层 internal/nft + 编译层 internal/proxy/fw；本文件是 Manager 接线面。
package proxy

import (
	"fmt"
	"strings"

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
		Pool:      spec.Pool, // B5：此前漏传——rotate/sticky 全退化为固定 OutIP
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

// RecomputeDefaultDeny 按当前 DB 状态重算默认拒绝尾行（API 删除规则后调用：
// Stop() 时规则尚未从库里删除，重算出的辖区包含它；DB 删除后必须再算一次）。
func (m *Manager) RecomputeDefaultDeny() {
	conn, err := m.nftConn()
	if err != nil {
		logf("默认拒绝尾行重算跳过（nft 引擎不可用）: %v", err)
		return
	}
	m.nftApplyMu.Lock()
	defer m.nftApplyMu.Unlock()
	m.reinstallDefaultDenyLocked(conn)
}

// reinstallDefaultDenyLocked 默认拒绝尾行重装（调用方持 nftApplyMu）。
// 辖区 = 存在中的 snat 规则入口网卡 ∪ 出口实体网卡（含停用规则，见
// computeDefaultDenySets 的语义说明）；完全无规则且无出口时才拆除尾行
// （本机不承担网关职责，不干预转发）。
func (m *Manager) reinstallDefaultDenyLocked(conn *nft.Conn) {
	ifaces, dnatBackends, denied, err := m.computeDefaultDenySets()
	if err != nil {
		// 复审 N5：DB 读失败时保留在位尾行（拆了装不回=漏拒绝——不保守方向）
		logf("默认拒绝尾行重算跳过（DB 读取失败，保留在位形态）: %v", err)
		return
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
	ifaces, dnatBackends, denied, err := m.computeDefaultDenySets()
	if err != nil || !denied {
		return // DB 读失败：不动 deny 形态（保守——拆了装不回=漏拒绝）
	}
	for _, r := range fw.CompileDefaultDenyEx(0, ifaces, dnatBackends) {
		conn.AddCompiled(r.Chain, r.Rule)
	}
}

// computeDefaultDenySets 默认拒绝尾行的辖区与豁免计算（纯读，复核建议：
// 此前两处逐行同构的拷贝合并于此——改辖区逻辑只动这一处）。
// 返回：snat 入口网卡集、dnat 后端 IP 集、是否启用默认拒绝。
//
// 管辖语义（B 方案，用户确认）：**只要系统里存在任何 snat 规则（含停用）
// 或任何出口实体，就维持默认拒绝**。理由：本产品的定位是一台网关，转发面
// 必须"默认不通、按规则放行"。早期实现按"启用中的规则"取辖区，导致停用最后
// 一条规则时默认拒绝行连同辖区一起消失，整机静默退化为全放行路由器
// （ip_forward 恒为 1），运维以为只是关了一条规则、实际是打开了整机转发。
//
// 辖区取值的两个来源取并集：
//   - 所有 snat 规则（无论 enabled）的入口网卡：停用的规则仍需守住它的入口，
//     否则"停用=放开该网卡全部流量"
//   - 所有出口实体的网卡：出口实体本身就是"允许出站的路径"，反向定义了
//     受管范围；没有 snat 规则但配了出口时同样要拒绝未声明流量
//
// dnat 侧不变：只取启用中规则的后端 IP（停用的发布不该继续把流量改写到后端，
// 但也不该因此放开 fwd——后端 IP 辖区随规则停用而收缩是正确的）。
func (m *Manager) computeDefaultDenySets() (ifaces, dnatBackends []string, denied bool, err error) {
	var rules []model.ForwardRule
	// 注意：这里**不过滤 enabled**——辖区必须覆盖停用规则，见上方注释
	if err := m.db.Where("protocol = ?", model.ProtocolSNAT).Find(&rules).Error; err != nil {
		return nil, nil, false, err
	}
	var dnatRules []model.ForwardRule
	if err := m.db.Where("protocol = ? AND enabled = ?", model.ProtocolDNAT, true).Find(&dnatRules).Error; err != nil {
		return nil, nil, false, err
	}
	seen := map[string]bool{}
	ifaces = make([]string, 0, len(rules))
	dnatBackends = make([]string, 0, len(dnatRules))
	for _, r := range rules {
		ifn := strings.TrimSpace(r.ListenAddr)
		if ifn != "" && !seen["i:"+ifn] {
			seen["i:"+ifn] = true
			ifaces = append(ifaces, ifn)
		}
		// 任何 snat 规则的存在（含停用）即启用默认拒绝
		denied = true
	}
	for _, r := range dnatRules {
		// dnat：辖区=后端 IP；白名单语义恒真（API 强制），发布行必然依赖兜底拒绝
		if bip, _, ok := splitHostPortOK(r.TargetAddr); ok && !seen["b:"+bip] {
			seen["b:"+bip] = true
			dnatBackends = append(dnatBackends, bip)
		}
		denied = true
	}
	// 出口实体同样定义受管范围：没有 snat 规则但配了出口时也要拒绝未声明流量，
	// 否则"只配出口不配规则"会退回全放行路由器。
	// 只有在 snat 规则完全没有定义辖区（无任何 snat 规则）时才用出口网卡兜底——
	// 有规则时辖区以规则的入口网卡为准，不额外扩大（避免误伤不经规则的旁路转发）。
	var egs []model.Egress
	if err := m.db.Where("enabled = ?", true).Find(&egs).Error; err != nil {
		return nil, nil, false, err
	}
	if len(egs) > 0 {
		denied = true
		if len(ifaces) == 0 {
			for _, e := range egs {
				ifn := strings.TrimSpace(e.Iface)
				if ifn != "" && !seen["i:"+ifn] {
					seen["i:"+ifn] = true
					ifaces = append(ifaces, ifn)
				}
			}
		}
	}
	return ifaces, dnatBackends, denied, nil
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

// purgeOrphanNFTRules nft 形态启动对账。
//
// **事故后的重写（2026-10-30，docs/incident-2026-10-30-orphan-reconcile.md）**
//
// 旧判据是「内核里有 haweb-nft 标记、但我的库里没有对应启用规则 = 孤儿」。
// 这个判据只在「内核里只有我自己装的规则」时成立。后果：用空库在生产机
// 启动一个测试实例，它把生产的所有 SNAT/DNAT 规则全判成孤儿拆掉，
// 转发面规则清空约 2 分钟。
//
// 新逻辑（方案 A + C）：
//
//  1. **按实例过滤**：只考虑 instance 等于本实例的规则。别的实例的规则
//     （含旧格式 `haweb-nft:<kind>:<id>`）一律跳过——它们不是我的孤儿。
//  2. **默认只告警不删**（方案 C）：即使确认是本实例的孤儿，也只在
//     `tuning.nft_reconcile_purge=true` 时才真删。默认行为是打印告警。
//     理由：孤儿残留只占几条规则的空间，误拆会断网。两种错误的代价不对称。
//  3. **实例 ID 为空时不拆除**：无法证明归属时，宁可留着。
//
// 需要清理旧孤儿时用显式运维动作（重建规则或手工删），不在启动路径自动做。
func (m *Manager) purgeOrphanNFTRules() {
	conn, err := m.nftConn()
	if err != nil {
		logf("[snat] nft 启动对账跳过（引擎连接不可用）: %v", err)
		return
	}
	instance := m.InstanceID()
	if instance == "" {
		// 方案 C 的一部分：没有实例 ID 就无法证明归属，绝不拆除。
		logf("[snat] nft 启动对账跳过（未启用实例隔离，无法证明规则归属）")
		return
	}
	m.nftApplyMu.Lock()
	defer m.nftApplyMu.Unlock()
	installed, err := conn.InstalledIDsByInstance(instance)
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
	var orphans []uint
	for _, kind := range []string{nft.KindSNAT, nft.KindDNAT} {
		for id := range installed[kind] {
			if live[id] {
				continue
			}
			orphans = append(orphans, id)
		}
	}
	if len(orphans) == 0 {
		m.reinstallDefaultDenyLocked(conn)
		return
	}
	if !m.opts().NFTPurgeOrphans {
		// 方案 C：默认只告警。孤儿残留只浪费几条规则，误拆会断网。
		logf("[snat] nft 启动对账发现 %d 条本实例孤儿规则 %v（未拆除：%s）",
			len(orphans), orphans, "tuning.nft_reconcile_purge 未开启")
		m.reinstallDefaultDenyLocked(conn)
		return
	}
	var purged []uint
	for _, kind := range []string{nft.KindSNAT, nft.KindDNAT} {
		for id := range installed[kind] {
			if live[id] {
				continue
			}
			if err := conn.PurgeByCommentFor(instance, kind, id); err == nil {
				purged = append(purged, id)
			}
		}
	}
	if len(purged) > 0 {
		logf("[snat] nft 启动对账：已拆除 %d 条本实例孤儿规则: %v", len(purged), purged)
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
