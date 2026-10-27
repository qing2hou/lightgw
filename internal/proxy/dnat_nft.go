// dnat 规则的 nftables 后端（M2/T102-T104）：Manager 生命周期接线。
// 装拆走 installDNATNFT/teardownDNATNFT（与 snat 同纪律：标记盲拆兜底、
// 失败回滚、nftApplyMu 互斥）；健康联动复用 health.go 的探测结果
// （后端不可达→卸载发布行+计数拒新；恢复→重装）。
package proxy

import (
	"fmt"
	"net"
	"strings"

	vnetlink "github.com/vishvananda/netlink"

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
		// 引用名单组时取组条目（同模式白名单组或中性 IP 组，条目即白名单）
		if rule.AclGroupID != 0 {
			var g model.AclGroup
			if err := m.db.First(&g, rule.AclGroupID).Error; err == nil &&
				model.AclGroupMatchesMode(g.Mode, model.AclModeWhitelist) {
				allow = g.Entries
			} else if err == nil {
				logf("规则[%s#%d] 引用的名单组#%d 与白名单模式不兼容（dnat），按无白名单处理",
					rule.Name, rule.ID, rule.AclGroupID)
				allow = ""
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
	// DEFECT-5：hairpin SNAT 源 = 后端路由出口网卡的 IP
	hairpin := ""
	if bip != "" {
		if ifn, _, err := routeIfaceOf(bip); err == nil && ifn != "" {
			hairpin = ipv4Of(ifn)
		}
	}
	return &fw.DNatSpec{
		ID: rule.ID, IfIn: ifInOf(lip), HairpinIP: hairpin,
		ListenIP: lip, ListenPort: lport,
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

	// 拆旧（注册表注销 + 两个 kind 标记盲拆——KindSNAT 复用是协议切换
	// 场景的兜底：从 snat 改成 dnat 时旧 KindSNAT 行残留）
	m.mu.Lock()
	if _, hadOld := m.snatRules[rule.ID]; hadOld || !rule.Enabled {
		delete(m.snatRules, rule.ID)
	}
	m.mu.Unlock()
	m.teardownSnatNFT(rule.ID)
	m.teardownDNATNFT(rule.ID)
	m.teardownDnatSilentDrop(rule.ID)
	if !rule.Enabled {
		m.killDNATSessions(spec)
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

// killDNATSessions 停用 dnat 时掐断本规则的存量发布会话（AC-2.5）。
// 锚点：orig dst = 发布 IP:端口（本规则的发布会话唯一特征——conntrack 表项
// 在 DNAT 前的 orig 元组）。复用 readConntrackTable/deleteConntrackEntry
// 的解析/删除路径；源未知的会话（conntrack 工具缺失）走老化兜底。
func (m *Manager) killDNATSessions(spec *fw.DNatSpec) {
	if spec == nil {
		return
	}
	lines := readConntrackTable()
	if lines == nil {
		logf("规则#%d 停用：conntrack 表不可读，存量发布会话将随老化断开", spec.ID)
		return
	}
	dst := net.JoinHostPort(spec.ListenIP, fmt.Sprintf("%d", spec.ListenPort))
	host, port, _ := net.SplitHostPort(dst)
	killed := 0
	for _, ln := range lines {
		c, ok := parseConntrackLine(ln)
		if !ok {
			continue
		}
		// 发布会话：orig dst == 发布 IP:端口（DNAT 前）
		if c.origDst != host || c.origDPort != port {
			continue
		}
		s := &snatRuleSpec{ID: spec.ID}
		if deleteConntrackEntry(s, c) {
			killed++
		}
	}
	if killed > 0 {
		logf("规则#%d 停用：已掐断 %d 条发布会话（发布 %s）", spec.ID, killed, dst)
	}
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

// dnatHealthToggle T104 健康联动：down → 卸载发布行；up → 重装。
// 卸载=按标记拆 dn at 全部形态（发布端口立即黑洞/拒绝——不再转发到死后端）；
// 重装=重新走 applyDNAT（校验+装载+统计）。
func (m *Manager) dnatHealthToggle(rule model.ForwardRule, up bool) {
	if up {
		// 复审窄竞态：探测期间规则可能已被禁用/删除（探测用的是旧快照）——
		// 动手前重读 DB，非启用态直接放弃重装（否则装回后无人拆卸直到重启）
		var cur model.ForwardRule
		if err := m.db.First(&cur, rule.ID).Error; err != nil || !cur.Enabled {
			return
		}
		// 评审 #3：不能走 applyDNAT 快路径——健康卸载只拆了内核行、注册表
		// 条目仍在，sameForwarding 恒真会直接 return（发布永不重装）。
		// 恢复=强制拆除（含注册表 + timeout 静默丢弃行）后全量重装。
		spec := m.buildDNATSpec(rule)
		m.mu.Lock()
		delete(m.snatRules, rule.ID)
		m.mu.Unlock()
		m.teardownDnatSilentDrop(spec.ID)
		if err := m.applyDNAT(rule); err != nil {
			logf("规则[%s#%d] 后端恢复但发布重装失败: %v", rule.Name, rule.ID, err)
			return
		}
		logf("规则[%s#%d] 后端恢复，发布已重新装载", rule.Name, rule.ID)
		_ = spec
		return
	}
	m.mu.Lock()
	delete(m.snatRules, rule.ID) // down 时同步注销（评审 #3：up 侧 sameForwarding 判定的前提）
	m.mu.Unlock()
	m.teardownDNATNFT(rule.ID)
	// 评审 #9：timeout 模式的静默丢弃——发布卸载后 SYN 进 INPUT 会回 RST
	// （=reject 表现）；timeout 语义要求丢弃，补 input 方向 drop 行
	spec := m.buildDNATSpec(rule)
	if spec.RejectMode == model.DnatRejectModeTimeout {
		if conn, err := m.nftConn(); err == nil {
			m.nftApplyMu.Lock()
			dropRules := fw.CompileDnatSilentDrop(*spec)
			for _, r := range dropRules {
				conn.AddCompiled(r.Chain, r.Rule)
			}
			if err := conn.FlushCommit(); err != nil {
				logf("规则[%s#%d] timeout 模式静默丢弃行装载失败: %v", rule.Name, rule.ID, err)
			}
			m.nftApplyMu.Unlock()
		}
	}
	logf("规则[%s#%d] 后端不可达，发布已卸载（存量客户端会话随 conntrack 老化）", rule.Name, rule.ID)
}

// teardownDnatSilentDrop 拆 timeout 模式静默丢弃行（按 KindDnatDrop 标记）。
func (m *Manager) teardownDnatSilentDrop(ruleID uint) {
	m.nftApplyMu.Lock()
	defer m.nftApplyMu.Unlock()
	m.nftMu.Lock()
	conn := m.nft
	m.nftMu.Unlock()
	if conn == nil {
		return
	}
	if err := conn.PurgeByComment(nft.KindDnatDrop, ruleID); err != nil {
		logf("规则#%d 静默丢弃行拆除失败: %v", ruleID, err)
	}
}

// ReadDNATCountersNFT dnat 规则计数快照（P2-2：API 摘要用；KindDNAT 标记）。
func (m *Manager) ReadDNATCountersNFT(ruleID uint, allowSrcs []string) *snatCounters {
	m.nftMu.Lock()
	conn := m.nft
	m.nftMu.Unlock()
	if conn != nil {
		m.nftApplyMu.Lock()
		res, err := conn.CountersByComment()
		m.nftApplyMu.Unlock()
		if err == nil {
			if pair, ok := res.ByRule[nft.Comment(nft.KindDNAT, ruleID)]; ok {
				return &snatCounters{
					PktsAccept: int64(pair.Accept.Packets), BytesAccept: int64(pair.Accept.Bytes),
					PktsDrop: int64(pair.Drop.Packets), BytesDrop: int64(pair.Drop.Bytes),
				}
			}
			return &snatCounters{} // 引擎在位但读不到该规则（未启用）
		}
	}
	return nil // 降级：dnat 无 exec 口径，返回 nil 由调用方标注 unknown
}

// localIfacesOf 持有指定 IP 的网卡名列表（发布地址归属查找）。
func localIfacesOf(ip string) []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.String() == ip {
				out = append(out, i.Name)
			}
		}
	}
	return out
}

// ifInOf 发布 IP 所在的首个网卡名（无则空）。
func ifInOf(ip string) string {
	if l := localIfacesOf(ip); len(l) > 0 {
		return l[0]
	}
	return ""
}

// routeIfaceOf 目标 IP 从本机出发的路由出口网卡名（hairpin IP 计算用——DEFECT-5）。
// 取后端真实转发出口（而非发布地址所在网卡），保证对端回程同段直达本机。
func routeIfaceOf(dstIP string) (string, net.IP, error) {
	ip := net.ParseIP(dstIP)
	if ip == nil {
		return "", nil, fmt.Errorf("非法 IP %q", dstIP)
	}
	routes, err := vnetlink.RouteList(nil, vnetlink.FAMILY_V4)
	if err != nil {
		return "", nil, err
	}
	var best *vnetlink.Route
	for i := range routes {
		r := &routes[i]
		if r.Dst != nil && !r.Dst.IP.Equal(net.IPv4zero) && r.Dst.Contains(ip) {
			best = r // 最长前缀已由内核排好序（RouteList 返回内核序）
			break
		}
		if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) {
			if best == nil {
				best = r // default 兜底
			}
		}
	}
	if best == nil {
		return "", nil, fmt.Errorf("无到 %s 的路由", dstIP)
	}
	ifn, err := vnetlink.LinkByIndex(best.LinkIndex)
	if err != nil {
		return "", nil, err
	}
	return ifn.Attrs().Name, best.Src, nil
}
