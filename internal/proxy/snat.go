package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"haproxyweb/internal/model"
	"haproxyweb/internal/nft"
)

// timeNewTicker 时间源（独立变量便于单测注入假时钟）。
var timeNewTicker = time.NewTicker

// SNAT 规则（协议 snat）：入口网卡进入的转发流量经出口网卡 SNAT 出去。
// 全部 iptables/tc 规则以 "haweb-sn:<ruleID>" comment 标记，删除按标记精确匹配，
// 绝不 flush 整链（与 docker/firewalld 等外来规则和平共处）。
//
// 形态：
//   nat 表 POSTROUTING：-o <out> [-s <名单>] -j SNAT --to-source <outIP>   （标记）
//   filter 表 FORWARD：  -i <in> -o <out> [-s <名单>] -j ACCEPT            （标记）
//   filter 表 FORWARD：  -i <in> -o <out> -j DROP（仅在配置白名单时兜底）   （标记）
//   tc ingress：        -i <in> total 闸 police rate（仅限速>0 时）         （标记，ftag）

const (
	snatCommentPrefix = "haweb-sn:"
	snatTcFtag        = "haweb_sn_rate"
)

// snatEntry 一条 SNAT/DNAT 规则的运行时对象（dnat 复用注册表）。
type snatEntry struct {
	ruleID    uint
	dnat      bool // dnat 规则（ifIn=发布IP、ifOut=后端IP 的复用语义）
	ifIn      string
	ifOut     string
	outIP     string   // 安装时的 SNAT 源地址（拆除需要完整形态匹配）
	rtTable   int      // 专属出口路由表号（0 = 无 egress 路由）
	egressGw  string   // 安装时的出口网关（快速路径比对用）
	allowSrcs []string // 白名单源（计数读 per-源 class 求和用）
	dstMode   string   // 目标名单模式（off/whitelist/blacklist；快速路径比对用）
	dstDeny   []string
	dstAllow  []string
}

// sameForwarding 转发形态（iptables 行 + 策略路由 + tc 挂载点）是否与 spec 一致：
// 一致时 applySNAT 可走零中断快速路径（只重做 tc 参数，不碰 iptables/路由）。
// 比对项 = 影响 iptables 行与路由表的全部字段；限速参数（额度/保底）刻意不比
// ——它们只进 tc，class replace 是热替换、不中断既有流。路由表 rtTable 不比：
// EgressGw 一致则既有表内容仍正确，保留在位。
func (e *snatEntry) sameForwarding(s *snatRuleSpec) bool {
	if e.ifIn != s.IfIn || e.ifOut != s.IfOut || e.outIP != s.OutIP || e.egressGw != s.EgressGw {
		return false
	}
	// 源名单逐项一致（顺序变化不影响语义，比对集合）
	if !sameStringSet(e.allowSrcs, s.AllowSrcs) {
		return false
	}
	// 目标名单一致
	if e.dstMode != s.DstAclMode {
		return false
	}
	switch s.DstAclMode {
	case model.AclModeWhitelist:
		if !sameStringSet(e.dstAllow, s.DstAllow) {
			return false
		}
	case model.AclModeBlacklist:
		if !sameStringSet(e.dstDeny, s.DstDeny) {
			return false
		}
	}
	return true
}

// sameStringSet 无序集合相等（nil 与空集视为相等）。
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, x := range a {
		seen[x] = true
	}
	for _, y := range b {
		if !seen[y] {
			return false
		}
	}
	return true
}

// spec 还原安装时的参数形态（拆除与计数用）。
func (e *snatEntry) spec() *snatRuleSpec {
	return &snatRuleSpec{ID: e.ruleID, IfIn: e.ifIn, IfOut: e.ifOut, OutIP: e.outIP,
		RtTable: e.rtTable, EgressGw: e.egressGw,
		AllowSrcs: e.allowSrcs, DstAclMode: e.dstMode, DstDeny: e.dstDeny, DstAllow: e.dstAllow}
}

// buildSnatSpec 由 ForwardRule 构建安装参数（源/目标名单均支持引用名单组）。
func (m *Manager) buildSnatSpec(rule model.ForwardRule) *snatRuleSpec {
	allow := rule.AllowList
	if rule.AclMode == model.AclModeWhitelist && rule.AclGroupID != 0 {
		var g model.AclGroup
		if err := m.db.First(&g, rule.AclGroupID).Error; err == nil && model.AclGroupMatchesMode(g.Mode, model.AclModeWhitelist) {
			allow = g.Entries
		} else {
			logf("规则[%s#%d] 引用的名单组#%d 失效（snat），按无白名单处理", rule.Name, rule.ID, rule.AclGroupID)
			allow = ""
		}
	}
	if rule.AclMode != model.AclModeWhitelist {
		allow = "" // off/旧语义：全放行
	}
	var srcs []string
	if b := strings.TrimSpace(allow); b != "" {
		if err := jsonUnmarshalStrings(b, &srcs); err != nil {
			logf("规则[%s#%d] 白名单解析失败（snat），按无白名单处理: %v", rule.Name, rule.ID, err)
			srcs = nil
		}
	}
	// 出口 SNAT 源地址：显式 snat_ip 优先（一卡多址下固化选择）；
	// 空 = 自动跟随出口网卡首个 IPv4，v6-only 网卡回落首个非 link-local v6
	// （v6 自动档——v6-only 出口的常见路径，复审 B8 缺口修复）
	outIP := strings.TrimSpace(rule.SnatIP)
	if outIP == "" {
		outIP = ipv4Of(rule.TargetAddr)
	}
	if outIP == "" {
		outIP = ipv6Of(rule.TargetAddr)
	}
	// 安全默认（API 已强校验，这里是直改库/导入的兜底）：无源名单的 snat
	// 不放行任何流量（AllowSrcs 为空时 iptables 形态退化为仅 conntrack 回程行
	// + 无 -s 的 DROP——为保持"不指定就不通"，把空的 AllowSrcs 特殊化为
	// 一个不匹配任何真实源的黑洞名单）。目标黑名单同样要求源：无源的黑名单
	// DROP 会误伤同网卡全部规则的转发（v2 事故同型），一并黑洞化。
	// 目标黑名单可能来自直配或名单组引用（组的有效性在下方展开时判定，
	// 这里只需知道"是否配了目标黑名单"）。
	hasDstDeny := len(parseIPListOrEmpty(rule.DstDenyList)) > 0 || rule.DstAclGroupID != 0
	needSrcs := rule.AclMode == model.AclModeWhitelist ||
		(strings.TrimSpace(rule.DstAclMode) == model.AclModeBlacklist && hasDstDeny)
	if len(srcs) == 0 && needSrcs {
		srcs = []string{"0.0.0.0/32"} // /32 的全零地址：不匹配任何正常源
	}
	// 带宽包成员：出向限速与保底改用包级配置（规则自身限速/保底字段忽略——限速统一在包）
	bwKBps, bwMinKBps := int64(0), int64(0)
	if rule.BWGroupID != 0 {
		var bg model.BWGroup
		if err := m.db.First(&bg, rule.BWGroupID).Error; err == nil {
			bwKBps = bg.TotalKBps
			bwMinKBps = bg.MinKBps
		} else {
			logf("规则[%s#%d] 引用的带宽包#%d 失效，按无限速处理", rule.Name, rule.ID, rule.BWGroupID)
		}
	}
	// T207：SNAT 源池解析（rotate/sticky 模式；成员归属出口网卡在 API 层强校验，
	// 引擎侧降级：非法成员剔除，全部非法则退回 fixed OutIP）
	var pool []string
	switch strings.TrimSpace(rule.SnatMode) {
	case "rotate", "sticky":
		var members []string
		if b := strings.TrimSpace(rule.SnatPool); b != "" {
			if err := jsonUnmarshalStrings(b, &members); err != nil {
				logf("规则[%s#%d] SNAT 池解析失败，退回固定源: %v", rule.Name, rule.ID, err)
			}
		}
		for _, m := range members {
			m = strings.TrimSpace(m)
			if net.ParseIP(m) == nil {
				continue
			}
			// S2：运行时归属复验——成员已从出口网卡移除时剔除（静默黑洞防护，
			// 与单 IP SnatIP 的复验同语义）；v4/v6 双族（v6 池走 NAT66）；
			// 全失效则退回 fixed
			belongs := false
			for _, v4 := range InterfaceIPv4s(rule.TargetAddr) {
				if v4 == m {
					belongs = true
					break
				}
			}
			if !belongs {
				for _, v6 := range InterfaceIPv6s(rule.TargetAddr) {
					if v6 == m {
						belongs = true
						break
					}
				}
			}
			if belongs {
				pool = append(pool, m)
			}
		}
		if len(pool) == 0 && len(members) > 0 {
			logf("规则[%s#%d] SNAT 池全部成员已不归属出口网卡 %s，退回固定源", rule.Name, rule.ID, rule.TargetAddr)
		}
	}
	// 目标名单：引用名单组时展开组条目（同模式组或中性 IP 组；组失效则回退
	// 直配——直配在引用组时被 API 强制为空，回退即"无目标限制"，是唯一可用的
	// 降级语义，且必须留日志线索）
	dstMode := strings.TrimSpace(rule.DstAclMode)
	dstAllowJSON, dstDenyJSON := rule.DstAllowList, rule.DstDenyList
	if rule.DstAclGroupID != 0 && (dstMode == model.AclModeWhitelist || dstMode == model.AclModeBlacklist) {
		var g model.AclGroup
		if err := m.db.First(&g, rule.DstAclGroupID).Error; err == nil && model.AclGroupMatchesMode(g.Mode, dstMode) {
			if dstMode == model.AclModeWhitelist {
				dstAllowJSON = g.Entries
			} else {
				dstDenyJSON = g.Entries
			}
		} else {
			logf("规则[%s#%d] 目标限制引用的名单组#%d 失效（snat），按无目标限制处理", rule.Name, rule.ID, rule.DstAclGroupID)
		}
	}
	return &snatRuleSpec{
		ID:           rule.ID,
		IfIn:         rule.ListenAddr, // snat 行复用：listen_addr=入口网卡
		IfOut:        rule.TargetAddr, // target_addr=出口网卡
		OutIP:        outIP,
		AllowSrcs:    srcs,
		DstAclMode:   dstMode,
		DstAllow:     parseIPListOrEmpty(dstAllowJSON),
		DstDeny:      parseIPListOrEmpty(dstDenyJSON),
		LimitKbps:    rule.UploadLimitKBps,
		DownloadKbps: rule.DownloadLimitKBps,
		BWGroupKBps:  bwKBps,
		MinKBps:      bwMinKBps, // 包级每源保底（0=默认 1024）
		EgressGw:     strings.TrimSpace(rule.EgressGw),
	}
}

// jsonUnmarshalStrings JSON 字符串数组反序列化。
func jsonUnmarshalStrings(s string, out *[]string) error {
	return json.Unmarshal([]byte(s), out)
}

// parseIPListOrEmpty 解析 JSON 字符串数组（非法/空串安全返回 nil）。
// 引擎侧兜底解析（API 层已强校验；这里是直改库/导入数据的降级路径）。
func parseIPListOrEmpty(jsonStr string) []string {
	if strings.TrimSpace(jsonStr) == "" {
		return nil
	}
	var out []string
	if err := jsonUnmarshalStrings(jsonStr, &out); err != nil {
		return nil
	}
	return out
}

// osReadFile/osWriteFile 独立变量便于测试桩替换（不引入全局 mock 框架）。
var (
	osReadFile  = os.ReadFile
	osWriteFile = func(name string, data []byte, perm os.FileMode) error { return os.WriteFile(name, data, perm) }
)

// applySNAT 应用一条 snat 规则（Manager.Apply 的 snat 分支）。
// 顺序：拆旧形态（含盲拆兜底）→（启用时）ip_forward 确保 → 安装 iptables → 挂 tc 限速 → 注册条目。
// 幂等关键：安装前总是按 comment 盲拆本规则全部形态（无论引擎是否记得上一代 spec——
// 热升级/规则改配置循环下 old.spec 形态可能与残余形态不一致，只按旧形态 -D 会漏拆而叠加双份）。
//
// 零中断快速路径：规则启用中且 iptables/路由形态参数不变（网卡/SNAT源/出口网关/
// 源名单/目标名单——tc 限速参数除外）时，只重做 tc 整形、完全不碰 iptables。
// 动机：FORWARD policy DROP 的机器上全拆重装存在黑洞窗口，存量 TCP 被丢包 →
// 对端 RST（实测：调带宽包额度即触发大流量下载断流）。
// tc 的 htb 参数改额度/保底是热替换（class replace），不中断既有流。
func (m *Manager) applySNAT(rule model.ForwardRule) error {
	spec := m.buildSnatSpec(rule)

	if rule.Enabled {
		m.mu.Lock()
		old := m.snatRules[rule.ID]
		m.mu.Unlock()
		// 快速路径判定：引擎记得上一代 + 转发形态参数全部一致 + 无出口脏标记
		// （B1：出口 up/down 翻转与 egress_ids 变更不在 sameForwarding 维度内，
		//  由 egressDirty 强制全路径——否则切换/回切/分担变化全部被吞）
		if old != nil && !m.egressDirty.Load() && old.sameForwarding(spec) {
			if err := spec.applySnatLimit(); err != nil {
				logf("规则[%s#%d] tc 限速重建失败（保持原限速）: %v", rule.Name, rule.ID, err)
			} else if spec.BWGroupKBps > 0 {
				logf("规则[%s#%d] 带宽参数已热更新（iptables 未动，存量连接不受影响）", rule.Name, rule.ID)
			}
			return nil
		}
	}

	// 拆旧（双保险：引擎记忆的旧形态精确拆 + comment 盲拆兜底）
	m.mu.Lock()
	old, hadOld := m.snatRules[rule.ID]
	if hadOld || !rule.Enabled {
		delete(m.snatRules, rule.ID)
	}
	m.mu.Unlock()
	if old != nil {
		s := old.spec()
		s.teardownSnat()
		m.teardownSnatNFT(rule.ID)
		_ = s.teardownSnatLimit()
		m.teardownEgressRouteNFT(s.RtTable)
		s.teardownEgressRoute() // exec 兜底（netlink 版失败/引擎不可用时）
		// 停用/删除时掐断本规则的存量穿越会话：iptables 拆除后，基线的
		// conntrack-ESTABLISHED 放行行会让已建连接继续跑到自然结束
		// （不限速、不受名单约束——实测 3.9G 下载停用后满速跑完）。
		// 停用语义要求"关闸即断"：按规则维度精确删 conntrack 表项，
		// 其他规则的源与会话不受影响（跨规则源重叠段只剔除不删）。
		if !rule.Enabled {
			s.killConntrackSessions(m.otherSnatRuleSrcs(rule.ID))
		}
	}
	if !rule.Enabled {
		return nil
	}
	// 盲拆兜底（幂等）：清除本规则 ID 的任何残余形态后再装，杜绝叠加
	snatPurgeByComment(rule.ID)

	if up, _ := InterfaceExists(spec.IfIn); !up {
		return fmt.Errorf("入口网卡 %s 不存在或未启用", spec.IfIn)
	}
	if up, _ := InterfaceExists(spec.IfOut); !up {
		return fmt.Errorf("出口网卡 %s 不存在或未启用", spec.IfOut)
	}
	// 显式 snat_ip 归属复验（保存后网卡地址可能被运维变更）：
	// 装一个已不属于本机的源地址会静默黑洞（出向可达、回程路由给真正持有人）——fail-fast
	if strings.TrimSpace(rule.SnatIP) != "" {
		belongs := false
		for _, v4 := range InterfaceIPv4s(spec.IfOut) {
			if v4 == strings.TrimSpace(rule.SnatIP) {
				belongs = true
				break
			}
		}
		if !belongs {
			return fmt.Errorf("SNAT 源 IP %s 已不在出口网卡 %s 上（网卡地址已变更？），已停用规则——请重新选择", rule.SnatIP, spec.IfOut)
		}
	}
	// 入口/出口同卡是合法的（单臂网关）：上游把网关指向本机同一网卡的地址，
	// 转发后再从该网卡发出。nft 侧 iif==oif 正常匹配；tc 限速在该网卡上
	// 同时承担下载（daddr=源）与上传（saddr=OutIP）两类 filter，二者 pref
	// 由 applySnatLimit 按方向分段，不会互相覆盖。
	if err := ensureIPForward(); err != nil {
		return err
	}
	// 同卡时必须关闭该网卡的 ICMP redirect 发送：内核看到"入口==出口且同网段"
	// 会直接回 ICMP redirect 让发送方绕开本机直连（实测路由缓存标记 <redirect>，
	// 包根本不进 FORWARD，规则计数恒为 0），单臂网关因此完全不转发。
	if spec.IfIn == spec.IfOut {
		if err := ensureNoSendRedirects(spec.IfIn); err != nil {
			// 不阻断主功能：部分环境（容器/只读 procfs）写不了，留痕即可
			logf("规则[%s#%d] 同卡部署需关闭 %s 的 send_redirects，写入失败（同网段目标可能不转发）: %v",
				rule.Name, rule.ID, spec.IfIn, err)
		}
	}
	// nftables 后端（T004）：fw 编译经 netlink 装载；旧 iptables 形态由
	// T006 启动迁移拆除，此处双形态拆除中 iptables 拆除仅作兜底（升级过渡期）
	spec.teardownSnatLegacy()
	if err := m.installSnatNFT(spec); err != nil {
		return err
	}
	if err := spec.applySnatLimit(); err != nil {
		// 限速失败不阻塞主功能：iptables 已装好，限速降级（状态里留痕）
		logf("规则[%s#%d] tc 入向限速未生效（降级为不限速）: %v", rule.Name, rule.ID, err)
	}
	// 出口策略路由（M3/T203/T204 优先走出口实体多路决策；无出口绑定时回落
	// 旧单网关形态——EgressGw 直配，兼容既有数据）：
	//   有 Egress 实体且规则未显式绑出口 → 全部启用出口的最大可用层 multipath
	//   规则显式绑 egress_ids → 绑定出口集的最大可用层
	//   无出口实体且配置 EgressGw → 单网关（v1 形态）
	{
		boundIDs := egressIDsOfRule(rule)
		var egCount int64
		m.db.Model(&model.Egress{}).Where("enabled = ?", true).Count(&egCount)
		hasEgressEntities := egCount > 0
		if hasEgressEntities {
			// 出口实体存在时统一走多出口模型（显式 EgressGw 仍优先直配？——
			// 产品语义：EgressGw 是出口实体化之前的旧字段；出口实体在场时以实体为准
			nexthops := m.egressNexthops(rule.ID, boundIDs)
			if len(nexthops) > 0 {
				spec.RtTable = m.snatAllocTable(rule.ID)
				if conn, cerr := m.nftConn(); cerr == nil {
					if rerr := conn.EnsureEgressRoute(spec.RtTable, spec.AllowSrcs, nexthops); rerr != nil {
						logf("规则[%s#%d] 多出口路由未生效（公网目标穿越可能不通）: %v", rule.Name, rule.ID, rerr)
						spec.RtTable = 0
					}
				}
			} else {
				logf("规则[%s#%d] 无可用出口（全部出口 down 或无绑定出口启用）——公网目标穿越不通", rule.Name, rule.ID)
			}
		} else if strings.TrimSpace(rule.EgressGw) != "" {
			// v6 出口网关：v6 策略路由表在 T205（v6 multipath/request 表）——
			// v4 表装不下 v6 nexthop，错误配置比没有更坏；SNAT66 本身照装
			if gwIP := net.ParseIP(strings.TrimSpace(rule.EgressGw)); gwIP != nil && gwIP.To4() == nil {
				logf("规则[%s#%d] v6 出口网关 %s 的策略路由将在后续版本支持（SNAT66 本身不受影响）", rule.Name, rule.ID, rule.EgressGw)
			} else {
				spec.RtTable = m.snatAllocTable(rule.ID)
				if conn, cerr := m.nftConn(); cerr == nil {
					nexthops := []nft.Nexthop{{Iface: spec.IfOut, Gw: net.ParseIP(spec.EgressGw), Weight: 1}}
					if rerr := conn.EnsureEgressRoute(spec.RtTable, spec.AllowSrcs, nexthops); rerr != nil {
						logf("规则[%s#%d] 出口策略路由未生效（公网目标穿越可能不通）: %v", rule.Name, rule.ID, rerr)
						spec.RtTable = 0
					}
				}
			}
		}
	}
	m.statsFor(rule) // 建统计条目
	m.mu.Lock()
	m.snatRules[rule.ID] = &snatEntry{ruleID: rule.ID, ifIn: spec.IfIn, ifOut: spec.IfOut, outIP: spec.OutIP, rtTable: spec.RtTable, egressGw: spec.EgressGw,
		allowSrcs: spec.AllowSrcs, dstMode: spec.DstAclMode, dstDeny: spec.DstDeny, dstAllow: spec.DstAllow}
	m.mu.Unlock()
	return nil
}

// ensureIPForward ip_forward=0 时写 1（单向：绝不关回——其他转发可能依赖）。
func ensureIPForward() error {
	b, err := osReadFile("/proc/sys/net/ipv4/ip_forward")
	if err == nil && strings.TrimSpace(string(b)) == "1" {
		return nil
	}
	if err := osWriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("开启 net.ipv4.ip_forward 失败（snat 规则需要内核转发）: %w", err)
	}
	logf("[snat] 已自动开启 net.ipv4.ip_forward（原值为 0）")
	return nil
}

// ensureNoSendRedirects 关闭指定网卡（及 all）的 ICMP redirect 发送。
//
// 为什么同卡 SNAT 必须关：内核在"入口接口 == 出口接口且目标与源同网段"时
// 判定为次优路径，直接给发送方回 ICMP redirect 并丢弃转发意图（`ip route get`
// 的缓存标记 <redirect>），包不进 FORWARD 链——nft 的 iif==oif 放行行永远
// 不命中，单臂网关表现为"规则在位但零转发"。
//
// 只写 send_redirects，不动 accept_redirects（那是收包侧语义，与本问题无关）。
func ensureNoSendRedirects(ifName string) error {
	paths := []string{
		"/proc/sys/net/ipv4/conf/all/send_redirects",
		"/proc/sys/net/ipv4/conf/" + ifName + "/send_redirects",
	}
	var firstErr error
	changed := false
	for _, p := range paths {
		b, err := osReadFile(p)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("读取 %s 失败: %w", p, err)
			}
			continue
		}
		if strings.TrimSpace(string(b)) == "0" {
			continue
		}
		if err := osWriteFile(p, []byte("0"), 0644); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("写入 %s 失败: %w", p, err)
			}
			continue
		}
		changed = true
	}
	if changed {
		logf("[snat] 已关闭 %s 的 send_redirects（单臂网关同卡转发的必要条件）", ifName)
	}
	return firstErr
}

// snatRuleSpec 由 ForwardRule 展开出的 iptables 规则参数（校验已在前置完成）。
type snatRuleSpec struct {
	ID           uint
	Pool         []string // SNAT 源池（T207；空 = fixed）
	IfIn         string   // 入口网卡名
	IfOut        string   // 出口网卡名
	OutIP        string   // 出口网卡当前主 IP（SNAT 目标）
	AllowSrcs    []string // 源网段白名单（CIDR/IP），空 = 放行全部
	DstAclMode   string   // 目标名单模式：off / whitelist / blacklist（空 = off 兼容旧数据）
	DstAllow     []string // 目标白名单（whitelist 模式生效；iptables -d 多值是 OR 语义）
	DstDeny      []string // 目标黑名单（blacklist 模式生效；每目标一行 -j DROP，先于 ACCEPT 命中）
	LimitKbps    int64    // 入向限速 KB/s（0 = 不限；tc ingress 挂入口网卡）
	DownloadKbps int64    // 出向限速 KB/s（0 = 不限；tc egress 挂出口网卡——穿越流量的下载方向）
	BWGroupKBps  int64    // 所属带宽包合计额度 KB/s（>0 时 DownloadKbps 忽略——导入共享 class）
	MinKBps      int64    // 成员保底带宽 KB/s（htb rate；闲时借用到包总额 ceil）
	EgressGw     string   // 出口网关（可选）：非空时安装 per-规则策略路由，出向决策强制走出口网卡
	RtTable      int      // 专属路由表号（EgressGw 非空时分配）
}

// comment 统一的 iptables comment 标记。
func (s *snatRuleSpec) comment() string {
	return snatCommentPrefix + strconv.FormatUint(uint64(s.ID), 10)
}

// ipv4Of 返回网卡的第一个 IPv4 主地址（无则空串——调用方据此判失败）。
func ipv4Of(ifName string) string {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLoopback() {
				return v4.String()
			}
		}
	}
	return ""
}

// InterfaceExists 网卡存在且 UP（API 校验用）。
func InterfaceExists(name string) (bool, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false, nil
	}
	return iface.Flags&net.FlagUp != 0, nil
}

// ListInterfaces 全部网卡（含全部 IPv4 地址与状态；API /api/interfaces 用）。
// IPS 为该网卡全部 IPv4（一卡多址全列，供 SNAT 出口 IP 下拉）；老的 IP 单值
// 字段保留为首地址（向下兼容既有前端调用点）。
type IfaceInfo struct {
	Name   string   `json:"name"`
	IPS    []string `json:"ips"`
	IP     string   `json:"ip"` // 首个 IPv4（兼容字段）
	Status string   `json:"status"`
}

func ListInterfaces() []IfaceInfo {
	out := make([]IfaceInfo, 0, 8)
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		status := "down"
		if i.Flags&net.FlagUp != 0 {
			status = "up"
		}
		ips := []string{}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLoopback() {
						ips = append(ips, v4.String())
					}
				}
			}
		}
		first := ""
		if len(ips) > 0 {
			first = ips[0]
		}
		out = append(out, IfaceInfo{Name: i.Name, IPS: ips, IP: first, Status: status})
	}
	return out
}

// ipv6Of 返回网卡的第一个非 link-local IPv6（v6 自动档；无则空串）。
func ipv6Of(ifName string) string {
	for _, v6 := range InterfaceIPv6s(ifName) {
		return v6
	}
	return ""
}

// InterfaceIPv6s 返回网卡全部 IPv6（v6 SNAT 源/池归属校验用；T210/B8）。
func InterfaceIPv6s(ifName string) []string {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	out := make([]string, 0, 2)
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip := ipn.IP; ip != nil && ip.To4() == nil && ip.To16() != nil && !ip.IsLinkLocalUnicast() {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

// InterfaceIPv4s 返回网卡全部 IPv4（出口 IP 归属校验用）。
func InterfaceIPv4s(ifName string) []string {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	out := make([]string, 0, 2)
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLoopback() {
				out = append(out, v4.String())
			}
		}
	}
	return out
}

// ---------- iptables 命令拼装（无 shell，数组参数直达 exec） ----------

// iptablesArgs nat+filter 全量规则参数（安装与对账比对共用同一来源，保证幂等形态一致）。
// 顺序契约：iptables 首次命中即终止 + 调用方逐条 -I FORWARD 1 执行（后执行的行排在链更前面）。
// 因此正确的**最终链序**（自上而下）必须是：
//
//	ACCEPT  -i in -o out -s <白名单>   ← 白名单内放行（最优先命中）
//	ACCEPT  conntrack ESTABLISHED     ← 回程放行
//	DROP    -i in -o out              ← 白名单外兜底（最后）
//
// 推导数组序（数组后面的行执行后更靠前）：DROP 最前、conntrack 中间、ACCEPT(-s) 最后。
//
// 多值展开：iptables 的 -s/-d 是单值参数（多次出现报 multiple flags not allowed），
// 源白名单与目标白名单均按笛卡尔积逐条展开（每行一个源组合，链上多行 = OR 语义）。
func (s *snatRuleSpec) iptablesArgs() [][]string {
	var rules [][]string

	srcs := s.AllowSrcs
	if len(srcs) == 0 {
		srcs = []string{""} // 无源名单：单行无 -s 形态
	}

	// ① nat POSTROUTING：SNAT 到出口网卡 IP（每源一行——源白名单各条都需改写）
	for _, src := range srcs {
		nat := []string{"-t", "nat", "-I", "POSTROUTING", "1", "-o", s.IfOut}
		if src != "" {
			nat = append(nat, "-s", src)
		}
		nat = append(nat,
			"-m", "comment", "--comment", s.comment(),
			"-j", "SNAT", "--to-source", s.OutIP)
		rules = append(rules, nat)
	}

	// ② 兜底 DROP——已移除（v2）：多规则同网卡时每条的“仅本规则白名单”DROP 会挡在
	// 别家 ACCEPT 之前误伤（实测：规则28 的 DROP 拦死了规则22 的白名单源）。
	// 白名单外交给 FORWARD 链尾 policy DROP：未命中任何 haweb ACCEPT 的流量自然被丢，
	// 语义等价且天然多规则兼容。旧形态拆除由 teardownArgs 覆盖。

	// ③ 回程放行：SNAT 会话的应答包按 conntrack 已建连放行（单行，与源无关）。
	// 没有这行，FORWARD 默认策略 DROP 的机器上回程全被丢——只放行出向等于单向黑洞。
	rules = append(rules, []string{
		"-I", "FORWARD", "1",
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"-m", "comment", "--comment", s.comment(), "-j", "ACCEPT"})

	// ④ 入向 ACCEPT（源×目标白名单笛卡尔积逐行；任一行命中即放行——OR 语义）
	for _, src := range srcs {
		if len(s.DstAllow) > 0 {
			for _, d := range s.DstAllow {
				acc := []string{"-I", "FORWARD", "1", "-i", s.IfIn, "-o", s.IfOut}
				if src != "" {
					acc = append(acc, "-s", src)
				}
				acc = append(acc, "-d", d,
					"-m", "comment", "--comment", s.comment(), "-j", "ACCEPT")
				rules = append(rules, acc)
			}
		} else {
			acc := []string{"-I", "FORWARD", "1", "-i", s.IfIn, "-o", s.IfOut}
			if src != "" {
				acc = append(acc, "-s", src)
			}
			acc = append(acc, "-m", "comment", "--comment", s.comment(), "-j", "ACCEPT")
			rules = append(rules, acc)
		}
	}

	// ⑤ 目标黑名单 DROP（blacklist 模式）：每（源×目标）一行，必须带 -s 本规则源——
	// 无源 DROP 会误伤同网卡其他规则的白名单源（v2 事故同型）。排在数组 ACCEPT 之后
	// → 执行后位于链首、先于本规则 ACCEPT 命中：黑名单目标即时拒绝（含既有会话的
	// 后续包——ESTABLISHED 回程行在其下，无法借道续命）。拒绝计数经 comment 进
	// readSnatDropCounters 的 DROP 归集。
	for _, src := range srcs {
		for _, d := range s.DstDeny {
			drop := []string{"-I", "FORWARD", "1", "-i", s.IfIn, "-o", s.IfOut}
			if src != "" {
				drop = append(drop, "-s", src)
			}
			drop = append(drop, "-d", d,
				"-m", "comment", "--comment", s.comment(), "-j", "DROP")
			rules = append(rules, drop)
		}
	}

	return rules
}

// teardownArgs 拆除全部形态（比安装多覆盖历史形态：源名单、目标名单各自可能
// "曾经没有→后来加上"，两维的旧形态都要包含；comment 盲拆兜底最终保证一行不剩）。
func (s *snatRuleSpec) teardownArgs() [][]string {
	rules := s.iptablesArgs()
	if len(s.AllowSrcs) > 0 {
		// 白名单更新过或创建时无名单、后来加上名单的两种历史形态都包含：
		// iptablesArgs 只产出当前形态，另补"无源匹配"形态（曾经 off→whitelist）
		nat := []string{"-t", "nat", "-D", "POSTROUTING", "-o", s.IfOut,
			"-m", "comment", "--comment", s.comment(),
			"-j", "SNAT", "--to-source", s.OutIP}
		acc := []string{"-D", "FORWARD", "-i", s.IfIn, "-o", s.IfOut,
			"-m", "comment", "--comment", s.comment(), "-j", "ACCEPT"}
		drop := []string{"-D", "FORWARD", "-i", s.IfIn, "-o", s.IfOut,
			"-m", "comment", "--comment", s.comment(), "-j", "DROP"}
		rules = append(rules, nat, acc, drop)
	}
	if len(s.DstAllow) > 0 || len(s.DstDeny) > 0 {
		// 目标名单历史形态：曾经无 -d 的 ACCEPT（无目标名单 → whitelist/blacklist 迁移）
		// （无源形态；带源的历史形态由 iptablesArgs 当前形态 + 盲拆兜底覆盖）
		acc := []string{"-D", "FORWARD", "-i", s.IfIn, "-o", s.IfOut,
			"-m", "comment", "--comment", s.comment(), "-j", "ACCEPT"}
		rules = append(rules, acc)
	}
	return rules
}

// runQuiet 执行命令，出错返回带 stderr 的错误（iptables 失败常见于非 root）。
func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s 失败: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// teardownSnatLegacy 拆除 iptables 形态（T004 迁移过渡期兜底：升级后旧形态
// 仍在位时按标记拆除；全新部署无 iptables 二进制时静默跳过）。
// 先按已知形态 -D，再按 comment 盲拆兜底（ResidueDrop 兜底语义沿承）。
func (s *snatRuleSpec) teardownSnatLegacy() {
	if _, err := exec.LookPath("iptables"); err != nil {
		return // 无 iptables 二进制：新形态部署，无旧形态可拆
	}
	for _, args := range s.teardownArgs() {
		_ = runQuiet("iptables", args...)
	}
	snatPurgeByComment(s.ID)
}

// teardownSnat 同 teardownSnatLegacy（旧名保留——manager.go 协议切换路径调用）。
func (s *snatRuleSpec) teardownSnat() { s.teardownSnatLegacy() }

// ---------- 启动对账：清扫孤儿（DB 无对应启用规则的 haweb-sn: 标记） ----------

var snatCommentRe = regexp.MustCompile(`haweb-sn:(\d+)`)

// ruleIDsOfCommentLines 从 iptables-save 输出中收集 haweb-sn: 标记的规则 ID 集合
// （对账数据源；非 root / 无 iptables 时返回空集不报错——降级为不对账）。
func snatInstalledRuleIDs() map[uint]bool {
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		return nil
	}
	return snatIDsFromSave(string(out))
}

// snatIDsFromSave 纯解析（测试直接喂 iptables-save 样例）。
func snatIDsFromSave(save string) map[uint]bool {
	ids := map[uint]bool{}
	for _, line := range strings.Split(save, "\n") {
		m := snatCommentRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if id, err := strconv.ParseUint(m[1], 10, 32); err == nil {
			ids[uint(id)] = true
		}
	}
	return ids
}

// ReconcileSnatTC 启动重启对账：tc 侧全清重建（此刻无监听/无规则，安全窗口）。
// 应用侧 teardown 已改为"只删自己的 filter、保留网卡 root"（防同卡互拆）——
// 意味着下线规则的 class/孤儿 ingress 会留存；重启对账清根。
func (m *Manager) ReconcileSnatTC() {
	ifaces := map[string]bool{}
	var rules []model.ForwardRule
	m.db.Where("protocol = ? AND enabled = ?", "snat", true).Find(&rules)
	for _, r := range rules {
		ifaces[r.ListenAddr] = true
	}
	for ifn := range ifaces {
		_ = runQuiet("tc", "qdisc", "del", "dev", ifn, "ingress")
		_ = runQuiet("tc", "qdisc", "del", "dev", ifn, "root")
	}
}

// PurgeOrphanSnatRules 启动对账：iptables 里带 haweb-sn: 标记但 DB 中不存在对应
// 启用 snat 规则的，全部按标记精确拆除（进程崩溃未清理的残留在此归零）。
// 返回清理的规则 ID 列表（供日志/测试）。
func (m *Manager) PurgeOrphanSnatRules() []uint {
	installed := snatInstalledRuleIDs()
	if len(installed) == 0 {
		return nil
	}
	// 从 DB 直接确认：启用的 snat 规则集合
	live := map[uint]bool{}
	var rules []struct{ ID uint }
	m.db.Raw("SELECT id FROM forward_rules WHERE protocol = 'snat' AND enabled = 1").Scan(&rules)
	for _, r := range rules {
		live[r.ID] = true
	}
	var purged []uint
	for id := range installed {
		if live[id] {
			continue
		}
		snatPurgeByComment(id)
		purged = append(purged, id)
	}
	return purged
}

// snatPurgeByComment 按标记盲拆：遍历两链全部规则行，comment 命中的以行号 -D。
func snatPurgeByComment(ruleID uint) {
	comment := snatCommentPrefix + strconv.FormatUint(uint64(ruleID), 10)
	// NAT 链与 FORWARD 链按行号从大到小删（行号变化安全）
	for _, table := range []string{"nat", "filter"} {
		chain := "FORWARD"
		if table == "nat" {
			chain = "POSTROUTING"
		}
		// 单规则 filter 行数上界：源白名单 1 + conntrack 1 + 目标黑名单 N（API 层
		// 未限目标条数）——256 轮防御上限（覆盖 ~250 条目标；超出由启动对账兜底）
		for round := 0; round < 256; round++ {
			out, err := exec.Command("iptables", "-t", table, "-L", chain, "--line-numbers", "-n").Output()
			if err != nil {
				return
			}
			lineNo := ""
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, comment) {
					f := strings.Fields(line)
					if len(f) >= 1 {
						lineNo = f[0]
					}
					break
				}
			}
			if lineNo == "" {
				break
			}
			if err := runQuiet("iptables", "-t", table, "-D", chain, lineNo); err != nil {
				return
			}
		}
	}
}

// ---------- tc 入向限速（ADR-2：ingress qdisc total 闸） ----------

// applySnatLimit 在入口网卡挂 ingress 限速总闸（替换式：先拆旧再挂新）。
// 限速语义 = 入向（该网卡收到包）后立即被 police 限流，超速部分 DROP。
// applySnatLimit SNAT 限速（ADR-9：自身限速彻底移除，仅带宽包共享）：
// 入包成员（BWGroupKBps>0）在入口网卡挂 per-包 htb 共享 class 1:100，
// 全部成员 filter 汇聚导入——同额度共享（PoC 实证）。未入包不限速。
func (s *snatRuleSpec) applySnatLimit() error {
	_ = s.teardownSnatLimit()
	if s.BWGroupKBps <= 0 || len(s.AllowSrcs) == 0 {
		return nil
	}

	// ===== 限速实现：扁平 htb，default 直连限速类（无分类器依赖）=====
	//
	// 本环境（virtio + Linux 6.8）实测结论，两条都导致过"限速完全不生效"：
	//  1) u32 filter 不参与分类：挂 `tc filter ... u32 match ... at 12/16`
	//     后各 class 的 Sent 恒为 0、流量全走 default，把限速类压到 1Kbit
	//     仍能 79.9MB/s 满速上传。
	//  2) 父类下挂子类时，未被 filter 指定的包无法归入子类，内核直接走
	//     direct queue 发出（direct_packets_stat 持续增长、class Sent 为 0、
	//     overlimits 不涨）。删掉子类后同一测试立刻正常：direct 不增、
	//     1:100 承载全部 33.5MB、overlimits 2424。
	//
	// 因此采用：qdisc default → 限速类 1:100（总额），不建子类、不做 filter
	// 分类。语义为"该网卡全部出向转发流量共享带宽包额度"。
	//
	// 代价（已文档化）：放弃每源保底分摊（MinKBps 仅保留为配置值）。per-源
	// 分配必须依赖 u32 分类或子类层级，两者在本环境均不可靠；细粒度限速
	// 待换 BPF/leaky-bucket 方案后实现。
	s.ensureHTB(s.IfIn)
	if err := s.applyHTBLimit(s.IfIn); err != nil {
		return err
	}
	// 上传方向：出口网卡与入口不同卡时另建一棵（同卡则上面已覆盖）
	if s.OutIP != "" && s.IfOut != s.IfIn {
		s.ensureHTB(s.IfOut)
		if err := s.applyHTBLimit(s.IfOut); err != nil {
			return err
		}
	}
	return nil
}

// applyHTBLimit 建立"限速总额类 + fq_codel 流公平"结构。
//
//	qdisc htb 1:   default 100                              ← 全部转向限速类
//	class 1:100    rate=ceil=<带宽包总额>                     ← 总额硬限
//	qdisc fq_codel 100: parent 1:100                        ← 流级公平调度
//	class 1:30     rate=10gbit                              ← 占位（不承载流量）
//
// 为什么是"default 直连 + fq_codel"而不是按源分类（详见 nft/anchor.go 的
// 长注释）：本环境所有按源分类的通路都不可用——u32 完全不参与分类；
// fw 只认奇数小整数 handle 且要求 mark 无额外位；flower 不支持 skb mark。
// 上传包在 egress 上源地址又已被 SNAT 改成网关 IP，按地址分类本就不可能。
//
// 实际保证：
//   - 总额：严格受 htb rate 约束（实测 8MB/s 配置跑出 6.67MB/s，差额为 TCP 开销）
//   - 公平：fq_codel 按流轮转，多连接并发时按流均分，单个源的多条连接
//     不会整体饿死其他源
//   - 每源硬保底（MinKBps）当前不生效，见 anchor.go 说明
//
// 幂等：class replace 自幂等；fq_codel 已存在则不重复添加（重复 add 会失败）；
// 顺带清理历史遗留的 per-源子类（旧版本建的 1:2..1:249，会让流量走 direct
// 路径绕过限速）。
func (s *snatRuleSpec) applyHTBLimit(ifn string) error {
	totalBits := strconv.FormatInt(s.BWGroupKBps*1024*8, 10)
	if err := runQuiet("tc", "class", "replace", "dev", ifn, "parent", "1:",
		"classid", bwGroupClassID, "htb",
		"rate", totalBits, "ceil", totalBits,
		"burst", "32k", "cburst", "32k"); err != nil {
		return err
	}
	// fq_codel 挂在限速类下（幂等：已有则跳过）
	if out, err := exec.Command("tc", "qdisc", "show", "dev", ifn).Output(); err == nil {
		if !strings.Contains(string(out), "qdisc fq_codel 100:") {
			_ = runQuiet("tc", "qdisc", "add", "dev", ifn, "parent", bwGroupClassID,
				"handle", "100:", "fq_codel")
		}
	}
	// 清理历史 per-源子类（旧版本按源建的 1:2..1:249）。
	// 注意必须跳过限速类 1:100 与占位类 1:30——早期版本这里从 2 遍历到 249，
	// 把刚建好的 1:100 一并删掉，导致 default 0x100 指向不存在的 class，
	// 内核把包全部走 direct 路径，限速彻底失效（实测 24MB/s 满速）。
	for n := 2; n <= 249; n++ {
		clsID := "1:" + strconv.Itoa(n)
		if clsID == bwGroupClassID || clsID == "1:30" {
			continue
		}
		_ = runQuiet("tc", "class", "del", "dev", ifn, "classid", clsID)
	}
	// 清理历史 u32/fw filter（本方案不依赖分类器，残留会干扰 direct 判定）
	_ = runQuiet("tc", "filter", "del", "dev", ifn, "parent", "1:")
	return nil
}

// srcClassID 源 IP -> 稳定 class ID（1:2..1:250）。限速绑定"源"而非规则：
// 同一源 IP 出现在多条规则时共享同一 member class（无论走哪条规则/端口）。
func srcClassID(src string) string {
	sum := 0
	for _, b := range []byte(src) {
		sum += int(b)
	}
	return fmt.Sprintf("1:%d", 2+sum%248)
}

// srcFilterPref 下载方向 filter pref（2..998；pref 1 固定保留）。
// 下载 filter 匹配 daddr=源，上传 filter 匹配 saddr=OutIP——入口/出口同卡
// （单臂网关）时两类 filter 落在同一个 qdisc 上，pref 必须分段不相交，
// 否则 tc filter replace 会按 pref 覆盖，导致某一方向限速失效。
// 本函数区段保持不变（2..998）：已部署规则的下载 filter 依赖该 pref 做精确拆除。
func srcFilterPref(src string) int {
	sum := 0
	for _, b := range []byte(src) {
		sum += int(b)
	}
	return 2 + sum%997
}

// uploadFilterPref 上传方向 filter pref（1002..1998，与下载区段 2..998 不相交）。
// 同卡部署下两方向共存的关键；双卡部署时上传 filter 在出口网卡、下载在入口
// 网卡，本就互不干扰，分段只是让两种拓扑共用一套代码。
func uploadFilterPref(src string) int {
	sum := 0
	for _, b := range []byte(src) {
		sum += int(b)
	}
	return 1002 + sum%997
}

// ensureHTB 保证指定网卡 root 是 htb，且 default 指向限速类 1:100。
//
// default 必须是限速类：本环境没有可用的分类器（见 applyHTBLimit 注释），
// 唯一可靠的限速路径就是让包默认进限速类。`tc qdisc change ... default N`
// 在本内核返回 "Change operation not supported"，default 不匹配时只能重建。
func (s *snatRuleSpec) ensureHTB(ifn string) {
	out, err := exec.Command("tc", "qdisc", "show", "dev", ifn).Output()
	if err == nil {
		info := string(out)
		// default 0x64 == 100（限速类）
		if strings.Contains(info, "qdisc htb") && strings.Contains(info, "default 0x64") {
			return
		}
	}
	_ = runQuiet("tc", "qdisc", "del", "dev", ifn, "root")
	_ = runQuiet("tc", "qdisc", "add", "dev", ifn, "root", "handle", "1:", "htb", "default", "100")
	_ = runQuiet("tc", "class", "add", "dev", ifn, "parent", "1:", "classid", "1:30",
		"htb", "rate", "10gbit")
}

// bwGroupClassID 带宽包共享 class（htb 下挂；所有包成员的 filter 都导入这里——共享额度）。
// 独立规则 class 固定 1:10；default 1:30 全速。
const bwGroupClassID = "1:100"

// ensureEgressHTB 保证入口网卡 root 是 htb（含 default 全速 class）。
// 已是 htb 则幂等跳过；否则替换（fq_codel 等）。
func (s *snatRuleSpec) ensureEgressHTB() {
	out, err := exec.Command("tc", "qdisc", "show", "dev", s.IfIn).Output()
	if err == nil && strings.Contains(string(out), "qdisc htb") {
		return
	}
	_ = runQuiet("tc", "qdisc", "del", "dev", s.IfIn, "root")
	_ = runQuiet("tc", "qdisc", "add", "dev", s.IfIn, "root", "handle", "1:", "htb", "default", "30")
	_ = runQuiet("tc", "class", "add", "dev", s.IfIn, "parent", "1:", "classid", "1:30",
		"htb", "rate", "10gbit")
}

// ipCidrToU32 IP/CIDR -> u32 matcher 的 (hex, mask)；at 16 = IP 头 daddr 偏移。
// 网段（如 172.16.41.0/24）必须带掩码（0xffffff00）——精确掩码 0xffffffff 会只匹配
// 网络地址一个 IP，网段内成员流量全部漏到 default class 不限速（实测 bug）。
func ipCidrToU32(s string) (hex, mask string, ok bool) {
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		if b := ipnet.IP.To4(); b != nil {
			m := ipnet.Mask
			return fmt.Sprintf("0x%02x%02x%02x%02x", b[0], b[1], b[2], b[3]),
				fmt.Sprintf("0x%02x%02x%02x%02x", m[0], m[1], m[2], m[3]), true
		}
		return "", "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		if b := ip.To4(); b != nil {
			return fmt.Sprintf("0x%02x%02x%02x%02x", b[0], b[1], b[2], b[3]), "0xffffffff", true
		}
	}
	return "", "", false
}

// teardownSnatLimit 清除本规则对入口网卡的限速痕迹（不整拆网卡共享结构）：
//   - ingress qdisc 是网卡级共享（ policiers per-filter），删自己的 policer filter；
//     qdisc 本身保留（其他规则可能仍在用）；无主共享时残留无功能影响（可被对账清）
//   - 出向：删本规则 filter（pref 1 的 flowid 1:10/1:100）；root htb 与 class 保留
//     （同卡其他规则的限速/包共享依赖它）。规则全下线后 root 残留只是空 htb（全速 default
//     1:30 承载一切）——由 ensureEgressHTB 幂等复用，不影响转发
//
// per-网卡共享结构的生命周期（root/class）随本机全部 snat 规则退化；
// 不做显式删除（空 htb 无行为差异，避免"拆 A 时把 B 拆掉"的互踩——评审必修2）。
func (s *snatRuleSpec) teardownSnatLimit() error {
	// 下载：删入口网卡自己源的 filter（pref 由源稳定 hash，不碰别人）。
	// 上传：删出口网卡 OutIP 源 filter。root htb/class 保留（他规则可能共用）。
	// 同卡部署（单臂网关）时 IfIn==IfOut，两个循环各自按 pref 精确命中，
	// 因下载区段(2..998)与上传区段(1002..1998)不相交，互不误删。
	for _, src := range s.AllowSrcs {
		_ = runQuiet("tc", "filter", "del", "dev", s.IfIn, "parent", "1:", "pref", strconv.Itoa(srcFilterPref(src)))
	}
	if s.OutIP != "" {
		_ = runQuiet("tc", "filter", "del", "dev", s.IfOut, "parent", "1:", "pref", strconv.Itoa(uploadFilterPref(s.OutIP)))
		// 旧版上传 filter 用的是 srcFilterPref 区段（升级前装的），同卡部署下
		// 会与下载 filter 争用 pref——首次重装时一并清掉。
		_ = runQuiet("tc", "filter", "del", "dev", s.IfOut, "parent", "1:", "pref", strconv.Itoa(srcFilterPref(s.OutIP)))
	}
	return nil
}

// ---------- 出口策略路由（eth0进→强制ens19出 的公网穿越场景） ----------
//
// 问题：内核对公网目标的 fib 查询走 main 表（默认 eth0 出），iptables FORWARD 的
// -o <出口网卡> 永不命中。实测（161）：为规则安装专属路由表 + ip rule（from 白名单源
// lookup 该表）后出向立刻改走出口网卡、SNAT 回程正常。表号从 201 起分配（1-200 留给
// 系统与 netplan），pref 1（最高优先级，先于 main）。
//
// 形态（全部带 haweb 标记，可对账可拆除）：
//   ip route add default via <egress_gw> dev <if_out> table <2xx>
//   ip rule add from <白名单源> ... lookup <2xx> pref 1   （每源一条，多源多规则）
// 注：per-规则 egress 路由仅在 egress_gw 配置时安装。

const (
	snatRouteTableBase = nft.RouteTableBase // 201：haweb 专属路由表号起点（200 以下留给系统）
	snatRouteTableEnd  = nft.RouteTableEnd  // 252：**不能取到 253+**（253 default/254 main/255 local 是内核保留表）
	snatRulePref       = 1                  // ip rule 优先级（最高，先于 main 的 32766）
)

// snatAllocTable 分配当前未占用的表号（仅选用本规则未占的）。
// 区间以 nft.RouteTableEnd 为界：早期版本取 201..300，一旦规则数超过 52 条
// 就会分配到 254（内核 main 表），装路由时覆盖/拆表时删除的正是整机默认路由。
func (m *Manager) snatAllocTable(ruleID uint) int {
	used := map[int]bool{}
	m.mu.Lock()
	for id, e := range m.snatRules {
		if id != ruleID && e.rtTable != 0 {
			used[e.rtTable] = true
		}
	}
	m.mu.Unlock()
	for t := snatRouteTableBase; t <= snatRouteTableEnd; t++ {
		if nft.IsReservedRouteTable(t) {
			continue // 冗余防护：区间常量若被误改也不落到保留表
		}
		if !used[t] {
			return t
		}
	}
	logf("[snat] 专属路由表段 %d-%d 已用尽，规则#%d 无法分配策略路由表",
		snatRouteTableBase, snatRouteTableEnd, ruleID)
	return 0
}

// installEgressRoute 安装 per-规则策略路由（出口网关直连网段外目标的出向决策）。
// 幂等：先拆后装。
func (s *snatRuleSpec) installEgressRoute() error {
	if s.EgressGw == "" || s.RtTable == 0 {
		return nil
	}
	s.teardownEgressRoute()
	if err := runQuiet("ip", "route", "replace", "default", "via", s.EgressGw,
		"dev", s.IfOut, "table", strconv.Itoa(s.RtTable)); err != nil {
		return fmt.Errorf("出口路由表 %d 建立失败（网关 %s 不可达？）: %w", s.RtTable, s.EgressGw, err)
	}
	for _, src := range s.AllowSrcs {
		// 清该源的全部残留（任意 pref 指向本表），幂等重装
		for i := 0; i < 8; i++ {
			out, err := exec.Command("ip", "rule", "list", "from", src).Output()
			if err != nil || !strings.Contains(string(out), "lookup "+strconv.Itoa(s.RtTable)) {
				break
			}
			_ = runQuiet("ip", "rule", "del", "from", src, "lookup", strconv.Itoa(s.RtTable))
		}
		if err := runQuiet("ip", "rule", "add", "from", src, "lookup", strconv.Itoa(s.RtTable), "pref", strconv.Itoa(snatRulePref)); err != nil {
			return fmt.Errorf("策略路由（from %s）安装失败: %w", src, err)
		}
	}
	return nil
}

// teardownEgressRoute 拆除本规则的策略路由。
// 只删"from 本规则白名单源 AND lookup 本表"的规则——绝不盲删 pref 槽：
// pref 1 全局同槽，多规则共用，盲删会把别家规则的 ip rule 一起清掉（实测事故：
// 规则重应用后另一条规则的路由消失、客户端全断）。
// 白名单历史值不可知（曾在旧规则形态下装过其他源）——对全表做源级清理：
// 删 lookup 本表 的全部 pref 1 规则（同表只可能属于本规则——表号 per-规则分配）。
func (s *snatRuleSpec) teardownEgressRoute() {
	if s.RtTable == 0 {
		return
	}
	tbl := strconv.Itoa(s.RtTable)
	// 解析 ip rule list，删除所有 lookup <tbl> 的规则（precise per-rule cleanup）
	out, err := exec.Command("ip", "rule", "list").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "lookup "+tbl) {
			continue
		}
		// 行形态："1:	from 192.168.10.152 lookup 202"
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		pref := strings.TrimSuffix(fields[0], ":")
		_ = runQuiet("ip", "rule", "del", "pref", pref, "from", strings.TrimPrefix(fields[3], ""), "lookup", tbl)
	}
	_ = runQuiet("ip", "route", "flush", "table", tbl)
}

// IPv4OfInterface 导出包装（API 层 snat 摘要用）。
func IPv4OfInterface(name string) string { return ipv4Of(name) }

// ---------- 停用掐断：本规则的存量穿越会话精确清除 ----------

// ctSession conntrack 表项的定位字段。
type ctSession struct {
	proto      string // tcp / udp
	origSrc    string // 出向原始源（穿越客户端 IP）
	origDst    string
	origSPort  string
	origDPort  string
	replySrc   string // SNAT 改写后的源（= OutIP）
	replyDst   string // 真实目标
	replySPort string
	replyDPort string
}

// otherSnatRuleSrcs 其他启用 snat 规则的源段全集（停用掐断 B 维度的排除集；
// 本条规则的存量已从引擎注销，不会算进自己）。
func (m *Manager) otherSnatRuleSrcs(excludeRuleID uint) []string {
	m.mu.Lock()
	ids := make([]uint, 0, len(m.snatRules))
	for id := range m.snatRules {
		if id != excludeRuleID {
			ids = append(ids, id)
		}
	}
	srcs := make([][]string, 0, len(ids))
	for _, id := range ids {
		if e := m.snatRules[id]; e != nil {
			srcs = append(srcs, e.allowSrcs)
		}
	}
	m.mu.Unlock()
	var out []string
	for _, s := range srcs {
		out = append(out, s...)
	}
	return out
}

// killConntrackSessions 停用 SNAT 时掐断本规则的存量穿越会话。
// iptables 拆除只挡新包——已建连接靠网关基线的 conntrack-ESTABLISHED
// 放行行继续跑到自然结束（实测：停用后 3.9G 下载不限速跑完）。
// 按规则维度精确删表项，任一命中即属本规则：
//
//	A. reply 源 = 本规则 SNAT 源（OutIP）——POSTROUTING 改写过的会话（最精确锚点）
//	B. orig 源 ∈ 本规则源段 且不与任何其他启用 snat 规则的源段重叠
//	   （未改写直连目标的放行会话；跨规则重叠宁漏杀——老化兜底，不错杀）
//
// 其他规则的源、本机自营流量（管理面/后端连接）、无关转发——一律不碰。
// conntrack 工具缺失或表不可读时降级（日志留痕，会话随 conntrack 老化断开）。
func (s *snatRuleSpec) killConntrackSessions(otherRuleSrcs []string) {
	lines := readConntrackTable()
	if lines == nil {
		logf("规则#%d 停用：conntrack 表不可读（内核模块未加载或无权限），存量会话将随 conntrack 老化自然断开", s.ID)
		return
	}
	if _, err := exec.LookPath("conntrack"); err != nil {
		logf("规则#%d 停用：缺少 conntrack 命令（apt install conntrack），存量会话将随 conntrack 老化自然断开", s.ID)
		return
	}
	exclusive := subtractSrcs(s.AllowSrcs, otherRuleSrcs)
	killed := 0
	for _, ln := range lines {
		c, ok := parseConntrackLine(ln)
		if !ok {
			continue
		}
		if !(s.OutIP != "" && c.replySrc == s.OutIP) && !ipInList(c.origSrc, exclusive) {
			continue
		}
		if deleteConntrackEntry(s, c) {
			killed++
		}
	}
	if killed > 0 {
		logf("规则#%d 停用：已掐断 %d 条本规则穿越会话（SNAT 源=%s），其他规则会话不受影响", s.ID, killed, s.OutIP)
	}
}

// ownsCTSession 判定（导出独立函数便于单测）。
func ownsCTSession(c *ctSession, outIP string, exclusiveSrcs []string) bool {
	if outIP != "" && c.replySrc == outIP {
		return true
	}
	return ipInList(c.origSrc, exclusiveSrcs)
}

// subtractSrcs 本规则源段减去跨规则源段（命中的剔除；宽段不含窄段不剔除——
// 错杀风险大的只剔除完全相同的段）。
func subtractSrcs(mine, others []string) []string {
	if len(others) == 0 {
		return mine
	}
	otherSet := map[string]bool{}
	for _, o := range others {
		otherSet[strings.TrimSpace(o)] = true
	}
	out := make([]string, 0, len(mine))
	for _, m := range mine {
		if !otherSet[strings.TrimSpace(m)] {
			out = append(out, m)
		}
	}
	return out
}

// ipInList IP 是否落在 IP/CIDR 列表。
func ipInList(ip string, list []string) bool {
	if ip == "" || len(list) == 0 {
		return false
	}
	a := net.ParseIP(ip)
	if a == nil {
		return false
	}
	for _, e := range list {
		if strings.Contains(e, "/") {
			if _, ipnet, err := net.ParseCIDR(e); err == nil && ipnet.Contains(a) {
				return true
			}
			continue
		}
		if e == ip {
			return true
		}
	}
	return false
}

// readConntrackTable 读内核 conntrack 表。优先 /proc/net/nf_conntrack（零依赖）；
// 内核未暴露 proc 接口时（CONFIG_NF_CONNTRACK_PROCFS=n 或模块未注册——实测
// Ubuntu 22.05 内核即如此）降级 conntrack -L（netlink，格式同为 key=value）。
// 两种来源都不可用返回 nil（调用方降级老化）。
func readConntrackTable() []string {
	// 行格式兼容两种内核形态（QA P1-1）：
	//   老格式（≤6.x 早期）："tcp 6 431997 ESTABLISHED src=..."
	//   新格式（6.x/6.18 实测）：  "ipv4     2 tcp      6 431999 ESTABLISHED src=..."
	//     —— L3 层名作前缀。老过滤 HasPrefix("tcp ") 在新格式下永不匹配 → 表恒空。
	// 统一剥离：先按空白分列，找到 tcp/udp 列的位置，去掉其前的 L3 前缀列。
	var out []string
	read := func(text string, forProc bool) []string {
		var lines []string
		for _, ln := range strings.Split(text, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			fields := strings.Fields(ln)
			// 老格式：fields[0] 即 l4 proto；新格式：fields[2]（ipv4/ipv6 层名 + 号 + l4）
			start := -1
			for i, f := range fields {
				if f == "tcp" || f == "udp" {
					start = i
					break
				}
			}
			if start == -1 {
				continue // 非 tcp/udp 表项（如 DCCP/SCTP/ICMP——icmP 有 v4/v6 行且无端口语义，跳过）
			}
			if forProc && start > 2 {
				continue // 异常态：层前缀超过 ipv4/ipv6+号两列——防御
			}
			lines = append(lines, strings.Join(fields[start:], " "))
		}
		return lines
	}
	if b, err := osReadFile("/proc/net/nf_conntrack"); err == nil {
		out = read(string(b), true)
		// /proc 可读但空表（无任何表项）时返回空切片——与不可读（nil）语义不同，
		// 调用方据 nil 判降级；但空表可能是 conntrack 模块列表为空——继续降级
		// conntrack -L 拿 netlink 全量（/proc 有 max 条数截断的老坑）
		if len(out) > 0 {
			return out
		}
	}
	out2, err := exec.Command("conntrack", "-L").Output()
	if err != nil {
		return out // /proc 读到的哪怕为空也优于 nil（conntrack 二进制缺失/失败）
	}
	lines := read(string(out2), false)
	if len(lines) > 0 {
		return lines
	}
	return out
}

// parseConntrackLine 解析单条 nf_conntrack 行（/proc/net/nf_conntrack 等号连写格式：
// tcp 6 431997 ESTABLISHED src=A dst=B sport=x dport=y src=C dst=D sport=p dport=q [ASSURED] mark=0 use=1
// 前一组是 orig（客户端→目标），后一组是 reply（SNAT 后）。
// key=val 连写为主；顺带兼容 conntrack -L 的空格分隔格式。
func parseConntrackLine(ln string) (*ctSession, bool) {
	fields := strings.Fields(ln)
	if len(fields) < 5 {
		return nil, false
	}
	c := &ctSession{}
	c.proto = strings.ToLower(strings.SplitN(fields[0], "=", 2)[0])
	if c.proto != "tcp" && c.proto != "udp" {
		return nil, false
	}
	type kv struct{ k, v string }
	var pairs []kv
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case strings.HasPrefix(f, "src=") || strings.HasPrefix(f, "dst=") ||
			strings.HasPrefix(f, "sport=") || strings.HasPrefix(f, "dport="):
			kv2 := strings.SplitN(f, "=", 2)
			pairs = append(pairs, kv{kv2[0], kv2[1]})
		case f == "src" || f == "dst" || f == "sport" || f == "dport":
			if i+1 < len(fields) {
				pairs = append(pairs, kv{f, fields[i+1]})
				i++
			}
		}
	}
	if len(pairs) < 8 {
		return nil, false
	}
	need := func(idx int, keys [4]string, dst *[4]string) bool {
		for j := 0; j < 4; j++ {
			if idx+j >= len(pairs) || pairs[idx+j].k != keys[j] {
				return false
			}
			dst[j] = pairs[idx+j].v
		}
		return true
	}
	var o, r [4]string
	if !need(0, [4]string{"src", "dst", "sport", "dport"}, &o) ||
		!need(4, [4]string{"src", "dst", "sport", "dport"}, &r) {
		return nil, false
	}
	c.origSrc, c.origDst, c.origSPort, c.origDPort = o[0], o[1], o[2], o[3]
	c.replySrc, c.replyDst, c.replySPort, c.replyDPort = r[0], r[1], r[2], r[3]
	return c, true
}

// deleteConntrackEntry conntrack -D 按 orig 四元组精确删除一条表项
// （-p proto -s orig源 -d orig目的 --sport/--dport orig 端口）。
// reply 侧不需要给：内核按 orig 四元组即可唯一定位表项。
func deleteConntrackEntry(s *snatRuleSpec, c *ctSession) bool {
	args := []string{"-D", "-p", c.proto,
		"-s", c.origSrc, "-d", c.origDst,
		"--sport", c.origSPort, "--dport", c.origDPort}
	out, err := exec.Command("conntrack", args...).CombinedOutput()
	if err != nil {
		// 表项可能已被内核老化（老化兜底自然成立）——这种不算失败
		ol := strings.ToLower(string(out))
		if strings.Contains(ol, "0 flow entries") {
			return false
		}
		logf("规则#%d 停用：conntrack 删除失败（老化兜底）: %v: %s", s.ID, err, strings.TrimSpace(string(out)))
		return false
	}
	return true
}

// 目标黑名单 per-目标 DROP 行，全部带本规则 comment——多行求和后返回完整计数。
// 返回值恒非 nil（iptables 不可用时零值））。
func readSnatDropCounters(ruleID uint) *snatCounters {
	comment := snatCommentPrefix + strconv.FormatUint(uint64(ruleID), 10)
	out, err := exec.Command("iptables", "-L", "FORWARD", "-v", "-x", "-n").Output()
	if err != nil {
		return &snatCounters{}
	}
	c := parseSnatCountersOutput(string(out), comment)
	if c == nil {
		return &snatCounters{}
	}
	return c
}

// ReadSnatCounters 导出包装（API 层 snat 摘要——读规则全部源 class 计数之和；
// 无 class（未入包/无限速）返回 DROP 计数兼容）。
func ReadSnatCounters(ruleID uint, ifIn string, allowSrcs []string) *snatCounters {
	if c := readSnatCounters(ruleID, ifIn, allowSrcs); c != nil {
		c.PktsDrop = readSnatDropCounters(ruleID).PktsDrop
		c.BytesDrop = readSnatDropCounters(ruleID).BytesDrop
		return c
	}
	return readSnatDropCounters(ruleID)
}

// ---------- 计数轮询（ADR-3：iptables 计数差分 → ruleStats/速率窗口） ----------

// snatCounters 一条 snat 规则的内核计数快照。
type snatCounters struct {
	PktsAccept  int64 // FORWARD ACCEPT 行计数（放行穿越）
	BytesAccept int64
	PktsDrop    int64 // FORWARD DROP 兜底行计数（白名单拒绝）
	BytesDrop   int64
}

// readSnatCounters 读单规则计数。
// 字节/包计数无法从 iptables 归属——FORWARD 的 ctstate 回程行全匹配（无源区分），
// 行序在前的规则吃掉全部回包计数（实测：双客户端并发时 22 独享 4M+ 速率、28 为 0）。
// 改从**该规则专属 htb 成员 class**取差分字段（Bytes/Pkts 为 class 累计计数，
// 与 FORWARD 语义一致的传输总字节——回程方向在此 class 整形）+ DROP 行保留 iptables
// 拒绝计数（白名单外交给策略 DROP 后拒绝计数已不可用——保留字段兼容调用方）。
func readSnatCounters(ruleID uint, ifIn string, allowSrcs []string) *snatCounters {
	// tc class 计数（per-源 class：多源规则求各源 class 之和）
	out, err := exec.Command("tc", "-s", "class", "show", "dev", ifIn).Output()
	if err != nil {
		return nil
	}
	drop := readSnatDropCounters(ruleID)
	c := &snatCounters{PktsDrop: drop.PktsDrop, BytesDrop: drop.BytesDrop}
	lines := strings.Split(string(out), "\n")
	// 该规则全部源 class（per-源 class，读出后求和）
	classes := map[string]bool{}
	for _, s := range allowSrcs {
		classes[srcClassID(s)] = true
	}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		matched := false
		classID := ""
		for cl := range classes {
			if strings.HasPrefix(t, "class htb "+cl+" ") {
				matched, classID = true, cl
				break
			}
		}
		if !matched || classID == "" {
			continue
		}
		delete(classes, classID)
		for _, l2 := range lines[i+1 : i+3] {
			f := strings.Fields(strings.TrimSpace(l2))
			if len(f) >= 4 && f[0] == "Sent" {
				b, _ := strconv.ParseInt(f[1], 10, 64)
				p, _ := strconv.ParseInt(f[2], 10, 64)
				c.BytesAccept += b
				c.PktsAccept += p
				break
			}
		}
		if len(classes) == 0 {
			break
		}
	}
	if len(classes) == len(allowSrcs) || allowSrcs == nil {
		return nil // 一个都没读到
	}
	return c
}

// parseSnatCountersOutput 纯解析（测试直接喂 iptables -L -v -x 样例）。
func parseSnatCountersOutput(out, comment string) *snatCounters {
	c := &snatCounters{}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, comment) {
			continue
		}
		f := strings.Fields(line)
		// 形态：pkts bytes target prot opt in out source destination + 选项（comment 在远端）
		if len(f) < 8 {
			continue
		}
		pkts, perr := strconv.ParseInt(f[0], 10, 64)
		bytes, berr := strconv.ParseInt(f[1], 10, 64)
		if perr != nil || berr != nil {
			continue
		}
		if f[2] == "ACCEPT" {
			// conntrack 回程行与白名单 ACCEPT 行同 comment：求和（放行穿越总量）
			c.PktsAccept += pkts
			c.BytesAccept += bytes
		} else if f[2] == "DROP" {
			// 目标黑名单 per-目标 DROP 行（N 目标 = N 行同 comment）：求和
			c.PktsDrop += pkts
			c.BytesDrop += bytes
		}
	}
	return c
}

// snatBaseline 每规则计数基线（会话内差分起点；进程重启后首帧建基线=从 0 计）。
type snatBaseline struct {
	accept int64
	drop   int64
	// sampledAt 上次采样时刻（unix 秒）。速率 = 本次差分 / 实际间隔——SNAT 的
	// 计数来自内核 nft counter，只能按轮询周期取差分，不能像连接级会话那样
	// 逐次 Add 到 rateMeter（那是每写一次就落一个秒槽的精确口径）。
	// 早期实现把 5s 的差分整块塞进 rateMeter 的"当前秒槽"，而 Rate() 恒按
	// 10 秒窗口求平均：槽里只有 2 个有数据、其余 8 个为空，显示值 = 真实值 / 5
	// （实测 46.7MB/s 下载显示 66KB/s，用户可见的严重偏差）。
	sampledAt int64
}

// pollSnatCounters 单轮全量轮询：读计数 → 差分入 ruleStats（速率窗口+拒绝计数）。
// 首 10 轮建基线（出现即建，未出现跳过）。
func (m *Manager) pollSnatCounters() {
	m.mu.Lock()
	entries := make([]*snatEntry, 0, len(m.snatRules))
	for _, e := range m.snatRules {
		entries = append(entries, e)
	}
	m.mu.Unlock()

	// M5/N3：优先 nft counter（netlink，无外部二进制依赖）。CountersByComment
	// 与安装 Flush 共享 lasting socket——必须持 nftApplyMu 防会话交错（否则
	// poll 的 dump 挤进安装的 send/receive 之间，安装被误判失败触发回滚）。
	// 引擎不可用（老机器/容器开发）降级旧 exec 口径（tc class + iptables DROP）。
	m.nftMu.Lock()
	nftConnRef := m.nft
	m.nftMu.Unlock()
	var counted *nft.CountersByCommentResult
	if nftConnRef != nil {
		m.nftApplyMu.Lock()
		counted, _ = nftConnRef.CountersByComment()
		m.nftApplyMu.Unlock()
	}
	for _, e := range entries {
		var c *snatCounters
		if counted != nil {
			c = countersFromNFT(counted, e.ruleID, e.allowSrcs)
		}
		if c == nil {
			c = readSnatCounters(e.ruleID, e.ifIn, e.allowSrcs)
		}
		if c == nil {
			continue
		}
		m.snatMu.Lock()
		base := m.snatBase[e.ruleID]
		first := base == nil
		nowSec := time.Now().Unix()
		if first {
			base = &snatBaseline{accept: c.BytesAccept, drop: c.BytesDrop, sampledAt: nowSec}
			m.snatBase[e.ruleID] = base
		}
		dUp := c.BytesAccept - base.accept
		dDrop := c.BytesDrop - base.drop
		if !first {
			if dUp > 0 {
				m.snatAcc[e.ruleID] += dUp // 会话内累计（展示口径见 ADR-3 注）
			}
			if dDrop > 0 {
				if st := m.statsLookup(e.ruleID); st != nil {
					st.Denied.Add(1)
				}
			}
		}
		// 速率：按【实际采样间隔】折算，而不是喂 rateMeter 的 10 秒窗口。
		// 内核 nft counter 只有轮询点能读差分，每 5s 才产生一次增量；把它整块
		// 塞进 rateMeter 的"当前秒槽"会让 10 个槽里只有 2 个有数据，而 Rate()
		// 恒除以 10，显示值被压低 5 倍（用户实测 46.7MB/s 下载显示 66KB/s）。
		//
		// 方向语义：fwd 放行行的 counter 统计双向穿越字节（内核只在 FORWARD
		// 计一次，无方向区分）。SNAT 的主流诉求是看总吞吐，故 up/down 同值展示。
		if !first && dUp > 0 {
			if st := m.statsLookup(e.ruleID); st != nil {
				if dt := nowSec - base.sampledAt; dt > 0 {
					st.SnatRateBps.Store(dUp / dt)
				}
				st.BytesUp.Add(dUp)
				st.BytesDown.Add(dUp)
			}
		} else if !first && dUp == 0 {
			// 本周期无流量：速率归零，避免静止规则长期显示历史峰值
			if st := m.statsLookup(e.ruleID); st != nil {
				st.SnatRateBps.Store(0)
			}
		}
		base.accept = c.BytesAccept
		base.drop = c.BytesDrop
		base.sampledAt = nowSec
		m.snatMu.Unlock()
	}
}

// snatLoop 计数轮询循环（5s 周期；随 Manager 生命期，升级交接时父进程停止）。
func (m *Manager) snatLoop() {
	t := timeNewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.snatDone:
			return
		case <-t.C:
			m.pollSnatCounters()
		}
	}
}

// statsLookup 锁内查规则统计条目（可能为 nil）。
func (m *Manager) statsLookup(id uint) *ruleStats {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	return m.stats[id]
}

// StartSnatPolling 启动计数轮询（main 启动序列与升级子进程各调一次）。
func (m *Manager) StartSnatPolling() {
	m.snatStartOnce.Do(func() {
		go m.snatLoop()
	})
}

// StopSnatPolling 停止轮询（升级交接父进程时调用，避免双进程双计数）。
func (m *Manager) StopSnatPolling() {
	m.snatStopOnce.Do(func() { close(m.snatDone) })
}
