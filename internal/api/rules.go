package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
)

type ruleInput struct {
	Name              string `json:"name"`
	Protocol          string `json:"protocol"`
	ListenAddr        string `json:"listen_addr"`
	TargetAddr        string `json:"target_addr"`
	AclMode           string `json:"acl_mode"`
	AllowList         string `json:"allow_list"`
	DenyList          string `json:"deny_list"`
	AclGroupID        uint   `json:"acl_group_id"`
	DstAclMode        string `json:"dst_acl_mode"`
	DstAllowList      string `json:"dst_allow_list"`
	DstDenyList       string `json:"dst_deny_list"`
	SnatIP            string `json:"snat_ip"`
	DnatRejectMode    string `json:"dnat_reject_mode"`
	SnatMode          string `json:"snat_mode"`
	SnatPool          string `json:"snat_pool"`
	EgressIDs         string `json:"egress_ids"`
	EgressGw          string `json:"egress_gw"`
	MinKBps           int64  `json:"min_kbps"`
	SourceIP          string `json:"source_ip"`
	UploadLimitKBps   int64  `json:"upload_limit_kbps"`
	DownloadLimitKBps int64  `json:"download_limit_kbps"`
	MaxConns          int    `json:"max_conns"`
	IdleTimeoutSec    int    `json:"idle_timeout_sec"`
	HealthCheck       *bool  `json:"health_check"`
	Enabled           bool   `json:"enabled"`
}

func (in *ruleInput) toRule() model.ForwardRule {
	return model.ForwardRule{
		Name:              strings.TrimSpace(in.Name),
		Protocol:          strings.ToLower(strings.TrimSpace(in.Protocol)),
		ListenAddr:        strings.TrimSpace(in.ListenAddr),
		TargetAddr:        strings.TrimSpace(in.TargetAddr),
		AclMode:           strings.TrimSpace(in.AclMode),
		AllowList:         strings.TrimSpace(in.AllowList),
		DenyList:          strings.TrimSpace(in.DenyList),
		AclGroupID:        in.AclGroupID,
		DstAclMode:        strings.TrimSpace(in.DstAclMode),
		DstAllowList:      strings.TrimSpace(in.DstAllowList),
		DstDenyList:       strings.TrimSpace(in.DstDenyList),
		SnatIP:            strings.TrimSpace(in.SnatIP),
		DnatRejectMode:    strings.TrimSpace(in.DnatRejectMode),
		SnatMode:          strings.TrimSpace(in.SnatMode),
		SnatPool:          strings.TrimSpace(in.SnatPool),
		EgressIDs:         strings.TrimSpace(in.EgressIDs),
		EgressGw:          strings.TrimSpace(in.EgressGw),
		MinKBps:           in.MinKBps,
		SourceIP:          strings.TrimSpace(in.SourceIP),
		UploadLimitKBps:   in.UploadLimitKBps,
		DownloadLimitKBps: in.DownloadLimitKBps,
		MaxConns:          in.MaxConns,
		IdleTimeoutSec:    in.IdleTimeoutSec,
		HealthCheck:       in.HealthCheck,
		Enabled:           in.Enabled,
	}
}

// validate 校验规则字段格式（含名单组引用的一致性，需查库确认组存在与模式）。
func (in *ruleInput) validate(h *handlers) error {
	if in.Name == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	switch in.Protocol {
	case model.ProtocolTCP, model.ProtocolUDP:
		// 目标名单仅 snat/dnat 规则支持；tcp/udp 的目标即后端地址
		if strings.TrimSpace(in.DstAclMode) != "" && in.DstAclMode != model.AclModeOff ||
			strings.TrimSpace(in.DstAllowList) != "" || strings.TrimSpace(in.DstDenyList) != "" {
			return fmt.Errorf("目标名单仅 snat 规则支持（tcp/udp 的目标就是后端地址，无需名单）")
		}
	case model.ProtocolSNAT:
		return h.validateSnat(in)
	case model.ProtocolDNAT:
		return h.validateDnat(in)
	default:
		return fmt.Errorf("协议必须是 tcp / udp / snat / dnat")
	}
	host, portStr, err := net.SplitHostPort(in.ListenAddr)
	if err != nil || (host != "" && net.ParseIP(host) == nil) {
		return fmt.Errorf("监听地址格式错误（应为 :端口 或 IP:端口）: %s", in.ListenAddr)
	}
	port, _ := strconv.Atoi(portStr)
	if port < 1 || port > 65535 {
		return fmt.Errorf("监听端口无效: %s", portStr)
	}
	if err := validateTarget(in.TargetAddr); err != nil {
		return err
	}
	// 名单组引用：off 模式不允许引用；组必须存在且模式与规则一致；
	// 引用组时不能再直配名单，名单条目完全来自组（展开在引擎 buildRuleConfig）
	groupRef := false
	if in.AclGroupID != 0 {
		if in.AclMode != model.AclModeWhitelist && in.AclMode != model.AclModeBlacklist {
			return fmt.Errorf("off 模式不能引用名单组，请选择白名单或黑名单模式")
		}
		var group model.AclGroup
		if err := h.DB.First(&group, in.AclGroupID).Error; err != nil {
			return fmt.Errorf("引用的名单组不存在（ID %d）", in.AclGroupID)
		}
		if group.Mode != in.AclMode {
			return fmt.Errorf("名单组[%s]是%s组，与规则的%s模式不匹配", group.Name, groupModeName(group.Mode), groupModeName(in.AclMode))
		}
		if in.AclMode == model.AclModeWhitelist && strings.TrimSpace(in.AllowList) != "" {
			return fmt.Errorf("已引用白名单组[%s]，不能再直配白名单条目（二选一）", group.Name)
		}
		if in.AclMode == model.AclModeBlacklist && strings.TrimSpace(in.DenyList) != "" {
			return fmt.Errorf("已引用黑名单组[%s]，不能再直配黑名单条目（二选一）", group.Name)
		}
		groupRef = true
	}
	// 直配名单校验（格式 + 非空门槛）；引用组时名单为空是合法的，
	// 此时跳过非空门槛、仅校验模式合法性与直配名单为空
	if groupRef {
		switch in.AclMode {
		case model.AclModeOff, model.AclModeWhitelist, model.AclModeBlacklist, "":
		default:
			return fmt.Errorf("无效的名单模式: %q", in.AclMode)
		}
	} else if err := proxy.ValidateLists(in.AclMode, in.AllowList, in.DenyList); err != nil {
		return err
	}
	// 显式模式下两名单互斥：选了哪种模式就只允许配置对应名单
	switch in.AclMode {
	case model.AclModeWhitelist:
		if strings.TrimSpace(in.DenyList) != "" {
			return fmt.Errorf("白名单模式下不能同时配置黑名单，请二选一")
		}
	case model.AclModeBlacklist:
		if strings.TrimSpace(in.AllowList) != "" {
			return fmt.Errorf("黑名单模式下不能同时配置白名单，请二选一")
		}
	}
	// 限速已统一到带宽包——规则级限速字段拒绝非零（前端两页均已无输入）
	if in.UploadLimitKBps != 0 || in.DownloadLimitKBps != 0 {
		return fmt.Errorf("规则不再单独设置限速：请加入带宽包（「带宽包」页配置合计额度与每源保底）")
	}
	if in.MaxConns < 0 {
		return fmt.Errorf("连接上限不能为负数")
	}
	if in.IdleTimeoutSec < 0 {
		return fmt.Errorf("空闲超时不能为负数")
	}
	// 后端连源 IP（可选）：必须是本机有效 IPv4（后端看到的连接来源）
	if ip := strings.TrimSpace(in.SourceIP); ip != "" {
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
			return fmt.Errorf("后端连接源 IP %q 不是合法的 IPv4 地址", ip)
		}
		local := false
		ifaces, _ := net.Interfaces()
		for _, ifn := range ifaces {
			addrs, _ := ifn.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.String() == ip {
					local = true
				}
			}
		}
		if !local {
			return fmt.Errorf("后端连接源 IP %s 不是本机地址（可用见 GET /api/interfaces）", ip)
		}
	}
	return nil
}

// groupModeName 模式中文名（错误文案用）。
func groupModeName(mode string) string {
	switch mode {
	case model.AclModeWhitelist:
		return "白名单"
	case model.AclModeBlacklist:
		return "黑名单"
	}
	return mode
}

// validateDnat dnat 规则专属校验（契约 API-D1）：
// listen_addr=完整 公网IP:端口（IP 必须归属本机网卡，含一卡多址）；target_addr=完整
// 内网后端 IP:端口；源名单复用 acl 白名单；dnat_reject_mode 二选一默认 reject；
// 不允许：dst_* 目标名单（穿越语义）、egress_gw/snat_ip（出口语义）。
func (h *handlers) validateDnat(in *ruleInput) error {
	if strings.TrimSpace(in.DstAclMode) != "" && in.DstAclMode != model.AclModeOff ||
		strings.TrimSpace(in.DstAllowList) != "" || strings.TrimSpace(in.DstDenyList) != "" {
		return fmt.Errorf("dnat 规则不支持目标名单（穿越语义，仅 snat 规则可用）")
	}
	if strings.TrimSpace(in.EgressGw) != "" || strings.TrimSpace(in.SnatIP) != "" {
		return fmt.Errorf("dnat 规则不支持出口网关/SNAT 源（出口语义，仅 snat 规则可用）")
	}
	// 评审 #6：dnat 仅支持白名单语义——blacklist 会被引擎静默丢弃变"全放行"
	// （安全反转），创建即拒绝
	if in.AclMode == model.AclModeBlacklist {
		return fmt.Errorf("dnat 规则不支持黑名单模式（仅 off / whitelist），黑名单语义不适用于端口发布")
	}
	switch strings.TrimSpace(in.DnatRejectMode) {
	case "", model.DnatRejectModeReject, model.DnatRejectModeTimeout:
	default:
		return fmt.Errorf("dnat_reject_mode 只能是 reject 或 timeout")
	}
	// 发布地址：完整 IP:port（端口语义同 tcp/udp 主校验，这里查 IP 归属）
	host, _, err := net.SplitHostPort(strings.TrimSpace(in.ListenAddr))
	if err != nil || host == "" {
		return fmt.Errorf("dnat 规则的发布地址必须是完整 IP:端口 形式（如 203.0.113.10:443）: %s", in.ListenAddr)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("发布地址 %q 不是合法 IP", host)
	}
	belongs := false
	ifaces, _ := net.Interfaces()
	for _, ifn := range ifaces {
		addrs, _ := ifn.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.String() == host {
				belongs = true
			}
		}
	}
	if !belongs {
		return fmt.Errorf("发布 IP %s 不归属任何本机网卡（可用地址见 GET /api/interfaces）", host)
	}
	// 后端：完整 IP:port；地址族必须一致（v1 不做 NAT64）
	thost, _, err := net.SplitHostPort(strings.TrimSpace(in.TargetAddr))
	if err != nil || thost == "" {
		return fmt.Errorf("dnat 规则的后端地址必须是完整 IP:端口 形式（如 10.0.1.5:8443）: %s", in.TargetAddr)
	}
	tip := net.ParseIP(thost)
	if tip == nil {
		return fmt.Errorf("后端地址 %q 不是合法 IP", thost)
	}
	lip := net.ParseIP(host)
	if (tip.To4() == nil) != (lip.To4() == nil) {
		return fmt.Errorf("发布地址族与后端地址族不一致（v1 不做 NAT64）: %s → %s", host, thost)
	}
	return nil
}

// validateSnat snat 规则专属校验：网卡存在性/互异/名单语义/组引用（对齐 design-snat.md 契约）。
// 字段复用：listen_addr=入口网卡、target_addr=出口网卡、upload_limit_kbps=入向总闸。
func (h *handlers) validateSnat(in *ruleInput) error {
	if in.AclMode != model.AclModeOff && in.AclMode != model.AclModeWhitelist {
		return fmt.Errorf("snat 规则的名单模式必须是 off（全放行）或 whitelist（白名单）")
	}
	// 安全默认：snat 必须指定源（直配网段或引用白名单组）——"不指定就不能通"。
	// 无源的 snat 规则没有可用语义（全放行已被否决），创建即拒绝防误配。
	// 目标黑名单同样要求白名单源模式：off 源 + 目标黑名单的组合在引擎里会
	// 落地为无源 DROP（跨规则误伤，v2 事故同型），在 API 层直接拒绝。
	if in.AclMode != model.AclModeWhitelist {
		if strings.TrimSpace(in.DstAclMode) == model.AclModeBlacklist {
			return fmt.Errorf("配置目标黑名单时源模式必须为白名单（off 源模式的目标黑名单会落地为无源 DROP，误伤同网卡其他规则）")
		}
		if strings.TrimSpace(in.AllowList) != "" || in.AclGroupID != 0 {
			return fmt.Errorf("SNAT 规则的源模式必须为白名单（whitelist）——off 模式不承载源名单")
		}
		return fmt.Errorf("SNAT 规则必须指定源 IP 或网段（至少一条，或引用白名单组）——未指定的源一律无法穿越")
	}
	if strings.TrimSpace(in.AllowList) == "" && in.AclGroupID == 0 {
		return fmt.Errorf("SNAT 规则必须指定源 IP 或网段（至少一条，或引用白名单组）——未指定的源一律无法穿越")
	}
	if up, _ := proxy.InterfaceExists(in.ListenAddr); !up {
		return fmt.Errorf("入口网卡 %q 不存在或未启用（可用网卡见 GET /api/interfaces）", strings.TrimSpace(in.ListenAddr))
	}
	if up, _ := proxy.InterfaceExists(in.TargetAddr); !up {
		return fmt.Errorf("出口网卡 %q 不存在或未启用（可用网卡见 GET /api/interfaces）", strings.TrimSpace(in.TargetAddr))
	}
	if strings.TrimSpace(in.ListenAddr) == strings.TrimSpace(in.TargetAddr) {
		return fmt.Errorf("入口与出口网卡不能相同: %s", in.ListenAddr)
	}
	if strings.TrimSpace(in.DenyList) != "" {
		return fmt.Errorf("snat 规则不支持黑名单（穿越转发无监听端口语义），请使用白名单")
	}
	// 出口网关（可选）：策略路由的下一跳，必须可从出口网卡直达（与出口网卡同网段）
	if gw := strings.TrimSpace(in.EgressGw); gw != "" {
		gwIP := net.ParseIP(gw)
		if gwIP == nil || gwIP.To4() == nil {
			return fmt.Errorf("出口网关 %q 不是合法的 IPv4 地址", gw)
		}
		if strings.TrimSpace(in.TargetAddr) != "" {
			outIP := proxy.IPv4OfInterface(strings.TrimSpace(in.TargetAddr))
			if outIP != "" {
				iface, err := net.InterfaceByName(strings.TrimSpace(in.TargetAddr))
				if err == nil {
					reachable := false
					for _, a := range ifaceAddrStrings(iface) {
						if _, ipnet, err := net.ParseCIDR(a); err == nil && ipnet.Contains(gwIP) {
							reachable = true
							break
						}
					}
					if !reachable {
						return fmt.Errorf("出口网关 %s 不在出口网卡 %s 的直连网段内（策略路由需同网段下一跳）", gw, strings.TrimSpace(in.TargetAddr))
					}
				}
			}
		}
	}
	// T207：SNAT 源模式与池校验（模式合法；池成员 1-32；成员须归属本机——
	// 绑定多网卡时按规则出口网卡校验；rotate/sticky 模式下 SnatIP 不再单独生效）
	switch mode := strings.TrimSpace(in.SnatMode); mode {
	case "", "fixed":
		if strings.TrimSpace(in.SnatPool) != "" {
			return fmt.Errorf("fixed 模式不配置 snat_pool（单 IP 用 snat_ip）")
		}
	case "rotate", "sticky":
		var members []string
		if err := json.Unmarshal([]byte(strings.TrimSpace(in.SnatPool)), &members); err != nil {
			return fmt.Errorf("snat_pool 必须是 JSON 字符串数组")
		}
		if len(members) < 1 || len(members) > 32 {
			return fmt.Errorf("snat_pool 成员数 %d 越界（1-32）", len(members))
		}
		outIf := strings.TrimSpace(in.TargetAddr)
		for _, m := range members {
			m = strings.TrimSpace(m)
			if net.ParseIP(m) == nil || net.ParseIP(m).To4() == nil {
				return fmt.Errorf("snat_pool 成员 %q 不是合法 IPv4", m)
			}
			found := false
			for _, v4 := range proxy.InterfaceIPv4s(outIf) {
				if v4 == m {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("snat_pool 成员 %s 不在出口网卡 %s 的地址列表中", m, outIf)
			}
		}
	default:
		return fmt.Errorf("snat_mode 只能是 fixed / rotate / sticky")
	}
	// T201：出口绑定校验（egress_ids 引用的出口必须存在且启用）
	if ids := strings.TrimSpace(in.EgressIDs); ids != "" {
		var eids []uint
		if err := json.Unmarshal([]byte(ids), &eids); err != nil {
			return fmt.Errorf("egress_ids 必须是 JSON 数字数组")
		}
		for _, eid := range eids {
			var eg model.Egress
			if err := h.DB.First(&eg, eid).Error; err != nil {
				return fmt.Errorf("egress_ids 引用了不存在的出口 #%d", eid)
			}
			if !eg.Enabled {
				return fmt.Errorf("egress_ids 引用了未启用的出口[%s] #%d", eg.Name, eid)
			}
		}
	}
	// 显式 SNAT 源 IP：必须是合法 IPv4 且当前绑定在出口网卡上（一卡多址中选一个）
	if ip := strings.TrimSpace(in.SnatIP); ip != "" {
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
			return fmt.Errorf("SNAT 源 IP %q 不是合法的 IPv4 地址", ip)
		}
		found := false
		for _, v4 := range proxy.InterfaceIPv4s(strings.TrimSpace(in.TargetAddr)) {
			if v4 == ip {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("SNAT 源 IP %s 不在出口网卡 %s 的地址列表中（可用见 GET /api/interfaces）", ip, strings.TrimSpace(in.TargetAddr))
		}
	}
	// 白名单列表（直配）
	if in.AclMode == model.AclModeWhitelist && strings.TrimSpace(in.AllowList) == "" && in.AclGroupID == 0 {
		return fmt.Errorf("白名单模式需配置名单条目或引用白名单组")
	}
	if strings.TrimSpace(in.AllowList) != "" {
		var entries []string
		if err := json.Unmarshal([]byte(in.AllowList), &entries); err != nil {
			return fmt.Errorf("白名单格式错误（应为 JSON 字符串数组）: %w", err)
		}
		for _, e := range entries {
			if !isCIDROrIP(e) {
				return fmt.Errorf("白名单条目 %q 不是合法的 IP 或网段", e)
			}
		}
	}
	// 组引用（仅白名单组）
	if in.AclGroupID != 0 {
		if in.AclMode != model.AclModeWhitelist {
			return fmt.Errorf("off 模式不能引用名单组")
		}
		var g model.AclGroup
		if err := h.DB.First(&g, in.AclGroupID).Error; err != nil {
			return fmt.Errorf("引用的名单组不存在（ID %d）", in.AclGroupID)
		}
		if g.Mode != model.AclModeWhitelist {
			return fmt.Errorf("snat 规则只能引用白名单组，[%s] 是黑名单组", g.Name)
		}
		if strings.TrimSpace(in.AllowList) != "" {
			return fmt.Errorf("已引用白名单组[%s]，不能再直配名单条目（二选一）", g.Name)
		}
	}
	// 目标名单（穿越后能/不能访问哪些目标 IP）：模式三选一，两名单互斥，
	// 显式模式要求对应名单非空；条目为 IP 或 CIDR；仅 snat 规则支持
	switch mode := strings.TrimSpace(in.DstAclMode); mode {
	case "", model.AclModeOff:
		if strings.TrimSpace(in.DstAllowList) != "" || strings.TrimSpace(in.DstDenyList) != "" {
			return fmt.Errorf("off 模式不能配置目标名单，请选择目标白名单或目标黑名单模式")
		}
	case model.AclModeWhitelist, model.AclModeBlacklist:
		// 互斥：选了哪种模式就只允许配置对应名单
		if mode == model.AclModeWhitelist && strings.TrimSpace(in.DstDenyList) != "" {
			return fmt.Errorf("目标白名单模式下不能同时配置目标黑名单，请二选一")
		}
		if mode == model.AclModeBlacklist && strings.TrimSpace(in.DstAllowList) != "" {
			return fmt.Errorf("目标黑名单模式下不能同时配置目标白名单，请二选一")
		}
		listJSON := in.DstAllowList
		if mode == model.AclModeBlacklist {
			listJSON = in.DstDenyList
		}
		var entries []string
		if strings.TrimSpace(listJSON) == "" {
			entries = nil
		} else if err := json.Unmarshal([]byte(listJSON), &entries); err != nil {
			return fmt.Errorf("%s格式错误（应为 JSON 字符串数组）: %w", groupModeName(mode), err)
		}
		if len(entries) == 0 {
			if mode == model.AclModeWhitelist {
				return fmt.Errorf("目标白名单模式需配置至少一条目标条目（空名单会拒绝全部目标）")
			}
			return fmt.Errorf("目标黑名单模式需配置至少一条目标条目（空名单等于不限，与 off 无异）")
		}
		for _, e := range entries {
			if !isCIDROrIP(e) {
				return fmt.Errorf("目标名单条目 %q 不是合法的 IP 或网段", e)
			}
		}
	default:
		return fmt.Errorf("无效的目标名单模式: %q（应为 off / whitelist / blacklist）", in.DstAclMode)
	}
	if in.MaxConns != 0 || in.IdleTimeoutSec != 0 {
		return fmt.Errorf("snat 规则不支持连接上限/空闲超时（内核转发无逐连接概念），请保持 0")
	}
	// SNAT 自身限速已彻底移除（ADR-9：限速只在带宽包）——非零值拒绝并指引进包
	if in.UploadLimitKBps != 0 || in.DownloadLimitKBps != 0 {
		return fmt.Errorf("SNAT 规则不再支持自身限速：要限速请加入带宽包（「带宽包」页配置）")
	}
	// 保底带宽已统一到带宽包级（包编辑处自定义）——规则级字段拒绝非零
	if in.MinKBps != 0 {
		return fmt.Errorf("规则不再单独设置保底带宽：请在所属带宽包中配置（0 = 包默认）")
	}
	if in.HealthCheck != nil && !*in.HealthCheck {
		// 恒关语义：允许传 true/缺省，显式 false 也接受（副作用仅入库存档）
		_ = in.HealthCheck
	}
	return nil
}

// ifaceAddrStrings 网卡的全部 CIDR 地址串（如 172.16.40.10/24）。
func ifaceAddrStrings(iface *net.Interface) []string {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			out = append(out, ipn.String())
		}
	}
	return out
}

// isCIDROrIP IPv4 地址或 IPv4 CIDR（IPv6 落库会让 iptables -s 安装失败——snat 白名单只认 v4）。
func isCIDROrIP(s string) bool {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		ip, _, err := net.ParseCIDR(s)
		return err == nil && ip != nil && ip.To4() != nil
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("目标地址不能为空")
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return fmt.Errorf("目标地址格式错误（应为 host:port）: %s", target)
	}
	return nil
}

// checkConflict 端口冲突检测（与所有已启用规则及 Web 后台端口比较）。
// TCP 与 UDP 分属不同协议栈，同端口号可共存；同协议同端口冲突。
// snat 无监听端口（listen_addr 是网卡名，SplitHostPort 得空串）——跳过比较，
// 冲突由 applySNAT 的网卡存在性/互异校验兜底；不跳过则任意两条 snat 互相误报。
func (h *handlers) checkConflict(rule model.ForwardRule) error {
	if rule.Protocol == model.ProtocolSNAT {
		return nil
	}
	_, portStr, _ := net.SplitHostPort(rule.ListenAddr)
	if rule.Protocol != model.ProtocolUDP && h.Cfg.ListenPort() > 0 {
		if strconv.Itoa(h.Cfg.ListenPort()) == portStr {
			return fmt.Errorf("端口 %s 与 Web 管理后台端口冲突", portStr)
		}
	}

	var others []model.ForwardRule
	h.DB.Where("id <> ?", rule.ID).Where("enabled = ?", true).Find(&others)

	for _, o := range others {
		_, oPort, _ := net.SplitHostPort(o.ListenAddr)
		if oPort != portStr {
			continue
		}
		// 评审 #10：dnat 的发布地址是完整 IP:端口——同端口不同 IP（一卡多址）
		// 不冲突；同 IP:端口 无论协议（都吃进本机 INPUT/DNAT）冲突
		if rule.Protocol == model.ProtocolDNAT || o.Protocol == model.ProtocolDNAT {
			if strings.EqualFold(strings.TrimSpace(o.ListenAddr), strings.TrimSpace(rule.ListenAddr)) &&
				(o.Protocol == model.ProtocolDNAT && rule.Protocol == model.ProtocolDNAT ||
					o.Protocol == rule.Protocol) {
				return fmt.Errorf("发布地址 %s 已被规则[%s]占用", rule.ListenAddr, o.Name)
			}
			continue
		}
		if o.Protocol == rule.Protocol {
			return fmt.Errorf("端口 %s 已被规则[%s]占用", portStr, o.Name)
		}
	}
	return nil
}

func ruleDetail(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ---------- handlers ----------

// serverError 记录内部错误详情并返回脱敏的统一响应，避免把驱动细节泄漏给客户端。
func (h *handlers) serverError(c *gin.Context, what string, err error) {
	log.Printf("[api] %s失败: %v", what, err)
	c.JSON(500, gin.H{"error": what + "失败，请查看服务端日志"})
}

// parseRuleID 解析路径参数中的规则 ID，非数字返回 400。
func parseRuleID(c *gin.Context) (int, bool) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "无效的规则 ID"})
		return 0, false
	}
	return id, true
}

// listRules 规则列表：分页 + 关键字搜索（名称/监听地址/目标地址模糊匹配）。
// 万级规则下前端不再全量拉取。
func (h *handlers) listRules(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	search := strings.TrimSpace(c.Query("search"))

	base := func() *gorm.DB {
		q := h.DB.Model(&model.ForwardRule{})
		// 类型过滤（菜单拆分后两个页各自只拉自己的类型；逗号分隔多值 OR：
		// 如 protocol=tcp,udp 拉全部端口映射类）
		if p := strings.TrimSpace(c.Query("protocol")); p != "" {
			vals := strings.Split(p, ",")
			q = q.Where("protocol IN ?", vals)
		}
		if search != "" {
			like := "%" + escapeLike(search) + "%"
			q = q.Where(
				"name LIKE ? ESCAPE '\\' OR listen_addr LIKE ? ESCAPE '\\' OR target_addr LIKE ? ESCAPE '\\'",
				like, like, like,
			)
		}
		return q
	}

	var total int64
	if err := base().Count(&total).Error; err != nil {
		h.serverError(c, "统计规则数", err)
		return
	}
	var rules []model.ForwardRule
	if err := base().Order("id").Offset((page - 1) * pageSize).Limit(pageSize).Find(&rules).Error; err != nil {
		h.serverError(c, "查询规则", err)
		return
	}

	// 批量取本页涉及的带宽包（去 N+1：每行 First 改一次 IN 查询）
	bwIDs := map[uint]bool{}
	for _, r := range rules {
		if r.BWGroupID != 0 {
			bwIDs[r.BWGroupID] = true
		}
	}
	bwMap := map[uint]model.BWGroup{}
	if len(bwIDs) > 0 {
		ids := make([]uint, 0, len(bwIDs))
		for id := range bwIDs {
			ids = append(ids, id)
		}
		var bgs []model.BWGroup
		h.DB.Where("id IN ?", ids).Find(&bgs)
		for _, bg := range bgs {
			bwMap[bg.ID] = bg
		}
	}

	live := h.Mgr.LiveStats()
	rates := map[uint][2]int64{}
	for _, rm := range h.Mgr.RuleMetrics() {
		rates[rm.ID] = [2]int64{rm.RateUpBps, rm.RateDownBps}
	}
	type ruleWithLive struct {
		model.ForwardRule
		Live   proxy.RuleLiveStat  `json:"live"`
		Health proxy.BackendHealth `json:"health"`
		// Snat 摘要（仅 protocol=snat 行；其余协议为 null 不占版面）
		Snat *snatSummary `json:"snat,omitempty"`
		// 所属带宽包（入包规则；null = 独立）
		BandwidthGroup *bwGroupBrief `json:"bandwidth_group,omitempty"`
	}
	items := make([]ruleWithLive, 0, len(rules))
	for _, r := range rules {
		w := ruleWithLive{
			ForwardRule: r,
			Live:        proxy.RuleLiveStat{},
			Health:      h.Mgr.BackendHealthOf(r.ID),
		}
		if st, ok := live[r.ID]; ok {
			w.Live = *st
		}
		if rt, ok := rates[r.ID]; ok {
			w.Live.RateUpBps = rt[0]
			w.Live.RateDownBps = rt[1]
		}
		if r.Protocol == model.ProtocolSNAT {
			w.Snat = h.snatSummaryOf(r)
		}
		// dnat 行注入访问统计（P2-2：前端"访问统计"列此前恒空——同 snat 摘要
		// 通道，但计数按 KindDNAT 标记聚合）
		if r.Protocol == model.ProtocolDNAT {
			w.Snat = h.dnatSummaryOf(r)
		}
		if bg, ok := bwMap[r.BWGroupID]; ok && r.BWGroupID != 0 {
			w.BandwidthGroup = &bwGroupBrief{ID: bg.ID, Name: bg.Name, TotalKBps: bg.TotalKBps}
		}
		items = append(items, w)
	}
	c.JSON(200, gin.H{"items": items, "total": total, "page": page, "page_size": pageSize})
}

func (h *handlers) createRule(c *gin.Context) {
	var in ruleInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := in.validate(h); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	rule := in.toRule()
	if rule.Enabled {
		if err := h.checkConflict(rule); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
	}
	if err := h.DB.Create(&rule).Error; err != nil {
		h.serverError(c, "保存规则", err)
		return
	}
	if err := h.Mgr.Apply(rule); err != nil {
		// 应用失败（如端口被外部进程占用）则回滚删除
		if delErr := h.DB.Delete(&model.ForwardRule{}, rule.ID).Error; delErr != nil {
			log.Printf("[api] 规则[%s#%d] 应用失败后回滚删除失败: %v", rule.Name, rule.ID, delErr)
		}
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.Audit.Record(h.username(c), "rule_create", ruleDetail(rule), h.clientIP(c))
	c.JSON(200, rule)
}

func (h *handlers) updateRule(c *gin.Context) {
	id, ok := parseRuleID(c)
	if !ok {
		return
	}
	var old model.ForwardRule
	if err := h.DB.First(&old, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "规则不存在"})
		return
	}
	var in ruleInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := in.validate(h); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	rule := in.toRule()
	rule.ID = old.ID
	if rule.Enabled {
		if err := h.checkConflict(rule); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
	}
	// 按输入全字段更新（含 AclMode/AclGroupID/SnatIP——前端两页各自表单显式提供；
	// BWGroupID 不入列表：带宽包成员关系由带宽包页管理，规则编辑不改归属）
	if err := h.DB.Model(&old).Select(
		"Name", "Protocol", "ListenAddr", "TargetAddr", "AclMode",
		"AllowList", "DenyList", "AclGroupID", "SnatIP", "EgressGw", "MinKBps", "SourceIP",
		"DstAclMode", "DstAllowList", "DstDenyList",
		// B6：M2/M3 新列显式加入（AGENTS 踩坑：Select 白名单漏新列=编辑静默丢字段）
		"DnatRejectMode", "SnatMode", "SnatPool", "EgressIDs",
		"UploadLimitKBps", "DownloadLimitKBps", "MaxConns", "IdleTimeoutSec", "HealthCheck", "Enabled",
	).Updates(rule).Error; err != nil {
		h.serverError(c, "保存规则", err)
		return
	}
	rule.BWGroupID = old.BWGroupID // 回填库内归属：引擎重建包 class（PUT 输入不含该字段）
	if err := h.Mgr.Apply(rule); err != nil {
		// 应用失败回滚到旧规则并恢复旧监听；回滚环节的失败必须全部暴露
		if dbErr := h.DB.Save(&old).Error; dbErr != nil {
			log.Printf("[api] 规则#%d 回滚数据库失败: %v", old.ID, dbErr)
		}
		if rbErr := h.Mgr.Apply(old); rbErr != nil {
			log.Printf("[api] 规则#%d 恢复旧监听失败，规则可能处于不一致状态: %v", old.ID, rbErr)
			c.JSON(500, gin.H{"error": "应用新配置失败，且回滚旧配置也失败，请检查该规则状态后重试"})
			return
		}
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.Audit.Record(h.username(c), "rule_update", ruleDetail(rule), h.clientIP(c))
	c.JSON(200, rule)
}

func (h *handlers) deleteRule(c *gin.Context) {
	id, ok := parseRuleID(c)
	if !ok {
		return
	}
	var rule model.ForwardRule
	if err := h.DB.First(&rule, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "规则不存在"})
		return
	}
	h.Mgr.Stop(rule)
	if err := h.DB.Delete(&model.ForwardRule{}, id).Error; err != nil {
		// 删除失败则恢复监听，避免出现"库里有但没监听"的不一致状态
		if rbErr := h.Mgr.Apply(rule); rbErr != nil {
			log.Printf("[api] 规则#%d 删除失败且恢复监听失败: %v", rule.ID, rbErr)
		}
		h.serverError(c, "删除规则", err)
		return
	}
	h.Mgr.ForgetRule(rule.ID) // 清理进程内指标条目
	h.Audit.Record(h.username(c), "rule_delete", ruleDetail(rule), h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}

func (h *handlers) enableRule(c *gin.Context) {
	h.setRuleEnabled(c, true)
}

// bwGroupBrief 规则列表附带的带宽包摘要。
type bwGroupBrief struct {
	ID        uint   `json:"id"`
	Name      string `json:"name"`
	TotalKBps int64  `json:"total_kbps"`
}

// snatSummary 列表行的 snat 摘要（design-snat.md API-R2）。
type snatSummary struct {
	IfIn     string `json:"if_in"`
	IfOut    string `json:"if_out"`
	SnatIP   string `json:"snat_ip"`
	Packets  int64  `json:"packets"`
	DeniedPk int64  `json:"denied_packets"`
}

// snatSummaryOf 由规则行构建摘要（计数读内核当前值，读不到给 -1 表示未知）。
func (h *handlers) snatSummaryOf(r model.ForwardRule) *snatSummary {
	ip := strings.TrimSpace(r.SnatIP)
	if ip == "" {
		ip = proxy.IPv4OfInterface(r.TargetAddr) // 自动档：当前网卡首地址
	}
	s := &snatSummary{
		IfIn:   r.ListenAddr,
		IfOut:  r.TargetAddr,
		SnatIP: ip,
	}
	var allowSrcs []string
	_ = json.Unmarshal([]byte(r.AllowList), &allowSrcs)
	if c := h.Mgr.ReadSnatCountersNFT(r.ID, r.ListenAddr, allowSrcs); c != nil {
		s.Packets = c.PktsAccept
		s.DeniedPk = c.PktsDrop
	}
	return s
}

// ruleLiveStats 单条规则的实时统计（活跃会话 + 最近窗口速率），
// 供外部系统按规则轮询（/api/rules/:id/live）。
func (h *handlers) ruleLiveStats(c *gin.Context) {
	id, ok := parseRuleID(c)
	if !ok {
		return
	}
	var rule model.ForwardRule
	if err := h.DB.First(&rule, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "规则不存在"})
		return
	}
	live := h.Mgr.LiveStats()
	st := live[uint(id)]
	if st == nil {
		st = &proxy.RuleLiveStat{}
	}
	var metric *proxy.RuleMetric
	for _, rm := range h.Mgr.RuleMetrics() {
		if rm.ID == uint(id) {
			metric = &rm
			break
		}
	}
	rateUp, rateDown := int64(0), int64(0)
	upBytes, downBytes := int64(st.UploadBytes), int64(st.DownloadBytes)
	if metric != nil {
		rateUp, rateDown = metric.RateUpBps, metric.RateDownBps
		// snat 无活跃会话概念：live 的累计字节取 RuleMetrics 的穿越累计，
		// 而非 LiveStats 的活跃会话字节（snat 下恒 0）
		if rule.Protocol == model.ProtocolSNAT {
			upBytes, downBytes = metric.BytesUp, metric.BytesDown
		}
	}
	c.JSON(200, gin.H{
		"rule_id":        rule.ID,
		"rule_name":      rule.Name,
		"enabled":        rule.Enabled,
		"active_conns":   st.ActiveConns,
		"upload_bytes":   upBytes,
		"download_bytes": downBytes,
		"rate_up_bps":    rateUp,
		"rate_down_bps":  rateDown,
		"window_seconds": 10,
	})
}

// ruleHealthHistory 指定规则的后端检测历史（落库数据，支持时间范围筛选）。
// start/end 为 unix 秒；缺省查询最近 24 小时，最长 31 天。
func (h *handlers) ruleHealthHistory(c *gin.Context) {
	id, ok := parseRuleID(c)
	if !ok {
		return
	}
	var rule model.ForwardRule
	if err := h.DB.First(&rule, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "规则不存在"})
		return
	}
	now := time.Now()
	end, start := now, now.Add(-24*time.Hour)
	if v, err := strconv.ParseInt(c.Query("start"), 10, 64); err == nil && v > 0 {
		start = time.Unix(v, 0)
	}
	if v, err := strconv.ParseInt(c.Query("end"), 10, 64); err == nil && v > 0 {
		end = time.Unix(v, 0)
	}
	if start.After(end) {
		start, end = end, start
	}
	if end.Sub(start) > 31*24*time.Hour {
		start = end.Add(-31 * 24 * time.Hour)
	}
	pts, avail, err := h.Mgr.BackendHealthRange(uint(id), start, end, proxy.HealthHistoryMaxPoints)
	if err != nil {
		h.serverError(c, "查询健康检测历史", err)
		return
	}
	snap := h.Mgr.BackendHealthOf(uint(id))
	c.JSON(200, gin.H{
		"checked":      snap.Checked,
		"up":           snap.Up,
		"last_check":   snap.LastCheck,
		"error":        snap.Error,
		"availability": avail,
		"points":       pts,
		"start":        start.Unix(),
		"end":          end.Unix(),
	})
}

func (h *handlers) disableRule(c *gin.Context) {
	h.setRuleEnabled(c, false)
}

func (h *handlers) setRuleEnabled(c *gin.Context, enabled bool) {
	id, ok := parseRuleID(c)
	if !ok {
		return
	}
	var rule model.ForwardRule
	if err := h.DB.First(&rule, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "规则不存在"})
		return
	}
	rule.Enabled = enabled
	if enabled {
		if err := h.checkConflict(rule); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
	}
	if err := h.DB.Model(&rule).Update("enabled", enabled).Error; err != nil {
		h.serverError(c, "保存规则状态", err)
		return
	}
	if err := h.Mgr.Apply(rule); err != nil {
		// 应用失败回滚数据库状态并恢复旧监听
		if dbErr := h.DB.Model(&rule).Update("enabled", !enabled).Error; dbErr != nil {
			log.Printf("[api] 规则#%d 回滚启用状态失败: %v", rule.ID, dbErr)
		}
		rollback := rule
		rollback.Enabled = !enabled
		if rbErr := h.Mgr.Apply(rollback); rbErr != nil {
			log.Printf("[api] 规则#%d 恢复旧状态失败，规则可能处于不一致状态: %v", rule.ID, rbErr)
			c.JSON(500, gin.H{"error": "应用失败且回滚也失败，请检查该规则状态后重试"})
			return
		}
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	action := "rule_disable"
	if enabled {
		action = "rule_enable"
	}
	h.Audit.Record(h.username(c), action, ruleDetail(rule), h.clientIP(c))
	c.JSON(200, rule)
}
