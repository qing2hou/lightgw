package proxy

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"haproxyweb/internal/model"
)

// ACL IP 黑白名单，按规则选择的名单模式生效：
//   - whitelist 模式：仅白名单生效，命中放行、未命中拒绝
//   - blacklist 模式：仅黑名单生效，命中拒绝、未命中放行
//   - off 模式：名单不生效，全部放行
//   - 空模式（旧数据兼容）：黑名单优先 + 白名单限制的并用量纲
type ACL struct {
	mode  string
	allow []netip.Prefix
	deny  []netip.Prefix
}

// AllowAll 空名单，全部放行。
var AllowAll = &ACL{}

// ParseACL 按模式解析名单。allowJSON/denyJSON 为 JSON 字符串数组（元素为 IP 或
// CIDR），空串视为空名单。mode 为空时维持旧版并用语义。
func ParseACL(mode, allowJSON, denyJSON string) (*ACL, error) {
	a := &ACL{mode: mode}
	var err error
	if a.allow, err = parseList(allowJSON); err != nil {
		return nil, fmt.Errorf("白名单格式错误: %w", err)
	}
	if a.deny, err = parseList(denyJSON); err != nil {
		return nil, fmt.Errorf("黑名单格式错误: %w", err)
	}
	switch mode {
	case model.AclModeOff, model.AclModeWhitelist, model.AclModeBlacklist, "":
	default:
		return nil, fmt.Errorf("无效的名单模式: %q（应为 off / whitelist / blacklist）", mode)
	}
	return a, nil
}

func parseList(jsonStr string) ([]netip.Prefix, error) {
	if jsonStr == "" {
		return nil, nil
	}
	var entries []string
	if err := json.Unmarshal([]byte(jsonStr), &entries); err != nil {
		return nil, fmt.Errorf("应为 JSON 字符串数组: %w", err)
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		p, err := parseEntry(e)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// parseEntry 支持单 IP（1.2.3.4）与 CIDR（192.168.1.0/24）。
func parseEntry(s string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("无效的 IP 或网段: %q", s)
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr.Unmap(), 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
}

// Allowed 判定给定 IP 是否放行。
func (a *ACL) Allowed(ip netip.Addr) bool {
	if a == nil || a.mode == model.AclModeOff {
		return true
	}
	ip = ip.Unmap()
	switch a.mode {
	case model.AclModeWhitelist:
		for _, p := range a.allow {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	case model.AclModeBlacklist:
		for _, p := range a.deny {
			if p.Contains(ip) {
				return false
			}
		}
		return true
	default:
		// 旧数据（空模式）：黑名单优先，白名单非空时须命中
		if len(a.allow) == 0 && len(a.deny) == 0 {
			return true
		}
		for _, p := range a.deny {
			if p.Contains(ip) {
				return false
			}
		}
		if len(a.allow) == 0 {
			return true
		}
		for _, p := range a.allow {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
}

// DenyMessage 拒绝原因说明（用于流量日志）。
func (a *ACL) DenyMessage() string {
	if a == nil {
		return "访问被拒绝"
	}
	switch a.mode {
	case model.AclModeWhitelist:
		return "IP 不在白名单内"
	case model.AclModeBlacklist:
		return "IP 命中黑名单"
	case model.AclModeOff:
		return "访问被拒绝"
	default:
		return "IP 不在访问名单允许范围"
	}
}

// ValidateLists 校验名单模式与 JSON 格式（API 层保存前调用）。
// whitelist 模式要求白名单非空，blacklist 模式要求黑名单非空，
// 防止出现"白名单模式但名单为空"导致拒绝所有访问的误配置。
func ValidateLists(mode, allowJSON, denyJSON string) error {
	a, err := ParseACL(mode, allowJSON, denyJSON)
	if err != nil {
		return err
	}
	switch mode {
	case model.AclModeWhitelist:
		if len(a.allow) == 0 {
			return fmt.Errorf("白名单模式需要至少配置一条白名单条目")
		}
	case model.AclModeBlacklist:
		if len(a.deny) == 0 {
			return fmt.Errorf("黑名单模式需要至少配置一条黑名单条目")
		}
	}
	return nil
}

// parseIPOrZero 解析失败返回零值地址；零值不会命中任何网段（非空白名单下被拒绝）。
func parseIPOrZero(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}
