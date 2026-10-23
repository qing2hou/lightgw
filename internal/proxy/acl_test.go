package proxy

import (
	"net/netip"
	"testing"

	"haproxyweb/internal/model"
)

func mustACL(t *testing.T, mode, allow, deny string) *ACL {
	t.Helper()
	a, err := ParseACL(mode, allow, deny)
	if err != nil {
		t.Fatalf("ParseACL error: %v", err)
	}
	return a
}

func ip(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}

func TestOffModeAllowAll(t *testing.T) {
	a := mustACL(t, model.AclModeOff, `["10.0.0.1"]`, `["10.0.0.2"]`)
	if !a.Allowed(ip("1.2.3.4")) || !a.Allowed(ip("10.0.0.1")) || !a.Allowed(ip("10.0.0.2")) {
		t.Fatal("off 模式名单不生效，应全部放行")
	}
}

// 空模式为旧数据兼容语义：黑名单优先 + 白名单限制
func TestLegacyModeDenyWins(t *testing.T) {
	a := mustACL(t, "", `["10.0.0.0/8"]`, `["10.1.1.1"]`)
	if a.Allowed(ip("10.1.1.1")) {
		t.Fatal("黑名单命中应拒绝，即使命中白名单")
	}
	if !a.Allowed(ip("10.2.3.4")) {
		t.Fatal("白名单网段内应放行")
	}
	if a.Allowed(ip("192.168.1.1")) {
		t.Fatal("白名单非空时未命中应拒绝")
	}
}

func TestLegacyModeEmptyLists(t *testing.T) {
	a := mustACL(t, "", "", "")
	if !a.Allowed(ip("1.2.3.4")) || !a.Allowed(ip("10.0.0.1")) {
		t.Fatal("空名单应全部放行")
	}
}

func TestWhitelistMode(t *testing.T) {
	a := mustACL(t, model.AclModeWhitelist, `["192.168.1.0/24", "127.0.0.1"]`, "")
	if !a.Allowed(ip("192.168.1.200")) || !a.Allowed(ip("127.0.0.1")) {
		t.Fatal("白名单命中应放行")
	}
	if a.Allowed(ip("192.168.2.1")) || a.Allowed(ip("8.8.8.8")) {
		t.Fatal("白名单未命中应拒绝")
	}
}

func TestBlacklistMode(t *testing.T) {
	a := mustACL(t, model.AclModeBlacklist, "", `["8.8.8.8", "172.16.0.0/12"]`)
	if a.Allowed(ip("8.8.8.8")) || a.Allowed(ip("172.20.1.1")) {
		t.Fatal("黑名单命中应拒绝")
	}
	if !a.Allowed(ip("1.1.1.1")) || !a.Allowed(ip("192.168.1.1")) {
		t.Fatal("黑名单未命中应放行")
	}
}

func TestIPv6(t *testing.T) {
	a := mustACL(t, model.AclModeWhitelist, `["::1", "fd00::/8"]`, "")
	if !a.Allowed(ip("::1")) || !a.Allowed(ip("fd12::1")) {
		t.Fatal("IPv6 白名单命中应放行")
	}
	if a.Allowed(ip("::2")) {
		t.Fatal("IPv6 白名单未命中应拒绝")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := ParseACL(model.AclModeWhitelist, `["not-an-ip"]`, ""); err == nil {
		t.Fatal("非法 IP 应报错")
	}
	if _, err := ParseACL(model.AclModeWhitelist, `["10.0.0.0/99"]`, ""); err == nil {
		t.Fatal("非法掩码应报错")
	}
	if _, err := ParseACL(model.AclModeWhitelist, `"not-an-array"`, ""); err == nil {
		t.Fatal("非数组 JSON 应报错")
	}
	if _, err := ParseACL("permissive", "", ""); err == nil {
		t.Fatal("无效的名单模式应报错")
	}
}

func TestValidateLists(t *testing.T) {
	if err := ValidateLists(model.AclModeWhitelist, "", ""); err == nil {
		t.Fatal("白名单模式名单为空应报错")
	}
	if err := ValidateLists(model.AclModeBlacklist, "", ""); err == nil {
		t.Fatal("黑名单模式名单为空应报错")
	}
	if err := ValidateLists(model.AclModeOff, "", ""); err != nil {
		t.Fatalf("off 模式空名单应通过: %v", err)
	}
	if err := ValidateLists(model.AclModeBlacklist, "", `["10.0.0.1"]`); err != nil {
		t.Fatalf("黑名单模式名单非空应通过: %v", err)
	}
}
