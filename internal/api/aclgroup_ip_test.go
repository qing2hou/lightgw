package api

import (
	"testing"

	"haproxyweb/internal/model"
)

// TestAclGroupModeValidation 名单组三种类型的校验：ip 组合法且需非空。
func TestAclGroupModeValidation(t *testing.T) {
	for _, mode := range []string{"whitelist", "blacklist", "ip"} {
		in := &aclGroupInput{Name: "g-" + mode, Mode: mode, Entries: []string{"192.168.1.0/24"}}
		if err := in.validate(); err != nil {
			t.Fatalf("类型 %s 应通过校验: %v", mode, err)
		}
	}
	in := &aclGroupInput{Name: "bad", Mode: "neutral", Entries: []string{"1.2.3.4"}}
	if err := in.validate(); err == nil {
		t.Fatal("非法类型应被拒绝")
	}
	// IP 组必须非空（空 IP 组被白名单引用等于拒绝全部）
	empty := &aclGroupInput{Name: "empty-ip", Mode: "ip"}
	if err := empty.validate(); err == nil {
		t.Fatal("空 IP 组应被拒绝")
	}
	// 黑名单组允许空（空黑名单 = 不拒绝任何，语义无副作用）
	emptyBL := &aclGroupInput{Name: "empty-bl", Mode: "blacklist"}
	if err := emptyBL.validate(); err != nil {
		t.Fatalf("空黑名单组应允许: %v", err)
	}
}

// TestAclGroupMatchesMode 组与引用方模式的兼容矩阵。
func TestAclGroupMatchesMode(t *testing.T) {
	cases := []struct {
		group, use string
		want       bool
	}{
		{"whitelist", "whitelist", true},
		{"whitelist", "blacklist", false},
		{"blacklist", "blacklist", true},
		{"blacklist", "whitelist", false},
		{"ip", "whitelist", true},
		{"ip", "blacklist", true},
		{"ip", "off", true},
	}
	for _, c := range cases {
		if got := model.AclGroupMatchesMode(c.group, c.use); got != c.want {
			t.Errorf("AclGroupMatchesMode(%s,%s)=%v，期望 %v", c.group, c.use, got, c.want)
		}
	}
}
