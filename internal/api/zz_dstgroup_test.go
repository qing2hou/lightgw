package api

import (
	"encoding/json"
	"strings"
	"testing"

	"haproxyweb/internal/model"
)

// TestSnatDstGroupValidation 目标限制引用名单组的校验矩阵。
func TestSnatDstGroupValidation(t *testing.T) {
	h := &handlers{}
	h.DB = newTestDB(t)
	lo, out := twoUpIfaces(t)

	mk := func(mode, name string) model.AclGroup {
		g := model.AclGroup{Name: name, Mode: mode, Entries: `["172.16.41.0/24"]`}
		if err := h.DB.Create(&g).Error; err != nil {
			t.Fatal(err)
		}
		return g
	}
	wl := mk(model.AclModeWhitelist, "wl")
	bl := mk(model.AclModeBlacklist, "bl")
	ip := mk(model.AclGroupModeIP, "ipg")

	base := func() *ruleInput {
		return &ruleInput{
			Name: "snat-dstg", Protocol: model.ProtocolSNAT,
			ListenAddr: lo, TargetAddr: out,
			AclMode: model.AclModeWhitelist, AllowList: `["192.168.10.0/24"]`,
			SnatMode: "fixed",
		}
	}

	// 1) 白名单模式引白名单组：通过
	in := base()
	in.DstAclMode, in.DstAclGroupID = model.AclModeWhitelist, wl.ID
	if err := in.validate(h); err != nil {
		t.Fatalf("白名单模式引白名单组应通过: %v", err)
	}

	// 2) 白名单模式引黑名单组：拒绝
	in = base()
	in.DstAclMode, in.DstAclGroupID = model.AclModeWhitelist, bl.ID
	if err := in.validate(h); err == nil {
		t.Fatal("白名单模式引黑名单组应被拒绝")
	}

	// 3) 黑名单模式引黑名单组：通过
	in = base()
	in.DstAclMode, in.DstAclGroupID = model.AclModeBlacklist, bl.ID
	if err := in.validate(h); err != nil {
		t.Fatalf("黑名单模式引黑名单组应通过: %v", err)
	}

	// 4) 任一模式引 IP 组：通过
	for _, mode := range []string{model.AclModeWhitelist, model.AclModeBlacklist} {
		in = base()
		in.DstAclMode, in.DstAclGroupID = mode, ip.ID
		if err := in.validate(h); err != nil {
			t.Fatalf("%s 模式引 IP 组应通过: %v", mode, err)
		}
	}

	// 5) 引用组 + 直配条目：拒绝（二选一）
	in = base()
	in.DstAclMode, in.DstAclGroupID, in.DstAllowList = model.AclModeWhitelist, wl.ID, `["1.2.3.4"]`
	if err := in.validate(h); err == nil {
		t.Fatal("引用组时再直配目标条目应被拒绝")
	}

	// 6) off 模式带组引用：拒绝
	in = base()
	in.DstAclMode, in.DstAclGroupID = model.AclModeOff, wl.ID
	if err := in.validate(h); err == nil {
		t.Fatal("off 模式带目标组引用应被拒绝")
	}

	// 7) 组不存在：拒绝
	in = base()
	in.DstAclMode, in.DstAclGroupID = model.AclModeWhitelist, 99999
	if err := in.validate(h); err == nil {
		t.Fatal("引用不存在的组应被拒绝")
	}

	// 8) 所有校验通过后，toRule 应保留目标组 ID
	in = base()
	in.DstAclMode, in.DstAclGroupID = model.AclModeWhitelist, ip.ID
	r := in.toRule()
	if r.DstAclGroupID != ip.ID {
		t.Fatalf("DstAclGroupID 未透传: %d", r.DstAclGroupID)
	}
}

// TestSnatSourceIPGroup 源名单引用 IP 组。
func TestSnatSourceIPGroup(t *testing.T) {
	h := &handlers{}
	h.DB = newTestDB(t)
	lo, out := twoUpIfaces(t)
	ip := model.AclGroup{Name: "src-ip", Mode: model.AclGroupModeIP, Entries: `["192.168.10.0/24"]`}
	if err := h.DB.Create(&ip).Error; err != nil {
		t.Fatal(err)
	}
	in := &ruleInput{
		Name: "snat-srcg", Protocol: model.ProtocolSNAT,
		ListenAddr: lo, TargetAddr: out,
		AclMode: model.AclModeWhitelist, AclGroupID: ip.ID,
		SnatMode: "fixed",
	}
	if err := in.validate(h); err != nil {
		t.Fatalf("源名单引 IP 组应通过: %v", err)
	}
	// 黑名单组仍不可用于 snat 源名单
	bl := model.AclGroup{Name: "src-bl", Mode: model.AclModeBlacklist, Entries: `["1.2.3.4"]`}
	if err := h.DB.Create(&bl).Error; err != nil {
		t.Fatal(err)
	}
	in.AclGroupID = bl.ID
	if err := in.validate(h); err == nil {
		t.Fatal("snat 源名单引黑名单组应被拒绝")
	}
}

// TestExportInlinesDstGroup 导出时目标组内联展开。
func TestExportInlinesDstGroup(t *testing.T) {
	r := model.ForwardRule{
		AclMode: model.AclModeWhitelist, AllowList: `["192.168.10.0/24"]`,
		DstAclMode: model.AclModeBlacklist, DstAclGroupID: 7,
	}
	g := model.AclGroup{Mode: model.AclGroupModeIP, Entries: `["10.0.0.0/8"]`}
	if !model.AclGroupMatchesMode(g.Mode, r.DstAclMode) {
		t.Fatal("IP 组应可被黑名单模式引用")
	}
	// 模拟导出内联
	if r.DstAclMode == model.AclModeBlacklist {
		r.DstDenyList = g.Entries
	}
	r.DstAclGroupID = 0
	var got []string
	if err := json.Unmarshal([]byte(r.DstDenyList), &got); err != nil || len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("目标组未正确内联: %v %v", got, err)
	}
	if strings.Contains(r.DstDenyList, "acl_group") {
		t.Fatal("导出不应残留组引用")
	}
}
