package api

import (
	"net"
	"testing"

	"haproxyweb/internal/model"
)

// TestFixedModeAcceptsEmptyPool 回归：fixed 模式下前端提交 snat_pool="[]"
// （列表控件未选成员）曾被判为"已配置源池"而 400，导致新建/编辑 SNAT 规则
// 在界面上永远保存不了。空数组与字段缺省必须等价。
func TestFixedModeAcceptsEmptyPool(t *testing.T) {
	h := &handlers{}
	lo, out := twoUpIfaces(t)

	for _, pool := range []string{"", "[]", " [ ] ", "null"} {
		in := &ruleInput{
			Name: "snat-regress", Protocol: model.ProtocolSNAT,
			ListenAddr: lo, TargetAddr: out,
			AclMode: model.AclModeWhitelist, AllowList: `["192.168.10.0/24"]`,
			SnatMode: "fixed", SnatPool: pool,
		}
		if err := in.validate(h); err != nil {
			t.Fatalf("fixed 模式 snat_pool=%q 应通过校验，实际拒绝: %v", pool, err)
		}
		if got := in.toRule().SnatPool; got != "" {
			t.Errorf("fixed 模式 snat_pool=%q 落库应归一为空串，实际 %q", pool, got)
		}
	}
}

// TestFixedModeRejectsNonEmptyPool fixed 模式仍须拒绝真配置了源池的请求。
func TestFixedModeRejectsNonEmptyPool(t *testing.T) {
	h := &handlers{}
	lo, out := twoUpIfaces(t)
	in := &ruleInput{
		Name: "snat-regress", Protocol: model.ProtocolSNAT,
		ListenAddr: lo, TargetAddr: out,
		AclMode: model.AclModeWhitelist, AllowList: `["192.168.10.0/24"]`,
		SnatMode: "fixed", SnatPool: `["192.168.10.170"]`,
	}
	if err := in.validate(h); err == nil {
		t.Fatal("fixed 模式配置了非空 snat_pool 应被拒绝")
	}
}

// TestRotateModeRequiresPool rotate/sticky 模式的空池报错须指明模式与数量。
func TestRotateModeRequiresPool(t *testing.T) {
	h := &handlers{}
	lo, out := twoUpIfaces(t)
	for _, mode := range []string{"rotate", "sticky"} {
		in := &ruleInput{
			Name: "snat-regress", Protocol: model.ProtocolSNAT,
			ListenAddr: lo, TargetAddr: out,
			AclMode: model.AclModeWhitelist, AllowList: `["192.168.10.0/24"]`,
			SnatMode: mode, SnatPool: "[]",
		}
		err := in.validate(h)
		if err == nil {
			t.Fatalf("%s 模式空源池应被拒绝", mode)
		}
	}
}

// TestIsEmptyJSONList 归一判据：空串/空数组/null 为空；非空数组与非法 JSON 不为空。
func TestIsEmptyJSONList(t *testing.T) {
	cases := map[string]bool{
		"":               true,
		"[]":             true,
		" [ ] ":          true,
		"null":           true,
		`["1.2.3.4"]`:    false,
		`[1]`:            false,
		`[""]`:           false,
		"not-json":       false,
		`{"a":1}`:        false,
		"[\"a\",\"b\"] ": false,
	}
	for in, want := range cases {
		if got := isEmptyJSONList(in); got != want {
			t.Errorf("isEmptyJSONList(%q) = %v，期望 %v", in, got, want)
		}
	}
}

// twoUpIfaces 取两块不同的 up 网卡（snat 校验要求入口≠出口）。
// 环境不具备时跳过——该用例的价值在校验分支，不在网卡本身。
func twoUpIfaces(t *testing.T) (in, out string) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("枚举网卡失败: %v", err)
	}
	var ups []string
	for _, i := range ifaces {
		if i.Flags&net.FlagUp != 0 && len(i.HardwareAddr) > 0 {
			ups = append(ups, i.Name)
		}
	}
	if len(ups) < 2 {
		t.Skipf("需要至少两块 up 的物理网卡，当前 %d 块", len(ups))
	}
	return ups[0], ups[1]
}
