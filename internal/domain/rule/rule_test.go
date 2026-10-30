package rule

import (
	"net/netip"
	"strings"
	"testing"

	"haproxyweb/internal/domain/model"
)

func mkRule(id uint, listen, backend string, enabled bool) model.Rule {
	return model.Rule{
		ID:       id,
		Name:     "r",
		Proto:    model.ProtoTCP,
		ListenAt: netip.MustParseAddrPort(listen),
		Backend:  netip.MustParseAddrPort(backend),
		Enabled:  enabled,
	}
}

func TestValidateOK(t *testing.T) {
	rules := []model.Rule{
		mkRule(1, "192.168.10.170:1022", "192.168.10.152:22", true),
		mkRule(2, "192.168.10.170:1023", "192.168.10.152:23", true),
	}
	if err := Validate(rules); err != nil {
		t.Fatalf("合法规则集应通过: %v", err)
	}
}

func TestValidateListenerConflict(t *testing.T) {
	rules := []model.Rule{
		mkRule(1, "192.168.10.170:1022", "192.168.10.152:22", true),
		mkRule(2, "192.168.10.170:1022", "192.168.10.153:22", true), // 同监听端点
	}
	err := Validate(rules)
	if err == nil {
		t.Fatal("监听端点冲突应报错")
	}
	if !strings.Contains(err.Error(), "都监听") {
		t.Fatalf("错误消息应说明冲突，实际: %v", err)
	}
}

func TestValidateConflictIgnoresDisabled(t *testing.T) {
	rules := []model.Rule{
		mkRule(1, "192.168.10.170:1022", "192.168.10.152:22", true),
		mkRule(2, "192.168.10.170:1022", "192.168.10.153:22", false), // 禁用
	}
	if err := Validate(rules); err != nil {
		t.Fatalf("禁用规则不参与冲突检测，实际: %v", err)
	}
}

func TestValidatePropagatesRuleError(t *testing.T) {
	bad := mkRule(1, "192.168.10.170:1022", "192.168.10.152:22", true)
	bad.Proto = "sctp"
	if err := Validate([]model.Rule{bad}); err == nil {
		t.Fatal("非法规则应报错")
	}
}

func TestEnabled(t *testing.T) {
	in := []model.Rule{
		mkRule(1, "10.0.0.1:1", "10.0.0.2:1", true),
		mkRule(2, "10.0.0.1:2", "10.0.0.2:2", false),
	}
	got := Enabled(in)
	if len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("应只剩规则#1，实际 %+v", got)
	}
}

func TestSortByID(t *testing.T) {
	in := []model.Rule{
		mkRule(3, "10.0.0.1:3", "10.0.0.2:3", true),
		mkRule(1, "10.0.0.1:1", "10.0.0.2:1", true),
		mkRule(2, "10.0.0.1:2", "10.0.0.2:2", true),
	}
	got := SortByID(in)
	if got[0].ID != 1 || got[1].ID != 2 || got[2].ID != 3 {
		t.Fatalf("排序错误: %d,%d,%d", got[0].ID, got[1].ID, got[2].ID)
	}
	if in[0].ID != 3 {
		t.Fatal("SortByID 不应修改入参")
	}
}

// TestBackendTargets 后端集合必须去重、排序、且只含启用规则。
//
// 这个集合用于默认拒绝的 dnat_target 作用域：只拒绝「目标是本产品后端」的
// 未打标流量，从而不影响同机 Docker/K8s。
func TestBackendTargets(t *testing.T) {
	rules := []model.Rule{
		mkRule(1, "192.168.10.170:1022", "192.168.10.152:22", true),
		mkRule(2, "192.168.10.170:1023", "192.168.10.152:23", true), // 同后端
		mkRule(3, "192.168.10.170:1024", "192.168.10.151:22", true),
		mkRule(4, "192.168.10.170:1025", "192.168.10.199:22", false), // 禁用
	}
	got := BackendTargets(rules)
	if len(got) != 2 {
		t.Fatalf("应去重为 2 个后端，实际 %d: %v", len(got), got)
	}
	if got[0].String() != "192.168.10.151" || got[1].String() != "192.168.10.152" {
		t.Fatalf("应按字典序，实际 %v", got)
	}
	for _, a := range got {
		if a.String() == "192.168.10.199" {
			t.Fatal("禁用规则的后端不应进集合")
		}
	}
}

func TestBackendTargetsEmpty(t *testing.T) {
	if got := BackendTargets(nil); len(got) != 0 {
		t.Fatalf("空输入应返回空集合，实际 %v", got)
	}
}

func TestConflicts(t *testing.T) {
	rules := []model.Rule{
		mkRule(1, "192.168.10.170:1022", "192.168.10.152:22", true),
		mkRule(2, "192.168.10.170:1022", "192.168.10.153:22", true),
		mkRule(3, "192.168.10.170:1022", "192.168.10.154:22", true),
		mkRule(4, "192.168.10.170:1023", "192.168.10.152:23", true),
	}
	got := Conflicts(rules)
	if len(got) != 1 {
		t.Fatalf("应有 1 组冲突，实际 %d: %+v", len(got), got)
	}
	if len(got[0].RuleIDs) != 3 {
		t.Fatalf("冲突应含 3 条规则，实际 %v", got[0].RuleIDs)
	}
	for i := 1; i < len(got[0].RuleIDs); i++ {
		if got[0].RuleIDs[i-1] >= got[0].RuleIDs[i] {
			t.Fatalf("冲突内的规则 ID 应升序，实际 %v", got[0].RuleIDs)
		}
	}
}

func TestConflictsNone(t *testing.T) {
	rules := []model.Rule{
		mkRule(1, "192.168.10.170:1022", "192.168.10.152:22", true),
		mkRule(2, "192.168.10.170:1023", "192.168.10.153:23", true),
	}
	if got := Conflicts(rules); len(got) != 0 {
		t.Fatalf("不应有冲突，实际 %+v", got)
	}
}

func TestExpandedSources(t *testing.T) {
	r := mkRule(1, "10.0.0.1:1", "10.0.0.2:1", true)
	if got := ExpandedSources(r); got != nil {
		t.Fatalf("ACLOff 应返回 nil（编译层不生成源匹配），实际 %v", got)
	}
	r.ACLMode = model.ACLWhitelist
	r.ACL = []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}
	got := ExpandedSources(r)
	if len(got) != 1 {
		t.Fatalf("应返回 1 条网段，实际 %v", got)
	}
}
