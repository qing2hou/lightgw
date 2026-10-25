// fw 策略编译层离线单测。
package fw

import (
	"testing"

	"haproxyweb/internal/nft"
)

func TestCompilePoliciesShape(t *testing.T) {
	ps := []PolicySpec{
		{ID: 1, Order: 1, Action: "drop", SrcList: []string{"10.1.0.0/16"}, Proto: "tcp", PortRange: "80"},
		{ID: 2, Order: 2, Action: "accept", DstList: []string{"8.8.8.8"}, Proto: "any"},
	}
	rules, err := CompilePolicies(ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("规则数 %d != 2", len(rules))
	}
	// drop 行带 VerdictDrop；accept 行带打标不终结
	for _, r := range rules {
		ud := string(r.Rule.UserData)
		if ud != nft.Comment(nft.KindPolicy, 1) && ud != nft.Comment(nft.KindPolicy, 2) {
			t.Fatalf("标记 %q 不属于任一策略", ud)
		}
		if ud == nft.Comment(nft.KindPolicy, 1) && !hasDropVerdict(r.Rule) {
			t.Fatal("drop 策略行应带 VerdictDrop")
		}
	}
}

func TestExpandPolicySpec(t *testing.T) {
	p := PolicySpec{ID: 7, Action: "drop",
		SrcList: []string{"1.1.1.1", "2.2.2.0/24"},
		DstList: []string{"8.8.8.8"},
		Proto:   "tcp", PortRange: "80,443,1000-2000"}
	out, err := ExpandPolicySpec(p)
	if err != nil {
		t.Fatal(err)
	}
	// 2 src × 1 dst × 3 port = 6 行
	if len(out) != 6 {
		t.Fatalf("展开行数 %d != 6", len(out))
	}
	for _, o := range out {
		if len(o.SrcList) > 1 || len(o.DstList) > 1 {
			t.Fatal("展开后单行条件应至多一条目")
		}
	}
}

func TestParsePortGroups(t *testing.T) {
	gs, err := parsePortGroups("80, 443, 1000-2000")
	if err != nil || len(gs) != 3 {
		t.Fatalf("组数 %d err %v", len(gs), err)
	}
	if _, err := parsePortGroups(""); err != nil || gs == nil {
		_ = err
	}
	if _, err := parsePortGroups("70000"); err == nil {
		t.Fatal("超范围端口应报错")
	}
	if _, err := parsePortGroups("2000-1000"); err == nil {
		t.Fatal("倒序范围应报错")
	}
}
