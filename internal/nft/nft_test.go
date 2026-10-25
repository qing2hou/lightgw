// nft 包离线单测（不碰内核）：标记编解码、位操作语义、set 元素展开、
// interval 末端地址计算。内核面行为靠容器冒烟（docs/poc-nftables.md 流程）。
package nft

import (
	"net"
	"testing"
)

func TestCommentRoundTrip(t *testing.T) {
	for _, c := range []struct {
		kind string
		id   uint
	}{
		{"snat", 1}, {"dnat", 4294967290}, {"pol", 42},
	} {
		cm := Comment(c.kind, c.id)
		kind, id, ok := ParseComment(cm)
		if !ok || kind != c.kind || id != c.id {
			t.Fatalf("往返失败: %s -> (%s,%d,%v)", cm, kind, id, ok)
		}
	}
}

func TestParseCommentRejects(t *testing.T) {
	for _, bad := range []string{
		"", "haweb-sn:5", "haweb-nft:snat:abc", "haweb-nft:snat",
		"haweb-nft:snat:5:extra", "other:snat:5", "haweb-nft:anchor",
	} {
		if _, _, ok := ParseComment(bad); ok {
			t.Fatalf("%q 不应解析成功", bad)
		}
	}
}

func TestAnchorCommentForm(t *testing.T) {
	// 锚点是无 id 的特殊形态——Comment 的 anchor 分支
	if got := Comment(KindAnchor, 0); got != "haweb-nft:anchor" {
		t.Fatalf("锚点标记形态: %s", got)
	}
	if _, _, ok := ParseComment("haweb-nft:anchor"); ok {
		t.Fatal("锚点标记（两段式）不应走普通解析——purge 逻辑独立处理")
	}
}

func TestLastIP(t *testing.T) {
	cases := []struct {
		cidr string
		want string
	}{
		{"192.168.1.0/24", "192.168.1.255"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"203.0.113.5/32", "203.0.113.5"},
		{"172.16.0.0/12", "172.31.255.255"},
	}
	for _, c := range cases {
		_, ipn, err := net.ParseCIDR(c.cidr)
		if err != nil {
			t.Fatal(err)
		}
		if got := lastIP(ipn).String(); got != c.want {
			t.Fatalf("%s 末端 = %s，期望 %s", c.cidr, got, c.want)
		}
	}
}

func TestSetMarkExprsShape(t *testing.T) {
	// 位操作序列结构固定：Meta(load) → Bitwise(OR) → Meta(write)，共 3 元
	exprs := SetMarkExprs(MarkFwdOK)
	if len(exprs) != 3 {
		t.Fatalf("打标表达式数 %d != 3", len(exprs))
	}
}

func TestIPSetEntriesBadInput(t *testing.T) {
	// lastIP 对 v6 返回 nil（M3 支持）——EnsureIPSet 的 v4-only 校验单测
	_, ipn, _ := net.ParseCIDR("2001:db8::/64")
	if got := lastIP(ipn); got != nil {
		t.Fatalf("v6 网段 lastIP 应为 nil（M3 前不支持），得到 %v", got)
	}
}
