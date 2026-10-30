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
	// 注意：`haweb-nft:anchor` 从 ParseCommentFull 引入后可解析（kind=anchor，
	// Legacy=true），但 ParseComment（旧接口）**仍不返回锚点**——
	// 锚点的 purge/对账走独立分支，不能与普通规则混在一起。
	for _, bad := range []string{
		"", "haweb-sn:5", "haweb-nft:snat:abc", "haweb-nft:snat",
		"haweb-nft:snat:5:extra", "other:snat:5", "haweb-nft:anchor",
	} {
		if k, _, ok := ParseComment(bad); ok && k != KindAnchor {
			t.Fatalf("%q 不应解析成功", bad)
		}
	}
}

func TestAnchorCommentForm(t *testing.T) {
	// 锚点是无 id 的特殊形态——Comment 的 anchor 分支
	if got := Comment(KindAnchor, 0); got != "haweb-nft:anchor" {
		t.Fatalf("锚点标记形态: %s", got)
	}
	// 新旧两种锚点形态都不应被 ParseComment 当成普通规则返回
	for _, ud := range []string{"haweb-nft:anchor", "haweb-nft:0123456789abcdef:anchor"} {
		if k, _, ok := ParseComment(ud); ok && k != KindAnchor {
			t.Fatalf("%q 不应被当作普通规则解析（得到 kind=%q）", ud, k)
		}
	}
	// 但 ParseCommentFull 必须能解析它们（对账需要判定实例归属）
	if pc, ok := ParseCommentFull("haweb-nft:0123456789abcdef:anchor"); !ok || pc.Kind != KindAnchor {
		t.Fatalf("ParseCommentFull 应解析新锚点，实际 %+v ok=%v", pc, ok)
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

func TestPolicyVerdictIsDrop(t *testing.T) {
	// 复审 M3-a：ACCEPT policy 存 -2（libiptc 编码），误判会把正常部署拒之门外
	cases := []struct {
		verdict int32
		want    bool
		what    string
	}{
		{-1, true, "DROP policy"},
		{-2, false, "ACCEPT policy（曾被误判的关键分支）"},
		{-5, true, "XT_RETURN（保守按 DROP）"},
		{0, true, "异常值保守按 DROP"},
		{1, true, "异常值保守按 DROP"},
	}
	for _, c := range cases {
		if got := policyVerdictIsDrop(c.verdict); got != c.want {
			t.Fatalf("%s（verdict=%d）: got %v want %v", c.what, c.verdict, got, c.want)
		}
	}
}

// TestReservedRouteTableGuard 路由表号护栏：拆除动作绝不能落到内核保留表。
// 生产事故回归——曾对 201..300 做孤儿扫描，把 254(main) 判成孤儿并删掉其
// 默认路由，目标主机整机失联。
func TestReservedRouteTableGuard(t *testing.T) {
	for _, tbl := range []int{0, 253, 254, 255, 32766, 32767, 1000} {
		if !IsReservedRouteTable(tbl) && (tbl < RouteTableBase || tbl > RouteTableEnd) {
			continue // 段外普通表号由段界判断拦下，不算保留表
		}
		if tbl == 1000 {
			t.Fatalf("表号 %d 不应被判定为保留表（应由段界拦下）", tbl)
		}
		if !IsReservedRouteTable(tbl) {
			t.Fatalf("表号 %d 应被判定为内核保留表", tbl)
		}
	}
	for _, tbl := range []int{201, 251, 252} {
		if IsReservedRouteTable(tbl) {
			t.Fatalf("表号 %d 是 haweb 专属段，不应算保留表", tbl)
		}
	}
	// 专属段必须严格低于 253，否则 main/local/default 会落进分配域
	if RouteTableEnd >= 253 {
		t.Fatalf("RouteTableEnd=%d 越界：253-255 是内核保留表", RouteTableEnd)
	}
	if RouteTableEnd < RouteTableBase {
		t.Fatalf("专属段区间非法: %d-%d", RouteTableBase, RouteTableEnd)
	}
}

// TestTearEgressRouteRefusesReserved 拆除动作对保留表/段外表必须拒做且不panic。
func TestTearEgressRouteRefusesReserved(t *testing.T) {
	c := &Conn{} // 不接内核：护栏应在外层就返回，不触碰 netlink
	for _, tbl := range []int{253, 254, 255, 32766, 1000, 300} {
		if err := c.TearEgressRoute(tbl, nil); err == nil {
			t.Fatalf("表号 %d 应被拒绝拆除", tbl)
		}
	}
	if err := c.TearEgressRoute(0, nil); err != nil {
		t.Fatalf("表号 0（未分配）应静默跳过，实际: %v", err)
	}
}
