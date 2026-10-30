package nft

import "testing"

const testInst = "0123456789abcdef"

// TestCommentForIncludesInstance 新格式必须带实例 ID。
func TestCommentForIncludesInstance(t *testing.T) {
	got := CommentFor(testInst, KindSNAT, 30)
	want := "haweb-nft:" + testInst + ":snat:30"
	if got != want {
		t.Fatalf("标记格式错误: %q，期望 %q", got, want)
	}
}

// TestCommentForEmptyInstanceFallback 空实例退化为旧格式（兼容）。
func TestCommentForEmptyInstanceFallback(t *testing.T) {
	if got := CommentFor("", KindSNAT, 30); got != "haweb-nft:snat:30" {
		t.Fatalf("空实例应退化为旧格式，实际 %q", got)
	}
}

// TestCommentForAnchor 锚点行也要带实例 ID（新格式）。
func TestCommentForAnchor(t *testing.T) {
	if got := CommentFor(testInst, KindAnchor, 0); got != "haweb-nft:"+testInst+":anchor" {
		t.Fatalf("锚点标记错误: %q", got)
	}
	if got := CommentFor("", KindAnchor, 0); got != "haweb-nft:anchor" {
		t.Fatalf("空实例锚点应为旧格式，实际 %q", got)
	}
}

// TestParseCommentFullNewFormat 新格式解析出实例 ID。
func TestParseCommentFullNewFormat(t *testing.T) {
	pc, ok := ParseCommentFull("haweb-nft:" + testInst + ":snat:30")
	if !ok {
		t.Fatal("应解析成功")
	}
	if pc.Instance != testInst || pc.Kind != KindSNAT || pc.ID != 30 || pc.Legacy {
		t.Fatalf("解析结果错误: %+v", pc)
	}
}

// TestParseCommentFullLegacyFormat 旧格式必须标记 Legacy=true。
//
// 这是修复的核心：对账把 Legacy 视为「非本实例」，绝不拆。
func TestParseCommentFullLegacyFormat(t *testing.T) {
	pc, ok := ParseCommentFull("haweb-nft:snat:30")
	if !ok {
		t.Fatal("旧格式应能解析（用于兼容）")
	}
	if pc.Instance != "" {
		t.Fatalf("旧格式不应有实例 ID，实际 %q", pc.Instance)
	}
	if !pc.Legacy {
		t.Fatal("★ 旧格式必须标记 Legacy=true（对账据此跳过）")
	}
	if pc.Kind != KindSNAT || pc.ID != 30 {
		t.Fatalf("解析结果错误: %+v", pc)
	}
}

// TestParseCommentFullAnchor 两种锚点格式。
func TestParseCommentFullAnchor(t *testing.T) {
	// 旧锚点
	pc, ok := ParseCommentFull("haweb-nft:anchor")
	if !ok || pc.Kind != KindAnchor || !pc.Legacy {
		t.Fatalf("旧锚点解析错误: %+v ok=%v", pc, ok)
	}
	// 新锚点
	pc, ok = ParseCommentFull("haweb-nft:" + testInst + ":anchor")
	if !ok || pc.Kind != KindAnchor || pc.Instance != testInst || pc.Legacy {
		t.Fatalf("新锚点解析错误: %+v ok=%v", pc, ok)
	}
}

// TestParseCommentFullInvalid 非法格式必须拒绝。
func TestParseCommentFullInvalid(t *testing.T) {
	bad := []string{
		"",
		"haweb-nft",
		"other:snat:30",
		"haweb-nft:snat",
		"haweb-nft:snat:abc",
		"haweb-nft:badinstance:snat:30", // 实例段非 16 位 hex
		"haweb-nft:" + testInst + ":snat:abc",
		"haweb-nft:a:b:c:d", // 5 段
	}
	for _, ud := range bad {
		if _, ok := ParseCommentFull(ud); ok {
			t.Fatalf("%q 应解析失败", ud)
		}
	}
}

// TestParseCommentBackwardCompat 旧接口 ParseComment 仍工作。
func TestParseCommentBackwardCompat(t *testing.T) {
	// 旧格式
	k, id, ok := ParseComment("haweb-nft:snat:30")
	if !ok || k != KindSNAT || id != 30 {
		t.Fatalf("旧接口解析旧格式失败: %q %d %v", k, id, ok)
	}
	// 新格式也能通过旧接口解析（kind/id 提取正确）
	k, id, ok = ParseComment("haweb-nft:" + testInst + ":dnat:7")
	if !ok || k != KindDNAT || id != 7 {
		t.Fatalf("旧接口解析新格式失败: %q %d %v", k, id, ok)
	}
}

// TestIsInstanceSegment 实例段判定。
func TestIsInstanceSegment(t *testing.T) {
	if !isInstanceSegment(testInst) {
		t.Fatal("合法实例 ID 应被识别")
	}
	for _, bad := range []string{"", "short", "0123456789ABCDEF",
		"0123456789abcdef0", "snat", "0123456789abcdeg"} {
		if isInstanceSegment(bad) {
			t.Fatalf("%q 不应被识别为实例 ID", bad)
		}
	}
}

// TestInstanceIsolationCritical 关键回归：两个实例的标记必须互不匹配。
//
// 事故场景：实例 A 装规则，实例 B 用空库启动做对账。
// B 必须看不到 A 的规则（否则会把它们拆掉）。
func TestInstanceIsolationCritical(t *testing.T) {
	instA := "aaaaaaaaaaaaaaaa"
	instB := "bbbbbbbbbbbbbbbb"
	commentA := CommentFor(instA, KindSNAT, 30)

	pc, ok := ParseCommentFull(commentA)
	if !ok {
		t.Fatal("A 的标记应可解析")
	}
	if pc.Instance != instA {
		t.Fatalf("归属应为 A，实际 %q", pc.Instance)
	}
	// B 视角：这条规则不属于 B
	if pc.Instance == instB {
		t.Fatal("★ B 不能认领 A 的规则")
	}
	// 旧格式：不属于任何实例
	pcOld, _ := ParseCommentFull("haweb-nft:snat:30")
	if pcOld.Legacy {
		// 正确：Legacy 规则不参与任何实例的对账
		return
	}
	t.Fatal("★ 旧格式必须标记 Legacy，否则会被任意实例拆掉")
}
