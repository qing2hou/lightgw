package shadowverify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakeReader struct {
	actual []RuleDigest
	err    error
}

func (f *fakeReader) ReadActual(ctx context.Context) ([]RuleDigest, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.actual, nil
}

func d(chain, match, action string) RuleDigest {
	return RuleDigest{Chain: chain, Match: match, Action: action}
}

// TestCompareEquivalent 相同集合判定等价。
func TestCompareEquivalent(t *testing.T) {
	a := []RuleDigest{d("srcnat", "saddr=10.0.0.1", "snat"), d("fwd", "daddr=10.0.0.2", "accept")}
	b := []RuleDigest{d("fwd", "daddr=10.0.0.2", "accept"), d("srcnat", "saddr=10.0.0.1", "snat")}
	diff := Compare(a, b)
	if !diff.Equivalent() {
		t.Fatalf("顺序不同但内容相同，应判等价: %+v", diff)
	}
	if diff.DesiredCount != 2 || diff.ActualCount != 2 {
		t.Fatalf("计数错误: %+v", diff)
	}
}

// TestCompareMissing 只在新产物里 → 缺失。
func TestCompareMissing(t *testing.T) {
	desired := []RuleDigest{d("srcnat", "saddr=10.0.0.1", "snat"), d("fwd", "daddr=10.0.0.2", "accept")}
	actual := []RuleDigest{d("fwd", "daddr=10.0.0.2", "accept")}
	diff := Compare(desired, actual)
	if diff.Equivalent() {
		t.Fatal("不应判等价")
	}
	if len(diff.OnlyInDesired) != 1 {
		t.Fatalf("应有 1 条缺失，实际 %d: %v", len(diff.OnlyInDesired), diff.OnlyInDesired)
	}
	if diff.OnlyInDesired[0].Chain != "srcnat" {
		t.Fatalf("缺失的应是 srcnat 那条，实际 %v", diff.OnlyInDesired[0])
	}
	if len(diff.OnlyInActual) != 0 {
		t.Fatalf("不应有多余，实际 %v", diff.OnlyInActual)
	}
}

// TestCompareExtra 只在现网里 → 多余。
func TestCompareExtra(t *testing.T) {
	desired := []RuleDigest{d("fwd", "daddr=10.0.0.2", "accept")}
	actual := []RuleDigest{
		d("fwd", "daddr=10.0.0.2", "accept"),
		d("fwd", "saddr=1.2.3.4", "drop"),
	}
	diff := Compare(desired, actual)
	if len(diff.OnlyInActual) != 1 {
		t.Fatalf("应有 1 条多余，实际 %d: %v", len(diff.OnlyInActual), diff.OnlyInActual)
	}
	if !strings.Contains(diff.OnlyInActual[0].Match, "1.2.3.4") {
		t.Fatalf("多余的应是 1.2.3.4 那条，实际 %v", diff.OnlyInActual[0])
	}
}

// TestCompareBothDirections 两侧都有独有项。
func TestCompareBothDirections(t *testing.T) {
	desired := []RuleDigest{d("a", "m1", "x"), d("b", "m2", "y")}
	actual := []RuleDigest{d("a", "m1", "x"), d("c", "m3", "z")}
	diff := Compare(desired, actual)
	if len(diff.OnlyInDesired) != 1 || len(diff.OnlyInActual) != 1 {
		t.Fatalf("应各 1 条，实际 缺失=%v 多余=%v", diff.OnlyInDesired, diff.OnlyInActual)
	}
}

// TestCompareEmpty 空集合处理。
func TestCompareEmpty(t *testing.T) {
	if diff := Compare(nil, nil); !diff.Equivalent() {
		t.Fatal("两个空集应判等价")
	}
	diff := Compare([]RuleDigest{d("a", "m", "x")}, nil)
	if diff.Equivalent() {
		t.Fatal("有内容的对空集不应等价")
	}
}

// TestNormalizeWhitespace 空白折叠。
func TestNormalizeWhitespace(t *testing.T) {
	cases := [][2]string{
		{"a   b\tc\n d", "a b c d"},
		{"  leading and trailing  ", "leading and trailing"},
		{"", ""},
	}
	for _, c := range cases {
		if got := Normalize(c[0]); got != c[1] {
			t.Fatalf("Normalize(%q) = %q，期望 %q", c[0], got, c[1])
		}
	}
}

// TestNormalizeCounterCounts counter 数值必须剥掉（运行时数据不是配置）。
func TestNormalizeCounterCounts(t *testing.T) {
	cases := [][2]string{
		{"counter packets 123 bytes 456 accept", "counter accept"},
		{"counter packets 0 bytes 0 drop", "counter drop"},
		{"counter accept", "counter accept"},
		{"packets 100 x", "x"},
		{"bytes 200 y", "y"},
	}
	for _, c := range cases {
		if got := Normalize(c[0]); got != c[1] {
			t.Fatalf("Normalize(%q) = %q，期望 %q", c[0], got, c[1])
		}
	}
}

// TestNormalizeInstanceID 实例 ID 段必须剥掉（每次部署可能不同）。
func TestNormalizeInstanceID(t *testing.T) {
	cases := [][2]string{
		{"comment haweb-nft:0123456789abcdef:snat:30", "comment haweb-nft:snat:30"},
		{"comment haweb-nft:snat:30", "comment haweb-nft:snat:30"},
		// 非 16 位 hex 的不剥（可能是 kind 本身）
		{"comment haweb-nft:snat:30:x", "comment haweb-nft:snat:30:x"},
		// 大写不剥（实例 ID 是小写）
		{"haweb-nft:0123456789ABCDEF:snat:1", "haweb-nft:0123456789ABCDEF:snat:1"},
	}
	for _, c := range cases {
		if got := Normalize(c[0]); got != c[1] {
			t.Fatalf("Normalize(%q) = %q，期望 %q", c[0], got, c[1])
		}
	}
}

// TestNormalizeRealWorldKernelOutput 真实内核输出的归一化（关键回归）。
//
// 这两条是同一规则的不同呈现：一条来自代码生成（带实例ID），
// 一条来自 nft list（带计数值）。归一化后必须相等。
func TestNormalizeRealWorldKernelOutput(t *testing.T) {
	fromCode := "iifname eth0 oifname eth0 @nh,96,32 0xc0a80a98 snat ip to 192.168.10.170 " +
		"comment haweb-nft:0123456789abcdef:snat:30"
	fromKernel := "iifname \"eth0\" oifname \"eth0\" @nh,96,32 0xc0a80a98 " +
		"counter packets 12345 bytes 678901 snat ip to 192.168.10.170 " +
		"comment \"haweb-nft:0123456789abcdef:snat:30\""
	// 这两条引号不同、counter 有值、空白不同——归一化后应只剩引号差异
	// （引号差异由上层提取 RuleDigest 时消除，这里只验证归一化本身稳定）
	a := Normalize(fromCode)
	b := Normalize(fromKernel)
	if !strings.Contains(a, "snat ip to 192.168.10.170") {
		t.Fatalf("归一化丢了动作: %q", a)
	}
	if strings.Contains(b, "12345") || strings.Contains(b, "678901") {
		t.Fatalf("★ 归一化没剥掉 counter 数值: %q", b)
	}
	if !strings.Contains(b, "haweb-nft:snat:30") {
		t.Fatalf("★ 归一化没剥掉实例 ID: %q", b)
	}
}

// TestVerifierEquivalent 端到端：等价时不报差异。
func TestVerifierEquivalent(t *testing.T) {
	rs := []RuleDigest{d("fwd", "m", "accept")}
	var logs []string
	v := NewVerifier(&fakeReader{actual: rs}, func(f string, a ...any) {
		logs = append(logs, fmt.Sprintf(f, a...)) // 渲染后再断言
	})
	diff, err := v.Verify(context.Background(), rs)
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	if !diff.Equivalent() {
		t.Fatal("应判等价")
	}
	if len(logs) == 0 {
		t.Fatal("应至少记录一条日志")
	}
	joined := strings.Join(logs, " ")
	if !strings.Contains(joined, "等价") {
		t.Fatalf("应记录等价日志，实际 %v", logs)
	}
}

// TestVerifierReportsDiff 有差异时逐条记录。
func TestVerifierReportsDiff(t *testing.T) {
	var logs []string
	v := NewVerifier(&fakeReader{actual: []RuleDigest{d("fwd", "old", "accept")}},
		func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	_, err := v.Verify(context.Background(), []RuleDigest{d("fwd", "new", "accept")})
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "缺失") || !strings.Contains(joined, "多余") {
		t.Fatalf("应同时报告缺失与多余，实际:\n%s", joined)
	}
}

// TestVerifierReadError 读取失败必须上报。
func TestVerifierReadError(t *testing.T) {
	v := NewVerifier(&fakeReader{err: errors.New("nft 不可用")}, nil)
	if _, err := v.Verify(context.Background(), nil); err == nil {
		t.Fatal("读取失败应报错")
	}
}

// TestVerifierNilReader 未配置 reader 必须报错。
func TestVerifierNilReader(t *testing.T) {
	v := NewVerifier(nil, nil)
	if _, err := v.Verify(context.Background(), nil); err == nil {
		t.Fatal("nil reader 应报错")
	}
}

// TestDiffSummary 摘要文本。
func TestDiffSummary(t *testing.T) {
	if s := (Diff{DesiredCount: 3, ActualCount: 3}).Summary(); !strings.Contains(s, "等价") {
		t.Fatalf("应含「等价」，实际 %q", s)
	}
	s := (Diff{
		DesiredCount:  3,
		ActualCount:   2,
		OnlyInDesired: []RuleDigest{{}},
	}).Summary()
	if !strings.Contains(s, "不等价") || !strings.Contains(s, "缺失 1") {
		t.Fatalf("摘要内容错误: %q", s)
	}
}
