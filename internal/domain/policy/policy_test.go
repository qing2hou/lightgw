package policy

import (
	"net/netip"
	"strings"
	"testing"

	"haproxyweb/internal/domain/model"
)

func pref(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr   { return netip.MustParseAddr(s) }

// TestSortedByOrder 必须按 Order 升序，Order 相同时按 ID 兜底。
func TestSortedByOrder(t *testing.T) {
	in := []model.Policy{
		{ID: 3, Order: 20, Action: model.ActionDrop},
		{ID: 1, Order: 10, Action: model.ActionAccept},
		{ID: 2, Order: 20, Action: model.ActionAllow},
	}
	got := Sorted(in)
	if got[0].ID != 1 || got[1].ID != 2 || got[2].ID != 3 {
		t.Fatalf("排序错误: %d,%d,%d", got[0].ID, got[1].ID, got[2].ID)
	}
	// 原切片不能被修改
	if in[0].ID != 3 {
		t.Fatal("Sorted 不应修改入参")
	}
}

func TestEnabledSortedFiltersDisabled(t *testing.T) {
	in := []model.Policy{
		{ID: 1, Order: 10, Enabled: false},
		{ID: 2, Order: 20, Enabled: true},
	}
	got := EnabledSorted(in)
	if len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("应只剩启用的策略#2，实际 %+v", got)
	}
}

func TestValidateOrderConflict(t *testing.T) {
	// 同 proto+port 上 Order 重复 → 评估顺序不确定 → 报错
	err := Validate([]model.Policy{
		{ID: 1, Order: 10, Proto: model.ProtoTCP, Port: 443,
			Action: model.ActionAccept, Enabled: true},
		{ID: 2, Order: 10, Proto: model.ProtoTCP, Port: 443,
			Action: model.ActionDrop, Enabled: true},
	})
	if err == nil {
		t.Fatal("Order 冲突应报错")
	}
	if !strings.Contains(err.Error(), "优先级相同") {
		t.Fatalf("错误消息应说明原因，实际: %v", err)
	}
}

func TestValidateOrderOKDifferentPorts(t *testing.T) {
	// 不同端口上 Order 相同是合法的（两者不会同时评估）
	if err := Validate([]model.Policy{
		{ID: 1, Order: 10, Proto: model.ProtoTCP, Port: 443,
			Action: model.ActionAccept, Enabled: true},
		{ID: 2, Order: 10, Proto: model.ProtoTCP, Port: 80,
			Action: model.ActionDrop, Enabled: true},
	}); err != nil {
		t.Fatalf("不同端口同 Order 应合法，实际: %v", err)
	}
}

func TestValidateDisabledIgnoredInConflict(t *testing.T) {
	if err := Validate([]model.Policy{
		{ID: 1, Order: 10, Proto: model.ProtoTCP, Port: 443,
			Action: model.ActionAccept, Enabled: true},
		{ID: 2, Order: 10, Proto: model.ProtoTCP, Port: 443,
			Action: model.ActionDrop, Enabled: false},
	}); err != nil {
		t.Fatalf("禁用策略不参与冲突检测，实际: %v", err)
	}
}

// TestEvaluateDropTerminates drop 必须终结。
func TestEvaluateDropTerminates(t *testing.T) {
	pols := []model.Policy{
		{ID: 1, Order: 10, Action: model.ActionDrop, Enabled: true},
		{ID: 2, Order: 20, Action: model.ActionAllow, Enabled: true},
	}
	v := Evaluate(pols, model.ProtoTCP, 443, addr("10.0.0.1"))
	if v.Action != model.ActionDrop || !v.Terminates || v.PolicyID != 1 {
		t.Fatalf("应命中策略#1 并终结，实际 %+v", v)
	}
}

// TestEvaluateAllowTerminates allow 必须终结放行，不再看后续策略。
func TestEvaluateAllowTerminates(t *testing.T) {
	pols := []model.Policy{
		{ID: 1, Order: 10, Action: model.ActionAllow, Enabled: true},
		{ID: 2, Order: 20, Action: model.ActionDrop, Enabled: true},
	}
	v := Evaluate(pols, model.ProtoTCP, 443, addr("10.0.0.1"))
	if v.Action != model.ActionAllow || !v.Terminates {
		t.Fatalf("应命中 allow 并终结（不能被后续 drop 覆盖），实际 %+v", v)
	}
}

// TestEvaluateAcceptDoesNotTerminate accept 只打标，必须继续评估到 drop。
//
// 这是 D-14 的核心语义：accept 不等于放行。
func TestEvaluateAcceptDoesNotTerminate(t *testing.T) {
	pols := []model.Policy{
		{ID: 1, Order: 10, Action: model.ActionAccept, Enabled: true},
		{ID: 2, Order: 20, Action: model.ActionDrop, Enabled: true},
	}
	v := Evaluate(pols, model.ProtoTCP, 443, addr("10.0.0.1"))
	if v.Action != model.ActionDrop {
		t.Fatalf("accept 不终结，应继续命中 drop，实际 %+v", v)
	}
}

// TestEvaluateAcceptOnly 只命中 accept 时返回 accept 且不终结。
func TestEvaluateAcceptOnly(t *testing.T) {
	pols := []model.Policy{
		{ID: 1, Order: 10, Action: model.ActionAccept, Enabled: true},
	}
	v := Evaluate(pols, model.ProtoTCP, 443, addr("10.0.0.1"))
	if v.Action != model.ActionAccept {
		t.Fatalf("应返回 accept，实际 %+v", v)
	}
	if v.Terminates {
		t.Fatal("accept 不应终结")
	}
	if v.PolicyID != 1 {
		t.Fatalf("应记录首个 accept 的策略 ID，实际 %d", v.PolicyID)
	}
}

// TestEvaluateNoMatch 无策略命中返回零值。
func TestEvaluateNoMatch(t *testing.T) {
	pols := []model.Policy{
		{ID: 1, Order: 10, Proto: model.ProtoTCP, Port: 443,
			Action: model.ActionDrop, Enabled: true},
	}
	v := Evaluate(pols, model.ProtoUDP, 53, addr("10.0.0.1"))
	if v.Action != "" || v.Terminates {
		t.Fatalf("不应命中，实际 %+v", v)
	}
}

// TestEvaluateSourceMatch 源网段过滤必须生效。
func TestEvaluateSourceMatch(t *testing.T) {
	pols := []model.Policy{
		{ID: 1, Order: 10, Action: model.ActionDrop, Enabled: true,
			Sources: []netip.Prefix{pref("192.168.10.0/24")}},
	}
	// 命中
	if v := Evaluate(pols, model.ProtoTCP, 443, addr("192.168.10.152")); v.Action != model.ActionDrop {
		t.Fatalf("同网段应命中 drop，实际 %+v", v)
	}
	// 不命中
	if v := Evaluate(pols, model.ProtoTCP, 443, addr("10.0.0.1")); v.Action != "" {
		t.Fatalf("异网段不应命中，实际 %+v", v)
	}
}

// TestAllowsForwardingAcceptNeedsRuleWhitelist accept 不等于放行（D-14）。
func TestAllowsForwardingAcceptNeedsRuleWhitelist(t *testing.T) {
	accept := Verdict{Action: model.ActionAccept, Terminates: false}
	if AllowsForwarding(accept, false) {
		t.Fatal("命中 accept 但规则白名单未命中时应拒绝（AND 语义）")
	}
	if !AllowsForwarding(accept, true) {
		t.Fatal("命中 accept 且规则白名单命中时应放行")
	}
}

func TestAllowsForwardingAllowAlways(t *testing.T) {
	allow := Verdict{Action: model.ActionAllow, Terminates: true}
	if !AllowsForwarding(allow, false) {
		t.Fatal("allow 应终结放行，不需要规则白名单")
	}
}

func TestAllowsForwardingDropAlways(t *testing.T) {
	drop := Verdict{Action: model.ActionDrop, Terminates: true}
	if AllowsForwarding(drop, true) {
		t.Fatal("drop 必须拒绝，与规则白名单无关")
	}
}

func TestAllowsForwardingNoPolicy(t *testing.T) {
	if !AllowsForwarding(Verdict{}, true) {
		t.Fatal("无策略命中时应按规则白名单放行")
	}
	if AllowsForwarding(Verdict{}, false) {
		t.Fatal("无策略命中且白名单未命中时应拒绝")
	}
}

func TestNeedRuleWhitelist(t *testing.T) {
	if NeedRuleWhitelist(Verdict{Action: model.ActionAllow}) {
		t.Fatal("allow 已终结，不需要白名单")
	}
	if !NeedRuleWhitelist(Verdict{Action: model.ActionAccept}) {
		t.Fatal("accept 需要白名单（AND 语义）")
	}
	if !NeedRuleWhitelist(Verdict{}) {
		t.Fatal("无命中时需要白名单")
	}
}

func TestExpandedSources(t *testing.T) {
	if got := ExpandedSources(model.Policy{}); got != nil {
		t.Fatalf("无源策略应返回 nil（编译层据此不生成匹配条件），实际 %v", got)
	}
	srcs := []netip.Prefix{pref("10.0.0.0/8")}
	got := ExpandedSources(model.Policy{Sources: srcs})
	if len(got) != 1 || got[0] != srcs[0] {
		t.Fatalf("应返回配置的源网段，实际 %v", got)
	}
}
