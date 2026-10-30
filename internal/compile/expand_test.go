package compile

import (
	"net/netip"
	"strings"
	"testing"

	"haproxyweb/internal/domain/model"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// TestExpandSinglePrefixUnchanged 单网段不需要展开，comment 保持不变。
//
// 理由：comment 是 Applier 精确删除规则的键。无谓地加 #0 后缀会让
// 每次编译产生不同的规则名，制造无意义的 diff。
func TestExpandSinglePrefixUnchanged(t *testing.T) {
	in := []Rule{{
		Comment: "haweb:fwd:1",
		Src:     AddrMatch{Prefixes: []netip.Prefix{pfx("192.168.10.0/24")}},
	}}
	out, err := ExpandAddrMatches(in)
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("单网段应保持 1 条，实际 %d", len(out))
	}
	if out[0].Comment != "haweb:fwd:1" {
		t.Fatalf("单网段 comment 不应变化，实际 %q", out[0].Comment)
	}
}

// TestExpandMultiSource 多源网段展开成多条，comment 加序号且唯一。
func TestExpandMultiSource(t *testing.T) {
	in := []Rule{{
		Comment: "haweb:fwd:1",
		Src: AddrMatch{Prefixes: []netip.Prefix{
			pfx("192.168.10.0/24"),
			pfx("10.0.0.0/8"),
			pfx("172.16.0.0/12"),
		}},
	}}
	out, err := ExpandAddrMatches(in)
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("3 个网段应展开成 3 条，实际 %d", len(out))
	}
	seen := map[string]bool{}
	for i, r := range out {
		if len(r.Src.Prefixes) != 1 {
			t.Fatalf("第 %d 条应只含 1 个网段，实际 %d", i, len(r.Src.Prefixes))
		}
		if seen[r.Comment] {
			t.Fatalf("comment 重复: %q", r.Comment)
		}
		seen[r.Comment] = true
		if !strings.HasPrefix(r.Comment, "haweb:fwd:1#") {
			t.Fatalf("展开后 comment 应带序号后缀，实际 %q", r.Comment)
		}
	}
}

// TestExpandCartesian 源 × 目的 按笛卡尔积展开。
func TestExpandCartesian(t *testing.T) {
	in := []Rule{{
		Comment: "t",
		Src:     AddrMatch{Prefixes: []netip.Prefix{pfx("10.0.0.0/8"), pfx("192.168.0.0/16")}},
		Dst:     AddrMatch{Prefixes: []netip.Prefix{pfx("172.16.30.1/32"), pfx("172.16.30.2/32"), pfx("172.16.30.3/32")}},
	}}
	out, err := ExpandAddrMatches(in)
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if len(out) != 6 {
		t.Fatalf("2 源 × 3 目的 = 6 条，实际 %d", len(out))
	}
	for i, r := range out {
		if len(r.Src.Prefixes) != 1 || len(r.Dst.Prefixes) != 1 {
			t.Fatalf("第 %d 条应各含 1 个网段，实际 src=%d dst=%d",
				i, len(r.Src.Prefixes), len(r.Dst.Prefixes))
		}
	}
}

// TestExpandEmptyDimensionKeepsRules 空白维度（不匹配）不能让规则消失。
//
// 回归：range nil 是零次迭代——若用 nil 表示「空维度」，只配了源网段
// 而没配目的地址的规则会一条都不生成（静默丢规则）。
func TestExpandEmptyDimensionKeepsRules(t *testing.T) {
	in := []Rule{{
		Comment: "t",
		Src:     AddrMatch{Prefixes: []netip.Prefix{pfx("10.0.0.0/8"), pfx("192.168.0.0/16")}},
		Dst:     AddrMatch{}, // 空：不匹配目的
	}}
	out, err := ExpandAddrMatches(in)
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("2 源 × 1（空） = 2 条，实际 %d（规则被静默丢弃？）", len(out))
	}
	for i, r := range out {
		if !r.Dst.Empty() {
			t.Fatalf("第 %d 条的目的匹配应保持为空，实际 %v", i, r.Dst.Prefixes)
		}
	}
}

// TestExpandBothEmpty 两维都空 → 1 条，不展开。
func TestExpandBothEmpty(t *testing.T) {
	out, err := ExpandAddrMatches([]Rule{{Comment: "t"}})
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if len(out) != 1 || out[0].Comment != "t" {
		t.Fatalf("应保持 1 条且 comment 不变，实际 %+v", out)
	}
}

// TestExpandNegatedMultiRejected 多网段 + 取反无法用展开表达，必须报错。
func TestExpandNegatedMultiRejected(t *testing.T) {
	in := []Rule{{
		Comment: "t",
		Src: AddrMatch{
			Prefixes: []netip.Prefix{pfx("10.0.0.0/8"), pfx("192.168.0.0/16")},
			Negated:  true,
		},
	}}
	if _, err := ExpandAddrMatches(in); err == nil {
		t.Fatal("多网段取反必须报错（需要 OR 语义，展开无法表达）")
	}
}

// TestExpandNegatedSingleAllowed 单网段取反可以保留（不需要展开）。
func TestExpandNegatedSingleAllowed(t *testing.T) {
	in := []Rule{{
		Comment: "t",
		Src:     AddrMatch{Prefixes: []netip.Prefix{pfx("10.0.0.0/8")}, Negated: true},
	}}
	out, err := ExpandAddrMatches(in)
	if err != nil {
		t.Fatalf("单网段取反应允许，实际: %v", err)
	}
	if len(out) != 1 || !out[0].Src.Negated {
		t.Fatal("取反标记应保留")
	}
}

// TestExpandDedupe 重复网段应先去重再展开。
func TestExpandDedupe(t *testing.T) {
	in := []Rule{{
		Comment: "t",
		Src: AddrMatch{Prefixes: []netip.Prefix{
			pfx("10.0.0.0/8"),
			pfx("10.0.0.0/8"), // 重复
			pfx("10.1.2.3/8"), // 归零后与第一条相同
		}},
	}}
	out, err := ExpandAddrMatches(in)
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("去重后应 1 条，实际 %d", len(out))
	}
}

// TestCompileExpandsMultiPrefix Plan 生成路径必须真的展开
// （不只是在 ExpandAddrMatches 单测里通过）。
func TestCompileExpandsMultiPrefix(t *testing.T) {
	r := model.Rule{
		ID:       1,
		Name:     "t",
		Proto:    model.ProtoTCP,
		ListenAt: netip.MustParseAddrPort("192.168.10.170:1022"),
		Backend:  netip.MustParseAddrPort("192.168.10.152:22"),
		Enabled:  true,
		ACLMode:  model.ACLWhitelist,
		ACL: []netip.Prefix{
			pfx("192.168.10.0/24"),
			pfx("10.0.0.0/8"),
			pfx("172.16.0.0/12"),
		},
	}
	c := &Compiler{Caps: Caps{TcNetlink: true}}
	p, err := c.Compile(State{Version: 1, Rules: []model.Rule{r}})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	// 白名单有 3 个网段 -> 3 条转发规则；DNAT 判定行也有 3 个源 -> 3 条
	fwd := p.Nft.Forward
	if len(fwd) != 3 {
		t.Fatalf("3 个白名单网段应展开成 3 条转发规则，实际 %d", len(fwd))
	}
	for i, rule := range fwd {
		if len(rule.Src.Prefixes) != 1 {
			t.Fatalf("第 %d 条应只含 1 个网段，实际 %d", i, len(rule.Src.Prefixes))
		}
	}
	// comment 必须全局唯一（Plan.Validate 已强制，这里再显式验一次）
	seen := map[string]bool{}
	for _, group := range [][]Rule{p.Nft.Forward, p.Nft.Dnat, p.Nft.Policy,
		p.Nft.Snat, p.Nft.Deny, p.Nft.Mss} {
		for _, rule := range group {
			if seen[rule.Comment] {
				t.Fatalf("comment 重复: %q", rule.Comment)
			}
			seen[rule.Comment] = true
		}
	}
}
