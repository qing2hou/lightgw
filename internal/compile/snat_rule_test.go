package compile

import (
	"net/netip"
	"strings"
	"testing"
)

func snatRule(id uint, srcs ...string) SnatRule {
	var pfx []netip.Prefix
	for _, s := range srcs {
		if strings.Contains(s, "/") {
			pfx = append(pfx, netip.MustParsePrefix(s))
		} else {
			a := netip.MustParseAddr(s)
			pfx = append(pfx, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return SnatRule{
		ID:             id,
		Name:           "snat-test",
		SourceNets:     pfx,
		OutIP:          netip.MustParseAddr("192.168.10.170"),
		IfIn:           "eth0",
		IfOut:          "eth0",
		MetaMarkExempt: 0x4,
		Enabled:        true,
		Counter:        true,
	}
}

// TestSnatRuleValidateNoProto 关键：SNAT 规则**不校验协议**。
//
// 这是缺口 3 的修复核心。旧实现复用 domain.Rule，而 rule.Validate 要求
// Proto ∈ {tcp,udp}，导致 SNAT 规则（protocol="snat"）编译直接失败。
func TestSnatRuleValidateNoProto(t *testing.T) {
	r := snatRule(30, "192.168.10.152")
	// SnatRule 里根本没有 Proto 字段——结构上就不可能校验协议
	if err := r.Validate(); err != nil {
		t.Fatalf("SNAT 规则不应校验协议，实际报错: %v", err)
	}
}

// TestSnatRuleValidateErrors 校验的边界条件。
func TestSnatRuleValidateErrors(t *testing.T) {
	base := snatRule(30, "192.168.10.152")

	// 无源网段
	r := base
	r.SourceNets = nil
	if err := r.Validate(); err == nil {
		t.Fatal("无源网段应报错（会匹配不到任何流量）")
	}

	// 无效网段
	r = base
	r.SourceNets = []netip.Prefix{{}}
	if err := r.Validate(); err == nil {
		t.Fatal("无效网段应报错")
	}

	// 未归零网段
	r = base
	r.SourceNets = []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")}
	if err := r.Validate(); err == nil {
		t.Fatal("未归零网段应报错")
	}

	// 出口地址无效
	r = base
	r.OutIP = netip.Addr{}
	if err := r.Validate(); err == nil {
		t.Fatal("无效出口地址应报错")
	}

	// IPv6（暂不支持）
	r = base
	r.OutIP = netip.MustParseAddr("2001:db8::1")
	if err := r.Validate(); err == nil {
		t.Fatal("IPv6 出口应报错")
	}
	r = base
	r.SourceNets = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	if err := r.Validate(); err == nil {
		t.Fatal("IPv6 源网段应报错")
	}
}

// TestCompileSnatRulesTwoPerSource 每条源网段生成两条规则（放行 + 回程计数）。
//
// 这是 AGENTS.md 的硬要求：SNAT counter 必须覆盖双向。
// 只装上行的计数会让页面速率只反映 ACK 小包（实测 3.54MB/s 显示 68.9KB/s）。
func TestCompileSnatRulesTwoPerSource(t *testing.T) {
	rules, err := CompileSnatRules([]SnatRule{snatRule(30, "192.168.10.152", "192.168.10.151")})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(rules) != 4 {
		t.Fatalf("★ 2 个源应生成 4 条规则（每个源：放行 + 回程计数），实际 %d", len(rules))
	}

	var accept, ret int
	for _, r := range rules {
		if strings.HasSuffix(r.Comment, ":return") {
			ret++
			// 回程行必须匹配 daddr（源网段），不能匹配 saddr
			if !r.Src.Empty() {
				t.Fatalf("★ 回程计数行不应有 saddr 条件: %+v", r)
			}
			if r.Dst.Empty() {
				t.Fatalf("★ 回程计数行必须有 daddr 条件: %+v", r)
			}
			if r.SnatTo.IsValid() {
				t.Fatalf("★ 回程计数行不能带 snat 动作: %+v", r)
			}
		} else {
			accept++
			if r.Src.Empty() {
				t.Fatalf("放行行必须有 saddr 条件: %+v", r)
			}
			if !r.SnatTo.IsValid() {
				t.Fatalf("放行行必须有 snat 动作: %+v", r)
			}
		}
	}
	if accept != 2 || ret != 2 {
		t.Fatalf("应 2 条放行 + 2 条回程计数，实际 %d + %d", accept, ret)
	}
}

// TestCompileSnatRulesMetaMarkExempt meta mark 豁免条件必须带上。
//
// 生产用途：0x4 是 MarkDNAT，发布流量（DNAT 会话）必须豁免 SNAT，
// 否则回程包被错误改写、发布直接断。
func TestCompileSnatRulesMetaMarkExempt(t *testing.T) {
	rules, err := CompileSnatRules([]SnatRule{snatRule(30, "192.168.10.152")})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.MetaMarkNotSet == nil {
			t.Fatalf("★ 每条规则都必须带 meta mark 豁免条件: %+v", r)
		}
		if *r.MetaMarkNotSet != 0x4 {
			t.Fatalf("豁免掩码应为 0x4（MarkDNAT），实际 0x%x", *r.MetaMarkNotSet)
		}
	}
	// 显式设为 0 时不生成条件
	r := snatRule(31, "10.0.0.1")
	r.MetaMarkExempt = 0
	rules, err = CompileSnatRules([]SnatRule{r})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range rules {
		if x.MetaMarkNotSet != nil {
			t.Fatal("MetaMarkExempt=0 时不应生成 meta mark 条件")
		}
	}
}

// TestCompileSnatRulesIifOif 网卡前置条件必须带上。
func TestCompileSnatRulesIifOif(t *testing.T) {
	rules, err := CompileSnatRules([]SnatRule{snatRule(30, "192.168.10.152")})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.IfIn != "eth0" || r.IfOut != "eth0" {
			t.Fatalf("★ 网卡条件丢失: IfIn=%q IfOut=%q", r.IfIn, r.IfOut)
		}
	}
}

// TestCompileSnatRulesDisabledSkipped 禁用规则不生成。
func TestCompileSnatRulesDisabledSkipped(t *testing.T) {
	r := snatRule(30, "192.168.10.152")
	r.Enabled = false
	rules, err := CompileSnatRules([]SnatRule{r})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("禁用规则不应生成，实际 %d 条", len(rules))
	}
}

// TestCompileSnatRulesCIDR 网段源（不是单 IP）也要正确处理。
func TestCompileSnatRulesCIDR(t *testing.T) {
	rules, err := CompileSnatRules([]SnatRule{snatRule(30, "192.168.10.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("应 2 条，实际 %d", len(rules))
	}
	// 放行行的源应是 /24
	if got := rules[0].Src.Prefixes[0].String(); got != "192.168.10.0/24" {
		t.Fatalf("源网段错误: %s", got)
	}
}

// TestCompileSnatRulesCommentUnique comment 必须唯一（Plan.Validate 强制）。
func TestCompileSnatRulesCommentUnique(t *testing.T) {
	rules, err := CompileSnatRules([]SnatRule{
		snatRule(30, "192.168.10.152", "192.168.10.151"),
		snatRule(31, "192.168.10.152"), // 与规则30 有相同源
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Comment] {
			t.Fatalf("★ comment 重复: %q", r.Comment)
		}
		seen[r.Comment] = true
	}
}

// TestSnatRulesFromModel 构造器：网段自动归零、校验前置。
func TestSnatRulesFromModel(t *testing.T) {
	r, err := SnatRulesFromModel(30, "test",
		[]netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")},
		netip.MustParseAddr("192.168.10.170"), "eth0", "eth0", 0x4)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	// 网段必须归零
	if got := r.SourceNets[0].String(); got != "10.0.0.0/8" {
		t.Fatalf("★ 网段未归零: %s（应为 10.0.0.0/8）", got)
	}

	// 无效输入应报错
	if _, err := SnatRulesFromModel(31, "x", nil,
		netip.MustParseAddr("192.168.10.170"), "", "", 0); err == nil {
		t.Fatal("空源列表应报错")
	}
	if _, err := SnatRulesFromModel(32, "x",
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		netip.Addr{}, "", "", 0); err == nil {
		t.Fatal("无效出口地址应报错")
	}
}

// TestSnatRulePrefixExported 前缀导出供 adapter 对账。
func TestSnatRulePrefixExported(t *testing.T) {
	if SnatRuleCommentPrefix() != "haweb:snatrule:" {
		t.Fatalf("前缀应为 haweb:snatrule:，实际 %q", SnatRuleCommentPrefix())
	}
}
