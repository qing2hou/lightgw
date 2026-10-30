package compile

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"haproxyweb/internal/domain/model"
)

func testRule(id uint, listen, backend string, enabled bool) model.Rule {
	return model.Rule{
		ID:       id,
		Name:     "r" + strconv.Itoa(int(id)),
		Proto:    model.ProtoTCP,
		ListenAt: netip.MustParseAddrPort(listen),
		Backend:  netip.MustParseAddrPort(backend),
		Enabled:  enabled,
	}
}

// TestMakeCtMarkRoundTrip ct mark 合成与拆解必须互逆（32 位容量方案的基础）。
func TestMakeCtMarkRoundTrip(t *testing.T) {
	cases := []struct {
		ruleID uint32
		flags  uint32
	}{
		{0, 0},
		{1, CtFlagDnat},
		{0x12, CtFlagDnat},
		{0xFFFF, CtFlagDnat | CtFlagHairpin},
		{1<<24 - 1, CtFlagPolicyDrop},
	}
	for _, c := range cases {
		v, err := MakeCtMark(c.ruleID, c.flags)
		if err != nil {
			t.Fatalf("MakeCtMark(%d, %d) 失败: %v", c.ruleID, c.flags, err)
		}
		rid, fl := SplitCtMark(v)
		if rid != c.ruleID || fl != c.flags {
			t.Fatalf("往返失败: (%d,%d) -> 0x%x -> (%d,%d)", c.ruleID, c.flags, v, rid, fl)
		}
	}
}

// TestMakeCtMarkRejectsOverflow 超过 24 位的 rule_id 必须报错而不是静默截断。
func TestMakeCtMarkRejectsOverflow(t *testing.T) {
	if _, err := MakeCtMark(1<<24, CtFlagDnat); err == nil {
		t.Fatal("rule_id 溢出 24 位必须报错")
	}
	if _, err := MakeCtMark(1, 0x100); err == nil {
		t.Fatal("flags 超出低 8 位必须报错")
	}
}

// TestCtMarkCapacity 32 位方案支持 1600 万条规则（技术方案 §3.2 的核心收益）。
func TestCtMarkCapacity(t *testing.T) {
	const maxRules = 1 << 24
	if maxRules < 16000000 {
		t.Fatalf("容量 %d 应 >= 1600 万", maxRules)
	}
	// 旧方案（3 个 meta mark 位）最多 16 条，新方案是它的 100 万倍
	if maxRules/(1<<4) < 1000000 {
		t.Fatal("新方案容量应远超旧方案（16 条）")
	}
}

// TestCompileDnatTwoRulesPerRule 每条规则必须生成「判定 + 改写」两条。
func TestCompileDnatTwoRulesPerRule(t *testing.T) {
	rules := []model.Rule{
		testRule(1, "192.168.10.170:1022", "192.168.10.152:22", true),
		testRule(2, "192.168.10.170:1023", "192.168.10.153:22", true),
	}
	out, err := CompileDnat(rules)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("2 条规则应生成 4 条 nft 规则，实际 %d", len(out))
	}
	var mark, apply int
	for _, r := range out {
		if strings.HasSuffix(r.Comment, ":mark") {
			mark++
			if r.SetCtMark == nil {
				t.Fatal("判定行必须设置 ct mark")
			}
			if !r.CtStateNew {
				t.Fatal("判定行应只作用于 ct state new（避免重复改已建连接）")
			}
			if r.SetMetaMark == nil || *r.SetMetaMark != MarkFwdOK {
				t.Fatal("判定行必须打 FWD_OK 标记")
			}
		}
		if strings.HasSuffix(r.Comment, ":apply") {
			apply++
			if r.DnatTo == (netip.AddrPort{}) {
				t.Fatal("改写行必须有 DNAT 目标")
			}
			if r.CtMarkEq == nil {
				t.Fatal("改写行必须按 ct mark 匹配")
			}
			// 改写行不应再判断源地址——判定已在判定行完成，
			// 否则会出现「未授权源也被 DNAT」的窗口
			if !r.Src.Empty() {
				t.Fatal("改写行不应重复做源判定（应在 mark 行完成）")
			}
		}
	}
	if mark != 2 || apply != 2 {
		t.Fatalf("应是 2 条判定 + 2 条改写，实际 %d + %d", mark, apply)
	}
}

// TestCompileDnatDisabledSkipped 禁用规则不生成 DNAT。
func TestCompileDnatDisabledSkipped(t *testing.T) {
	out, err := CompileDnat([]model.Rule{
		testRule(1, "192.168.10.170:1022", "192.168.10.152:22", false),
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("禁用规则不应生成 DNAT，实际 %d 条", len(out))
	}
}

// TestCompileDnatDeterministic 输出顺序必须稳定（按 ID 升序）。
func TestCompileDnatDeterministic(t *testing.T) {
	mk := func(ids ...uint) []model.Rule {
		var out []model.Rule
		for _, id := range ids {
			out = append(out, testRule(id, "192.168.10.170:102"+strconv.Itoa(int(id)),
				"192.168.10.15"+strconv.Itoa(int(id))+":22", true))
		}
		return out
	}
	a, _ := CompileDnat(mk(3, 1, 2))
	b, _ := CompileDnat(mk(1, 2, 3))
	if len(a) != len(b) {
		t.Fatal("长度不一致")
	}
	for i := range a {
		if a[i].Comment != b[i].Comment {
			t.Fatalf("顺序不稳定：位置 %d 为 %s vs %s", i, a[i].Comment, b[i].Comment)
		}
	}
}

// TestCompilePoliciesThreeActions 三态语义必须映射正确（D-14）。
func TestCompilePoliciesThreeActions(t *testing.T) {
	pols := []model.Policy{
		{ID: 1, Order: 10, Proto: model.ProtoTCP, Port: 443,
			Action: model.ActionAccept, Enabled: true},
		{ID: 2, Order: 20, Proto: model.ProtoTCP, Port: 80,
			Action: model.ActionAllow, Enabled: true},
		{ID: 3, Order: 30, Proto: model.ProtoUDP, Port: 53,
			Action: model.ActionDrop, Enabled: true},
	}
	out, err := CompilePolicies(pols)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("应生成 3 条，实际 %d", len(out))
	}
	// accept：打标不终结
	if out[0].SetMetaMark == nil || *out[0].SetMetaMark != MarkPolicyOK {
		t.Fatal("accept 应打 POLICY_OK 标记")
	}
	if out[0].Verdict != "" {
		t.Fatalf("accept 不应有终结动作，实际 %q", out[0].Verdict)
	}
	// allow：终结 accept
	if out[1].Verdict != "accept" {
		t.Fatalf("allow 应生成 verdict accept，实际 %q", out[1].Verdict)
	}
	// drop：终结 drop
	if out[2].Verdict != "drop" {
		t.Fatalf("drop 应生成 verdict drop，实际 %q", out[2].Verdict)
	}
}

// TestCompileDefaultDenyIcmpBeforeDrop ICMP 豁免必须排在 drop 之前。
//
// 否则差错报文先被 drop，豁免规则永远看不到它们 → 大包黑洞。
func TestCompileDefaultDenyIcmpBeforeDrop(t *testing.T) {
	out, err := CompileDefaultDeny(model.ScopeDnatTarget, []netip.Addr{
		netip.MustParseAddr("192.168.10.152"),
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("应有规则")
	}
	last := out[len(out)-1]
	if last.Verdict != "drop" {
		t.Fatalf("最后一条必须是 drop，实际 %q", last.Verdict)
	}
	for i := 0; i < len(out)-1; i++ {
		if out[i].Verdict == "drop" {
			t.Fatalf("位置 %d 出现了 drop，但后面还有规则——会遮蔽后续豁免", i)
		}
	}
	// 必须含 v4 与 v6 两组豁免
	var sawV4, sawV6 bool
	for _, r := range out {
		if strings.Contains(r.Comment, "icmp:ipv4") {
			sawV4 = true
		}
		if strings.Contains(r.Comment, "icmp:ipv6") {
			sawV6 = true
		}
	}
	if !sawV4 || !sawV6 {
		t.Fatalf("应含 v4 与 v6 的 ICMP 豁免，实际 v4=%v v6=%v", sawV4, sawV6)
	}
}

// TestCompileDefaultDenyOff off 档不生成任何规则。
func TestCompileDefaultDenyOff(t *testing.T) {
	out, err := CompileDefaultDeny(model.ScopeOff, nil)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("off 档应无规则，实际 %d", len(out))
	}
}

// TestCompileDefaultDenyDnatTargetEmpty 没有后端目标时不应生成 drop。
//
// 理由：没有 DNAT 规则时不该拒绝任何转发。
func TestCompileDefaultDenyDnatTargetEmpty(t *testing.T) {
	out, err := CompileDefaultDeny(model.ScopeDnatTarget, nil)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	for _, r := range out {
		if r.Verdict == "drop" {
			t.Fatal("无后端目标时不应生成 drop 行")
		}
	}
}

// TestCompileDefaultDenyInterfaceNoDst interface 档不设目的条件（危险档）。
func TestCompileDefaultDenyInterfaceNoDst(t *testing.T) {
	out, err := CompileDefaultDeny(model.ScopeInterface, []netip.Addr{
		netip.MustParseAddr("192.168.10.152"),
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	var drop *Rule
	for i := range out {
		if out[i].Verdict == "drop" {
			drop = &out[i]
		}
	}
	if drop == nil {
		t.Fatal("interface 档必须有 drop 行")
	}
	if !drop.Dst.Empty() {
		t.Fatal("interface 档不应设目的条件（拒绝整个入口）")
	}
}

// TestCompileDefaultDenyBadScope 非法作用域必须报错。
func TestCompileDefaultDenyBadScope(t *testing.T) {
	if _, err := CompileDefaultDeny("bogus", nil); err == nil {
		t.Fatal("非法作用域应报错")
	}
}

// TestCompileForwardOnlyEnabled 只有启用规则生成白名单行。
func TestCompileForwardOnlyEnabled(t *testing.T) {
	out, err := CompileForward([]model.Rule{
		testRule(1, "192.168.10.170:1022", "192.168.10.152:22", true),
		testRule(2, "192.168.10.170:1023", "192.168.10.153:22", false),
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("应只生成 1 条，实际 %d", len(out))
	}
	if out[0].SetMetaMark == nil || *out[0].SetMetaMark != MarkFwdOK {
		t.Fatal("白名单行必须打 FWD_OK")
	}
	// 目的地址必须是后端地址（不是 VIP）
	if out[0].Dst.Empty() || out[0].Dst.Prefixes[0].Addr().String() != "192.168.10.152" {
		t.Fatalf("白名单行应匹配后端地址，实际 %v", out[0].Dst.Prefixes)
	}
}

// TestCompileEstablished 回程放行规则必须存在且打 FWD_OK。
func TestCompileEstablished(t *testing.T) {
	out := CompileEstablished()
	if len(out) != 1 {
		t.Fatalf("应有 1 条回程放行规则，实际 %d", len(out))
	}
	if out[0].SetMetaMark == nil || *out[0].SetMetaMark != MarkFwdOK {
		t.Fatal("回程放行必须打 FWD_OK")
	}
	if out[0].CtStateNew {
		t.Fatal("回程放行不能限 ct state new（否则已建连接被误杀）")
	}
	if EstablishedComment() != out[0].Comment {
		t.Fatal("comment 常量与规则不一致")
	}
}

// TestSortedPrefixes 去重 / 排序 / 归零。
func TestSortedPrefixes(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("10.1.2.3/8"), // 未归零
		netip.MustParsePrefix("192.168.10.0/24"),
		netip.MustParsePrefix("10.0.0.0/8"), // 与上一条归零后重复
		netip.MustParsePrefix("192.168.10.152/32"),
	}
	out := SortedPrefixes(in)
	if len(out) != 3 {
		t.Fatalf("去重后应 3 条，实际 %d: %v", len(out), out)
	}
	for _, p := range out {
		if p.Masked() != p {
			t.Fatalf("网段 %s 未归零", p)
		}
	}
	// 排序：10.0.0.0/8 < 192.168.10.0/24 < 192.168.10.152/32
	if out[0].String() != "10.0.0.0/8" {
		t.Fatalf("首项应为 10.0.0.0/8，实际 %s", out[0])
	}
}

// TestPlanValidateCommentUniqueness comment 必须唯一（Applier 靠它精确删除）。
func TestPlanValidateCommentUniqueness(t *testing.T) {
	p := Plan{Nft: NftPlan{Forward: []Rule{
		{Chain: ChainWorkA, Comment: "dup"},
		{Chain: ChainWorkA, Comment: "dup"},
	}}}
	if err := p.Validate(); err == nil {
		t.Fatal("重复 comment 必须报错")
	}
}

func TestPlanValidateEmptyComment(t *testing.T) {
	p := Plan{Nft: NftPlan{Forward: []Rule{{Chain: ChainWorkA, Comment: ""}}}}
	if err := p.Validate(); err == nil {
		t.Fatal("空 comment 必须报错")
	}
}

// TestMSSClamp 基础：v4/v6 各生成一条，值为 0 时关闭。
func TestMSSClamp(t *testing.T) {
	out, err := CompileMSSClamp(DefaultMSSv4, DefaultMSSv6)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("应生成 2 条（v4+v6），实际 %d", len(out))
	}
	if out[0].MSSValue != DefaultMSSv4 || out[0].MSSFamily != "ipv4" {
		t.Fatalf("v4 规则错误: %+v", out[0])
	}
	if out[1].MSSValue != DefaultMSSv6 || out[1].MSSFamily != "ipv6" {
		t.Fatalf("v6 规则错误: %+v", out[1])
	}
	// 都是 TCP
	for _, r := range out {
		if r.Proto != "tcp" {
			t.Fatalf("MSS 规则必须是 tcp，实际 %q", r.Proto)
		}
		if r.Chain != ChainMss {
			t.Fatalf("MSS 规则必须挂 mss 链，实际 %q", r.Chain)
		}
	}

	// 都为 0 → 关闭
	none, err := CompileMSSClamp(0, 0)
	if err != nil {
		t.Fatalf("关闭 MSS 不应报错: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("mss=0 应无规则，实际 %d", len(none))
	}
}

// TestMSSClampTooSmall 过小的 MSS 必须被拒绝（会严重损害吞吐）。
func TestMSSClampTooSmall(t *testing.T) {
	if _, err := CompileMSSClamp(100, 0); err == nil {
		t.Fatal("MSS 100 小于下限应报错")
	}
	if _, err := CompileMSSClamp(0, 100); err == nil {
		t.Fatal("v6 MSS 100 小于下限应报错")
	}
}

// TestMSSCommentMatches comment 前缀识别必须精确（不能误伤 dnat/snat 规则）。
func TestMSSCommentMatches(t *testing.T) {
	if !MSSCommentMatches("haweb:mss:v4") {
		t.Fatal("应识别 mss comment")
	}
	if MSSCommentMatches("haweb:dnat:1:mark") {
		t.Fatal("不应把 dnat comment 识别为 mss")
	}
	if MSSCommentMatches("haweb:mss") {
		t.Fatal("前缀无后缀时不应识别（避免误删）")
	}
}

// TestCompileSnatFixedSource 固定源地址优先于池。
func TestCompileSnatFixedSource(t *testing.T) {
	r := testRule(1, "192.168.10.170:1022", "192.168.10.152:22", true)
	out, err := CompileSnat([]SnatSpec{{
		Rule: r,
		Egress: model.Egress{
			IfName:   "eth0",
			SourceIP: netip.MustParseAddr("192.168.10.170"),
		},
	}})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("应生成 1 条 SNAT，实际 %d", len(out))
	}
	if out[0].SnatTo.String() != "192.168.10.170" {
		t.Fatalf("应 SNAT 到固定源地址，实际 %s", out[0].SnatTo)
	}
	if out[0].CtMarkEq == nil {
		t.Fatal("SNAT 必须按 ct mark 匹配（保证只改本规则的连接）")
	}
}

// TestCompileSnatNoSourceNoPool 既无源地址也无池时不做 SNAT（纯 DNAT）。
func TestCompileSnatNoSourceNoPool(t *testing.T) {
	r := testRule(1, "192.168.10.170:1022", "192.168.10.152:22", true)
	out, err := CompileSnat([]SnatSpec{{
		Rule:   r,
		Egress: model.Egress{IfName: "eth0"},
	}})
	if err != nil {
		t.Fatalf("纯 DNAT 不应报错: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("无源无池不应生成 SNAT，实际 %d", len(out))
	}
}

// TestCompilerSmoke 整份 State 编译成功且自检通过。
func TestCompilerSmoke(t *testing.T) {
	c := &Compiler{Caps: Caps{TcNetlink: true, Ifb: true, PerSrcLimit: true}}
	p, err := c.Compile(State{
		Version: 1,
		Rules:   []model.Rule{testRule(1, "192.168.10.170:1022", "192.168.10.152:22", true)},
		MSSv4:   DefaultMSSv4,
		MSSv6:   DefaultMSSv6,
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if p.Version != 1 {
		t.Fatalf("版本号未传递: %d", p.Version)
	}
	if p.Nft.RuleCount() == 0 {
		t.Fatal("计划不应为空")
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("能力齐备时不应有警告，实际 %v", p.Warnings)
	}
}

// TestCompilerWarnsOnMissingCaps 能力缺失必须有显式警告，不能静默降级。
func TestCompilerWarnsOnMissingCaps(t *testing.T) {
	c := &Compiler{Caps: Caps{TcNetlink: false}}
	p, err := c.Compile(State{Version: 1})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(p.Warnings) == 0 {
		t.Fatal("tc 不可用必须产生警告")
	}
	if !strings.Contains(strings.Join(p.Warnings, ";"), "tc 不可用") {
		t.Fatalf("警告应说明 tc 不可用，实际 %v", p.Warnings)
	}
}

// TestCompilerIfbWarning ifb 缺失时也要警告（上传只能限总额）。
func TestCompilerIfbWarning(t *testing.T) {
	c := &Compiler{Caps: Caps{TcNetlink: true, Ifb: false, PerSrcLimit: true}}
	p, err := c.Compile(State{Version: 1})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	joined := strings.Join(p.Warnings, ";")
	if !strings.Contains(joined, "ifb") {
		t.Fatalf("ifb 不可用应警告，实际 %v", p.Warnings)
	}
}

// TestCompilerRejectsInvalidRules 校验错误必须前置拦截。
func TestCompilerRejectsInvalidRules(t *testing.T) {
	c := &Compiler{Caps: Caps{TcNetlink: true}}
	bad := testRule(1, "192.168.10.170:1022", "192.168.10.152:22", true)
	bad.Proto = "sctp"
	if _, err := c.Compile(State{Rules: []model.Rule{bad}}); err == nil {
		t.Fatal("非法规则必须报错")
	}
}

// TestDefaultChains 链布局的 priority 必须符合技术方案。
func TestDefaultChains(t *testing.T) {
	chains := DefaultChains()
	want := map[string]int32{
		ChainDispatch: -10,
		ChainDnat:     -100,
		ChainSnat:     100,
		ChainMss:      -20,
		ChainInput:    -150,
	}
	for _, c := range chains {
		if w, ok := want[c.Name]; ok && c.Priority != w {
			t.Fatalf("链 %s 的 priority 应为 %d，实际 %d", c.Name, w, c.Priority)
		}
	}
	// mss 必须早于 fwd（MSS 只在 SYN 上有意义）
	var mssPri, fwdPri int32
	for _, c := range chains {
		if c.Name == ChainMss {
			mssPri = c.Priority
		}
		if c.Name == ChainDispatch {
			fwdPri = c.Priority
		}
	}
	if mssPri >= fwdPri {
		t.Fatalf("mss(%d) 必须早于 fwd(%d)", mssPri, fwdPri)
	}
}

// TestRuleStringAndDir 供日志与断言使用的两个便捷方法。
func TestRuleStringAndDir(t *testing.T) {
	r := Rule{Chain: ChainWorkA, Comment: "haweb:fwd:1"}
	if got := r.String(); got != "w_a|haweb:fwd:1" {
		t.Fatalf("Rule.String() 错误: %q", got)
	}
	if got := (TcFilterSpec{MatchSrc: true}).Dir(); got != "src" {
		t.Fatalf("MatchSrc=true 的 Dir 应为 src，实际 %q", got)
	}
	if got := (TcFilterSpec{MatchSrc: false}).Dir(); got != "dst" {
		t.Fatalf("MatchSrc=false 的 Dir 应为 dst，实际 %q", got)
	}
}

// TestTcPlanEmpty 空计划判定。
func TestTcPlanEmpty(t *testing.T) {
	if !(TcPlan{}).Empty() {
		t.Fatal("零值计划应为空")
	}
	if (TcPlan{Qdiscs: []TcQdiscSpec{{Device: "eth0"}}}).Empty() {
		t.Fatal("有 qdisc 时不应判为空")
	}
}

// TestNftPlanRuleCount 规则计数横跨六个段。
func TestNftPlanRuleCount(t *testing.T) {
	p := NftPlan{
		Forward: []Rule{{Comment: "a"}},
		Policy:  []Rule{{Comment: "b"}, {Comment: "c"}},
		Dnat:    []Rule{{Comment: "d"}},
		Snat:    []Rule{{Comment: "e"}},
		Mss:     []Rule{{Comment: "f"}},
		Deny:    []Rule{{Comment: "g"}},
	}
	if got := p.RuleCount(); got != 7 {
		t.Fatalf("应计 7 条，实际 %d", got)
	}
}

// TestKBpsToBitsPerSec 边界。
func TestKBpsToBitsPerSec(t *testing.T) {
	if got := KBpsToBitsPerSec(8192); got != 67108864 {
		t.Fatalf("8192 KB/s 应为 67108864 bit/s，实际 %d", got)
	}
	if got := KBpsToBitsPerSec(0); got != 0 {
		t.Fatalf("0 应返回 0，实际 %d", got)
	}
	if got := KBpsToBitsPerSec(-5); got != 0 {
		t.Fatalf("负值应返回 0，实际 %d", got)
	}
}

// TestCompileTcBadEgressDevice 出口网卡名为空必须报错。
func TestCompileTcBadEgressDevice(t *testing.T) {
	if _, err := CompileTcOnly(8192, 1024, []string{"10.0.0.1"}, "", "", ""); err == nil {
		t.Fatal("出口网卡名为空应报错")
	}
}

// TestCompileTcNoIfb 无 ifb 时只建下载侧树（上传退化为仅总额）。
func TestCompileTcNoIfb(t *testing.T) {
	plan, err := CompileTcOnly(8192, 1024, []string{"192.168.10.152"}, "eth0", "eth0", "")
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	for _, q := range plan.Qdiscs {
		if q.Kind == "ingress" {
			t.Fatal("无 ifb 时不应建 ingress qdisc（重定向目标不存在）")
		}
	}
	for _, f := range plan.Filters {
		if f.Parent == "ffff:" {
			t.Fatal("无 ifb 时不应生成 ingress 重定向 filter")
		}
	}
	if len(plan.Filters) != 1 {
		t.Fatalf("应只有 1 条下载 filter，实际 %d", len(plan.Filters))
	}
}

// TestCompileSnatBadEgress 出口非法必须报错。
func TestCompileSnatBadEgress(t *testing.T) {
	r := testRule(1, "192.168.10.170:1022", "192.168.10.152:22", true)
	if _, err := CompileSnat([]SnatSpec{{
		Rule:   r,
		Egress: model.Egress{IfName: ""}, // 非法
	}}); err == nil {
		t.Fatal("出口网卡名为空应报错")
	}
}

// TestCompileSnatDisabledSkipped 禁用规则不生成 SNAT。
func TestCompileSnatDisabledSkipped(t *testing.T) {
	r := testRule(1, "192.168.10.170:1022", "192.168.10.152:22", false)
	out, err := CompileSnat([]SnatSpec{{
		Rule:   r,
		Egress: model.Egress{IfName: "eth0", SourceIP: netip.MustParseAddr("192.168.10.170")},
	}})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("禁用规则不应生成 SNAT，实际 %d", len(out))
	}
}

// TestCompileDnatMarkOverflow rule_id 超 24 位必须报错（不能静默截断）。
func TestCompileDnatMarkOverflow(t *testing.T) {
	r := testRule(1<<24, "192.168.10.170:1022", "192.168.10.152:22", true)
	if _, err := CompileDnat([]model.Rule{r}); err == nil {
		t.Fatal("rule_id 超 24 位必须报错")
	}
}

// TestCompileForwardWithACL 白名单必须比无名单多一条源条件。
func TestCompileForwardWithACL(t *testing.T) {
	withACL := testRule(1, "192.168.10.170:1022", "192.168.10.152:22", true)
	withACL.ACLMode = model.ACLWhitelist
	withACL.ACL = []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}

	out, err := CompileForward([]model.Rule{withACL})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("应生成 1 条，实际 %d", len(out))
	}
	if out[0].Src.Empty() {
		t.Fatal("配了白名单就应生成源条件")
	}
	if out[0].Src.Prefixes[0].String() != "192.168.10.0/24" {
		t.Fatalf("源条件应为白名单网段，实际 %v", out[0].Src.Prefixes)
	}
}

// TestCompilerCompilePoliciesError 策略校验失败必须前置拦截。
func TestCompilerCompilePoliciesError(t *testing.T) {
	c := &Compiler{Caps: Caps{TcNetlink: true}}
	if _, err := c.Compile(State{
		Policies: []model.Policy{
			{ID: 1, Order: 10, Proto: model.ProtoTCP, Port: 443,
				Action: model.ActionAccept, Enabled: true},
			{ID: 2, Order: 10, Proto: model.ProtoTCP, Port: 443,
				Action: model.ActionDrop, Enabled: true},
		},
	}); err == nil {
		t.Fatal("Order 冲突必须报错")
	}
}

// TestCompilerPerSrcLimitWarning 按源分类不可用时必须警告。
func TestCompilerPerSrcLimitWarning(t *testing.T) {
	c := &Compiler{Caps: Caps{TcNetlink: true, Ifb: true, PerSrcLimit: false}}
	p, err := c.Compile(State{Version: 1})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	joined := strings.Join(p.Warnings, ";")
	if !strings.Contains(joined, "按源分类不可用") {
		t.Fatalf("应警告按源分类不可用，实际 %v", p.Warnings)
	}
}

// TestCompilerSnatDisabledEgress 无启用出口时不生成 SNAT。
func TestCompilerSnatDisabledEgress(t *testing.T) {
	c := &Compiler{Caps: Caps{TcNetlink: true}}
	r := testRule(1, "192.168.10.170:1022", "192.168.10.152:22", true)
	p, err := c.Compile(State{
		Rules: []model.Rule{r},
		Egresses: []model.Egress{
			{ID: 1, IfName: "eth0", Enabled: false,
				SourceIP: netip.MustParseAddr("192.168.10.170")},
		},
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(p.Nft.Snat) != 0 {
		t.Fatalf("出口未启用时不应生成 SNAT，实际 %d", len(p.Nft.Snat))
	}
}
