package nftables

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/google/nftables/expr"

	"haproxyweb/internal/compile"
	"haproxyweb/internal/domain/model"
)

// modelRule 是构造测试用 domain 规则的便捷函数。
type modelRule = model.Rule

// mkModelRule 造一条最小的可编译规则（DNAT 到 192.168.10.152:22）。
func mkModelRule() model.Rule {
	return model.Rule{
		ID:       1,
		Name:     "t",
		Proto:    model.ProtoTCP,
		ListenAt: netip.MustParseAddrPort("192.168.10.170:1022"),
		Backend:  netip.MustParseAddrPort("192.168.10.152:22"),
		Enabled:  true,
	}
}

// TestTranslatePlanNil nil 计划必须报错。
func TestTranslatePlanNil(t *testing.T) {
	if _, _, err := TranslatePlan(nil); err == nil {
		t.Fatal("nil 计划应报错")
	}
}

// TestTranslateDNATRequiresProto 真机实测：dnat 之前必须有传输层协议匹配，
// 否则内核报 "transport protocol mapping is only valid after transport protocol match"。
func TestTranslateDNATRequiresProto(t *testing.T) {
	mark := uint32(0x100)
	_, err := translateRule(compile.Rule{
		Comment:  "test",
		Proto:    "", // 缺协议
		CtMarkEq: &mark,
		DnatTo:   netip.MustParseAddrPort("192.168.10.152:22"),
	})
	if err == nil {
		t.Fatal("DNAT 缺协议必须报错（内核会拒绝）")
	}
	if !strings.Contains(err.Error(), "传输层协议") {
		t.Fatalf("错误消息应说明缺协议，实际: %v", err)
	}
}

// TestTranslateSNATRequiresProto SNAT 同理。
func TestTranslateSNATRequiresProto(t *testing.T) {
	mark := uint32(0x100)
	_, err := translateRule(compile.Rule{
		Comment:  "test",
		Proto:    "",
		CtMarkEq: &mark,
		SnatTo:   netip.MustParseAddr("192.168.10.170"),
	})
	if err == nil {
		t.Fatal("SNAT 缺协议必须报错")
	}
}

// TestTranslateCounterBeforeNAT 真机实测：NAT 是终结语句，
// counter 必须在它**之前**，否则内核报 "Statement after terminal statement has no effect"。
func TestTranslateCounterBeforeNAT(t *testing.T) {
	mark := uint32(0x100)
	out, err := translateRule(compile.Rule{
		Comment:  "test",
		Proto:    "tcp",
		DstPort:  1022,
		CtMarkEq: &mark,
		DnatTo:   netip.MustParseAddrPort("192.168.10.152:22"),
		Counter:  true,
	})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	counterIdx, natIdx := -1, -1
	for i, e := range out {
		if _, ok := e.(*expr.Counter); ok {
			counterIdx = i
		}
		if _, ok := e.(*expr.NAT); ok {
			natIdx = i
		}
	}
	if counterIdx < 0 {
		t.Fatal("counter 缺失")
	}
	if natIdx < 0 {
		t.Fatal("NAT 缺失")
	}
	if counterIdx > natIdx {
		t.Fatalf("counter（位置 %d）必须在 NAT（位置 %d）之前——NAT 是终结语句", counterIdx, natIdx)
	}
	// NAT 必须是最后一条
	if natIdx != len(out)-1 {
		t.Fatalf("NAT 必须是最后一条表达式，实际位置 %d / 共 %d 条", natIdx, len(out))
	}
}

// TestTranslateCtMarkAndNATMutex 同一条规则里既设 ct mark 又做 NAT 必须报错
// （寄存器冲突：二者都用 Register 1）。
func TestTranslateCtMarkAndNATMutex(t *testing.T) {
	mark := uint32(0x100)
	set := uint32(0x200)
	_, err := translateRule(compile.Rule{
		Comment:   "test",
		Proto:     "tcp",
		CtMarkEq:  &mark,
		SetCtMark: &set,
		DnatTo:    netip.MustParseAddrPort("192.168.10.152:22"),
	})
	if err == nil {
		t.Fatal("ct mark + NAT 共存必须报错")
	}
	if !strings.Contains(err.Error(), "寄存器") {
		t.Fatalf("错误消息应说明寄存器冲突，实际: %v", err)
	}
}

// TestTranslateDNATWithPort dnat 必须生成两个立即数（地址 + 端口）+ NAT。
func TestTranslateDNATWithPort(t *testing.T) {
	mark := uint32(0x100)
	out, err := translateRule(compile.Rule{
		Comment:  "t",
		Proto:    "tcp",
		DstPort:  1022, // 传输层上下文锚点（内核要求）
		CtMarkEq: &mark,
		DnatTo:   netip.MustParseAddrPort("192.168.10.152:22"),
	})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	var imms int
	var nat *expr.NAT
	for _, e := range out {
		switch v := e.(type) {
		case *expr.Immediate:
			imms++
		case *expr.NAT:
			nat = v
		}
	}
	if imms != 2 {
		t.Fatalf("带端口的 DNAT 应有 2 个立即数（地址+端口），实际 %d", imms)
	}
	if nat == nil {
		t.Fatal("NAT 表达式缺失")
	}
	if nat.Type != expr.NATTypeDestNAT {
		t.Fatalf("NAT 类型应为 DestNAT，实际 %v", nat.Type)
	}
	if nat.RegProtoMin != 2 {
		t.Fatalf("RegProtoMin 应为 2（端口在 reg2），实际 %d", nat.RegProtoMin)
	}
}

// TestTranslateSNATWithPortAnchor snat 只换地址（不生成端口立即数），
// 但规则仍需 DstPort 作为传输层上下文锚点。
func TestTranslateSNATWithPortAnchor(t *testing.T) {
	mark := uint32(0x100)
	out, err := translateRule(compile.Rule{
		Comment:  "t",
		Proto:    "tcp",
		DstPort:  1022, // 传输层上下文锚点（内核要求）
		CtMarkEq: &mark,
		SnatTo:   netip.MustParseAddr("192.168.10.170"),
	})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	var nat *expr.NAT
	for _, e := range out {
		if v, ok := e.(*expr.NAT); ok {
			nat = v
		}
	}
	if nat == nil {
		t.Fatal("NAT 表达式缺失")
	}
	if nat.Type != expr.NATTypeSourceNAT {
		t.Fatalf("NAT 类型应为 SourceNAT，实际 %v", nat.Type)
	}
	if nat.RegProtoMin != 0 {
		t.Fatalf("SNAT 不需要端口，RegProtoMin 应为 0，实际 %d", nat.RegProtoMin)
	}
}

// TestTranslateCtMarkMatchesRuleMask ct mark 匹配必须带位掩码
// （rule_id << 8，低 8 位是 flag，不能整值比较）。
func TestTranslateCtMarkMatchesRuleMask(t *testing.T) {
	ruleMark := uint32(0x12) << 8
	out, err := translateRule(compile.Rule{
		Comment:  "t",
		Proto:    "tcp",
		CtMarkEq: &ruleMark,
	})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	var sawMask bool
	for _, e := range out {
		if bw, ok := e.(*expr.Bitwise); ok {
			if len(bw.Mask) == 4 && bw.Mask[0] == 0xff && bw.Mask[1] == 0xff && bw.Mask[2] == 0xff && bw.Mask[3] == 0x00 {
				sawMask = true
			}
		}
	}
	if !sawMask {
		t.Fatal("ct mark 匹配必须带 0xFFFFFF00 掩码（低 8 位是 flag）")
	}
}

// TestTranslateAddrMatchMultiPrefixRejected 多网段必须由调用方展开，
// 翻译器不能静默取第一个（否则「配了 3 个网段只匹配 1 个」）。
func TestTranslateAddrMatchMultiPrefixRejected(t *testing.T) {
	m := compile.AddrMatch{Prefixes: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}}
	if _, err := translateAddrMatch(m, true); err == nil {
		t.Fatal("多网段必须报错（要求调用方展开）")
	}
}

// TestTranslateAddrMatchHost 单主机用 Cmp（不需要 bitwise）。
func TestTranslateAddrMatchHost(t *testing.T) {
	m := compile.AddrMatch{Prefixes: []netip.Prefix{
		netip.MustParsePrefix("192.168.10.152/32"),
	}}
	out, err := translateAddrMatch(m, true)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("/32 应只用 Payload+Cmp（2 条），实际 %d 条", len(out))
	}
	if _, ok := out[1].(*expr.Cmp); !ok {
		t.Fatal("第二条应为 Cmp")
	}
}

// TestTranslateAddrMatchCIDR CIDR 必须用 bitwise 掩码。
func TestTranslateAddrMatchCIDR(t *testing.T) {
	m := compile.AddrMatch{Prefixes: []netip.Prefix{
		netip.MustParsePrefix("192.168.10.0/24"),
	}}
	out, err := translateAddrMatch(m, false)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("/24 应用 Payload+Bitwise+Cmp（3 条），实际 %d 条", len(out))
	}
	bw, ok := out[1].(*expr.Bitwise)
	if !ok {
		t.Fatal("第二条应为 Bitwise")
	}
	if len(bw.Mask) != 4 || bw.Mask[0] != 0xff || bw.Mask[1] != 0xff || bw.Mask[2] != 0xff || bw.Mask[3] != 0x00 {
		t.Fatalf("/24 的掩码应为 ffffff00，实际 %x", bw.Mask)
	}
}

// TestCidrMaskV4 掩码生成必须正确（非整字节边界是经典错误来源）。
func TestCidrMaskV4(t *testing.T) {
	cases := []struct {
		bits int
		want []byte
	}{
		{0, []byte{0, 0, 0, 0}},
		{8, []byte{0xff, 0, 0, 0}},
		{12, []byte{0xff, 0xf0, 0, 0}},
		{24, []byte{0xff, 0xff, 0xff, 0}},
		{26, []byte{0xff, 0xff, 0xff, 0xc0}},
		{32, []byte{0xff, 0xff, 0xff, 0xff}},
	}
	for _, c := range cases {
		got := cidrMaskV4(c.bits)
		if len(got) != 4 {
			t.Fatalf("/%d 掩码长度应为 4，实际 %d", c.bits, len(got))
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("/%d 掩码错误: %x，期望 %x", c.bits, got, c.want)
			}
		}
	}
}

func TestCidrMaskV6(t *testing.T) {
	if got := cidrMaskV6(0); len(got) != 16 || got[0] != 0 {
		t.Fatalf("/0 应为全零 16 字节，实际 %x", got)
	}
	if got := cidrMaskV6(128); len(got) != 16 || got[15] != 0xff {
		t.Fatalf("/128 应为全一 16 字节，实际 %x", got)
	}
	got := cidrMaskV6(64)
	if got[7] != 0xff || got[8] != 0x00 {
		t.Fatalf("/64 应前 8 字节全一、后 8 字节全零，实际 %x", got)
	}
}

// TestTranslateMSS MSS 必须先生成 SYN 匹配，再生成 maxseg 写入。
func TestTranslateMSS(t *testing.T) {
	out, err := translateMSS(compile.Rule{MSSValue: 1360, MSSFamily: "ipv4"})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	if len(out) < 5 {
		t.Fatalf("MSS 表达式至少 5 条（SYN匹配 3 + exthdr 2），实际 %d", len(out))
	}
	// 第 0 条：读 TCP flags
	pl, ok := out[0].(*expr.Payload)
	if !ok || pl.Offset != 13 {
		t.Fatalf("首条应为 Payload 读 TCP flags（偏移 13），实际 %+v", out[0])
	}
	// 必须含 Exthdr
	var hasExthdr bool
	for _, e := range out {
		if _, ok := e.(*expr.Exthdr); ok {
			hasExthdr = true
		}
	}
	if !hasExthdr {
		t.Fatal("MSS 必须用 Exthdr 写 maxseg 选项")
	}
}

// TestTranslateMSSZeroValue MSS 值为 0 必须报错。
func TestTranslateMSSZeroValue(t *testing.T) {
	if _, err := translateMSS(compile.Rule{}); err == nil {
		t.Fatal("MSS 值为 0 应报错")
	}
}

// TestTranslatePlanRoutesDNATToTwoChains DNAT 段的判定行与改写行必须分到
// pre / dnat 两个不同工作链。
func TestTranslatePlanRoutesDNATToTwoChains(t *testing.T) {
	p, err := (&compile.Compiler{Caps: compile.Caps{TcNetlink: true}}).Compile(compile.State{
		Version: 1,
		Rules:   []modelRule{mkModelRule()},
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	set, _, err := TranslatePlan(p)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	// pre 链应含 2 条：① 回程放行（established）② DNAT 判定行
	// dnat 链应含 1 条：DNAT 改写行
	//
	// 为什么回程放行在 pre：它必须在默认拒绝之前给已建连接打 FWD_OK，
	// 否则配置重载瞬间存量连接会被自己的默认拒绝误杀。
	if len(set[WorkPre]) != 2 {
		t.Fatalf("pre 链应 2 条（回程放行 + DNAT 判定），实际 %d", len(set[WorkPre]))
	}
	if len(set[WorkDnat]) != 1 {
		t.Fatalf("dnat 链应 1 条（DNAT 改写），实际 %d", len(set[WorkDnat]))
	}
	// 改写行（含 NAT 表达式）不能出现在 pre 链
	for _, exprs := range set[WorkPre] {
		for _, e := range exprs {
			if _, ok := e.(*expr.NAT); ok {
				t.Fatal("NAT 表达式不应出现在 pre 链（地址改写必须在 dnat 链）")
			}
		}
	}
}

// TestTranslatePlanMSSGoesToFixed MSS 必须进固定链，不进版本化工作链。
func TestTranslatePlanMSSGoesToFixed(t *testing.T) {
	p, err := (&compile.Compiler{Caps: compile.Caps{TcNetlink: true}}).Compile(compile.State{
		Version: 1, MSSv4: compile.DefaultMSSv4, MSSv6: compile.DefaultMSSv6,
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	set, fixed, err := TranslatePlan(p)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	if len(fixed[ChainMSS]) != 2 {
		t.Fatalf("固定链 mss 应有 2 条，实际 %d", len(fixed[ChainMSS]))
	}
	for _, work := range workChains {
		for _, exprs := range set[work] {
			for _, e := range exprs {
				if _, ok := e.(*expr.Exthdr); ok {
					t.Fatalf("MSS 表达式不应出现在工作链 %s 里", work)
				}
			}
		}
	}
}

// TestApplyFixed 固定链装载必须幂等（重复装载不累积）。
func TestApplyFixed(t *testing.T) {
	e := newTestEngine(t)
	fixed := map[string][][]expr.Any{
		ChainMSS: {
			{&expr.Counter{}},
			{&expr.Counter{}},
		},
	}
	if err := e.ApplyFixed(fixed); err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	n1, _ := e.ChainRuleCount(ChainMSS)
	if n1 != 2 {
		t.Fatalf("首次装载应有 2 条，实际 %d", n1)
	}
	// 重复装载不应累积
	if err := e.ApplyFixed(fixed); err != nil {
		t.Fatalf("二次装载失败: %v", err)
	}
	n2, _ := e.ChainRuleCount(ChainMSS)
	if n2 != 2 {
		t.Fatalf("重复装载后应仍为 2 条（幂等），实际 %d", n2)
	}
}

// TestApplyFixedNotReady 未初始化时返回 ErrNotReady。
func TestApplyFixedNotReady(t *testing.T) {
	e := &Engine{}
	if err := e.ApplyFixed(nil); err == nil {
		t.Fatal("未初始化应报错")
	}
}

// TestTranslateUnknownVerdict 未知 verdict 必须报错。
func TestTranslateUnknownVerdict(t *testing.T) {
	if _, err := translateRule(compile.Rule{Comment: "t", Verdict: "reject"}); err == nil {
		t.Fatal("未知 verdict 应报错")
	}
}

// TestTranslateUnknownProto 未知协议必须报错。
func TestTranslateUnknownProto(t *testing.T) {
	if _, err := translateRule(compile.Rule{Comment: "t", Proto: "sctp"}); err == nil {
		t.Fatal("未知协议应报错")
	}
}

// TestTranslateIcmpRule ICMP 豁免必须：① 先匹配 L4 协议 ② 用传输头基址读 type
// ③ 多类型用单条 Cmp + 多字节 Data。
//
// 真机 `nft -j` 输出：
//
//	{"payload": {"protocol": "icmp", "field": "type"}}  → Base=TransportHeader, Offset=0
//	{"right": {"set": ["destination-unreachable", "time-exceeded"]}}
func TestTranslateIcmpRule(t *testing.T) {
	out, err := translateIcmpRule(compile.Rule{
		Comment:    "haweb:deny:icmp:ipv4",
		IcmpFamily: "ipv4",
		IcmpTypes:  []uint8{3, 11},
		Verdict:    "accept",
	})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	// ① 协议匹配（Meta l4proto == 1）
	meta, ok := out[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyL4PROTO {
		t.Fatalf("首条应为 Meta{l4proto}，实际 %+v", out[0])
	}
	cmp, ok := out[1].(*expr.Cmp)
	if !ok || len(cmp.Data) != 1 || cmp.Data[0] != 1 { // IPPROTO_ICMP = 1
		t.Fatalf("第二条应为 Cmp{proto==1}，实际 %+v", out[1])
	}
	// ② type 用传输头基址 + 偏移 0
	pl, ok := out[2].(*expr.Payload)
	if !ok {
		t.Fatalf("第三条应为 Payload，实际 %+v", out[2])
	}
	if pl.Base != expr.PayloadBaseTransportHeader {
		t.Fatalf("★ ICMP type 必须用 TransportHeader 基址（不是 NetworkHeader），实际 %v", pl.Base)
	}
	if pl.Offset != 0 || pl.Len != 1 {
		t.Fatalf("type 偏移应为 0、长度 1，实际 offset=%d len=%d", pl.Offset, pl.Len)
	}
	// ③ 多类型集合比较
	cmp2, ok := out[3].(*expr.Cmp)
	if !ok {
		t.Fatalf("第四条应为 Cmp，实际 %+v", out[3])
	}
	if len(cmp2.Data) != 2 || cmp2.Data[0] != 3 || cmp2.Data[1] != 11 {
		t.Fatalf("类型集合应为 [3, 11]，实际 %v", cmp2.Data)
	}
	// ④ verdict
	if _, ok := out[4].(*expr.Verdict); !ok {
		t.Fatalf("最后一条应为 Verdict，实际 %+v", out[4])
	}
}

// TestTranslateIcmpV6 ICMPv6 用协议号 58。
func TestTranslateIcmpV6(t *testing.T) {
	out, err := translateIcmpRule(compile.Rule{
		Comment:    "haweb:deny:icmp:ipv6",
		IcmpFamily: "ipv6",
		IcmpTypes:  []uint8{1, 2, 3},
		Verdict:    "accept",
	})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	cmp := out[1].(*expr.Cmp)
	if cmp.Data[0] != 58 { // IPPROTO_ICMPV6 = 58
		t.Fatalf("ICMPv6 协议号应为 58，实际 %d", cmp.Data[0])
	}
	cmp2 := out[3].(*expr.Cmp)
	if len(cmp2.Data) != 3 {
		t.Fatalf("应有 3 个类型，实际 %d", len(cmp2.Data))
	}
}

// TestTranslateIcmpSingleType 单类型也要正确。
func TestTranslateIcmpSingleType(t *testing.T) {
	out, err := translateIcmpRule(compile.Rule{
		Comment: "t", IcmpFamily: "ipv4", IcmpTypes: []uint8{3}, Verdict: "accept",
	})
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	cmp := out[3].(*expr.Cmp)
	if len(cmp.Data) != 1 || cmp.Data[0] != 3 {
		t.Fatalf("单类型应为 [3]，实际 %v", cmp.Data)
	}
}

// TestTranslateIcmpErrors ICMP 规则的错误分支。
func TestTranslateIcmpErrors(t *testing.T) {
	if _, err := translateIcmpRule(compile.Rule{Comment: "t", IcmpFamily: "ipv4"}); err == nil {
		t.Fatal("空类型集合应报错")
	}
	if _, err := translateIcmpRule(compile.Rule{
		Comment: "t", IcmpFamily: "ipx", IcmpTypes: []uint8{1},
	}); err == nil {
		t.Fatal("非法地址族应报错")
	}
	if _, err := translateIcmpRule(compile.Rule{
		Comment: "t", IcmpFamily: "ipv4", IcmpTypes: []uint8{3}, Verdict: "reject",
	}); err == nil {
		t.Fatal("未知 verdict 应报错")
	}
}

// TestTranslatePlanIcmpGoesToFwd ICMP 豁免必须落在 fwd 工作链，且在 drop 之前。
func TestTranslatePlanIcmpGoesToFwd(t *testing.T) {
	c := &compile.Compiler{Caps: compile.Caps{TcNetlink: true}}
	p, err := c.Compile(compile.State{
		Version:   1,
		DenyScope: model.ScopeDnatTarget,
		Rules: []model.Rule{{
			ID:       1,
			Name:     "t",
			Proto:    model.ProtoTCP,
			ListenAt: netip.MustParseAddrPort("192.168.10.170:1022"),
			Backend:  netip.MustParseAddrPort("192.168.10.152:22"),
			Enabled:  true,
		}},
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	set, _, err := TranslatePlan(p)
	if err != nil {
		t.Fatalf("翻译失败: %v", err)
	}
	fwd := set[WorkFwd]
	if len(fwd) == 0 {
		t.Fatal("fwd 链应有规则")
	}
	// 必须含 ICMP 的 proto 匹配（Meta l4proto）
	var icmpCnt, dropCnt int
	for _, exprs := range fwd {
		for _, e := range exprs {
			if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyL4PROTO {
				icmpCnt++
			}
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
				dropCnt++
			}
		}
	}
	if icmpCnt < 2 {
		t.Fatalf("应有 IPv4 + IPv6 两条 ICMP 豁免（各含 l4proto 匹配），实际 %d", icmpCnt)
	}
	if dropCnt != 1 {
		t.Fatalf("应有恰好 1 条 drop（默认拒绝行），实际 %d", dropCnt)
	}
	// ICMP 豁免必须在 drop 之前
	firstDrop := -1
	icmpBefore := 0
	for i, exprs := range fwd {
		isDrop := false
		for _, e := range exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
				isDrop = true
			}
		}
		if isDrop && firstDrop < 0 {
			firstDrop = i
		}
		if !isDrop {
			for _, e := range exprs {
				if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyL4PROTO {
					if firstDrop < 0 {
						icmpBefore++
					}
				}
			}
		}
	}
	if icmpBefore < 2 {
		t.Fatalf("ICMP 豁免必须排在 drop 之前（否则差错报文先被 drop），"+
			"实际 drop 前只有 %d 条", icmpBefore)
	}
}
