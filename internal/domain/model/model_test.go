package model

import (
	"net/netip"
	"testing"
)

func TestProtoValid(t *testing.T) {
	for _, p := range []Proto{ProtoTCP, ProtoUDP} {
		if !p.Valid() {
			t.Fatalf("%q 应有效", p)
		}
	}
	for _, p := range []Proto{"", "icmp", "TCP"} {
		if p.Valid() {
			t.Fatalf("%q 应无效", p)
		}
	}
}

func TestPolicyActionSemantics(t *testing.T) {
	// 三档语义：接受的是「打标不终结」，allow/drop 终结
	cases := []struct {
		a          PolicyAction
		valid      bool
		terminates bool
	}{
		{ActionAccept, true, false},
		{ActionAllow, true, true},
		{ActionDrop, true, true},
		{"permit", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		if got := c.a.Valid(); got != c.valid {
			t.Fatalf("%q.Valid() = %v，期望 %v", c.a, got, c.valid)
		}
		if got := c.a.Terminates(); got != c.terminates {
			t.Fatalf("%q.Terminates() = %v，期望 %v（D-14 语义）", c.a, got, c.terminates)
		}
	}
}

func TestDenyScopeValid(t *testing.T) {
	for _, s := range []DenyScope{ScopeOff, ScopeDnatTarget, ScopeInterface} {
		if !s.Valid() {
			t.Fatalf("%q 应有效", s)
		}
	}
	if DenyScope("all").Valid() {
		t.Fatal("\"all\" 应无效")
	}
	// 默认档必须是 dnat_target —— 用 interface 会误杀同机 Docker/K8s（D-13）
	if ScopeDnatTarget != "dnat_target" {
		t.Fatalf("默认拒绝作用域的默认档应为 dnat_target，实际 %q", ScopeDnatTarget)
	}
}

func TestAclGroupMatchesMode(t *testing.T) {
	// 中性 ip 组两种模式都能用；whitelist/blacklist 组只能配对应模式
	cases := []struct {
		kind AclGroupKind
		mode ACLMode
		want bool
	}{
		{GroupIP, ACLWhitelist, true},
		{GroupIP, ACLBlacklist, true},
		{GroupWhitelist, ACLWhitelist, true},
		{GroupWhitelist, ACLBlacklist, false},
		{GroupBlacklist, ACLBlacklist, true},
		{GroupBlacklist, ACLWhitelist, false},
		{GroupIP, ACLOff, false},
	}
	for _, c := range cases {
		if got := AclGroupMatchesMode(c.kind, c.mode); got != c.want {
			t.Fatalf("AclGroupMatchesMode(%q, %q) = %v，期望 %v", c.kind, c.mode, got, c.want)
		}
	}
}

func TestACLModeValidate(t *testing.T) {
	if err := ACLWhitelist.Validate(GroupBlacklist); err == nil {
		t.Fatal("白名单模式配黑名单组应报错")
	}
	if err := ACLWhitelist.Validate(GroupIP); err != nil {
		t.Fatalf("白名单模式配中性组应通过，实际: %v", err)
	}
	if err := ACLOff.Validate(""); err != nil {
		t.Fatalf("off 模式不应校验组类型，实际: %v", err)
	}
	// 错误消息必须是中文（C-05）
	err := ACLMode("bogus").Validate(GroupIP)
	if err == nil {
		t.Fatal("无效模式应报错")
	}
}

func TestCtKeyRoundTrip(t *testing.T) {
	k := CtKey{
		SrcAddr: netip.MustParseAddr("192.168.10.152"),
		DstAddr: netip.MustParseAddr("172.16.30.10"),
		SrcPort: 51234,
		DstPort: 9098,
		Proto:   ProtoTCP,
	}
	s := k.String()
	got, err := ParseCtKey(s)
	if err != nil {
		t.Fatalf("解析 %q 失败: %v", s, err)
	}
	if got != k {
		t.Fatalf("往返不一致：%+v vs %+v", got, k)
	}
}

func TestCtKeyParseErrors(t *testing.T) {
	bad := []string{
		"",
		"tcp 192.168.1.1 -> 10.0.0.1:80",       // 格式不完整
		"icmp 192.168.1.1:1 -> 10.0.0.1:80",    // 协议非法
		"tcp 192.168.1.1:99999 -> 10.0.0.1:80", // 端口越界
		"tcp nope:1 -> 10.0.0.1:80",            // 地址非法
	}
	for _, s := range bad {
		if _, err := ParseCtKey(s); err == nil {
			t.Fatalf("解析 %q 应报错", s)
		}
	}
}

func TestCtKeyValidateAddrFamily(t *testing.T) {
	k := CtKey{
		SrcAddr: netip.MustParseAddr("192.168.1.1"),
		DstAddr: netip.MustParseAddr("2001:db8::1"),
		SrcPort: 1, DstPort: 2, Proto: ProtoTCP,
	}
	if err := k.Validate(); err == nil {
		t.Fatal("混合地址族应报错")
	}
}

func rule() Rule {
	return Rule{
		ID:       1,
		Name:     "t1",
		Proto:    ProtoTCP,
		ListenAt: netip.MustParseAddrPort("192.168.10.170:1022"),
		Backend:  netip.MustParseAddrPort("192.168.10.152:22"),
		Enabled:  true,
	}
}

func TestRuleValidateOK(t *testing.T) {
	if err := rule().Validate(); err != nil {
		t.Fatalf("合法规则应通过，实际: %v", err)
	}
}

func TestRuleValidateErrors(t *testing.T) {
	base := rule()

	t.Run("协议无效", func(t *testing.T) {
		r := base
		r.Proto = "sctp"
		if err := r.Validate(); err == nil {
			t.Fatal("应报错")
		}
	})
	t.Run("监听端口为0", func(t *testing.T) {
		r := base
		r.ListenAt = netip.MustParseAddrPort("192.168.10.170:0")
		if err := r.Validate(); err == nil {
			t.Fatal("应报错")
		}
	})
	t.Run("后端端口为0", func(t *testing.T) {
		r := base
		r.Backend = netip.MustParseAddrPort("192.168.10.152:0")
		if err := r.Validate(); err == nil {
			t.Fatal("应报错")
		}
	})
	t.Run("地址族不一致", func(t *testing.T) {
		r := base
		r.Backend = netip.MustParseAddrPort("[2001:db8::1]:22")
		if err := r.Validate(); err == nil {
			t.Fatal("应报错")
		}
	})
	t.Run("白名单为空但配了网段", func(t *testing.T) {
		r := base
		r.ACLMode = ACLOff
		r.ACL = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
		if err := r.Validate(); err == nil {
			t.Fatal("应报错")
		}
	})
	t.Run("白名单模式但无网段", func(t *testing.T) {
		r := base
		r.ACLMode = ACLWhitelist
		if err := r.Validate(); err == nil {
			t.Fatal("应报错（会匹配不到任何流量）")
		}
	})
	t.Run("网段未归零", func(t *testing.T) {
		r := base
		r.ACLMode = ACLWhitelist
		r.ACL = []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")}
		if err := r.Validate(); err == nil {
			t.Fatal("应报错（网络地址未归零）")
		}
	})
	t.Run("连接数为负", func(t *testing.T) {
		r := base
		r.MaxConns = -1
		if err := r.Validate(); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestRuleImmutability(t *testing.T) {
	r := rule()
	nb := netip.MustParseAddrPort("192.168.10.153:22")
	r2 := r.WithBackend(nb)
	if r.Backend == nb {
		t.Fatal("WithBackend 不应修改原值（不可变语义）")
	}
	if r2.Backend != nb {
		t.Fatalf("副本后端应为 %s，实际 %s", nb, r2.Backend)
	}

	r3 := r.WithEnabled(false)
	if !r.Enabled {
		t.Fatal("WithEnabled 不应修改原值")
	}
	if r3.Enabled {
		t.Fatal("副本应为禁用")
	}
}

func TestRuleSameTarget(t *testing.T) {
	r := rule()
	if !r.SameTarget(r) {
		t.Fatal("同一规则应判定为 SameTarget")
	}
	if r.SameTarget(r.WithEnabled(false)) {
		t.Fatal("启停状态不同不应 SameTarget")
	}
	if r.SameTarget(r.WithBackend(netip.MustParseAddrPort("10.0.0.1:22"))) {
		t.Fatal("后端不同不应 SameTarget")
	}
}

func TestRuleListenerKey(t *testing.T) {
	k := rule().ListenerKey()
	if k.Port != 1022 || k.Proto != ProtoTCP || k.Addr.String() != "192.168.10.170" {
		t.Fatalf("监听端点键错误: %+v", k)
	}
}

func TestNewPoolDedupe(t *testing.T) {
	p, err := NewPool([]netip.Addr{
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("203.0.113.1"), // 重复
		netip.MustParseAddr("203.0.113.2"),
	})
	if err != nil {
		t.Fatalf("重复成员应去重而非报错，实际: %v", err)
	}
	if p.Len() != 2 {
		t.Fatalf("去重后应为 2 个成员，实际 %d", p.Len())
	}
}

func TestNewPoolFamilyMismatch(t *testing.T) {
	if _, err := NewPool([]netip.Addr{
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("2001:db8::1"),
	}); err == nil {
		t.Fatal("混合地址族应报错")
	}
}

func TestPoolImmutability(t *testing.T) {
	p, err := NewPool([]netip.Addr{netip.MustParseAddr("203.0.113.1")})
	if err != nil {
		t.Fatal(err)
	}
	got := p.Members()
	got[0] = netip.MustParseAddr("1.1.1.1") // 试图篡改
	if p.Members()[0].String() != "203.0.113.1" {
		t.Fatal("Members() 必须返回副本（不可变语义被破坏）")
	}
}

func TestPoolEmpty(t *testing.T) {
	p, err := NewPool(nil)
	if err != nil {
		t.Fatalf("空池应合法: %v", err)
	}
	if !p.IsEmpty() || p.Len() != 0 {
		t.Fatal("空池判定错误")
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("空池校验应通过: %v", err)
	}
	if got := p.String(); got != "(空池)" {
		t.Fatalf("空池 String 应为 \"(空池)\"，实际 %q", got)
	}
}

func TestBWGroupValidate(t *testing.T) {
	if err := (BWGroup{TotalKBps: 8192, MinKBps: 1024}).Validate(); err != nil {
		t.Fatalf("合法带宽包应通过: %v", err)
	}
	if err := (BWGroup{TotalKBps: 0}).Validate(); err == nil {
		t.Fatal("总额为 0 应报错")
	}
	if err := (BWGroup{TotalKBps: 100, MinKBps: 200}).Validate(); err == nil {
		t.Fatal("保底大于总额应报错")
	}
}

func TestBWGroupEffectiveMin(t *testing.T) {
	g := BWGroup{TotalKBps: 8192}
	if got := g.EffectiveMinKBps(1024); got != 1024 {
		t.Fatalf("未配置保底应取默认值，实际 %d", got)
	}
	g.MinKBps = 512
	if got := g.EffectiveMinKBps(1024); got != 512 {
		t.Fatalf("已配置保底应取配置值，实际 %d", got)
	}
}

func TestPolicyMatchesPort(t *testing.T) {
	p := Policy{Proto: ProtoTCP, Port: 443}
	if !p.MatchesPort(ProtoTCP, 443) {
		t.Fatal("应匹配同协议同端口")
	}
	if p.MatchesPort(ProtoUDP, 443) {
		t.Fatal("不应匹配不同协议")
	}
	if p.MatchesPort(ProtoTCP, 80) {
		t.Fatal("不应匹配不同端口")
	}
	wild := Policy{Port: 0}
	if !wild.MatchesPort(ProtoUDP, 12345) {
		t.Fatal("Port=0 应匹配所有端口")
	}
}

func TestPolicyValidate(t *testing.T) {
	if err := (Policy{Action: ActionDrop, Order: 1}).Validate(); err != nil {
		t.Fatalf("合法策略应通过: %v", err)
	}
	if err := (Policy{Action: "permit", Order: 1}).Validate(); err == nil {
		t.Fatal("非法动作应报错")
	}
	if err := (Policy{Action: ActionDrop, Order: -1}).Validate(); err == nil {
		t.Fatal("负优先级应报错")
	}
}

func TestEgressValidate(t *testing.T) {
	if err := (Egress{IfName: "eth0"}).Validate(); err != nil {
		t.Fatalf("合法出口应通过: %v", err)
	}
	if err := (Egress{IfName: "  "}).Validate(); err == nil {
		t.Fatal("空网卡名应报错")
	}
	if err := (Egress{
		IfName:   "eth0",
		Gateway:  netip.MustParseAddr("192.168.10.1"),
		SourceIP: netip.MustParseAddr("2001:db8::1"),
	}).Validate(); err == nil {
		t.Fatal("地址族不一致应报错")
	}
}

func TestAclGroupValidate(t *testing.T) {
	if err := (AclGroup{Kind: GroupWhitelist, CIDRs: []netip.Prefix{
		netip.MustParsePrefix("192.168.10.0/24"),
	}}).Validate(); err != nil {
		t.Fatalf("合法名单组应通过: %v", err)
	}
	if err := (AclGroup{Kind: "bogus"}).Validate(); err == nil {
		t.Fatal("非法类型应报错")
	}
	if err := (AclGroup{Kind: GroupIP, CIDRs: []netip.Prefix{
		netip.MustParsePrefix("10.1.2.3/8"),
	}}).Validate(); err == nil {
		t.Fatal("未归零网段应报错")
	}
}

// TestACLModeEmptyStringCompat 零值 ACLMode（空串）必须按 off 处理。
//
// 回归：AGENTS.md「空模式是旧数据兼容语义」——历史规则的 acl_mode 字段
// 就是空串，若判为非法，所有旧规则都会校验不过。
func TestACLModeEmptyStringCompat(t *testing.T) {
	r := rule()
	r.ACLMode = "" // 零值
	if err := r.Validate(); err != nil {
		t.Fatalf("零值 ACLMode 应按 off 处理，实际报错: %v", err)
	}
	r.DstACLMode = ""
	if err := r.Validate(); err != nil {
		t.Fatalf("零值 DstACLMode 应按 off 处理，实际报错: %v", err)
	}
}

func TestPoolValidateErrors(t *testing.T) {
	// 构造一个非法 Pool（绕过 NewPool 走零值路径）
	var p Pool
	if err := p.Validate(); err != nil {
		t.Fatalf("零值池应通过校验: %v", err)
	}
	if p.Members() != nil {
		t.Fatal("空池 Members() 应返回 nil")
	}
}

func TestPoolStringNonEmpty(t *testing.T) {
	p, err := NewPool([]netip.Addr{
		netip.MustParseAddr("203.0.113.1"),
		netip.MustParseAddr("203.0.113.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.String(); got != "203.0.113.1,203.0.113.2" {
		t.Fatalf("多成员池 String 错误: %q", got)
	}
}

func TestNewPoolInvalidAddr(t *testing.T) {
	if _, err := NewPool([]netip.Addr{{}}); err == nil {
		t.Fatal("无效地址应报错")
	}
}

func TestCtKeyValidateBadProto(t *testing.T) {
	k := CtKey{
		SrcAddr: netip.MustParseAddr("10.0.0.1"),
		DstAddr: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 1, DstPort: 2,
		Proto: "",
	}
	if err := k.Validate(); err == nil {
		t.Fatal("空协议应报错")
	}
}

func TestCtKeyValidateBadAddrs(t *testing.T) {
	base := CtKey{
		SrcAddr: netip.MustParseAddr("10.0.0.1"),
		DstAddr: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 1, DstPort: 2, Proto: ProtoTCP,
	}
	k := base
	k.SrcAddr = netip.Addr{}
	if err := k.Validate(); err == nil {
		t.Fatal("无效源地址应报错")
	}
	k = base
	k.DstAddr = netip.Addr{}
	if err := k.Validate(); err == nil {
		t.Fatal("无效目的地址应报错")
	}
}

func TestAclGroupMatchesModeOff(t *testing.T) {
	// 任何组类型配 off 模式都不匹配（off 表示不用名单）
	for _, k := range []AclGroupKind{GroupIP, GroupWhitelist, GroupBlacklist} {
		if AclGroupMatchesMode(k, ACLOff) {
			t.Fatalf("%q 不应匹配 off 模式", k)
		}
	}
}

func TestACLModeValidateBadGroupKind(t *testing.T) {
	if err := ACLWhitelist.Validate("bogus"); err == nil {
		t.Fatal("非法组类型应报错")
	}
}

func TestPolicyValidateBadProto(t *testing.T) {
	if err := (Policy{Action: ActionDrop, Proto: "sctp"}).Validate(); err == nil {
		t.Fatal("非法协议应报错")
	}
}

func TestPolicyValidateBadSources(t *testing.T) {
	if err := (Policy{Action: ActionDrop, Sources: []netip.Prefix{{}}}).Validate(); err == nil {
		t.Fatal("无效源网段应报错")
	}
	if err := (Policy{Action: ActionDrop, Sources: []netip.Prefix{
		netip.MustParsePrefix("10.1.2.3/8"),
	}}).Validate(); err == nil {
		t.Fatal("未归零源网段应报错")
	}
}
