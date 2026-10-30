package ctnl

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// mkNLA 构造一个 NLA（供构造测试用消息）。
func mkNLA(typ uint16, payload []byte) []byte {
	return appendNLA(nil, typ, payload)
}

// v4 返回 4 字节网络序地址。
func v4(s string) []byte {
	a := netip.MustParseAddr(s).As4()
	return a[:]
}

// v6 返回 16 字节地址。
func v6(s string) []byte {
	a := netip.MustParseAddr(s).As16()
	return a[:]
}

// buildTuple 构造一个 CTA_TUPLE_* 的 payload。
func buildTuple(src, dst string, proto uint8, sport, dport uint16) []byte {
	ip := mkNLA(CTATupleIPV4Src, v4(src))
	ip = append(ip, mkNLA(CTATupleIPV4Dst, v4(dst))...)
	pr := mkNLA(CTATupleProtoNum, []byte{proto})
	sp := make([]byte, 2)
	binary.BigEndian.PutUint16(sp, sport)
	pr = append(pr, mkNLA(CTATupleProtoSrcPort, sp)...)
	dp := make([]byte, 2)
	binary.BigEndian.PutUint16(dp, dport)
	pr = append(pr, mkNLA(CTATupleProtoDstPort, dp)...)

	out := mkNLA(CTATupleIP, ip)
	out = append(out, mkNLA(CTATupleProto, pr)...)
	return out
}

// buildFlowMsg 构造一条完整的 conntrack 消息体（nfgenmsg + attrs）。
func buildFlowMsg(src, dst string, proto uint8, sport, dport uint16, status uint32) []byte {
	body := []byte{0, NFNetlinkV0, 0, 0} // nfgenmsg
	body = append(body, mkNLA(CTAATupleOrig, buildTuple(src, dst, proto, sport, dport))...)
	st := make([]byte, 4)
	binary.BigEndian.PutUint32(st, status)
	body = append(body, mkNLA(CTAAStatus, st)...)
	// counters
	cnt := mkNLA(CTAACountersPackets, func() []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, 1234)
		return b
	}())
	cnt = append(cnt, mkNLA(CTAACountersBytes, func() []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, 5678)
		return b
	}())...)
	body = append(body, mkNLA(CTAACounters, cnt)...)
	return body
}

// TestParseFlowBasic 基本解析：五元组 + 状态 + 计数。
func TestParseFlowBasic(t *testing.T) {
	msg := buildFlowMsg("192.168.10.152", "172.16.30.10", 6, 51234, 9098, IPSSeenReply|IPSAssured)
	f, err := ParseFlow(msg)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if f.Orig.SrcAddr.String() != "192.168.10.152" {
		t.Fatalf("源地址错误: %s", f.Orig.SrcAddr)
	}
	if f.Orig.DstAddr.String() != "172.16.30.10" {
		t.Fatalf("目的地址错误: %s", f.Orig.DstAddr)
	}
	if f.Orig.SrcPort != 51234 || f.Orig.DstPort != 9098 {
		t.Fatalf("端口错误: %d -> %d", f.Orig.SrcPort, f.Orig.DstPort)
	}
	if f.Orig.Proto != 6 {
		t.Fatalf("协议应为 6(tcp)，实际 %d", f.Orig.Proto)
	}
	if !f.IsEstablished() {
		t.Fatal("应识别为 established（IPS_SEEN_REPLY）")
	}
	if !f.IsAssured() {
		t.Fatal("应识别为 assured")
	}
	if f.IsNatted() {
		t.Fatal("无 NAT 位时不应判定为 NAT")
	}
	if f.Packets != 1234 || f.Bytes != 5678 {
		t.Fatalf("计数错误: packets=%d bytes=%d", f.Packets, f.Bytes)
	}
}

// TestParseFlowNatted NAT 位识别。
func TestParseFlowNatted(t *testing.T) {
	msg := buildFlowMsg("10.0.0.1", "10.0.0.2", 6, 1, 2, IPSSrcNAT)
	f, err := ParseFlow(msg)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !f.IsNatted() {
		t.Fatal("IPS_SRC_NAT 应判定为 NAT")
	}
}

// TestParseFlowIPv6 IPv6 五元组解析。
func TestParseFlowIPv6(t *testing.T) {
	ip := mkNLA(CTATupleIPV6Src, v6("2001:db8::1"))
	ip = append(ip, mkNLA(CTATupleIPV6Dst, v6("2001:db8::2"))...)
	pr := mkNLA(CTATupleProtoNum, []byte{17})
	tuple := mkNLA(CTATupleIP, ip)
	tuple = append(tuple, mkNLA(CTATupleProto, pr)...)

	body := []byte{10, NFNetlinkV0, 0, 0}
	body = append(body, mkNLA(CTAATupleOrig, tuple)...)
	f, err := ParseFlow(body)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if f.Orig.SrcAddr.String() != "2001:db8::1" {
		t.Fatalf("IPv6 源地址错误: %s", f.Orig.SrcAddr)
	}
	if f.Orig.Proto != 17 {
		t.Fatalf("协议应为 17(udp)，实际 %d", f.Orig.Proto)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("合法 IPv6 会话应通过校验: %v", err)
	}
}

// TestParseFlowTooShort 消息太短必须报错。
func TestParseFlowTooShort(t *testing.T) {
	if _, err := ParseFlow([]byte{0, 0}); err == nil {
		t.Fatal("长度不足 nfgenmsg 应报错")
	}
}

// TestParseAttrsMalformed 损坏的属性（len<4 或超界）必须报错而不是死循环。
func TestParseAttrsMalformed(t *testing.T) {
	// len = 0
	if _, err := parseAttrs([]byte{0, 0, 0, 0}); err == nil {
		t.Fatal("len=0 必须报错（否则死循环）")
	}
	// len = 2（< 4）
	if _, err := parseAttrs([]byte{2, 0, 0, 0}); err == nil {
		t.Fatal("len<4 必须报错")
	}
	// 声明长度超界
	if _, err := parseAttrs([]byte{100, 0, 1, 0, 1, 2}); err == nil {
		t.Fatal("长度超界必须报错")
	}
}

// TestParseAttrsAlignment 属性按 4 字节对齐推进。
func TestParseAttrsAlignment(t *testing.T) {
	// 一个 5 字节 payload 的属性（4 头 + 5 = 9 → 对齐到 12）
	buf := mkNLA(1, []byte{1, 2, 3, 4, 5})
	buf = append(buf, mkNLA(2, []byte{9, 9})...)
	attrs, err := parseAttrs(buf)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(attrs) != 2 {
		t.Fatalf("应有 2 个属性，实际 %d", len(attrs))
	}
	if attrs[0].typ != 1 || len(attrs[0].value) != 5 {
		t.Fatalf("第一个属性错误: typ=%d len=%d", attrs[0].typ, len(attrs[0].value))
	}
	if attrs[1].typ != 2 || attrs[1].value[0] != 9 {
		t.Fatalf("第二个属性错误: %+v", attrs[1])
	}
}

// TestParseAttrsNestedFlag nested 标志必须被剥掉。
func TestParseAttrsNestedFlag(t *testing.T) {
	buf := appendNLA(nil, CTATupleIP|NLAFNested, []byte{1, 2, 3, 4})
	attrs, err := parseAttrs(buf)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(attrs) != 1 {
		t.Fatalf("应有 1 个属性，实际 %d", len(attrs))
	}
	if attrs[0].typ != CTATupleIP {
		t.Fatalf("nested 标志应被剥掉，实际 typ=0x%x", attrs[0].typ)
	}
}

// TestFlowValidate 校验：缺地址/缺协议/固定模板与期望连接必须被拒。
func TestFlowValidate(t *testing.T) {
	good := Flow{
		Orig: Tuple{
			SrcAddr: netip.MustParseAddr("10.0.0.1"),
			DstAddr: netip.MustParseAddr("10.0.0.2"),
			Proto:   6,
		},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("合法会话应通过: %v", err)
	}

	// 缺源地址
	bad := good
	bad.Orig.SrcAddr = netip.Addr{}
	if err := bad.Validate(); err == nil {
		t.Fatal("缺源地址应报错")
	}
	// 缺协议
	bad = good
	bad.Orig.Proto = 0
	if err := bad.Validate(); err == nil {
		t.Fatal("缺协议应报错")
	}
	// 地址族不一致
	bad = good
	bad.Orig.DstAddr = netip.MustParseAddr("2001:db8::1")
	if err := bad.Validate(); err == nil {
		t.Fatal("地址族不一致应报错")
	}
	// 模板
	bad = good
	bad.Status = IPSTemplate
	if err := bad.Validate(); err == nil {
		t.Fatal("IPS_TEMPLATE 应被拒")
	}
	// 期望连接
	bad = good
	bad.Status = IPSExpected
	if err := bad.Validate(); err == nil {
		t.Fatal("IPS_EXPECTED 应被拒")
	}
}

// TestBuildDeleteRequestRoundTrip 构造的删除请求必须能被自己的解析器读回
// （验证 NLA 编码的对称性）。
func TestBuildDeleteRequestRoundTrip(t *testing.T) {
	tuple := Tuple{
		SrcAddr: netip.MustParseAddr("192.168.10.152"),
		DstAddr: netip.MustParseAddr("172.16.30.10"),
		SrcPort: 51234,
		DstPort: 9098,
		Proto:   6,
	}
	body, err := BuildDeleteRequest(tuple, Tuple{}, 0, 100, 0)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if len(body) < NFGenMsgSize {
		t.Fatalf("请求体过短: %d", len(body))
	}
	// family 应为 AF_INET=2
	if body[0] != 2 {
		t.Fatalf("IPv4 的 family 应为 2，实际 %d", body[0])
	}
	// 用 ParseFlow 读回（属性布局与 conntrack 消息一致）
	f, err := ParseFlow(body)
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if f.Orig.SrcAddr != tuple.SrcAddr || f.Orig.DstAddr != tuple.DstAddr {
		t.Fatalf("地址读回错误: %+v", f.Orig)
	}
	if f.Orig.SrcPort != tuple.SrcPort || f.Orig.DstPort != tuple.DstPort {
		t.Fatalf("端口读回错误: %d -> %d", f.Orig.SrcPort, f.Orig.DstPort)
	}
	if f.Orig.Proto != tuple.Proto {
		t.Fatalf("协议读回错误: %d", f.Orig.Proto)
	}
}

// TestBuildDeleteRequestIPv6 IPv6 的 family 应为 AF_INET6=10。
func TestBuildDeleteRequestIPv6(t *testing.T) {
	body, err := BuildDeleteRequest(Tuple{
		SrcAddr: netip.MustParseAddr("2001:db8::1"),
		DstAddr: netip.MustParseAddr("2001:db8::2"),
		Proto:   6,
	}, Tuple{}, 0, 100, 0)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if body[0] != 10 {
		t.Fatalf("IPv6 的 family 应为 10，实际 %d", body[0])
	}
	f, err := ParseFlow(body)
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if f.Orig.SrcAddr.String() != "2001:db8::1" {
		t.Fatalf("IPv6 读回错误: %s", f.Orig.SrcAddr)
	}
}

// TestBuildDeleteRequestErrors 非法输入必须报错。
func TestBuildDeleteRequestErrors(t *testing.T) {
	base := Tuple{
		SrcAddr: netip.MustParseAddr("10.0.0.1"),
		DstAddr: netip.MustParseAddr("10.0.0.2"),
		Proto:   6,
	}
	// 缺地址
	bad := base
	bad.SrcAddr = netip.Addr{}
	if _, err := BuildDeleteRequest(bad, Tuple{}, 0, 0, 0); err == nil {
		t.Fatal("缺源地址应报错")
	}
	// 地址族不一致
	bad = base
	bad.DstAddr = netip.MustParseAddr("2001:db8::1")
	if _, err := BuildDeleteRequest(bad, Tuple{}, 0, 0, 0); err == nil {
		t.Fatal("地址族不一致应报错")
	}
	// 协议为 0
	bad = base
	bad.Proto = 0
	if _, err := BuildDeleteRequest(bad, Tuple{}, 0, 0, 0); err == nil {
		t.Fatal("协议为 0 应报错")
	}
}

// TestMessageType 消息类型必须是 subsys<<8 | msgtype。
func TestMessageType(t *testing.T) {
	if got := MessageType(IPCTNLMsgDump); got != 0x0103 {
		t.Fatalf("DUMP 消息类型应为 0x0103，实际 0x%04x", got)
	}
	if got := MessageType(IPCTNLMsgDelete); got != 0x0101 {
		t.Fatalf("DELETE 消息类型应为 0x0101，实际 0x%04x", got)
	}
}

// TestEventTypeOf 事件类型解析。
func TestEventTypeOf(t *testing.T) {
	cases := []struct {
		typ  uint16
		want EventType
	}{
		{MessageType(IPCTNLMsgNew), EventNew},
		{MessageType(IPCTNLMsgDelete), EventDestroy},
		{MessageType(IPCTNLMsgGet), EventUpdate},
	}
	for _, c := range cases {
		got, err := eventTypeOf(c.typ)
		if err != nil {
			t.Fatalf("类型 0x%04x 解析失败: %v", c.typ, err)
		}
		if got != c.want {
			t.Fatalf("类型 0x%04x 应为 %v，实际 %v", c.typ, c.want, got)
		}
	}
	// 非 conntrack 子系统
	if _, err := eventTypeOf(0x0200); err == nil {
		t.Fatal("非 conntrack 子系统应报错")
	}
}

// TestEventTypeString 事件类型字符串（供日志）。
func TestEventTypeString(t *testing.T) {
	for _, c := range []struct {
		e    EventType
		want string
	}{
		{EventNew, "new"},
		{EventUpdate, "update"},
		{EventDestroy, "destroy"},
		{EventType(99), "unknown"},
	} {
		if got := c.e.String(); got != c.want {
			t.Fatalf("%d 的字符串应为 %q，实际 %q", c.e, c.want, got)
		}
	}
}

// TestAppendNLAAlignment NLA 必须 4 字节对齐。
func TestAppendNLAAlignment(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 5, 8, 9} {
		buf := appendNLA(nil, 1, make([]byte, n))
		if len(buf)%4 != 0 {
			t.Fatalf("payload %d 字节时总长 %d 未对齐", n, len(buf))
		}
		// 长度字段必须等于 4+payload
		if got := int(binary.LittleEndian.Uint16(buf[0:2])); got != 4+n {
			t.Fatalf("payload %d 时长度字段应为 %d，实际 %d", n, 4+n, got)
		}
	}
}
