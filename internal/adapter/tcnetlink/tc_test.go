package tcnetlink

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"haproxyweb/internal/compile"
)

// TestParseHandle handle 解析必须正确处理 major:minor（含十六进制）。
func TestParseHandle(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"1:", 0x00010000},
		// tc 的 major:minor 是十六进制：1:208 = 0x1_0208
		{"1:208", 0x00010208},
		{"1:100", 0x00010100},
		{"1:199", 0x00010199},
		{"ffff:", 0xffff0000},
		{"1:1ff", 0x000101ff},
	}
	for _, c := range cases {
		got, err := parseHandle(c.in)
		if err != nil {
			t.Fatalf("parseHandle(%q) 失败: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("parseHandle(%q) = 0x%x，期望 0x%x", c.in, got, c.want)
		}
	}
	// 非法输入
	for _, bad := range []string{"", "abc", "1", "10000:1"} {
		if _, err := parseHandle(bad); err == nil {
			t.Fatalf("parseHandle(%q) 应报错", bad)
		}
	}
}

// TestHandleStr 反向格式化。
func TestHandleStr(t *testing.T) {
	if got := handleStr(0x00010208); got != "1:208" {
		t.Fatalf("handleStr 错误: %q", got)
	}
}

// TestParentHandle root 必须映射到 HANDLE_ROOT。
func TestParentHandle(t *testing.T) {
	if got := parentHandle("root"); got != netlink.HANDLE_ROOT {
		t.Fatalf("root 应映射到 HANDLE_ROOT，实际 0x%x", got)
	}
	if got := parentHandle(""); got != netlink.HANDLE_ROOT {
		t.Fatalf("空串应映射到 HANDLE_ROOT，实际 0x%x", got)
	}
	if got := parentHandle("1:"); got != 0x00010000 {
		t.Fatalf("\"1:\" 应映射到 0x10000，实际 0x%x", got)
	}
}

// TestPrefixToU32 网段转 u32 必须带真实掩码（不是 0xffffffff）。
//
// 回归：网段用精确掩码会让 /24 只匹配网络地址一个 IP，网段内其他成员的
// 流量全部漏到 default class → 不限速。
func TestPrefixToU32(t *testing.T) {
	cases := []struct {
		p        string
		wantVal  uint32
		wantMask uint32
	}{
		{"192.168.10.152/32", 0xc0a80a98, 0xffffffff},
		{"192.168.10.0/24", 0xc0a80a00, 0xffffff00},
		{"10.0.0.0/8", 0x0a000000, 0xff000000},
		{"172.16.0.0/12", 0xac100000, 0xfff00000},
		{"0.0.0.0/0", 0x00000000, 0x00000000},
	}
	for _, c := range cases {
		p := netip.MustParsePrefix(c.p)
		val, mask, err := prefixToU32(p)
		if err != nil {
			t.Fatalf("%s 转换失败: %v", c.p, err)
		}
		if val != c.wantVal {
			t.Fatalf("%s 的值应为 0x%08x，实际 0x%08x", c.p, c.wantVal, val)
		}
		if mask != c.wantMask {
			t.Fatalf("%s 的掩码应为 0x%08x，实际 0x%08x", c.p, c.wantMask, mask)
		}
	}
}

// TestPrefixToU32RejectsIPv6 u32 只支持 IPv4，v6 必须报错。
func TestPrefixToU32RejectsIPv6(t *testing.T) {
	if _, _, err := prefixToU32(netip.MustParsePrefix("2001:db8::/32")); err == nil {
		t.Fatal("IPv6 应报错（u32 只支持 v4）")
	}
}

// TestSrcDstOffset D-16：src=12，dst=16，写反就是 14.8 倍超速事故。
func TestSrcDstOffset(t *testing.T) {
	if got := srcDstOffset(true); got != 12 {
		t.Fatalf("源地址偏移应为 12，实际 %d", got)
	}
	if got := srcDstOffset(false); got != 16 {
		t.Fatalf("目的地址偏移应为 16，实际 %d", got)
	}
}

// TestApplyRejectsInvalidPlan 非法计划必须在校验阶段被拦住，不能写进内核。
func TestApplyRejectsInvalidPlan(t *testing.T) {
	// default 指向内层类 —— compile.TcPlan.Validate 应拦住
	plan := compile.TcPlan{
		Qdiscs: []compile.TcQdiscSpec{
			{Device: "eth0", Parent: "root", Handle: "1:", Kind: "htb", Default: 100},
		},
		Classes: []compile.TcClassSpec{
			{ClassID: compile.TcTotalClass, IsLeaf: false},
			{ClassID: compile.TcRootMajor | 201, ParentClassID: compile.TcTotalClass, IsLeaf: true},
		},
	}
	e := NewEngineWith(nil, func(compile.TcPlan) error {
		t.Fatal("非法计划不应走到执行层")
		return nil
	})
	if err := e.Apply(plan); err == nil {
		t.Fatal("default 指向内层类的计划必须被拒绝")
	}
}

// TestApplyEmptyNoop 空计划是合法的（不限速），不做任何事。
func TestApplyEmptyNoop(t *testing.T) {
	called := false
	e := NewEngineWith(nil, func(compile.TcPlan) error {
		called = true
		return nil
	})
	if err := e.Apply(compile.TcPlan{}); err != nil {
		t.Fatalf("空计划不应报错: %v", err)
	}
	if called {
		t.Fatal("空计划不应调用执行层")
	}
}

// TestApplyPassesValidPlan 合法计划应被放行到执行层。
func TestApplyPassesValidPlan(t *testing.T) {
	var got compile.TcPlan
	e := NewEngineWith(nil, func(p compile.TcPlan) error {
		got = p
		return nil
	})
	plan, err := compile.CompileTcOnly(8192, 1024,
		[]string{"192.168.10.152"}, "eth0", "eth0", "ifb-hw1")
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if err := e.Apply(plan); err != nil {
		t.Fatalf("合法计划应通过: %v", err)
	}
	if len(got.Classes) == 0 {
		t.Fatal("执行层未收到计划")
	}
}

// TestBuildU32FilterDownloadIsDst 下载方向的 u32 filter 必须用 at 16（daddr）。
func TestBuildU32FilterDownloadIsDst(t *testing.T) {
	link := &fakeLink{idx: 7, name: "eth0"}
	f := compile.TcFilterSpec{
		Device:   "eth0",
		Parent:   "1:",
		Pref:     5,
		MatchSrc: false, // 下载
		Match:    netip.MustParsePrefix("192.168.10.152/32"),
		FlowID:   "1:201",
	}
	u32, err := buildU32Filter(link, f)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if len(u32.Sel.Keys) != 1 {
		t.Fatalf("应有 1 个 key，实际 %d", len(u32.Sel.Keys))
	}
	if u32.Sel.Keys[0].Off != 16 {
		t.Fatalf("★ 下载方向必须 at 16（daddr），实际 %d", u32.Sel.Keys[0].Off)
	}
	if u32.Sel.Keys[0].Mask != 0xffffffff {
		t.Fatalf("/32 掩码应为 0xffffffff，实际 0x%x", u32.Sel.Keys[0].Mask)
	}
	if u32.Priority != 5 {
		t.Fatalf("pref 应为 5，实际 %d", u32.Priority)
	}
	// flowid 1:201 → 0x1_0201（十六进制）
	if u32.ClassId != 0x00010201 {
		t.Fatalf("flowid 1:201 应解析为 0x10201，实际 0x%x", u32.ClassId)
	}
}

// TestBuildU32FilterUploadIsSrc C-17：上传方向必须 at 12（saddr）。
func TestBuildU32FilterUploadIsSrc(t *testing.T) {
	link := &fakeLink{idx: 7, name: "ifb-hw1"}
	f := compile.TcFilterSpec{
		Device:   "ifb-hw1",
		Parent:   "1:",
		Pref:     1005,
		MatchSrc: true, // 上传
		Match:    netip.MustParsePrefix("192.168.10.152/32"),
		FlowID:   "1:201",
	}
	u32, err := buildU32Filter(link, f)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if u32.Sel.Keys[0].Off != 12 {
		t.Fatalf("★ 上传方向必须 at 12（saddr），实际 %d（D-16 事故写法）", u32.Sel.Keys[0].Off)
	}
}

// TestBuildU32FilterCIDRMask 网段必须带真实掩码（不是 /32）。
func TestBuildU32FilterCIDRMask(t *testing.T) {
	link := &fakeLink{idx: 7, name: "eth0"}
	f := compile.TcFilterSpec{
		Parent: "1:", Pref: 5,
		Match:  netip.MustParsePrefix("192.168.10.0/24"),
		FlowID: "1:201",
	}
	u32, err := buildU32Filter(link, f)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if u32.Sel.Keys[0].Mask != 0xffffff00 {
		t.Fatalf("/24 掩码应为 0xffffff00，实际 0x%x（用 /32 会漏掉网段内其他 IP）",
			u32.Sel.Keys[0].Mask)
	}
}

// TestMirredRequiresSrc ingress 重定向必须 match src。
func TestMirredRequiresSrc(t *testing.T) {
	e := NewEngineWith(func(name string) (netlink.Link, error) {
		return &fakeLink{idx: 7, name: name}, nil
	}, nil)
	f := compile.TcFilterSpec{
		Device: "eth0", Parent: "ffff:", Pref: 1005,
		MatchSrc: false, // 错：上传必须 src
		Match:    netip.MustParsePrefix("192.168.10.152/32"),
		MirredTo: "ifb-hw1",
	}
	err := e.applyMirred(&fakeLink{idx: 7, name: "eth0"}, f)
	if err == nil {
		t.Fatal("ingress 重定向用 dst 必须报错")
	}
	if !strings.Contains(err.Error(), "src") {
		t.Fatalf("错误消息应指出必须 src，实际: %v", err)
	}
}

// TestMirredRequiresTarget 缺少 mirred 目标设备必须报错（不能静默跳过）。
func TestMirredRequiresTarget(t *testing.T) {
	e := NewEngineWith(func(name string) (netlink.Link, error) {
		return &fakeLink{idx: 7, name: name}, nil
	}, nil)
	f := compile.TcFilterSpec{
		Device: "eth0", Parent: "ffff:", Pref: 1005,
		MatchSrc: true,
		Match:    netip.MustParsePrefix("192.168.10.152/32"),
		MirredTo: "", // 缺目标
	}
	if err := e.applyMirred(&fakeLink{idx: 7, name: "eth0"}, f); err == nil {
		t.Fatal("缺少 mirred 目标必须报错")
	}
}

// fakeLink 是 netlink.Link 的最小实现，只提供测试需要的字段。
type fakeLink struct {
	idx  int
	name string
}

func (l *fakeLink) Attrs() *netlink.LinkAttrs {
	return &netlink.LinkAttrs{Index: l.idx, Name: l.name}
}
func (l *fakeLink) Type() string { return "fake" }
