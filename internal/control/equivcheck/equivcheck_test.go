package equivcheck

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	dbmodel "haproxyweb/internal/model"
)

// realNftOutput 是 .170 上 `nft -a list table inet haweb` 的真实输出形态。
const realNftOutput = `table inet haweb { # handle 5
	chain pre_mark { # handle 1
		type filter hook prerouting priority mangle; policy accept;
		ct state established,related meta mark set meta mark | 0x00000001 # handle 2
	}

	chain dstnat { # handle 3
		type nat hook prerouting priority dstnat; policy accept;
	}

	chain fwd { # handle 9
		type filter hook forward priority filter - 10; policy accept;
		iifname "eth0" oifname "eth0" meta mark & 0x00000004 == 0x00000000 @nh,96,32 0xc0a80a98 counter packets 11704 bytes 105635780 meta mark set meta mark | 0x00000001 # handle 10
		iifname "eth0" oifname "eth0" meta mark & 0x00000004 == 0x00000000 @nh,128,32 0xc0a80a98 counter packets 15176 bytes 63693645 # handle 12
		iifname "eth0" meta mark & 0x00000001 == 0x00000000 counter packets 0 bytes 0 drop # handle 14
	}

	chain srcnat { # handle 15
		type nat hook postrouting priority srcnat; policy accept;
		iifname "eth0" oifname "eth0" meta mark & 0x00000004 == 0x00000000 @nh,96,32 0xc0a80a98 snat ip to 192.168.10.170 # handle 16
		iifname "eth0" oifname "eth0" meta mark & 0x00000004 == 0x00000000 @nh,96,32 0xc0a80a97 snat ip to 192.168.10.170 # handle 17
	}

	chain input { # handle 18
		type filter hook input priority filter; policy accept;
	}
}`

// TestParseNftListingReal 解析真实输出，规则数、链归属、动作都要对。
func TestParseNftListingReal(t *testing.T) {
	rs := ParseNftListing(realNftOutput)
	// 应提取 6 条规则：pre_mark 1 + fwd 3 + srcnat 2
	if len(rs) != 6 {
		t.Fatalf("应解析出 6 条规则，实际 %d: %+v", len(rs), rs)
	}
	byChain := map[string]int{}
	for _, r := range rs {
		byChain[r.Chain]++
	}
	if byChain["pre_mark"] != 1 || byChain["fwd"] != 3 || byChain["srcnat"] != 2 {
		t.Fatalf("链归属错误: %v", byChain)
	}
	// dstnat / input 是空链，不应有规则
	if byChain["dstnat"] != 0 || byChain["input"] != 0 {
		t.Fatalf("空链不应有规则: %v", byChain)
	}
}

// TestParseNftListingStripsHandle 行尾的 `# handle N` 必须去掉。
func TestParseNftListingStripsHandle(t *testing.T) {
	for _, r := range ParseNftListing(realNftOutput) {
		if strings.Contains(r.Match, "# handle") {
			t.Fatalf("★ 未去掉 handle 注解: %q", r.Match)
		}
	}
}

// TestParseNftListingStripsCounterCounts counter 数值必须归一化掉。
func TestParseNftListingStripsCounterCounts(t *testing.T) {
	for _, r := range ParseNftListing(realNftOutput) {
		if strings.Contains(r.Match, "11704") || strings.Contains(r.Match, "105635780") ||
			strings.Contains(r.Match, "15176") || strings.Contains(r.Match, "63693645") {
			t.Fatalf("★ 未剥掉 counter 数值: %q", r.Match)
		}
	}
}

// TestParseNftListingSkipsTypeLines 链类型声明不能被当成规则。
func TestParseNftListingSkipsTypeLines(t *testing.T) {
	for _, r := range ParseNftListing(realNftOutput) {
		if strings.HasPrefix(r.Match, "type ") {
			t.Fatalf("★ 把 type 声明当成了规则: %q", r.Match)
		}
	}
}

// TestParseNftListingEmpty 空输出返回空切片。
func TestParseNftListingEmpty(t *testing.T) {
	if rs := ParseNftListing(""); len(rs) != 0 {
		t.Fatalf("空输入应返回空，实际 %d", len(rs))
	}
}

// TestParseNftListingStable 同一输入两次解析必须完全一致（比对依赖稳定性）。
func TestParseNftListingStable(t *testing.T) {
	a := ParseNftListing(realNftOutput)
	b := ParseNftListing(realNftOutput)
	if len(a) != len(b) {
		t.Fatal("两次解析长度不同")
	}
	for i := range a {
		if a[i].Key() != b[i].Key() {
			t.Fatalf("第 %d 条不稳定: %q vs %q", i, a[i].Key(), b[i].Key())
		}
	}
}

// TestLegacyReaderRequiresTable 表名为空必须报错。
func TestLegacyReaderRequiresTable(t *testing.T) {
	r := NewLegacyReader("")
	if _, err := r.ReadActual(context.Background()); err == nil {
		t.Fatal("空表名应报错")
	}
}

// TestLegacyReaderCommandError 命令失败必须上报。
func TestLegacyReaderCommandError(t *testing.T) {
	r := NewLegacyReaderWithRunner("haweb", func(...string) (string, error) {
		return "", errors.New("nft: command not found")
	})
	if _, err := r.ReadActual(context.Background()); err == nil {
		t.Fatal("命令失败应报错")
	}
}

// TestLegacyReaderOK 正常路径。
func TestLegacyReaderOK(t *testing.T) {
	r := NewLegacyReaderWithRunner("haweb", func(args ...string) (string, error) {
		// 断言用法正确（只读，不带任何写参数）
		joined := strings.Join(args, " ")
		if joined != "nft -a list table inet haweb" {
			t.Fatalf("★ 命令形态不对（必须只读）: %q", joined)
		}
		return realNftOutput, nil
	})
	rs, err := r.ReadActual(context.Background())
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	if len(rs) != 6 {
		t.Fatalf("应 6 条，实际 %d", len(rs))
	}
}

// TestLegacyReaderCanceled ctx 取消必须被尊重。
func TestLegacyReaderCanceled(t *testing.T) {
	r := NewLegacyReaderWithRunner("haweb", func(...string) (string, error) { return "", nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.ReadActual(ctx); err == nil {
		t.Fatal("已取消应报错")
	}
}

// TestCidrToHex IPv4 转 nft 的十六进制。
func TestCidrToHex(t *testing.T) {
	cases := [][2]string{
		{"192.168.10.152", "0xc0a80a98"},
		{"192.168.10.0/24", "0xc0a80a00"},
		{"10.0.0.1", "0x0a000001"},
		{"172.16.30.10", "0xac101e0a"},
	}
	for _, c := range cases {
		if got := cidrToHex(c[0]); got != c[1] {
			t.Fatalf("cidrToHex(%q) = %q，期望 %q", c[0], got, c[1])
		}
	}
	// 无法解析时原样返回（会产生差异供人工核对，不 panic）
	if got := cidrToHex("not-an-ip"); got != "not-an-ip" {
		t.Fatalf("无法解析应原样返回，实际 %q", got)
	}
}

// TestSplitList JSON 数组解析（AGENTS.md 记录过这个字段是 JSON 字符串）。
func TestSplitList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`["192.168.10.152","192.168.10.151"]`, []string{"192.168.10.152", "192.168.10.151"}},
		{`["a"]`, []string{"a"}},
		{"", nil},
		{"[]", nil},
		{"null", nil},
		{`[ "a" , "b" ]`, []string{"a", "b"}},
	}
	for _, c := range cases {
		got := splitList(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("splitList(%q) = %v，期望 %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("splitList(%q) = %v，期望 %v", c.in, got, c.want)
			}
		}
	}
}

// TestCompileStateExpandsACLGroup 名单组必须被展开（缺口 1 的回归）。
func TestCompileStateExpandsACLGroup(t *testing.T) {
	rules := Rules{
		ForwardRules: []dbmodel.ForwardRule{{
			ID: 30, Protocol: "snat", Enabled: true,
			AclMode: "whitelist", AllowList: "", AclGroupID: 1,
			SnatIP: "192.168.10.170",
		}},
		AclGroups: []dbmodel.AclGroup{{
			ID: 1, Mode: "whitelist",
			Entries: `["192.168.10.152","192.168.10.151"]`,
		}},
	}
	st, warns := CompileState(rules, 1)
	for _, w := range warns {
		t.Logf("warn: %s", w)
	}
	if len(st.Rules) != 1 {
		t.Fatalf("应转换出 1 条规则，实际 %d", len(st.Rules))
	}
	if len(st.Rules[0].ACL) != 2 {
		t.Fatalf("★ 名单组应展开成 2 个源，实际 %d: %v", len(st.Rules[0].ACL), st.Rules[0].ACL)
	}
}

// TestCompileStateMissingGroupSkips 引用的名单组不存在时跳过并告警（不当作无源）。
func TestCompileStateMissingGroup(t *testing.T) {
	rules := Rules{
		ForwardRules: []dbmodel.ForwardRule{{
			ID: 30, Protocol: "snat", Enabled: true, AclGroupID: 99,
			SnatIP: "192.168.10.170",
		}},
	}
	st, warns := CompileState(rules, 1)
	if len(st.Rules) != 0 {
		t.Fatalf("组不存在应跳过，实际转换出 %d 条", len(st.Rules))
	}
	found := false
	for _, w := range warns {
		if strings.Contains(w, "名单组#99") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应告警说明组#99 不存在，实际 %v", warns)
	}
}

// TestCompileStateSkipsUserlandRules tcp/udp 规则不进 nft 比对面。
func TestCompileStateSkipsUserlandRules(t *testing.T) {
	rules := Rules{
		ForwardRules: []dbmodel.ForwardRule{{
			ID: 3, Protocol: "tcp", Enabled: true,
		}},
	}
	st, _ := CompileState(rules, 1)
	if len(st.Rules) != 0 {
		t.Fatalf("tcp 规则不应进 compile.State.Rules，实际 %d 条", len(st.Rules))
	}
}

// TestCompileStateDisabledSkipped 禁用规则不参与编译。
func TestCompileStateDisabledSkipped(t *testing.T) {
	rules := Rules{
		ForwardRules: []dbmodel.ForwardRule{{
			ID: 30, Protocol: "snat", Enabled: false, SnatIP: "192.168.10.170",
			AllowList: `["192.168.10.152"]`,
		}},
	}
	st, _ := CompileState(rules, 1)
	if len(st.Rules) != 0 {
		t.Fatal("禁用规则不应参与编译")
	}
}

// TestExpectFromDBReportsModelingGap 走真实编译路径会失败，且错误说明原因。
//
// **这是一条「记录已知缺陷」的测试，不是「验证功能正常」的测试。**
//
// 实测发现：compile 层的 rule.Validate 要求 Proto ∈ {tcp,udp}，
// 但 SNAT 规则没有协议概念（现网规则#30 的 protocol 字段是 "snat"）。
// 这是 S0 遗留的建模缺口：domain.Rule 是为 DNAT（端口转发）设计的。
//
// 本测试固化这个事实，防止有人误以为「B-1 的等价性比对已经可用」。
// 等 compile 层补上 SNAT 独立类型后，本测试应改为断言成功。
func TestExpectFromDBReportsModelingGap(t *testing.T) {
	rules := Rules{
		ForwardRules: []dbmodel.ForwardRule{{
			ID: 30, Name: "test", Protocol: "snat", Enabled: true,
			AclMode: "whitelist", AclGroupID: 1, SnatIP: "192.168.10.170",
		}},
		AclGroups: []dbmodel.AclGroup{{
			ID: 1, Mode: "whitelist", Entries: `["192.168.10.152"]`,
		}},
		Egresses: []dbmodel.Egress{{ID: 4, Name: "eth0", Iface: "eth0"}},
	}
	_, _, err := ExpectFromDB(rules, 1)
	if err == nil {
		t.Fatal("★ 建模缺口已修？请把本测试改为断言成功，并更新 docs/equivcheck-result.md")
	}
	if !strings.Contains(err.Error(), "建模不匹配") {
		t.Fatalf("错误应说明建模不匹配，实际: %v", err)
	}
	if !strings.Contains(err.Error(), "SNAT") {
		t.Fatalf("错误应提到 SNAT，实际: %v", err)
	}
}

// TestCompileStateProducesRule 转换本身能产出规则（缺口在 Compile 不在转换）。
func TestCompileStateProducesRule(t *testing.T) {
	rules := Rules{
		ForwardRules: []dbmodel.ForwardRule{{
			ID: 30, Name: "test", Protocol: "snat", Enabled: true,
			AclGroupID: 1, SnatIP: "192.168.10.170",
		}},
		AclGroups: []dbmodel.AclGroup{{
			ID: 1, Mode: "whitelist", Entries: `["192.168.10.152"]`,
		}},
		Egresses: []dbmodel.Egress{{ID: 4, Name: "eth0", Iface: "eth0"}},
	}
	st, warns := CompileState(rules, 1)
	for _, w := range warns {
		t.Logf("warn: %s", w)
	}
	if len(st.Rules) != 1 {
		t.Fatalf("转换应产出 1 条规则，实际 %d", len(st.Rules))
	}
	r := st.Rules[0]
	if r.Pool.Len() != 1 {
		t.Fatalf("SNAT 目标池应有 1 个地址，实际 %d", r.Pool.Len())
	}
	if len(r.ACL) != 1 {
		t.Fatalf("白名单应有 1 个源，实际 %d", len(r.ACL))
	}
}

// TestPrefixToHex 网段转十六进制。
func TestPrefixToHex(t *testing.T) {
	cases := [][2]string{
		{"192.168.10.152/32", "0xc0a80a98"},
		{"10.0.0.0/8", "0x0a000000"},
	}
	for _, c := range cases {
		p := netip.MustParsePrefix(c[0])
		if got := prefixToHex(p); got != c[1] {
			t.Fatalf("prefixToHex(%q) = %q，期望 %q", c[0], got, c[1])
		}
	}
	// IPv6 原样返回（B-1 只处理 v4）
	if got := prefixToHex(netip.MustParsePrefix("2001:db8::/32")); got != "2001:db8::/32" {
		t.Fatalf("IPv6 应原样返回，实际 %q", got)
	}
}
