// fw 编译层离线单测：纯函数，验证编译产物的结构不变量（链归属/标记/表达式形态）。
package fw

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"haproxyweb/internal/nft"
)

func TestCompileSNATShape(t *testing.T) {
	s := Spec{
		ID: 7, IfIn: "eth0", IfOut: "ens19", OutIP: "172.16.40.9",
		AllowSrcs: []string{"192.168.1.0/24", "10.1.1.5"},
		DstMode:   "blacklist", DstDeny: []string{"203.0.113.9"},
	}
	rules, err := CompileSNAT(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("无编译产物")
	}
	// 全部规则带本规则标记
	ud := nft.Comment(nft.KindSNAT, 7)
	for _, r := range rules {
		if string(r.Rule.UserData) != ud {
			t.Fatalf("规则标记 %s != %s", r.Rule.UserData, ud)
		}
		if r.Rule.Table.Name != nft.Table {
			t.Fatalf("表归属 %s", r.Rule.Table.Name)
		}
	}
	// 至少各一条：pre_mark established 打标 / fwd 黑名单 DROP / srcnat SNAT
	var hasPre, hasDrop, hasSNAT bool
	for _, r := range rules {
		switch {
		case r.Chain == nft.ChainPreMark:
			hasPre = true
			if !hasExpr(r.Rule, "*expr.Ct") {
				t.Fatal("pre_mark 行应含 ct 表达式")
			}
		case r.Chain == nft.ChainFwd:
			for _, e := range r.Rule.Exprs {
				if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
					hasDrop = true
				}
			}
		case r.Chain == nft.ChainSrcNAT:
			hasSNAT = true
			if !hasExpr(r.Rule, "*expr.NAT") {
				t.Fatal("srcnat 行应含 NAT 表达式")
			}
		}
	}
	if !hasPre || !hasDrop || !hasSNAT {
		t.Fatalf("形态缺行: pre=%v drop=%v snat=%v", hasPre, hasDrop, hasSNAT)
	}
}

func TestCompileSNATNoSrcNoDst(t *testing.T) {
	// off 模式无源名单：全放行形态（旧 "无 -s ACCEPT" 等价）
	s := Spec{ID: 9, IfIn: "eth0", IfOut: "ens19", OutIP: "172.16.40.9", DstMode: "off"}
	rules, err := CompileSNAT(s)
	if err != nil {
		t.Fatal(err)
	}
	var iifOnly int
	for _, r := range rules {
		if r.Chain != nft.ChainFwd {
			continue
		}
		// 该形态的 fwd 行不含 saddr payload（无源匹配）
		for _, e := range r.Rule.Exprs {
			if p, ok := e.(*expr.Payload); ok && p.Offset == offSaddr {
				t.Fatal("off 无源形态不应有 saddr 匹配")
			}
		}
		iifOnly++
	}
	if iifOnly == 0 {
		t.Fatal("off 无源形态应有入口网卡维度放行行")
	}
}

func TestCompileSNATBadIP(t *testing.T) {
	s := Spec{ID: 1, IfIn: "eth0", IfOut: "ens19", OutIP: "not-an-ip"}
	if _, err := CompileSNAT(s); err == nil {
		t.Fatal("非法 SNAT 源应报错")
	}
	s2 := Spec{ID: 1, IfIn: "eth0", IfOut: "ens19", OutIP: "1.2.3.4",
		DstMode: "blacklist", DstDeny: []string{"bogus"}}
	if _, err := CompileSNAT(s2); err == nil {
		t.Fatal("非法黑名单目标应报错")
	}
}

// hasExpr 规则内是否含某类型表达式（%T 形态匹配）。
func hasExpr(r *nftables.Rule, typeName string) bool {
	for _, e := range r.Exprs {
		if strings.Contains(fmt.Sprintf("%T", e), typeName) {
			return true
		}
	}
	return false
}

func TestCompileSNATBlacklistHasSourceDimension(t *testing.T) {
	// 评审 M1 防回归：黑名单 DROP 行必须带源维度（v2 事故同型——无源 DROP
	// 会误伤同网卡其他规则的源）
	s := Spec{
		ID: 5, IfIn: "eth0", IfOut: "ens19", OutIP: "1.2.3.4",
		AllowSrcs: []string{"192.168.1.0/24"}, DstMode: "blacklist",
		DstDeny: []string{"203.0.113.9"},
	}
	rules, err := CompileSNAT(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.Chain != nft.ChainFwd {
			continue
		}
		var hasDrop, hasSaddr bool
		for _, e := range r.Rule.Exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
				hasDrop = true
			}
			if p, ok := e.(*expr.Payload); ok && p.Offset == offSaddr {
				hasSaddr = true
			}
		}
		if hasDrop && !hasSaddr {
			t.Fatal("黑名单 DROP 行缺源维度（v2 事故同型回归）")
		}
	}
}

func TestCompileSNATAllRowsHaveOIF(t *testing.T) {
	// 评审 M2 防回归：fwd 放行行与 srcnat 行必须有出口网卡维度（防多网卡机器
	// 从第三网卡出的包被误改写/误放行）
	s := Spec{
		ID: 5, IfIn: "eth0", IfOut: "ens19", OutIP: "1.2.3.4",
		AllowSrcs: []string{"10.1.1.5"}, DstMode: "off",
	}
	rules, err := CompileSNAT(s)
	if err != nil {
		t.Fatal(err)
	}
	oifCount := 0
	for _, r := range rules {
		if r.Chain != nft.ChainFwd && r.Chain != nft.ChainSrcNAT {
			continue
		}
		for _, e := range r.Rule.Exprs {
			if m, ok := e.(*expr.Meta); ok && m.Key == expr.MetaKeyOIFNAME {
				oifCount++
				break
			}
		}
	}
	if oifCount == 0 {
		t.Fatal("fwd/srcnat 行全部缺失出口网卡维度")
	}
}

func TestCompileSNATEmptyOutIPFails(t *testing.T) {
	// 评审 M8 防回归：空 SNAT 源 fail-fast（静默装出无 SNAT 的单向黑洞）
	s := Spec{ID: 9, IfIn: "eth0", IfOut: "ens19", OutIP: "", DstMode: "off"}
	if _, err := CompileSNAT(s); err == nil {
		t.Fatal("空 OutIP 应报错（旧 installSnat fail-fast 语义）")
	}
}

func TestCompileDefaultDenyShape(t *testing.T) {
	rules := CompileDefaultDeny(0, []string{"eth0", "ens19"})
	if len(rules) != 2 {
		t.Fatalf("默认拒绝行数 %d != 入口网卡数 2", len(rules))
	}
	for _, r := range rules {
		if !hasExpr(r.Rule, "*expr.Counter") || !hasDropVerdict(r.Rule) {
			t.Fatal("默认拒绝行应含 counter + drop")
		}
	}
	if CompileDefaultDeny(0, nil) != nil {
		t.Fatal("空入口集应返回 nil（vanilla 全通）")
	}
}

func hasDropVerdict(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
			return true
		}
	}
	return false
}

func TestCompileSNATDstWhitelistNoSrc(t *testing.T) {
	// 复审 N4 防回归：off + 目标白名单 + 无源白名单 → 必须编译出
	// 无源(仅 iif/oif/daddr)的目标白名单放行行（旧形态 "-i in -o out -d X ACCEPT"）
	s := Spec{ID: 3, IfIn: "eth0", IfOut: "ens19", OutIP: "1.2.3.4",
		DstMode: "whitelist", DstAllow: []string{"10.0.1.0/24"}}
	rules, err := CompileSNAT(s)
	if err != nil {
		t.Fatal(err)
	}
	fwdAccept := 0
	for _, r := range rules {
		if r.Chain != nft.ChainFwd || hasDropVerdict(r.Rule) {
			continue
		}
		var hasDaddr, hasSaddr bool
		for _, e := range r.Rule.Exprs {
			if p, ok := e.(*expr.Payload); ok {
				if p.Offset == offDaddr {
					hasDaddr = true
				}
				if p.Offset == offSaddr {
					hasSaddr = true
				}
			}
		}
		if hasDaddr && !hasSaddr {
			fwdAccept++
		}
	}
	if fwdAccept == 0 {
		t.Fatal("目标白名单×无源组合应有带 daddr 无 saddr 的放行行（旧形态语义）")
	}
}

func TestCIDRMatchDataBytes(t *testing.T) {
	// B2 回归：v4 CIDR 的 Cmp Data 必须是网络地址本身（曾回归为 To16 切片全零）
	rules, err := CompileSNAT(Spec{
		ID: 1, IfIn: "e0", IfOut: "e1", OutIP: "1.2.3.4",
		AllowSrcs: []string{"192.168.1.0/24"}, DstMode: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rules {
		if r.Chain != nft.ChainSrcNAT {
			continue
		}
		for i := 0; i+1 < len(r.Rule.Exprs); i++ {
			bw, ok1 := r.Rule.Exprs[i].(*expr.Bitwise)
			cm, ok2 := r.Rule.Exprs[i+1].(*expr.Cmp)
			if !ok1 || !ok2 {
				continue
			}
			if len(bw.Mask) != 4 {
				continue
			}
			want := []byte{192, 168, 1, 0}
			if string(cm.Data) != string(want) {
				t.Fatalf("v4 CIDR Cmp Data = %v，期望网络地址 %v（B2 回归：To16 切片全零）", cm.Data, want)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("未在 srcnat 行找到 CIDR Bitwise+Cmp 对")
	}
}

func TestCIDRMatchDataBytesV6(t *testing.T) {
	// 复审建议：v6 CIDR 的 Cmp Data 锁字节（To16 路径——将来最易改坏的行）
	rules, err := CompileSNAT(Spec{
		ID: 2, IfIn: "e0", IfOut: "e1", OutIP: "fd00::1",
		AllowSrcs: []string{"fd00:ab::/64"}, DstMode: "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rules {
		if r.Chain != nft.ChainSrcNAT {
			continue
		}
		for i := 0; i+1 < len(r.Rule.Exprs); i++ {
			bw, ok1 := r.Rule.Exprs[i].(*expr.Bitwise)
			cm, ok2 := r.Rule.Exprs[i+1].(*expr.Cmp)
			if !ok1 || !ok2 || len(bw.Mask) != 16 {
				continue
			}
			// 网络 fd00:00ab:: → 前 8 字节 [fd 00 00 ab 00..]，后 8 字节零
			want := make([]byte, 16)
			want[0], want[1], want[2], want[3] = 0xfd, 0x00, 0x00, 0xab
			if string(cm.Data) != string(want) {
				t.Fatalf("v6 CIDR Cmp Data = % x，期望 % x", cm.Data, want)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("未在 srcnat 行找到 v6 CIDR Bitwise+Cmp（16B）对")
	}
}
