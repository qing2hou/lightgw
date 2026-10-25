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
