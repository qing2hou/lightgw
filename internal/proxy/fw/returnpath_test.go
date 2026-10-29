package fw

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// TestReturnPathCounterRows 回程计数行必须存在且只计数不判决。
//
// 回归：放行行以 saddr=白名单源 为条件，只命中"客户端→服务器"方向；
// 下载回程包（源=公网服务器、目的=客户端）靠 pre_mark 的 established
// 打标放行，绕过所有 counter → 页面速率只反映 ACK 小包（实测 3.54MB/s
// 下载显示 68.9KB/s，正是 ACK 的字节速率）。
func TestReturnPathCounterRows(t *testing.T) {
	s := Spec{
		ID: 1, IfIn: "eth0", IfOut: "eth0", OutIP: "192.168.10.170",
		AllowSrcs: []string{"192.168.10.152", "192.168.10.0/24"},
		DstMode:   "off",
	}
	rules, err := CompileSNAT(s)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	// 统计 fwd 链里"按目的地址匹配的回程计数行"
	var returnRows int
	for _, r := range rules {
		if r.Chain != "fwd" {
			continue
		}
		var hasCtr, hasDaddr bool
		for _, e := range r.Rule.Exprs {
			switch v := e.(type) {
			case *expr.Counter:
				hasCtr = true
			case *expr.Payload:
				// v4 目的地址偏移 16（源地址偏移 12）——据此区分放行行与回程行
				if v.Offset == offDaddr && v.Len == 4 {
					hasDaddr = true
				}
			}
		}
		if hasCtr && hasDaddr {
			returnRows++
		}
	}
	if returnRows != len(s.AllowSrcs) {
		t.Fatalf("回程计数行数 = %d，期望 %d（每白名单源一条）", returnRows, len(s.AllowSrcs))
	}
}

// TestReturnPathNoCounterWhenNoSrc 无源白名单时不装回程计数行（无回程语义）。
func TestReturnPathNoCounterWhenNoSrc(t *testing.T) {
	s := Spec{ID: 2, IfIn: "eth0", IfOut: "eth1", OutIP: "172.16.40.10", DstMode: "off"}
	rules := returnPathCounterRows(&nftables.Table{Family: nftables.TableFamilyINet, Name: "haweb"}, "haweb-nft:snat:2", s)
	if len(rules) != 0 {
		t.Fatalf("无源时不应产生回程计数行，实际 %d 条", len(rules))
	}
}
