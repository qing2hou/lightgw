//go:build qa

// QA P5 一次性验证（M3 AC-6.1/6.3 池映射语义：同源恒同 IP；池成员增减重分配）。
// go test -tags=qa -run TestQAPool ./internal/proxy/fw/
package fw

import (
	"fmt"
	"testing"
)

func TestQAPoolMemberDeterministic(t *testing.T) {
	pool := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	// 同源恒同 IP（sticky 语义）：重复调用 10 次不变
	src := "192.168.1.100"
	first := PoolMemberOf(src, pool)
	if first == "" {
		t.Fatalf("同源映射不应为空")
	}
	for i := 0; i < 10; i++ {
		if got := PoolMemberOf(src, pool); got != first {
			t.Fatalf("同源映射不稳定: %s != %s", got, first)
		}
	}
	// 不同源在池内分布（127 个连续源 → 3 池成员都应被覆盖）
	counts := map[string]int{}
	for i := 1; i <= 127; i++ {
		s := fmt.Sprintf("192.168.1.%d", i)
		m := PoolMemberOf(s, pool)
		if m == "" {
			t.Fatalf("源 %s 映射为空", s)
		}
		known := false
		for _, p := range pool {
			if p == m {
				known = true
			}
		}
		if !known {
			t.Fatalf("源 %s 映射到池外成员 %s", s, m)
		}
		counts[m]++
	}
	t.Logf("127 源分布: %v（各成员均>0 → 池全量利用）", counts)
	for _, p := range pool {
		if counts[p] == 0 {
			t.Fatalf("池成员 %s 从未被分配（死成员）", p)
		}
	}
	// 池成员移除（AC-6.3：成员从网卡移除不再分配给新会话）——
	// 语义在引擎侧是"重建 spec.Pool 后重装"；此处验证 2 池映射仍确定性 + 同源恒同
	pool2 := []string{"10.0.0.1", "10.0.0.2"}
	for i := 1; i <= 127; i++ {
		s := fmt.Sprintf("192.168.1.%d", i)
		m := PoolMemberOf(s, pool2)
		if m != "10.0.0.1" && m != "10.0.0.2" {
			t.Fatalf("2 池映射应只落在两个成员内，得 %s", m)
		}
	}
	// 增减重分配幅度证据（h=131 多项式 hash：增量源段近似连续 h，mod 变化幅度 ≈ |old-new|/new 理论界附近）
	dist := 0
	pool4 := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
	for i := 1; i <= 127; i++ {
		s := fmt.Sprintf("192.168.1.%d", i)
		if PoolMemberOf(s, pool) != PoolMemberOf(s, pool4) {
			dist++
		}
	}
	t.Logf("3->4 成员重分配 %d/127（连续源段实测；h 多项式 131 对连续小数值分布均匀，mod 换模全量重排——记录：桶位移）", dist)
	if dist == 0 {
		t.Fatalf("扩容未产生任何重分配（不可能）")
	}
}
