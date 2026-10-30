package bandwidth

import (
	"strings"
	"testing"
)

// TestCheckOversubscriptionOK 保底之和 ≤ 总额时不构成超额订阅。
func TestCheckOversubscriptionOK(t *testing.T) {
	// 生产现场配置：总额 8192 KB/s（8MB/s），保底 1024，2 个源
	o := CheckOversubscription(8192, 1024, 2)
	if o.Oversubscribed {
		t.Fatalf("2 源 × 1024 = 2048 ≤ 8192，不应超额，实际 %+v", o)
	}
	if o.RequiredKBps != 2048 {
		t.Fatalf("需求应为 2048，实际 %d", o.RequiredKBps)
	}
	// 恰好等于总额的边界：8 源 × 1024 = 8192，不算超额
	o = CheckOversubscription(8192, 1024, 8)
	if o.Oversubscribed {
		t.Fatalf("8 源 × 1024 = 8192 恰等于总额，不应判超额，实际 %+v", o)
	}
}

// TestCheckOversubscriptionOver 超额订阅必须被识别。
//
// 实测依据（docs/poc-result.md §4.2.1）：Σ保底 > 总额时 HTB 无法把总额压成
// 硬上限，合计会突破。N=12 / 总额4MB/s 实测跑出 11.50MB/s（超 187.6%）。
func TestCheckOversubscriptionOver(t *testing.T) {
	o := CheckOversubscription(8192, 1024, 9) // 9 × 1024 = 9216 > 8192
	if !o.Oversubscribed {
		t.Fatalf("9 源 × 1024 = 9216 > 8192，应判超额，实际 %+v", o)
	}
	if o.RequiredKBps != 9216 {
		t.Fatalf("需求应为 9216，实际 %d", o.RequiredKBps)
	}
}

// TestCheckOversubscriptionDefaultMin 保底为 0 时应用默认值 1024。
func TestCheckOversubscriptionDefaultMin(t *testing.T) {
	o := CheckOversubscription(8192, 0, 2)
	if o.MinKBps != DefaultMinKBps {
		t.Fatalf("保底为 0 应取默认 %d，实际 %d", DefaultMinKBps, o.MinKBps)
	}
	if o.RequiredKBps != 2*DefaultMinKBps {
		t.Fatalf("需求应为 %d，实际 %d", 2*DefaultMinKBps, o.RequiredKBps)
	}
}

// TestValidateOversubscriptionMessage 错误消息必须含三个数（总额/保底/成员数）且为中文。
func TestValidateOversubscriptionMessage(t *testing.T) {
	err := ValidateOversubscription(8192, 1024, 20)
	if err == nil {
		t.Fatal("超额订阅应报错")
	}
	msg := err.Error()
	for _, want := range []string{"8192", "1024", "20", "超额订阅"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误消息应包含 %q，实际: %s", want, msg)
		}
	}
	// 必须给出「可改到多少」这个可执行建议
	if !strings.Contains(msg, "请降低保底") {
		t.Fatalf("错误消息应给出修改建议，实际: %s", msg)
	}
}

func TestValidateOversubscriptionOK(t *testing.T) {
	if err := ValidateOversubscription(8192, 1024, 2); err != nil {
		t.Fatalf("合法配置应通过: %v", err)
	}
	if err := ValidateOversubscription(0, 1024, 2); err == nil {
		t.Fatal("总额为 0 应报错")
	}
}

func TestAllocatableMinKBps(t *testing.T) {
	cases := []struct {
		total, sources, want int64
	}{
		{8192, 2, 4096},
		{8192, 8, 1024},
		{8192, 0, 8192}, // 无成员时返回总额本身
		{0, 4, 0},
		{8192, 100, 81}, // 整除截断
	}
	for _, c := range cases {
		got := AllocatableMinKBps(c.total, int(c.sources))
		if got != c.want {
			t.Fatalf("AllocatableMinKBps(%d, %d) = %d，期望 %d", c.total, c.sources, got, c.want)
		}
	}
}

// TestAllocateBasic 基本分配：每源 rate=保底、ceil=总额。
func TestAllocateBasic(t *testing.T) {
	p := Allocate(8192, 1024, []string{"192.168.10.152", "192.168.10.151"})
	if p.TotalKBps != 8192 || p.MinKBps != 1024 {
		t.Fatalf("Plan 头部错误: %+v", p)
	}
	if len(p.Entries) != 2 {
		t.Fatalf("应有 2 条分配，实际 %d", len(p.Entries))
	}
	for _, e := range p.Entries {
		if e.GuaranteedKBps != 1024 {
			t.Fatalf("源 %s 保底应为 1024，实际 %d", e.Source, e.GuaranteedKBps)
		}
		if e.CeilKBps != 8192 {
			t.Fatalf("源 %s 上限应为总额 8192，实际 %d", e.Source, e.CeilKBps)
		}
	}
	if p.Oversubscribed {
		t.Fatal("2 源不应超额")
	}
}

// TestAllocateDeterministicOrder 分配结果必须按源字典序排列（顺序不稳定会导致
// 每次 Apply 产生无意义 diff）。
func TestAllocateDeterministicOrder(t *testing.T) {
	a := Allocate(8192, 1024, []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"})
	b := Allocate(8192, 1024, []string{"10.0.0.2", "10.0.0.3", "10.0.0.1"})
	if len(a.Entries) != len(b.Entries) {
		t.Fatal("长度不一致")
	}
	for i := range a.Entries {
		if a.Entries[i].Source != b.Entries[i].Source {
			t.Fatalf("顺序不稳定：位置 %d 为 %s vs %s",
				i, a.Entries[i].Source, b.Entries[i].Source)
		}
	}
	if a.Entries[0].Source != "10.0.0.1" {
		t.Fatalf("应按字典序，首项应为 10.0.0.1，实际 %s", a.Entries[0].Source)
	}
}

// TestAllocateDedupe 重复源必须去重（同一源只分配一份保底）。
func TestAllocateDedupe(t *testing.T) {
	p := Allocate(8192, 1024, []string{"10.0.0.1", "10.0.0.1", "", "10.0.0.2"})
	if len(p.Entries) != 2 {
		t.Fatalf("去重后应有 2 条，实际 %d: %+v", len(p.Entries), p.Entries)
	}
}

// TestAllocateMinClampedToTotal 单源保底超过总额时截到总额（合法，不报错）。
func TestAllocateMinClampedToTotal(t *testing.T) {
	p := Allocate(1024, 8192, []string{"10.0.0.1"})
	if p.MinKBps != 1024 {
		t.Fatalf("单源保底应被截到总额 1024，实际 %d", p.MinKBps)
	}
	if p.Oversubscribed {
		t.Fatalf("单源吃满总额不算超额，实际判为超额: %+v", p)
	}
}

// TestAllocateOversubscribedFlag 超额订阅必须在 Plan 上置位。
func TestAllocateOversubscribedFlag(t *testing.T) {
	srcs := make([]string, 20)
	for i := range srcs {
		srcs[i] = "10.0.1." + string(rune('1'+i%9))
	}
	p := Allocate(8192, 1024, srcs)
	if !p.Oversubscribed {
		t.Fatalf("20 源 × 1024 = 20480 > 8192，应置超额标记: %+v", p)
	}
}

func TestAllocateEmptySources(t *testing.T) {
	p := Allocate(8192, 1024, nil)
	if len(p.Entries) != 0 {
		t.Fatalf("无源时不应有分配，实际 %d 条", len(p.Entries))
	}
	if p.Oversubscribed {
		t.Fatal("无源不应超额")
	}
}

func TestSharedTotalKBps(t *testing.T) {
	if got := SharedTotalKBps([]int64{8192, 16384, 4096}); got != 16384 {
		t.Fatalf("应返回最大值 16384，实际 %d", got)
	}
	if got := SharedTotalKBps(nil); got != 0 {
		t.Fatalf("空输入应返回 0，实际 %d", got)
	}
}
