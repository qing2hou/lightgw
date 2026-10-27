package proxy

import (
	"testing"

	"haproxyweb/internal/nft"
)

// TestSnatAllocTableAvoidsReserved 分配器绝不能产出 253-255（内核保留表）。
// 生产事故回归：早期区间取 201..300，第 53 条规则起就会分到 254(main)。
func TestSnatAllocTableAvoidsReserved(t *testing.T) {
	m := &Manager{snatRules: map[uint]*snatEntry{}}
	seen := map[int]bool{}
	for i := 0; i < 60; i++ {
		id := uint(i + 1)
		tbl := m.snatAllocTable(id)
		if tbl == 0 {
			break // 段已用尽属预期（见下个用例）
		}
		if nft.IsReservedRouteTable(tbl) {
			t.Fatalf("分配器产出了内核保留表 %d（规则#%d）", tbl, id)
		}
		if tbl < nft.RouteTableBase || tbl > nft.RouteTableEnd {
			t.Fatalf("分配器产出段外表 %d（规则#%d）", tbl, id)
		}
		if seen[tbl] {
			t.Fatalf("表号 %d 重复分配", tbl)
		}
		seen[tbl] = true
		m.snatRules[id] = &snatEntry{ruleID: id, rtTable: tbl}
	}
	if len(seen) == 0 {
		t.Fatal("分配器未产出任何表号")
	}
}

// TestSnatAllocTableExhausted 段用尽时返回 0（调用方据此不装策略路由），
// 且永远不会溢出到保留表。
func TestSnatAllocTableExhausted(t *testing.T) {
	m := &Manager{snatRules: map[uint]*snatEntry{}}
	// 占满整个专属段
	n := 0
	for tbl := nft.RouteTableBase; tbl <= nft.RouteTableEnd; tbl++ {
		if nft.IsReservedRouteTable(tbl) {
			continue
		}
		n++
		m.snatRules[uint(n)] = &snatEntry{ruleID: uint(n), rtTable: tbl}
	}
	if got := m.snatAllocTable(uint(n + 1)); got != 0 {
		t.Fatalf("段已用尽应返回 0，实际 %d（若为 254 即事故）", got)
	}
}
