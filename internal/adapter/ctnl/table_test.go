package ctnl

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func mkFlow(i int, status uint32) Flow {
	return Flow{
		Orig: Tuple{
			SrcAddr: netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			DstAddr: netip.MustParseAddr("172.16.30.10"),
			SrcPort: uint16(10000 + i),
			DstPort: 9098,
			Proto:   6,
		},
		Status:  status,
		Packets: uint64(i),
		Bytes:   uint64(i * 100),
	}
}

// TestTablePutGet 基本存取。
func TestTablePutGet(t *testing.T) {
	tb := NewTable()
	f := mkFlow(1, IPSSeenReply)
	tb.Put(f)
	if tb.Len() != 1 {
		t.Fatalf("应有 1 条会话，实际 %d", tb.Len())
	}
	got, ok := tb.Get(KeyOf(f))
	if !ok {
		t.Fatal("应能取回会话")
	}
	if got.Flow.Orig.SrcAddr != f.Orig.SrcAddr {
		t.Fatalf("取回的会话不匹配")
	}
}

// TestTablePutIdempotent 重复 Put 只更新，不新增。
func TestTablePutIdempotent(t *testing.T) {
	tb := NewTable()
	f := mkFlow(1, IPSSeenReply)
	tb.Put(f)
	tb.Put(f)
	tb.Put(f)
	if tb.Len() != 1 {
		t.Fatalf("重复 Put 后应仍为 1 条，实际 %d", tb.Len())
	}
}

// TestTableFirstSeenStable FirstSeen 只在首次设置。
//
// 回归：若每次 UPDATE 都覆盖 FirstSeen，「会话持续时长」永远显示为 0。
func TestTableFirstSeenStable(t *testing.T) {
	tb := NewTable()
	base := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	now := base
	tb.now = func() time.Time { return now }

	f := mkFlow(1, 0)
	tb.Put(f)
	first, _ := tb.Get(KeyOf(f))

	now = base.Add(30 * time.Second)
	tb.Put(f) // UPDATE
	after, _ := tb.Get(KeyOf(f))

	if !after.FirstSeen.Equal(first.FirstSeen) {
		t.Fatalf("FirstSeen 不应被 UPDATE 覆盖: %v -> %v", first.FirstSeen, after.FirstSeen)
	}
	if !after.LastSeen.After(first.LastSeen) {
		t.Fatal("LastSeen 应被 UPDATE 刷新")
	}
}

// TestTableDelete 删除后 Len 减少、Get 失败。
func TestTableDelete(t *testing.T) {
	tb := NewTable()
	f := mkFlow(1, 0)
	tb.Put(f)
	tb.Delete(KeyOf(f))
	if tb.Len() != 0 {
		t.Fatalf("删除后应为 0 条，实际 %d", tb.Len())
	}
	if _, ok := tb.Get(KeyOf(f)); ok {
		t.Fatal("删除后不应能取回")
	}
}

// TestTableDeleteMissing 删除不存在的 key 无副作用。
func TestTableDeleteMissing(t *testing.T) {
	tb := NewTable()
	tb.Delete(KeyOf(mkFlow(99, 0))) // 不应 panic
	if tb.Len() != 0 {
		t.Fatalf("应为 0 条，实际 %d", tb.Len())
	}
}

// TestTableSharding 大量会话必须分散到多个分片（保证锁争用低）。
func TestTableSharding(t *testing.T) {
	tb := NewTable()
	const n = 1000
	for i := 0; i < n; i++ {
		tb.Put(mkFlow(i, 0))
	}
	if tb.Len() != n {
		t.Fatalf("应有 %d 条，实际 %d", n, tb.Len())
	}
	// 至少用到 16 个分片（32 分片下 1000 条几乎必然全用上）
	used := 0
	for i := range tb.sh {
		if len(tb.sh[i].m) > 0 {
			used++
		}
	}
	if used < 16 {
		t.Fatalf("1000 条会话只用了 %d 个分片（分布不均）", used)
	}
}

// TestTableSnapshotDeterministic Snapshot 顺序必须稳定（按 FirstSeen）。
func TestTableSnapshotDeterministic(t *testing.T) {
	tb := NewTable()
	base := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	tick := 0
	tb.now = func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}
	for i := 0; i < 10; i++ {
		tb.Put(mkFlow(i, 0))
	}
	a := tb.Snapshot()
	b := tb.Snapshot()
	if len(a) != len(b) {
		t.Fatal("两次快照长度不一致")
	}
	for i := range a {
		if a[i].Key != b[i].Key {
			t.Fatalf("快照顺序不稳定：位置 %d 为 %v vs %v", i, a[i].Key, b[i].Key)
		}
	}
	// 必须按 FirstSeen 升序
	for i := 1; i < len(a); i++ {
		if a[i].FirstSeen.Before(a[i-1].FirstSeen) {
			t.Fatalf("快照未按 FirstSeen 升序")
		}
	}
}

// TestTableSnapshotIsCopy 快照必须是副本（改它不影响表）。
func TestTableSnapshotIsCopy(t *testing.T) {
	tb := NewTable()
	f := mkFlow(1, 0)
	tb.Put(f)
	snap := tb.Snapshot()
	snap[0].Flow.Bytes = 999999
	got, _ := tb.Get(KeyOf(f))
	if got.Flow.Bytes == 999999 {
		t.Fatal("Snapshot 必须返回副本")
	}
}

// TestTableReplaceAll 全量替换：新增的进、消失的出、保留的更新。
func TestTableReplaceAll(t *testing.T) {
	tb := NewTable()
	a := mkFlow(1, 0)
	b := mkFlow(2, 0)
	c := mkFlow(3, 0)
	tb.Put(a)
	tb.Put(b)

	// 新一轮 dump：b 仍在（更新过）、c 新增、a 消失
	b2 := b
	b2.Bytes = 777
	tb.ReplaceAll([]Flow{b2, c})

	if tb.Len() != 2 {
		t.Fatalf("替换后应有 2 条，实际 %d", tb.Len())
	}
	if _, ok := tb.Get(KeyOf(a)); ok {
		t.Fatal("a 应被删除（dump 里没有）")
	}
	gotB, ok := tb.Get(KeyOf(b))
	if !ok || gotB.Flow.Bytes != 777 {
		t.Fatalf("b 应被更新为 777 bytes，实际 %+v", gotB.Flow)
	}
	if _, ok := tb.Get(KeyOf(c)); !ok {
		t.Fatal("c 应被新增")
	}
}

// TestTableReplaceAllSkipsInvalid dump 里的非法条目应被跳过。
func TestTableReplaceAllSkipsInvalid(t *testing.T) {
	tb := NewTable()
	good := mkFlow(1, 0)
	tmpl := mkFlow(2, 0)
	tmpl.Status = IPSTemplate
	tb.ReplaceAll([]Flow{good, tmpl})
	if tb.Len() != 1 {
		t.Fatalf("模板会话应被跳过，只剩 1 条，实际 %d", tb.Len())
	}
}

// TestTableStats 汇总统计。
func TestTableStats(t *testing.T) {
	tb := NewTable()
	tb.Put(mkFlow(1, IPSSeenReply|IPSAssured))
	tb.Put(mkFlow(2, IPSSrcNAT))
	tb.Put(mkFlow(3, 0))
	st := tb.Stats()
	if st.Total != 3 {
		t.Fatalf("总数应为 3，实际 %d", st.Total)
	}
	if st.Established != 1 {
		t.Fatalf("established 应为 1，实际 %d", st.Established)
	}
	if st.Natted != 1 {
		t.Fatalf("natted 应为 1，实际 %d", st.Natted)
	}
	// bytes = 1*100 + 2*100 + 3*100 = 600
	if st.TotalBytes != 600 {
		t.Fatalf("总字节应为 600，实际 %d", st.TotalBytes)
	}
	// pkts = 1+2+3 = 6
	if st.TotalPkts != 6 {
		t.Fatalf("总包数应为 6，实际 %d", st.TotalPkts)
	}
}

// TestTableConcurrent 并发读写必须无竞态（-race 下验证）。
func TestTableConcurrent(t *testing.T) {
	tb := NewTable()
	const n = 200
	var wg sync.WaitGroup
	// 写
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				tb.Put(mkFlow(base*n+i, 0))
			}
		}(w)
	}
	// 读
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = tb.Snapshot()
				_ = tb.Stats()
				_ = tb.Len()
			}
		}()
	}
	wg.Wait()
	if got := tb.Len(); got != 8*n {
		t.Fatalf("应有 %d 条，实际 %d", 8*n, got)
	}
}

// TestShardOfDistribution 分片哈希必须分布均匀。
func TestShardOfDistribution(t *testing.T) {
	counts := make([]int, shards)
	const n = 10000
	for i := 0; i < n; i++ {
		counts[shardOf(KeyOf(mkFlow(i, 0)))]++
	}
	want := n / shards
	for i, c := range counts {
		if c < want/2 || c > want*2 {
			t.Fatalf("分片 %d 有 %d 条（期望约 %d），分布不均", i, c, want)
		}
	}
}

// TestCompareKey 键比较必须全序（Snapshot 排序依赖它）。
func TestCompareKey(t *testing.T) {
	a := KeyOf(mkFlow(1, 0))
	b := KeyOf(mkFlow(2, 0))
	if compareKey(a, a) != 0 {
		t.Fatal("同键应返回 0")
	}
	if compareKey(a, b) >= 0 {
		t.Fatal("a 应小于 b（地址更小）")
	}
	if compareKey(b, a) <= 0 {
		t.Fatal("b 应大于 a")
	}
}
