package logstore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func entry(i int) Entry {
	return Entry{Kind: "traffic", At: time.Now(), Data: i}
}

// TestRecordNeverBlocks 硬要求 1：通道满时 Record 必须立即返回，不阻塞。
//
// 这是转发路径能安全调用本包的前提——日志系统慢了绝不能拖住会话处理。
//
// **确定性构造**：不依赖「sink 阻塞 + 调度时序」（那样结果会随 GC/调度抖动
// 而变化，测出来时好时坏）。这里直接构造一个「只有入口通道、没有消费者」
// 的 Writer：手工把 ch 填满，随后的 Record 必须走 default 分支。
func TestRecordNeverBlocks(t *testing.T) {
	w := &Writer{
		ch:   make(chan Entry, ChannelSize),
		done: make(chan struct{}),
	}
	// 先填满入口通道（模拟「消费者完全停止」）
	for i := 0; i < ChannelSize; i++ {
		w.ch <- entry(i)
	}
	// 之后的 Record 必须立即返回 false 并计数
	const extra = 500
	start := time.Now()
	var rejected int
	for i := 0; i < extra; i++ {
		if !w.Record(entry(i)) {
			rejected++
		}
	}
	elapsed := time.Since(start)

	t.Logf("通道已满时 %d 次 Record 耗时 %v，拒绝 %d 条", extra, elapsed, rejected)
	if rejected != extra {
		t.Fatalf("★ 通道满后应全部拒绝，实际拒绝 %d/%d", rejected, extra)
	}
	if w.Dropped() != uint64(extra) {
		t.Fatalf("★ 丢弃数应为 %d，实际 %d", extra, w.Dropped())
	}
	// 非阻塞的量化证据：500 次全部拒绝，总耗时必须极短
	if elapsed > 10*time.Millisecond {
		t.Fatalf("★ %d 次 Record 耗时 %v，Record 可能被阻塞了", extra, elapsed)
	}
	// 干净收尾（这个 Writer 没有 dispatch goroutine，Close 会 panic 在 wait 上？
	// 不会：wg 计数为 0，wait 立即返回）
	if err := w.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
}

// TestRecordIsFast Record 单次调用必须是微秒级（非阻塞的另一面）。
func TestRecordIsFast(t *testing.T) {
	w := New(NewMemorySink("m"))
	defer w.Close()
	const n = 10000
	start := time.Now()
	for i := 0; i < n; i++ {
		w.Record(entry(i))
	}
	el := time.Since(start)
	perOp := el / n
	t.Logf("%d 次 Record 耗时 %v（每次 %v）", n, el, perOp)
	if perOp > 10*time.Microsecond {
		t.Fatalf("★ 单次 Record 平均 %v，应 < 10μs（否则会拖慢转发路径）", perOp)
	}
}

// TestBatchSizeRespected 硬要求 2：必须攒批写入，不是逐条。
func TestBatchSizeRespected(t *testing.T) {
	s := NewMemorySink("m")
	w := New(s)
	// 灌 BatchSize 条
	for i := 0; i < BatchSize; i++ {
		w.Record(entry(i))
	}
	// 等一批写完
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, e, _ := s.Counts(); b >= 1 && e >= BatchSize {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	batches, entries, _ := s.Counts()
	t.Logf("批次数=%d 条目数=%d（BatchSize=%d）", batches, entries, BatchSize)
	if entries < BatchSize {
		t.Fatalf("应写入至少 %d 条，实际 %d", BatchSize, entries)
	}
	// 关键：批次数必须远小于条目数（证明是批写不是逐条）
	if batches >= entries {
		t.Fatalf("★ 批次数 %d >= 条目数 %d，说明没攒批", batches, entries)
	}
	_ = w.Close()
}

// TestSlowSinkDoesNotBlockOthers 硬要求 3：一个 sink 慢不能拖死其他 sink。
func TestSlowSinkDoesNotBlockOthers(t *testing.T) {
	slow := NewMemorySink("slow")
	slowBlock := make(chan struct{})
	slow.WriteFn = func(ctx context.Context, batch []Entry) error {
		<-slowBlock // 永久阻塞
		return nil
	}
	fast := NewMemorySink("fast")
	w := New(slow, fast)

	for i := 0; i < 2000; i++ {
		w.Record(entry(i))
	}
	// fast 必须仍然收到数据（不能因为 slow 阻塞而饿死）
	deadline := time.Now().Add(3 * time.Second)
	var fastEntries int
	for time.Now().Before(deadline) {
		_, fastEntries, _ = fast.Counts()
		if fastEntries > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("fast sink 收到 %d 条（slow sink 已阻塞）", fastEntries)
	if fastEntries == 0 {
		t.Fatal("★ 慢 sink 不应阻塞其它 sink")
	}
	close(slowBlock)
	_ = w.Close()
}

// TestDroppedReported 硬要求 4：丢弃数必须可读（/metrics、/healthz 的数据源）。
func TestDroppedReported(t *testing.T) {
	w := New(NewMemorySink("m"))
	defer w.Close()
	st := w.Stats()
	if st.Dropped != 0 || st.Received != 0 {
		t.Fatalf("初始应全零，实际 %+v", st)
	}
	for i := 0; i < 10; i++ {
		w.Record(entry(i))
	}
	st = w.Stats()
	if st.Received != 10 {
		t.Fatalf("received 应为 10，实际 %d", st.Received)
	}
	if len(st.SinkNames) != 1 || st.SinkNames[0] != "m" {
		t.Fatalf("sink 名列表错误: %v", st.SinkNames)
	}
}

// TestDropRate 丢弃率计算。
func TestDropRate(t *testing.T) {
	w := New() // 无 sink：所有条目都会走 broadcast 时被判丢弃
	if w.DropRate() != 0 {
		t.Fatal("未收到任何条目时丢弃率应为 0")
	}
	for i := 0; i < 100; i++ {
		w.Record(entry(i))
	}
	time.Sleep(200 * time.Millisecond)
	_ = w.Close()
	// 无 sink 时 100% 丢弃
	if got := w.DropRate(); got != 1.0 {
		t.Fatalf("无 sink 时丢弃率应为 1.0，实际 %f", got)
	}
}

// TestNoSinkStillWorks 无 sink 时 Writer 仍可用（不 panic）。
func TestNoSinkStillWorks(t *testing.T) {
	w := New()
	for i := 0; i < 100; i++ {
		w.Record(entry(i))
	}
	if err := w.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
}

// TestCloseFlushesRemainder 关闭时必须把通道里的残余刷出去。
func TestCloseFlushesRemainder(t *testing.T) {
	s := NewMemorySink("m")
	w := New(s)
	// 只写 10 条（不够凑一批，靠 Close 时的 drain）
	for i := 0; i < 10; i++ {
		w.Record(entry(i))
	}
	if err := w.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	_, entries, closed := s.Counts()
	if entries != 10 {
		t.Fatalf("★ 关闭时应刷出全部 10 条，实际 %d（低流量时日志会滞留）", entries)
	}
	if !closed {
		t.Fatal("关闭后 sink 应被关闭")
	}
}

// TestCloseTwice Close 必须幂等。
func TestCloseTwice(t *testing.T) {
	w := New(NewMemorySink("m"))
	if err := w.Close(); err != nil {
		t.Fatalf("首次关闭失败: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("二次关闭应幂等，实际: %v", err)
	}
}

// TestRecordAfterClose Record 在关闭后不能 panic（旧实现 close(ch) 会 panic）。
func TestRecordAfterClose(t *testing.T) {
	w := New(NewMemorySink("m"))
	_ = w.Close()
	// 不应 panic
	ok := w.Record(entry(1))
	if ok {
		t.Log("关闭后 Record 返回 true（条目被接收但不会写出）")
	}
}

// TestConcurrentRecord 并发 Record 必须安全（-race 下验证）。
func TestConcurrentRecord(t *testing.T) {
	s := NewMemorySink("m")
	w := New(s)
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if w.Record(entry(base*500 + i)) {
					accepted.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	_ = w.Close()
	total := int64(8 * 500)
	t.Logf("接受 %d / %d（丢弃 %d）", accepted.Load(), total, w.Dropped())
	if accepted.Load()+int64(w.Dropped()) != total {
		t.Fatalf("接受+丢弃 应等于总数：%d + %d != %d",
			accepted.Load(), w.Dropped(), total)
	}
}

// TestSinkCloseErrorPropagates sink 关闭错误必须上报。
func TestSinkCloseErrorPropagates(t *testing.T) {
	fs := &failCloseSink{}
	w := New(fs)
	_ = w.Close()
	if err := w.Close(); err == nil {
		t.Fatal("sink 关闭失败时应从 Close 返回错误")
	}
}

type failCloseSink struct{ MemorySink }

func (f *failCloseSink) Name() string { return "failclose" }
func (f *failCloseSink) Close() error { return errors.New("模拟关闭失败") }
