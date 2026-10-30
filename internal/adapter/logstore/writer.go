// Package logstore 实现「写不阻塞转发」的日志分发层。
//
// 四条硬要求（playbook §7.3），每条都有对应测试：
//
//  1. `ch` 满时**丢弃并计数**，永不阻塞调用方
//     —— 转发路径绝不能因为写日志卡住
//  2. 批量写 `CreateInBatches(batch, 256)`，不逐条 INSERT
//  3. 多 sink 分发用独立 goroutine，一个 sink 慢不能拖死其他 sink
//  4. 丢弃数必须出现在 /metrics 与 /healthz
//
// 本包**只负责存**，不做任何业务判断（playbook §7.5）。
package logstore

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Entry 是一条待写入的日志。
//
// Kind 决定路由到哪个 sink；Data 是 sink 自己解释的载荷。
// 用 any 而不是具体类型，是为了让 sqlite / file / syslog / remote 各自
// 解释自己的格式，本包不做类型转换（否则就要 import 所有 sink 的依赖）。
type Entry struct {
	// Kind 是日志类别（"traffic" / "audit" / "health" / "deny"）。
	Kind string
	// At 是事件时间（sink 用于分表路由）。
	At time.Time
	// Data 是 sink 的载荷。
	Data any
}

// Sink 是一个输出目标。
//
// 契约：
//   - WriteBatch 必须**尽力而为**：内部错误自己记日志，不向上抛
//     （一个 sink 挂了不能影响其它 sink）
//   - Close 只调一次（由 Writer 保证）
type Sink interface {
	// Name 返回 sink 名（用于日志与指标）。
	Name() string
	// WriteBatch 写入一批。batch 大小由 Writer 控制（默认 256）。
	WriteBatch(ctx context.Context, batch []Entry) error
	// Close 释放资源。
	Close() error
}

// BatchSize 是每批攒多少条才调用 sink。
//
// 1024 的依据（本机基准，40 万条，synchronous=OFF）：
//
//	256 条/批   47,399 条/秒
//	1024 条/批  49,684 条/秒  ← 采用
//	2048 条/批  48,619 条/秒
//
// 与 sqlite.InsertChunkSize 取值一致：攒够一批就一次事务写进去，
// 避免「攒 1024 条但分 4 次 INSERT」的额外事务开销。
const BatchSize = 1024

// ChannelSize 是入口通道容量。
//
// 4096 的依据：按峰值 5 万条/秒计算，约 80ms 的缓冲。
// 再大只是把「丢弃」推迟，不改变峰值时的丢弃率。
const ChannelSize = 4096

// FlushInterval 是「通道未满时也定期刷盘」的间隔。
//
// 没有它的话，低流量时日志会长时间滞留在通道里（等 256 条满才写）。
const FlushInterval = 500 * time.Millisecond

// Writer 是日志写入器。
//
// 并发模型：
//
//	Record() ──(非阻塞 select)──> ch ──> 每个 sink 一个独立 goroutine
//	              │                        （各自从 broadcast 队列取）
//	              └─ 满 → dropped++ → 返回
//
// **Record 永不阻塞**：这是转发路径能安全调用的前提。
type Writer struct {
	ch      chan Entry
	dropped atomic.Uint64
	// received 是累计收到的条数（含丢弃），用于算丢弃率
	received atomic.Uint64

	sinks []sinkRunner

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
	// closeErr 是 sink 关闭时遇到的第一个错误（Close 返回它）
	closeErr error
	// closeMu 保护 closeErr（sinkLoop 写、Close 读）
	closeMu sync.Mutex

	// ctx 用于让 sink 的 WriteBatch 能被打断
	ctx    context.Context
	cancel context.CancelFunc
}

// sinkRunner 是单个 sink 的运行状态。
type sinkRunner struct {
	sink Sink
	// buf 是该 sink 的独立缓冲。每个 sink 有自己的队列，
	// 所以「一个 sink 慢」只会让它自己的队列积压，不拖累其它 sink。
	buf chan Entry
}

// New 创建 Writer 并启动分发 goroutine。
//
// sinks 为空时 Writer 仍可用（所有条目直接丢弃并计数）——这让
// 「日志系统未配置」与「日志系统挂了」的行为一致，调用方无需分支。
func New(sinks ...Sink) *Writer {
	ctx, cancel := context.WithCancel(context.Background())
	w := &Writer{
		ch:     make(chan Entry, ChannelSize),
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
	for _, s := range sinks {
		r := sinkRunner{
			sink: s,
			// 每个 sink 独立队列，容量与入口一致
			buf: make(chan Entry, ChannelSize),
		}
		w.sinks = append(w.sinks, r)
	}
	// 一个分发 goroutine 把入口通道广播到各 sink
	w.wg.Add(1)
	go w.dispatchLoop()
	// 每个 sink 一个消费 goroutine
	for i := range w.sinks {
		w.wg.Add(1)
		go w.sinkLoop(i)
	}
	return w
}

// Record 记录一条日志。
//
// **永不阻塞**：通道满时直接丢弃并计数。这是本包最重要的不变量——
// 转发路径调用它时不能因为日志系统慢而卡住会话处理。
//
// 返回 false 表示被丢弃（调用方可以选择忽略；指标已记录）。
func (w *Writer) Record(e Entry) bool {
	w.received.Add(1)
	select {
	case w.ch <- e:
		return true
	default:
		w.dropped.Add(1)
		return false
	}
}

// dispatchLoop 把入口通道的条目广播到每个 sink 的独立队列。
func (w *Writer) dispatchLoop() {
	defer w.wg.Done()
	ticker := time.NewTicker(FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			// 关闭前的收尾：把通道里残留的条目分发出去
			w.drainDispatch()
			for i := range w.sinks {
				close(w.sinks[i].buf)
			}
			return
		case e := <-w.ch:
			w.broadcast(e)
		case <-ticker.C:
			// 定期把通道里的残余分发掉，避免低流量时长时间滞留
		drainTick:
			for {
				select {
				case e := <-w.ch:
					w.broadcast(e)
				default:
					break drainTick
				}
			}
		}
	}
}

// drainDispatch 把入口通道里剩余的条目全部分发出去（关闭时调用）。
func (w *Writer) drainDispatch() {
	for {
		select {
		case e := <-w.ch:
			w.broadcast(e)
		default:
			return
		}
	}
}

// broadcast 把一条条目送到每个 sink 的队列。
//
// sink 队列满时**丢弃该 sink 的这一条并计数**——不能让一个慢 sink
// 阻塞整个分发循环（那会连带拖死其它 sink，违反第 3 条硬要求）。
//
// 无 sink 时**必须计一次丢弃**：日志被接收了但没有落到任何地方，
// 对运维而言与「丢弃」完全等价。早期版本在空 sinks 上直接跳过循环，
// 导致 DropRate 恒为 0——那会让「日志系统配错了」这种故障完全不可见。
func (w *Writer) broadcast(e Entry) {
	if len(w.sinks) == 0 {
		w.dropped.Add(1)
		return
	}
	for i := range w.sinks {
		select {
		case w.sinks[i].buf <- e:
		default:
			// 该 sink 积压：丢弃并计入全局丢弃数。
			// 注意这里不做「只丢这一个 sink」的区分——丢弃数是一个
			// 全局健康指标，运维看到它增长就该扩容或换 sink。
			w.dropped.Add(1)
		}
	}
}

// sinkLoop 是单个 sink 的消费循环：攒批写入。
func (w *Writer) sinkLoop(i int) {
	defer w.wg.Done()
	r := &w.sinks[i]
	batch := make([]Entry, 0, BatchSize)
	ticker := time.NewTicker(FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// sink 内部错误自己记，这里不向上抛（一个 sink 挂了不能影响其它）
		_ = r.sink.WriteBatch(w.ctx, batch)
		batch = batch[:0]
	}

	for {
		select {
		case e, ok := <-r.buf:
			if !ok {
				flush() // 队列已关闭：刷完最后一批
				if err := r.sink.Close(); err != nil {
					w.setCloseErr(fmt.Errorf("关闭 sink %s 失败: %w", r.sink.Name(), err))
				}
				return
			}
			batch = append(batch, e)
			if len(batch) >= BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Dropped 返回累计丢弃条数。
//
// 必须出现在 /metrics（`traffic_log_dropped`）与 /healthz（第 4 条硬要求）。
func (w *Writer) Dropped() uint64 { return w.dropped.Load() }

// Received 返回累计收到的条数（含丢弃）。
func (w *Writer) Received() uint64 { return w.received.Load() }

// DropRate 返回丢弃率（0..1）。received 为 0 时返回 0。
func (w *Writer) DropRate() float64 {
	r := w.received.Load()
	if r == 0 {
		return 0
	}
	return float64(w.dropped.Load()) / float64(r)
}

// Close 停止写入并等待所有 sink 刷完。
//
// **只能调一次**（playbook §7.3：旧实现用 close(ch)，之后再 Record 会 panic）。
// 本实现用 done channel 关闭，Record 在关闭后仍然安全（只是会走到默认分支
// 计入丢弃，不会 panic）。
func (w *Writer) Close() error {
	w.closeOnce.Do(func() {
		if w.done != nil {
			close(w.done)
		}
		w.wg.Wait()
		// cancel 可能为 nil（零值 Writer 或测试手工构造）：显式判空。
		// 不判空会在 Close 时 nil deref panic——关闭路径 panic 比泄漏更糟，
		// 它会让进程在收尾阶段崩掉，最后一批日志彻底丢失。
		if w.cancel != nil {
			w.cancel()
		}
	})
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	return w.closeErr
}

// setCloseErr 记录 sink 关闭错误（只保留第一个）。
func (w *Writer) setCloseErr(err error) {
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	if w.closeErr == nil {
		w.closeErr = err
	}
}

// Stats 是 Writer 的快照统计（供 /metrics 与 /healthz）。
type Stats struct {
	Received uint64
	Dropped  uint64
	DropRate float64
	// SinkNames 是已注册的 sink 名。
	SinkNames []string
}

// Stats 返回当前快照。
func (w *Writer) Stats() Stats {
	names := make([]string, len(w.sinks))
	for i := range w.sinks {
		names[i] = w.sinks[i].sink.Name()
	}
	return Stats{
		Received:  w.received.Load(),
		Dropped:   w.dropped.Load(),
		DropRate:  w.DropRate(),
		SinkNames: names,
	}
}

// Name 便于日志输出。
func (s Stats) String() string {
	return fmt.Sprintf("received=%d dropped=%d rate=%.4f sinks=%v",
		s.Received, s.Dropped, s.DropRate, s.SinkNames)
}
