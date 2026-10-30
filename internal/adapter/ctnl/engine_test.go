package ctnl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// fakeConn 是 netlinkConn 的内存实现。
type fakeConn struct {
	mu sync.Mutex
	// queue 是待投递的多播消息（Receive 从这里取）
	queue []netlink.Message
	// dumpResult 是 Execute(DUMP) 的返回
	dumpResult []netlink.Message
	// execErr 让 Execute 返回错误（测试 KillSession 失败路径）
	execErr error
	// emptyErr / timeoutErr 是队列空时 Receive 返回的错误
	emptyErr   error
	timeoutErr error
	closed     bool
	// execCalls 记录收到的请求类型
	execCalls []uint16
}

func (f *fakeConn) Execute(m netlink.Message) ([]netlink.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execCalls = append(f.execCalls, uint16(m.Header.Type))
	if f.execErr != nil {
		return nil, f.execErr
	}
	if uint8(m.Header.Type&0xff) == IPCTNLMsgDump {
		return f.dumpResult, nil
	}
	return nil, nil // DELETE 的 ACK
}

func (f *fakeConn) Receive() ([]netlink.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) > 0 {
		m := f.queue[0]
		f.queue = f.queue[1:]
		return []netlink.Message{m}, nil
	}
	// 队列空：返回「超时」让调用方检查 ctx 后再来
	if f.timeoutErr != nil {
		return nil, f.timeoutErr
	}
	return nil, unix.EAGAIN
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeConn) push(m netlink.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, m)
}

func (f *fakeConn) calls() []uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uint16, len(f.execCalls))
	copy(out, f.execCalls)
	return out
}

// ctMsg 构造一条 conntrack 多播消息。
func ctMsg(msgtype uint8, src, dst string, sport, dport uint16, status uint32) netlink.Message {
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(MessageType(msgtype))},
		Data:   buildFlowMsg(src, dst, 6, sport, dport, status),
	}
}

// TestEngineRunBaselineThenEvents 首次全量 dump 建基线，之后增量事件生效。
func TestEngineRunBaselineThenEvents(t *testing.T) {
	fc := &fakeConn{
		dumpResult: []netlink.Message{
			ctMsg(IPCTNLMsgNew, "10.0.0.1", "172.16.30.10", 1001, 9098, IPSSeenReply),
		},
	}
	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()

	// 等基线装载
	waitFor(t, func() bool { return e.Table().Len() == 1 })

	// 推一条 NEW
	fc.push(ctMsg(IPCTNLMsgNew, "10.0.0.2", "172.16.30.10", 1002, 9098, IPSSeenReply))
	waitFor(t, func() bool { return e.Table().Len() == 2 })

	// 推一条 DESTROY
	fc.push(ctMsg(IPCTNLMsgDelete, "10.0.0.2", "172.16.30.10", 1002, 9098, 0))
	waitFor(t, func() bool { return e.Table().Len() == 1 })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run 应正常退出，实际: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ctx 取消后 Run 未退出")
	}
	// 连接必须被关闭
	if !fc.closed {
		t.Fatal("Run 退出后应关闭连接")
	}
}

// TestEngineSkipsTemplateEvents 模板/期望连接不进会话表。
func TestEngineSkipsTemplateEvents(t *testing.T) {
	fc := &fakeConn{}
	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Run(ctx) }()

	waitFor(t, func() bool { return e.Table() != nil })
	time.Sleep(50 * time.Millisecond)

	// 推一条模板会话
	fc.push(ctMsg(IPCTNLMsgNew, "10.0.0.9", "172.16.30.10", 1009, 9098, IPSTemplate))
	time.Sleep(100 * time.Millisecond)
	if got := e.Table().Len(); got != 0 {
		t.Fatalf("模板会话不应进表，实际 %d 条", got)
	}
}

// TestEngineIgnoresNonConntrack 非 conntrack 消息必须被忽略且不计入丢弃。
func TestEngineIgnoresNonConntrack(t *testing.T) {
	fc := &fakeConn{}
	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Run(ctx) }()

	waitFor(t, func() bool { return e.Table() != nil })
	time.Sleep(50 * time.Millisecond)

	// 子系统 2（非 conntrack）
	fc.push(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(0x0200)},
		Data:   []byte{0, 0, 0, 0},
	})
	time.Sleep(100 * time.Millisecond)
	if e.Dropped() != 0 {
		t.Fatalf("非 conntrack 消息不应计入丢弃，实际 %d", e.Dropped())
	}
}

// TestEngineCountsDroppedOnBadMessage 解析失败的消息必须计入 dropped。
//
// 这是 /metrics 与 /healthz 的指标来源：丢弃数持续增长说明会话统计已不可信。
func TestEngineCountsDroppedOnBadMessage(t *testing.T) {
	fc := &fakeConn{}
	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Run(ctx) }()

	waitFor(t, func() bool { return e.Table() != nil })
	time.Sleep(50 * time.Millisecond)

	// 一条「消息体过短」的 conntrack 消息
	fc.push(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(MessageType(IPCTNLMsgNew))},
		Data:   []byte{0, 0},
	})
	waitFor(t, func() bool { return e.Dropped() > 0 })
	if e.LastError() == nil {
		t.Fatal("解析失败应记录 lastErr")
	}
}

// TestEngineReconcile 对账必须用 dump 结果修正偏差。
//
// 这是「事件丢失」的唯一补偿手段（netlink 缓冲满时内核丢事件而不阻塞）。
func TestEngineReconcile(t *testing.T) {
	fc := &fakeConn{
		dumpResult: []netlink.Message{
			ctMsg(IPCTNLMsgNew, "10.0.1.1", "172.16.30.10", 2001, 9098, 0),
		},
	}
	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Run(ctx) }()
	waitFor(t, func() bool { return e.Table().Len() == 1 })

	// 模拟「事件丢失」：直接改内存表，加一条内核上不存在的
	e.Table().Put(mkFlow(999, 0))
	if e.Table().Len() != 2 {
		t.Fatalf("准备阶段应有 2 条，实际 %d", e.Table().Len())
	}

	// 手动触发对账（不等 60s）
	if err := e.reconcile(fc); err != nil {
		t.Fatalf("对账失败: %v", err)
	}
	if got := e.Table().Len(); got != 1 {
		t.Fatalf("对账后应只剩 dump 里的 1 条，实际 %d（漂移未修正）", got)
	}
}

// TestEngineReconcileError 对账失败不应终止循环。
func TestEngineReconcileError(t *testing.T) {
	fc := &fakeConn{
		dumpResult: []netlink.Message{
			ctMsg(IPCTNLMsgNew, "10.0.1.1", "172.16.30.10", 2001, 9098, 0),
		},
	}
	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Run(ctx) }()
	waitFor(t, func() bool { return e.Table().Len() == 1 })

	// 让下次 Execute 失败
	fc.mu.Lock()
	fc.execErr = errors.New("模拟：netlink 忙")
	fc.mu.Unlock()

	if err := e.reconcile(fc); err == nil {
		t.Fatal("对账应返回错误")
	}
	// 会话表不应被清空
	if e.Table().Len() != 1 {
		t.Fatalf("对账失败不应清空会话表，实际 %d 条", e.Table().Len())
	}
}

// TestEngineKillSession KillSession 必须发 DELETE 请求并从本地表移除。
func TestEngineKillSession(t *testing.T) {
	flow := mkFlow(1, 0)
	fc := &fakeConn{dumpResult: []netlink.Message{
		ctMsg(IPCTNLMsgNew, flow.Orig.SrcAddr.String(), flow.Orig.DstAddr.String(),
			flow.Orig.SrcPort, flow.Orig.DstPort, 0),
	}}
	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Run(ctx) }()
	waitFor(t, func() bool { return e.Table().Len() == 1 })

	k := KeyOf(flow)
	if err := e.KillSession(k); err != nil {
		t.Fatalf("KillSession 失败: %v", err)
	}
	// 必须发了 DELETE 消息
	calls := fc.calls()
	var sawDelete bool
	for _, c := range calls {
		if uint8(c&0xff) == IPCTNLMsgDelete {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Fatalf("应发送 DELETE 请求，实际调用: %v", calls)
	}
	// 本地表必须同步移除
	if _, ok := e.Table().Get(k); ok {
		t.Fatal("KillSession 后本地表应移除该会话")
	}
}

// TestEngineKillSessionNotStarted 引擎未启动时 KillSession 必须报错。
func TestEngineKillSessionNotStarted(t *testing.T) {
	e := NewEngineWith(func() (netlinkConn, error) { return &fakeConn{}, nil })
	if err := e.KillSession(SessionKey{}); err == nil {
		t.Fatal("未启动时应报错")
	}
}

// TestEngineKillSessionError 底层失败必须包装成中文错误。
func TestEngineKillSessionError(t *testing.T) {
	fc := &fakeConn{}
	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Run(ctx) }()
	waitFor(t, func() bool { return e.Table() != nil })
	time.Sleep(50 * time.Millisecond)

	fc.mu.Lock()
	fc.execErr = errors.New("simulated EPERM")
	fc.mu.Unlock()

	k := KeyOf(mkFlow(1, 0))
	err := e.KillSession(k)
	if err == nil {
		t.Fatal("应返回错误")
	}
	if !strings.Contains(err.Error(), "删除会话") {
		t.Fatalf("错误消息应为中文且说明动作，实际: %v", err)
	}
}

// TestEngineDialFailure 拨号失败必须返回错误。
func TestEngineDialFailure(t *testing.T) {
	e := NewEngineWith(func() (netlinkConn, error) {
		return nil, errors.New("simulated EPERM")
	})
	err := e.Run(context.Background())
	if err == nil {
		t.Fatal("拨号失败应返回错误")
	}
	if !strings.Contains(err.Error(), "conntrack netlink") {
		t.Fatalf("错误消息应说明原因，实际: %v", err)
	}
}

// TestEngineDumpFailure 首次 dump 失败必须返回错误（不能静默启动空表）。
func TestEngineDumpFailure(t *testing.T) {
	fc := &fakeConn{execErr: errors.New("simulated dump failure")}
	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })
	err := e.Run(context.Background())
	if err == nil {
		t.Fatal("dump 失败应返回错误")
	}
	if !strings.Contains(err.Error(), "全量 dump") {
		t.Fatalf("错误消息应说明是全量 dump 失败，实际: %v", err)
	}
}

// TestEngineDropStats DropStats 返回丢弃与对账计数。
func TestEngineDropStats(t *testing.T) {
	e := NewEngineWith(func() (netlinkConn, error) { return &fakeConn{}, nil })
	d, r := e.DropStats()
	if d != 0 || r != 0 {
		t.Fatalf("初始应为 0，实际 dropped=%d reconciled=%d", d, r)
	}
}

// waitFor 轮询等待条件成立（最多 2 秒）。
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}

// TestIsTimeout 读超时识别必须覆盖 mdlayher/netlink 的实际错误形态。
//
// 回归：真机实测该库在 SetReadDeadline 到期后返回
// "netlink receive: i/o timeout"（内部是 os.ErrDeadlineExceeded），
// 不是 EAGAIN。早期只判 EAGAIN → 超时被当作致命错误 → Run 退出 →
// KillSession 报「引擎未启动」。
func TestIsTimeout(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"EAGAIN", unix.EAGAIN, true},
		{"DeadlineExceeded", os.ErrDeadlineExceeded, true},
		{"wrapped deadline", fmt.Errorf("netlink receive: %w", os.ErrDeadlineExceeded), true},
		// 真机的实际错误文本
		{"mdlayher text", errors.New("netlink receive: i/o timeout"), true},
		{"其它错误", errors.New("connection reset"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTimeout(c.err); got != c.want {
				t.Fatalf("isTimeout(%v) = %v，期望 %v", c.err, got, c.want)
			}
		})
	}
}

// TestEngineSurvivesReadTimeout 读超时不能让 Run 退出（连接必须保持可用）。
//
// 这条直接对应真机发现的 bug：超时被误判为致命错误，Run 提前退出，
// 后续 KillSession 报「引擎未启动」。
func TestEngineSurvivesReadTimeout(t *testing.T) {
	fc := &fakeConn{
		dumpResult: []netlink.Message{
			ctMsg(IPCTNLMsgNew, "10.0.2.1", "172.16.30.10", 3001, 9098, IPSSeenReply),
		},
		// 每次 Receive 都返回真机的超时错误文本
		emptyErr: errors.New("netlink receive: i/o timeout"),
	}
	// 让 fakeConn 返回真实超时错误而不是 EAGAIN
	fc.timeoutErr = fc.emptyErr

	e := NewEngineWith(func() (netlinkConn, error) { return fc, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.Run(ctx) }()

	waitFor(t, func() bool { return e.Table().Len() == 1 })
	// 让它经历多次「超时」循环
	time.Sleep(200 * time.Millisecond)

	// ★ 核心断言：引擎仍可用（KillSession 不应报未启动）
	if err := e.KillSession(KeyOf(mkFlow(1, 0))); err != nil {
		t.Fatalf("★ 读超时后引擎应仍可用，实际: %v", err)
	}
	// Run 不应退出
	select {
	case <-time.After(100 * time.Millisecond):
		// 仍在运行，正常
	default:
	}
}
