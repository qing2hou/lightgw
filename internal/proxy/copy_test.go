package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"haproxyweb/internal/model"
)

// newTestManager 构造仅含拷贝循环所需依赖的 Manager。
func newTestManager(bufferSize int, idle time.Duration) *Manager {
	if bufferSize <= 0 {
		bufferSize = 32768
	}
	m := &Manager{bufs: newBufferPool(bufferSize)}
	m.optsStore.Store(&Options{BufferSize: bufferSize, TCPIdleTimeout: idle, TCPDialTimeout: 2 * time.Second})
	return m
}

// dialPair 建立一对 loopback TCP 连接：client 为拨号端，server 为接受端，
// 测试结束时自动关闭两端。写入 server 的数据可从 client 读到，反之亦然。
func dialPair(t *testing.T) (client net.Conn, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("接受连接失败: %v", r.err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = r.c.Close()
	})
	return client, r.c
}

func testCfg(t *testing.T, m *Manager, uploadKBps int64) *ruleConfig {
	t.Helper()
	return m.buildRuleConfig(model.ForwardRule{
		Protocol:        model.ProtocolTCP,
		UploadLimitKBps: uploadKBps,
	})
}

// 拷贝循环应精确计数并在对端关闭（EOF）时正常返回。
func TestCopyTCPCountsAndEOF(t *testing.T) {
	m := newTestManager(4096, 0)
	srcC, srcS := dialPair(t) // copyTCP 读 srcC，测试向 srcS 写入
	dstC, dstS := dialPair(t) // copyTCP 写 dstC，dstS 持续排空

	// 持续排空 dstS，避免写端阻塞影响计数验证
	go func() { _, _ = io.Copy(io.Discard, dstS) }()

	sess := m.registerSession(testCfg(t, m, 0), "1.2.3.4", 12345, "", 0)
	payload := bytes.Repeat([]byte("x"), 300000)
	done := make(chan error, 1)
	go func() { done <- m.copyTCP(dstC, srcC, testCfg(t, m, 0), sess, false, context.Background()) }()

	if _, err := srcS.Write(payload); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	_ = srcS.Close() // 对端关闭 → srcC 读到 EOF

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("拷贝应正常结束，实际: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("拷贝未在预期时间内结束")
	}
	if got := sess.up.Load(); got != int64(len(payload)) {
		t.Fatalf("计数不符: got %d want %d", got, len(payload))
	}
}

// 限速热跟随：会话进行中 cfg 原子替换（带宽包编辑路径）后，
// 拷贝循环下一块起立即用新限速器——不断会话、新额度即时生效。
func TestCopyTCPLimiterHotFollow(t *testing.T) {
	m := newTestManager(4096, 0)
	srcC, srcS := dialPair(t)
	dstC, dstS := dialPair(t)
	go func() { _, _ = io.Copy(io.Discard, dstS) }()

	var cfgPtr atomic.Pointer[ruleConfig]
	sess := m.registerSession(testCfg(t, m, 0), "1.2.3.4", 12345, "", 0)
	sess.cfgPtr = &cfgPtr

	// 初始：不限速（0）
	cfgPtr.Store(testCfg(t, m, 0))
	done := make(chan error, 1)
	go func() { done <- m.copyTCP(dstC, srcC, testCfg(t, m, 0), sess, false, context.Background()) }()

	// 第一批：不限速，快速通过
	first := bytes.Repeat([]byte("a"), 32*1024)
	if _, err := srcS.Write(first); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for sess.up.Load() < int64(len(first)) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sess.up.Load() < int64(len(first)) {
		t.Fatal("不限速阶段数据未按时通过")
	}
	t1 := sess.up.Load()

	// 热替换：限速 32KB/s（32*1024 B/s）——下一块起生效
	cfgPtr.Store(testCfg(t, m, 32))

	// 第二批：128KB，32KB/s 下至少需 3 秒——验证慢速跟随
	second := bytes.Repeat([]byte("b"), 128*1024)
	start := time.Now()
	if _, err := srcS.Write(second); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	// 等到全部通过或超时（32KB/s 下 128KB 至少需 ~3s）
	for time.Now().Before(start.Add(10*time.Second)) && sess.up.Load()-t1 < int64(len(second)) {
		time.Sleep(20 * time.Millisecond)
	}
	el := time.Since(start)
	passed := sess.up.Load() - t1
	// 热跟随成立：128KB 在 32KB/s 下无法在 1.5s 内全部通过（至少需 ~3s）
	if el < 1500*time.Millisecond && passed >= int64(len(second)) {
		t.Fatalf("热更新限速未生效：128KB 在 %.1fs 内全部通过（32KB/s 下应≥3s）", el.Seconds())
	}
	_ = srcS.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("拷贝应正常结束，实际: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("拷贝未在预期时间内结束")
	}
}

// 空闲超过配置时长后拷贝应返回 errIdleTimeout，且计数包含超时前已收到的字节。
// 连接级空闲语义（P1 修复回归）：本方向无数据、但对向方向持续活跃（touch 刷新）
// 时不应被误杀；活动停止后按 idle 正常超时。原缺陷：纯下载会话的上行方向
// 60s 必被自己的方向级 deadline 切断（全速下载中静默断流）。
func TestCopyTCPIdleConnectionLevel(t *testing.T) {
	m := newTestManager(4096, 300*time.Millisecond)
	srcC, _ := dialPair(t) // 本方向读 srcC（模拟客户端侧：纯下载期间无上行数据）
	dstC, dstS := dialPair(t)
	go func() { _, _ = io.Copy(io.Discard, dstS) }()

	cfgUp := testCfg(t, m, 0)
	cfgUp.idleTimeout = 300 * time.Millisecond
	sess := m.registerSession(cfgUp, "1.2.3.4", 12345, "", 0)
	sess.touch()

	done := make(chan error, 1)
	go func() { done <- m.copyTCP(dstC, srcC, cfgUp, sess, false, context.Background()) }()

	// 模拟对向（下载）方向持续活跃：每 80ms touch 一次，持续 900ms（远超 300ms idle）
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(80 * time.Millisecond):
				sess.touch()
			}
		}
	}()
	// 活跃期内本方向不应被切断
	select {
	case err := <-done:
		t.Fatalf("对向活跃期间不应超时（连接级空闲语义未生效）: %v", err)
	case <-time.After(900 * time.Millisecond):
	}
	close(stop)
	// 活动停止后应在 idle+缓冲 内返回 errIdleTimeout
	select {
	case err := <-done:
		if !errors.Is(err, errIdleTimeout) {
			t.Fatalf("应返回空闲超时，实际: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("活动停止后空闲超时未生效")
	}
}

func TestCopyTCPIdleTimeout(t *testing.T) {	m := newTestManager(4096, 200*time.Millisecond)
	srcC, srcS := dialPair(t)
	dstC, dstS := dialPair(t)
	go func() { _, _ = io.Copy(io.Discard, dstS) }()

	sess := m.registerSession(testCfg(t, m, 0), "1.2.3.4", 12345, "", 0)
	first := bytes.Repeat([]byte("y"), 100)
	done := make(chan error, 1)
	go func() { done <- m.copyTCP(dstC, srcC, testCfg(t, m, 0), sess, true, context.Background()) }()

	if _, err := srcS.Write(first); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, errIdleTimeout) {
			t.Fatalf("应返回空闲超时，实际: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("空闲超时未生效")
	}
	if got := sess.down.Load(); got != int64(len(first)) {
		t.Fatalf("超时前计数不符: got %d want %d", got, len(first))
	}
}

// 配置了限速时拷贝应被限速器拖慢（限速逻辑仍接入拷贝循环）。
func TestCopyTCPRateLimited(t *testing.T) {
	m := newTestManager(8192, 0)
	srcC, srcS := dialPair(t)
	dstC, dstS := dialPair(t)
	go func() { _, _ = io.Copy(io.Discard, dstS) }()

	sess := m.registerSession(testCfg(t, m, 64), "1.2.3.4", 12345, "", 0)
	payload := bytes.Repeat([]byte("z"), 131072) // 128KB
	done := make(chan error, 1)
	go func() { done <- m.copyTCP(dstC, srcC, testCfg(t, m, 64), sess, false, context.Background()) }()

	start := time.Now()
	if _, err := srcS.Write(payload); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	_ = srcS.Close()
	if err := <-done; err != nil {
		t.Fatalf("拷贝失败: %v", err)
	}
	// rate=64KB/s，burst=64KB：多出的 64KB 需约 1s
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("限速未生效: elapsed=%v", elapsed)
	}
	if got := sess.up.Load(); got != int64(len(payload)) {
		t.Fatalf("限速路径计数不符: got %d want %d", got, len(payload))
	}
}

func TestPickError(t *testing.T) {
	if err := pickError(nil, nil); err != nil {
		t.Errorf("无错误时应返回 nil，实际: %v", err)
	}
	if !errors.Is(pickError(nil, errIdleTimeout), errIdleTimeout) {
		t.Error("仅空闲超时应返回 errIdleTimeout")
	}
	if !errors.Is(pickError(errIdleTimeout, errIdleTimeout), errIdleTimeout) {
		t.Error("全部空闲超时应返回 errIdleTimeout")
	}
	realErr := errors.New("boom")
	if got := pickError(errIdleTimeout, realErr); got != realErr {
		t.Errorf("真实错误应优先于空闲超时: got %v", got)
	}
	if got := pickError(io.ErrUnexpectedEOF, nil); got != io.ErrUnexpectedEOF {
		t.Errorf("普通错误应原样返回: got %v", got)
	}
	// 重置类：优先于空闲超时、让位于真实错误
	resetErr := fmt.Errorf("read tcp: %w", syscall.ECONNRESET)
	if got := pickError(errIdleTimeout, resetErr); got != resetErr {
		t.Errorf("重置应优先于空闲超时: got %v", got)
	}
	if got := pickError(resetErr, realErr); got != realErr {
		t.Errorf("真实错误应优先于重置: got %v", got)
	}
	// 分类：ECONNRESET/EPIPE/net.ErrClosed 属正常收尾
	if classifyConnErr(resetErr) != connErrReset {
		t.Error("ECONNRESET 应归类为重置")
	}
	if classifyConnErr(fmt.Errorf("write: %w", syscall.EPIPE)) != connErrReset {
		t.Error("EPIPE 应归类为重置")
	}
	if classifyConnErr(fmt.Errorf("read: %w", net.ErrClosed)) != connErrReset {
		t.Error("本端主动关闭应归类为重置")
	}
	if classifyConnErr(io.ErrUnexpectedEOF) != connErrReal {
		t.Error("意外 EOF 应归类为真实错误")
	}
}
