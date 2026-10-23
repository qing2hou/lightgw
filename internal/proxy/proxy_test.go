package proxy

import (
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/model"
	"haproxyweb/internal/trafficlog"
)

// newFullManager 带真实 SQLite 与流量日志写入器的 Manager，可跑完整转发链路。
func newFullManager(t *testing.T, opts Options) *Manager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "t.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.TrafficLog{}, &model.ForwardRule{}, &model.HealthLog{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	tlog := trafficlog.New(db, 1)
	t.Cleanup(func() { tlog.Close() })
	return NewManager(db, tlog, 0, opts)
}

// freePort 借一个空闲 TCP 端口（借出即释放，极端并发下可能被抢占，测试可接受）。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("借用端口失败: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// echoServer TCP 回显后端。
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动回显后端失败: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// echoUDPServer UDP 回显后端。
func echoUDPServer(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("启动 UDP 回显后端失败: %v", err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().String()
}

// applyListen 应用一条启用规则并返回其监听地址。
func applyListen(t *testing.T, m *Manager, rule model.ForwardRule) string {
	t.Helper()
	port := freePort(t)
	rule.ListenAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	rule.Enabled = true
	if err := m.Apply(rule); err != nil {
		t.Fatalf("应用规则失败: %v", err)
	}
	return rule.ListenAddr
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("条件未在超时内满足")
}

// 全局连接上限：第 2 条连接被拒绝，名额释放后恢复可用。
func TestGlobalConnLimit(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096, MaxGlobalConns: 1})
	listen := applyListen(t, m, model.ForwardRule{
		Name: "g", Protocol: model.ProtocolTCP, TargetAddr: echoServer(t),
	})

	c1, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("第一个连接应能建立: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(m.ActiveSessions()) == 1 })

	c2, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("TCP 层应能完成握手: %v", err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("超出全局上限的连接应被关闭")
	}
	waitFor(t, 2*time.Second, func() bool { return m.rejectedGlobal.Load() == 1 })

	// 释放名额后新连接可用且转发正常（回显）
	_ = c1.Close()
	waitFor(t, 2*time.Second, func() bool { return len(m.ActiveSessions()) == 0 })
	c3, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("释放后连接应能建立: %v", err)
	}
	defer func() { _ = c3.Close() }()
	if _, err := c3.Write([]byte("ping")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	_ = c3.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c3.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("回显不符: n=%d err=%v", n, err)
	}
}

// 规则级连接上限：与全局互不影响，行为一致。
func TestRuleConnLimit(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096})
	listen := applyListen(t, m, model.ForwardRule{
		Name: "r", Protocol: model.ProtocolTCP, TargetAddr: echoServer(t), MaxConns: 1,
	})

	c1, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("第一个连接应能建立: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(m.ActiveSessions()) == 1 })

	c2, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("TCP 层应能完成握手: %v", err)
	}
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := c2.Read(buf); err == nil {
		t.Fatal("超出规则上限的连接应被关闭")
	}
	waitFor(t, 2*time.Second, func() bool { return m.rejectedRule.Load() == 1 })
	_ = c1.Close()
}

// UDP 全局会话上限：新客户端的包被丢弃，现有会话不受影响。
func TestUDPGlobalConnLimit(t *testing.T) {
	m := newFullManager(t, Options{MaxGlobalConns: 1})
	listen := applyListen(t, m, model.ForwardRule{
		Name: "u", Protocol: model.ProtocolUDP, TargetAddr: echoUDPServer(t),
	})

	a, err := net.Dial("udp", listen)
	if err != nil {
		t.Fatalf("UDP 拨号失败: %v", err)
	}
	defer func() { _ = a.Close() }()
	if _, err := a.Write([]byte("ping")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(m.ActiveSessions()) == 1 })
	_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := a.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("回显不符: n=%d err=%v", n, err)
	}

	// 第二个客户端：全局会话已满，包应被丢弃
	b, err := net.Dial("udp", listen)
	if err != nil {
		t.Fatalf("UDP 拨号失败: %v", err)
	}
	defer func() { _ = b.Close() }()
	if _, err := b.Write([]byte("beep")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	_ = b.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := b.Read(buf); err == nil {
		t.Fatal("超出全局上限的 UDP 会话包应被丢弃")
	}
	waitFor(t, 2*time.Second, func() bool { return m.rejectedGlobal.Load() == 1 })
}

// panic 隔离模式冒烟：defer 内直接 recover + 计数，进程不退出。
func TestPanicIsolation(t *testing.T) {
	m := newTestManager(4096, 0)
	before := m.panics.Load()
	func() {
		defer func() {
			if r := recover(); r != nil {
				m.logPanic("测试协程", r)
			}
		}()
		panic("boom")
	}()
	if m.panics.Load() != before+1 {
		t.Fatalf("panic 计数未增加: %d -> %d", before, m.panics.Load())
	}
}

// StopAll 应排空存量连接：客户端断开后排空完成且流量日志落库。
func TestStopAllDrainsActiveConns(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096, DrainTimeout: 5 * time.Second})
	listen := applyListen(t, m, model.ForwardRule{
		Name: "d", Protocol: model.ProtocolTCP, TargetAddr: echoServer(t),
	})

	c1, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(m.ActiveSessions()) == 1 })

	done := make(chan struct{})
	go func() {
		m.StopAll()
		close(done)
	}()
	// 客户端未断开前，排空不应完成
	time.Sleep(300 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("客户端未断开前 StopAll 不应返回")
	default:
	}

	_ = c1.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("排空未在预期时间内完成")
	}
	assertTrafficLogged(t, m.db, 1)
}

// 排空超时后应强制关闭存量连接，流量日志仍落库。
func TestStopAllForceClosesOnDrainTimeout(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096, DrainTimeout: 300 * time.Millisecond})
	listen := applyListen(t, m, model.ForwardRule{
		Name: "f", Protocol: model.ProtocolTCP, TargetAddr: echoServer(t),
	})

	c1, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer func() { _ = c1.Close() }()
	waitFor(t, 2*time.Second, func() bool { return len(m.ActiveSessions()) == 1 })

	done := make(chan struct{})
	go func() {
		m.StopAll()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("强制关闭后 StopAll 未返回")
	}
	assertTrafficLogged(t, m.db, 1)
}

// assertTrafficLogged 等待流量日志异步批量落库后断言条数。
func assertTrafficLogged(t *testing.T, db *gorm.DB, want int64) {
	t.Helper()
	var n int64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := db.Model(&model.TrafficLog{}).Count(&n).Error; err != nil {
			t.Fatalf("查询流量日志失败: %v", err)
		}
		if n >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("流量日志条数不足: got %d want >= %d", n, want)
}

// 规则指标快照应随会话生命周期正确累计，ForgetRule 后条目被清理。
func TestRuleMetricsSnapshot(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096})
	listen := applyListen(t, m, model.ForwardRule{
		Name: "m", Protocol: model.ProtocolTCP, TargetAddr: echoServer(t),
	})

	c1, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(m.ActiveSessions()) == 1 })

	rms := m.RuleMetrics()
	if len(rms) != 1 {
		t.Fatalf("应有 1 条规则指标，实际 %d", len(rms))
	}
	rm := rms[0]
	if rm.Name != "m" || rm.Protocol != model.ProtocolTCP || rm.ConnCurrent != 1 || rm.ConnTotal != 1 {
		t.Errorf("规则指标不符: %+v", rm)
	}

	if _, err := c1.Write([]byte("hello")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	buf := make([]byte, 5)
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c1.Read(buf); err != nil {
		t.Fatalf("回显读取失败: %v", err)
	}
	if m.RuleMetrics()[0].BytesUp < 5 {
		t.Errorf("上传字节数应已累计: %+v", m.RuleMetrics()[0])
	}

	_ = c1.Close()
	waitFor(t, 2*time.Second, func() bool { return len(m.ActiveSessions()) == 0 })

	rm = m.RuleMetrics()[0]
	if rm.ConnCurrent != 0 {
		t.Errorf("会话结束后 ConnCurrent 应归零: %+v", rm)
	}

	m.ForgetRule(rm.ID)
	if len(m.RuleMetrics()) != 0 {
		t.Error("ForgetRule 后指标条目应被清理")
	}
}

// 后端拨号失败必须立即关闭客户端连接（曾存在悬挂到 GC 才回收的缺陷）。
func TestDialFailureClosesClient(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096})
	// 借一个端口后立即归还，构造"必然拒绝连接"的目标
	port := freePort(t)
	listen := applyListen(t, m, model.ForwardRule{
		Name: "fail", Protocol: model.ProtocolTCP, TargetAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
	})

	c, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer func() { _ = c.Close() }()

	// 客户端应在 2s 内收到关闭（EOF/重置），而不是悬挂
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("后端不可达时客户端连接应被立即关闭")
	}
	assertTrafficLogged(t, m.db, 1)
}

// 客户端以 RST 强制断开（关窗口/传完即退的典型行为）应记为正常关闭而非出错。
func TestPeerResetLoggedAsClosed(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096})
	listen := applyListen(t, m, model.ForwardRule{
		Name: "rst", Protocol: model.ProtocolTCP, TargetAddr: echoServer(t),
	})

	c, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(m.ActiveSessions()) == 1 })

	// SO_LINGER(0) + Close = 发送 RST 而非 FIN
	tc := c.(*net.TCPConn)
	_ = tc.SetLinger(0)
	_ = tc.Close()

	assertTrafficLogged(t, m.db, 1)
	var tl model.TrafficLog
	if err := m.db.Order("id DESC").First(&tl).Error; err != nil {
		t.Fatalf("查询日志失败: %v", err)
	}
	if tl.Status != model.StatusClosed {
		t.Errorf("对端 RST 应记为正常关闭，实际 %q（%s）", tl.Status, tl.ErrorMsg)
	}
	if !strings.Contains(tl.ErrorMsg, "reset") {
		t.Errorf("说明列应保留重置原话，实际: %q", tl.ErrorMsg)
	}
}
