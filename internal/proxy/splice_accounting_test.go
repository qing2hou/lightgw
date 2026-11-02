// splice 快路径的字节记账回归（2026-11-02）。
//
// 历史缺陷：copyFast 直接 `TCPConn.ReadFrom(src)` 一口气搬完整个会话，
// 字节数只在返回时入账一次 → 传输期间实时速率与会话字节恒为 0，
// 用户看到"上传/下载时实时速率和会话表都没数据"。
//
// 修复：用 io.LimitedReader 分块（spliceChunk），每块返回即 addBytes 记账。
// 这些测试锁住"中途可见"这个行为。
package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestCopyFastAccountsProgressively 断言 copyFast 在传输**进行中**就能看到字节增长。
//
// 构造：一个慢速发送端（分多块、块间 sleep），大小超过 spliceChunk 或至少
// 多块。若实现退化成"一次性 ReadFrom"，中途采样会恒为 0。
func TestCopyFastAccountsProgressively(t *testing.T) {
	m := newTestManager(0, 60*time.Second)
	sess := &session{}

	// 服务端：接受连接后持续写入，块间停顿，模拟长传输
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer func() { _ = ln.Close() }()

	const chunk = 256 << 10 // 256KB
	const rounds = 8
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, chunk)
		for i := 0; i < rounds; i++ {
			if _, err := c.Write(buf); err != nil {
				return
			}
			time.Sleep(40 * time.Millisecond)
		}
	}()

	// 客户端：连上去后作为 copyFast 的 src（读）
	src, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer func() { _ = src.Close() }()

	// dst：本地另一个监听的对端（copyFast 往它写）
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer func() { _ = ln2.Close() }()
	go func() {
		c, err := ln2.Accept()
		if err != nil {
			return
		}
		// 只读不写，读完丢弃
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}()
	dstConn, err := net.Dial("tcp", ln2.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer func() { _ = dstConn.Close() }()

	go func() { _ = m.copyFast(dstConn, src, sess, true) }()

	// 传输进行中采样：必须能看到字节增长
	var sawProgress bool
	for i := 0; i < 15; i++ {
		time.Sleep(40 * time.Millisecond)
		if sess.down.Load() > 0 {
			sawProgress = true
			break
		}
	}
	if !sawProgress {
		t.Fatal("★ copyFast 传输期间字节恒为 0：实时速率与会话表都不会有数据")
	}
	t.Logf("传输中已见字节: %d", sess.down.Load())

	<-done
}

// TestCopyFastFeedsRateMeter 断言 copyFast 走 addBytes，从而喂到速率窗口。
//
// 若实现只加原子量（sess.down / stats.BytesDown）而不调 addBytes，
// RateUp/RateDown 恒为 0，页面显示 0 B/s。
func TestCopyFastFeedsRateMeter(t *testing.T) {
	m := newTestManager(0, 60*time.Second)
	st := &ruleStats{Name: "t", Protocol: "tcp"}
	sess := &session{stats: st}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 128<<10)
		for i := 0; i < 6; i++ {
			if _, err := c.Write(buf); err != nil {
				return
			}
			time.Sleep(40 * time.Millisecond)
		}
	}()

	src, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer func() { _ = src.Close() }()

	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = ln2.Close() }()
	go func() {
		c, err := ln2.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}()
	dstConn, err := net.Dial("tcp", ln2.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer func() { _ = dstConn.Close() }()

	done := make(chan struct{})
	go func() { defer close(done); _ = m.copyFast(dstConn, src, sess, true) }()

	// 速率窗口在传输中就该有非零值
	var sawRate bool
	for i := 0; i < 15; i++ {
		time.Sleep(40 * time.Millisecond)
		if st.RateDown.Rate() > 0 {
			sawRate = true
			break
		}
	}
	if !sawRate {
		t.Fatal("★ copyFast 未喂速率窗口（RateDown 恒 0）：页面实时速率会显示 0")
	}
	<-done
}
