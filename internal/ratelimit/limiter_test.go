package ratelimit

import (
	"context"
	"testing"
	"time"
)

// 限速器应把等待时间压在配置速率附近。
// rate=8192B/s burst=8192，总量 16384B：初始桶放行 8192，其余 8192 需等待约 1s。
func TestLimitedRate(t *testing.T) {
	l := New(0, 8192) // 下载方向 8KB/s
	start := time.Now()
	l.WaitDownload(context.Background(), 16384)
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond {
		t.Fatalf("elapsed=%v, 限速未生效", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("elapsed=%v, 等待时间过长", elapsed)
	}
}

func TestUnlimited(t *testing.T) {
	l := New(0, 0)
	start := time.Now()
	l.WaitDownload(context.Background(), 1<<20)
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("不限速时不应产生等待")
	}
}

// 单次等待超过桶容量时应分块且不 panic。
func TestWaitNChunking(t *testing.T) {
	l := New(0, 1000) // burst=4096
	start := time.Now()
	waitN(l.download, context.Background(), 4900) // 首块 4096 立即，第二块 804 需约 0.8s
	if time.Since(start) < 500*time.Millisecond {
		t.Fatalf("应产生等待时间")
	}
}

// TryWait 超时语义：拿不到配额返回 false，不无限阻塞。
func TestTryWaitTimeout(t *testing.T) {
	l := New(0, 100) // burst=4096；先耗尽桶，再要求远超速率的配额
	l.WaitDownload(context.Background(), 4096)
	start := time.Now()
	if l.TryWaitDownload(1<<20, 50*time.Millisecond) {
		t.Fatal("配额不足时应返回 false")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("TryWait 不应阻塞超过 maxWait 太多")
	}
	if !l.TryWaitDownload(1, 50*time.Millisecond) {
		t.Log("桶随时间恢复，此断言仅记录行为")
	}
}

// TestSharedModeTryWaitEnforced 回归（2026-11-02）：shared 形态下
// TryWaitUpload/TryWaitDownload 必须真正限速。
//
// 历史 bug：两个方法直接读 l.upload/l.download，而 NewSharedTotal 只设置
// l.shared，前两者是 nil → tryN 见 nil 直接返回 true，限速被完全绕过。
// 表现为：UDP 规则绑了带宽包（带宽包走 shared 形态）也照样满速。
// 生产影响面：UDP 的双向限速对绑包规则全部失效。
func TestSharedModeTryWaitEnforced(t *testing.T) {
	l := NewSharedTotal(100) // 100 B/s

	// 1 万字节远超桶容量：限速生效时必然超时返回 false
	if l.TryWaitUpload(10000, 20*time.Millisecond) {
		t.Fatal("★ shared 形态下 TryWaitUpload 未限速（直接放行）")
	}
	if l.TryWaitDownload(10000, 20*time.Millisecond) {
		t.Fatal("★ shared 形态下 TryWaitDownload 未限速（直接放行）")
	}
}

// TestSharedModeIsShared 上传与下载共用同一个桶——一侧耗尽后另一侧也必须等。
func TestSharedModeIsShared(t *testing.T) {
	l := NewSharedTotal(1000) // 1000 B/s，桶 4096 起步

	// 先耗尽：拿 4096（整个桶容量）应成功（桶初始满）
	if !l.TryWaitUpload(4096, 50*time.Millisecond) {
		t.Fatal("首个请求应能在桶满时通过")
	}
	// 紧接着再要 4096：桶已空，20ms 只能补 20 字节 → 必须失败
	if l.TryWaitDownload(4096, 20*time.Millisecond) {
		t.Fatal("★ 上传耗尽后下载仍能拿到配额，说明未共用同一个桶")
	}
}

// TestSeparateModeIndependent 非 shared 形态（New）下两个方向互不影响。
func TestSeparateModeIndependent(t *testing.T) {
	l := New(100, 0) // 只限上传
	if l.TryWaitUpload(100000, 20*time.Millisecond) {
		t.Fatal("上传方向应受限")
	}
	if !l.TryWaitDownload(100000, 20*time.Millisecond) {
		t.Fatal("未配置下载限速时不应受阻")
	}
}

// TestNilLimiterTryWait nil Limiter 不 panic，且视为不限速。
func TestNilLimiterTryWait(t *testing.T) {
	var l *Limiter
	if !l.TryWaitUpload(999999, time.Millisecond) || !l.TryWaitDownload(999999, time.Millisecond) {
		t.Fatal("nil Limiter 应视为不限速")
	}
}
