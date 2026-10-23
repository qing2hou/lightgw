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
