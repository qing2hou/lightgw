package ratelimit

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

const (
	// 桶容量：允许秒级突发。大额度（带宽包 1000MB/s 级）时 4MB 封顶会让等待循环
	// 退化成"每 4MB 等一次令牌"的节流器（实测 1000M 额度只跑 4MB/s）——
	// 大额度按比例放宽到 64MB。
	minBurst = 4096
	maxBurst = 4 << 20
	bigBurst = 64 << 20
)

// Limiter 规则级共享限速器，上传/下载方向独立。nil Limiter 或 0 速率表示不限。
// SharedTotal 形态（NewSharedTotal）：双向等同一个桶——上下行合计单额度
// （带宽包语义：两个方向合计不超额）。
type Limiter struct {
	upload   *rate.Limiter
	download *rate.Limiter
	shared   *rate.Limiter // 非 nil 时 upload/download 桶被忽略
}

func newRateLimiter(bytesPerSec int64) *rate.Limiter {
	if bytesPerSec <= 0 {
		return nil
	}
	burst := bytesPerSec
	cap := int64(maxBurst)
	if bytesPerSec > int64(maxBurst) {
		cap = int64(bigBurst) // 大额度按 64MB 桶（1000M 额度下 32KB 块近乎零等待）
	}
	if burst > cap {
		burst = cap
	}
	if burst < minBurst {
		burst = minBurst
	}
	return rate.NewLimiter(rate.Limit(bytesPerSec), int(burst))
}

func New(uploadBytesPerSec, downloadBytesPerSec int64) *Limiter {
	l := &Limiter{}
	l.upload = newRateLimiter(uploadBytesPerSec)
	l.download = newRateLimiter(downloadBytesPerSec)
	return l
}

// NewSharedTotal 双向合计单额度（bytesPerSec 为上下行总和上限）。
func NewSharedTotal(bytesPerSec int64) *Limiter {
	return &Limiter{shared: newRateLimiter(bytesPerSec)}
}

// Disabled 两个方向是否都不限速（splice 快路径的选择条件）。
func (l *Limiter) Disabled() bool {
	return l.upload == nil && l.download == nil && l.shared == nil
}

// WaitUpload 阻塞等待 n 字节的上传配额（shared 形态下与下载共享同一桶）。
func (l *Limiter) WaitUpload(ctx context.Context, n int) {
	if l.shared != nil {
		waitN(l.shared, ctx, n)
		return
	}
	waitN(l.upload, ctx, n)
}

// WaitDownload 阻塞等待 n 字节的下载配额（shared 形态下与上传共享同一桶）。
func (l *Limiter) WaitDownload(ctx context.Context, n int) {
	if l.shared != nil {
		waitN(l.shared, ctx, n)
		return
	}
	waitN(l.download, ctx, n)
}

func waitN(l *rate.Limiter, ctx context.Context, n int) {
	if l == nil || n <= 0 {
		return
	}
	// 单次 WaitN 不允许超过桶容量，分块等待
	for n > 0 {
		chunk := n
		if chunk > l.Burst() {
			chunk = l.Burst()
		}
		if err := l.WaitN(ctx, chunk); err != nil {
			return
		}
		n -= chunk
	}
}

// TryWaitUpload 尝试在 maxWait 内获取 n 字节上传配额，超时返回 false（UDP 丢包场景）。
func (l *Limiter) TryWaitUpload(n int, maxWait time.Duration) bool {
	return tryN(l.upload, n, maxWait)
}

// TryWaitDownload 尝试在 maxWait 内获取 n 字节下载配额，超时返回 false。
func (l *Limiter) TryWaitDownload(n int, maxWait time.Duration) bool {
	return tryN(l.download, n, maxWait)
}

func tryN(l *rate.Limiter, n int, maxWait time.Duration) bool {
	if l == nil || n <= 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxWait)
	defer cancel()
	for n > 0 {
		chunk := n
		if chunk > l.Burst() {
			chunk = l.Burst()
		}
		if err := l.WaitN(ctx, chunk); err != nil {
			return false
		}
		n -= chunk
	}
	return true
}
