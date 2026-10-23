package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Options 转发引擎运行参数，来自配置 tuning 节，进程生命周期内不变。
type Options struct {
	MaxGlobalConns         int           // 进程级并发连接总上限，0 = 不限
	TCPIdleTimeout         time.Duration // TCP 空闲连接超时（可被规则覆盖），0 = 禁用
	TCPDialTimeout         time.Duration // TCP 后端拨号超时
	UDPSessionIdle         time.Duration // UDP 会话空闲回收时间
	UDPLimiterMaxWait      time.Duration // UDP 限速单包最长等待
	BufferSize             int           // TCP 拷贝缓冲区字节数
	Splice                 bool          // 零拷贝快路径（仅无限速规则）
	DrainTimeout           time.Duration // 优雅关闭排空宽限，0 = 不等待
	HealthCheckInterval    time.Duration // 后端健康检查周期（仅 TCP 规则），<=0 取默认 60s
	HealthLogRetentionDays int           // 健康检测记录保留天数（入库），<=0 不清理
	GlobalUploadKBps       int64         // 整机上传带宽上限 KB/s，0 = 不限
	GlobalDownloadKBps     int64         // 整机下载带宽上限 KB/s，0 = 不限
	HealthWebhookURL       string        // 健康状态翻转通知地址，空 = 关闭
}

// errIdleTimeout TCP 空闲超时哨兵错误：空闲断开属正常关闭，流量日志不记为 error。
var errIdleTimeout = errors.New("连接空闲超时")

// bufferPool 固定尺寸拷贝缓冲池。所有 TCP 连接共享，消除每连接 2×buf 的稳态堆分配。
type bufferPool struct {
	pool sync.Pool
}

func newBufferPool(size int) *bufferPool {
	return &bufferPool{pool: sync.Pool{New: func() any {
		b := make([]byte, size)
		return &b
	}}}
}

func (p *bufferPool) get() *[]byte  { return p.pool.Get().(*[]byte) }
func (p *bufferPool) put(b *[]byte) { p.pool.Put(b) }

// copyTCP 单向拷贝循环：读 src 写 dst，循环内完成字节数统计、限速等待与空闲超时续期。
// 相比 io.Copy + 包装链：零额外堆分配（池化缓冲）、每块读后即续期 deadline、
// 计数不经过包装对象。EOF 视为正常结束返回 nil。
//
// 空闲超时语义（连接级）：deadline 基于**会话级最后活动时刻**（sess.lastActive，
// 任一方向有数据都刷新）判定，而非本方向自己的读活动——纯下行/纯上行会话
// （如 wget 下载全程客户端不发数据）不会因对向无数据被误杀（P1 缺陷修复：
// 原实现两方向各自 deadline，纯下载 60s 必被上行方向的空闲超时切断）。
// 实现：Read deadline 取 min(连接级截止, now+1s 轮询)；到点后复查 lastActive
// ——对向延长了活动则重新装填继续阻塞（纯等待场景每秒至多一次空转唤醒），
// 连接级真超时才返回 errIdleTimeout。
//
// 限速热跟随：每块数据前从 entry.cfg 原子指针重取限速器——带宽包编辑/规则更新
// 触发 cfg.Store 后，存量连接下一块即用新额度（不中断会话、即时生效）。
const idlePollInterval = time.Second

func (m *Manager) copyTCP(dst, src net.Conn, cfg *ruleConfig, sess *session, download bool, ctx context.Context) error {
	buf := m.bufs.get()
	defer m.bufs.put(buf)

	idle := cfg.idleTimeout
	limiter := cfg.limiter
	for {
		if idle > 0 {
			limit := sess.activeAt().Add(idle) // 连接级空闲截止
			dl := limit
			if now := time.Now(); dl.After(now.Add(idlePollInterval)) {
				dl = now.Add(idlePollInterval) // 截止还很远：先装轮询刻度
			} else if !dl.After(now) {
				dl = now.Add(100 * time.Millisecond) // 已过期：短暂等待统一走超时路径
			}
			_ = src.SetReadDeadline(dl)
			_ = dst.SetWriteDeadline(dl)
		}
		n, rerr := src.Read(*buf)
		if n > 0 {
			sess.touch() // 连接级活动：对向方向的空闲窗口随之后移
			sess.addBytes(download, int64(n))
			// 热跟随：配置可能已被原子替换（带宽包编辑等 tc-only 场景），
			// 取当前快照的限速器——存量连接立即按新额度整形
			if l := sess.currentLimiter(); l != nil {
				limiter = l
			}
			if download {
				limiter.WaitDownload(ctx, n)
			} else {
				limiter.WaitUpload(ctx, n)
			}
			// 整机带宽上限：规则限速之后二次等待（两处任一为 0 都视为不限）
			if gl := m.globalLimiter.Load(); gl != nil {
				if download {
					gl.WaitDownload(ctx, n)
				} else {
					gl.WaitUpload(ctx, n)
				}
			}
			written := 0
			for written < n {
				if idle > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(idle))
				}
				nw, werr := dst.Write((*buf)[written:n])
				written += nw
				if werr != nil {
					return werr
				}
			}
		}
		if rerr != nil {
			switch {
			case errors.Is(rerr, io.EOF):
				return nil
			case errors.Is(rerr, os.ErrDeadlineExceeded):
				// 轮询刻度到期：对向方向延长了连接级活动 → 重新装填继续等
				if idle > 0 && time.Now().Before(sess.activeAt().Add(idle)) {
					continue
				}
				return errIdleTimeout
			default:
				return rerr
			}
		}
	}
}
