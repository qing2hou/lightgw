package proxy

import (
	"io"
	"net"

	"haproxyweb/internal/ratelimit"
)

// copyFast splice 快路径：仅当 tuning.splice 开启且规则双向不限速时使用
// （见 spliceEligible）。dst 为裸 *net.TCPConn 时委托其 ReadFrom，
// src 同为裸连接即触发 Linux splice 零拷贝。
//
// 与慢路径的取舍：无空闲超时（仅靠内核 keepalive 回收死连接）。
//
// **分块搬运**（spliceChunk）：`TCPConn.ReadFrom` 会阻塞到对端关闭或出错才
// 返回，期间字节数完全不可见。历史上直接用它导致传输期间实时速率与会话
// 字节恒为 0，只有会话结束才一次性入账——用户看到的现象就是"上传/下载时
// 实时速率和会话表都没数据"。分块后每块返回即记账并喂速率窗口，代价只是
// 每块一次系统调用（32MB 一块，10Gbps 下也仅 ~40 次/秒）。
func (m *Manager) copyFast(dst, src net.Conn, sess *session, download bool) error {
	tc, ok := dst.(*net.TCPConn)
	if !ok {
		// 非 TCP 连接（理论上不会出现）：退化为用户态拷贝，同样逐块记账
		return m.copyFastUserspace(dst, src, sess, download)
	}
	for {
		// LimitedReader 让 ReadFrom 搬满一块就返回，从而能中途记账
		lr := &io.LimitedReader{R: src, N: spliceChunk}
		n, err := tc.ReadFrom(lr)
		if n > 0 {
			// 每块都走 addBytes：live 字节、规则累计、实时速率窗口三者同步。
			// 绕开 addBytes 只加原子量会让速率窗口永远为空。
			sess.addBytes(download, n)
			sess.touch()
		}
		if err != nil {
			return err
		}
		// 本块没读满 = 对端已无更多数据（EOF）
		if lr.N > 0 {
			return nil
		}
	}
}

// spliceChunk 是零拷贝单次搬运的最大字节数（见 copyFast 的分块说明）。
const spliceChunk = 32 << 20

// copyFastUserspace 非 TCP 兜底路径：用户态拷贝，逐块记账。
func (m *Manager) copyFastUserspace(dst, src net.Conn, sess *session, download bool) error {
	buf := m.bufs.get()
	defer m.bufs.put(buf)
	for {
		n, rerr := src.Read(*buf)
		if n > 0 {
			written := 0
			for written < n {
				nw, werr := dst.Write((*buf)[written:n])
				written += nw
				if werr != nil {
					return werr
				}
			}
			sess.addBytes(download, int64(n))
			sess.touch()
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

// spliceEligible 是否满足快路径条件：全局开关开启、规则未配置限速、整机带宽不限
// （限速需要用户态等待令牌，与零拷贝互斥）。
func (m *Manager) spliceEligible(cfg *ruleConfig) bool {
	return m.opts().Splice && cfg.limiter.Disabled() && m.globalBandwidth().Disabled()
}

// zeroBandwidth 未配置整机带宽上限时的空限速器（Disabled()=true），
// 保证零值构造的 Manager（测试场景）也不会拿到 nil。
var zeroBandwidth = ratelimit.New(0, 0)

// globalBandwidth 整机带宽限速器（永不返回 nil，Disabled() 判断是否不限）。
func (m *Manager) globalBandwidth() *ratelimit.Limiter {
	if gl := m.globalLimiter.Load(); gl != nil {
		return gl
	}
	return zeroBandwidth
}
