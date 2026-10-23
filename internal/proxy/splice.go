package proxy

import (
	"io"
	"net"

	"haproxyweb/internal/ratelimit"
)

// copyFast splice 快路径：仅当 tuning.splice 开启且规则双向不限速时使用
// （见 spliceEligible）。dst 为裸 *net.TCPConn 时委托其 ReadFrom，
// src 同为裸连接即触发 Linux splice 零拷贝，字节数在 ReadFrom 返回时累计。
// 与慢路径的取舍：无空闲超时（仅靠内核 keepalive 回收死连接）、live 字节统计滞后；
// 速率口径同样滞后——总量在会话结束时一次性入账会把 GB 级会话折成幻影速率尖峰，
// 因此 splice 路径只进累计计数（BytesUp/Down），跳过速率窗口（Rate 恒 0，
// 与实时字节同口径的已知边界，README 已声明）。
func (m *Manager) copyFast(dst, src net.Conn, sess *session, download bool) error {
	var n int64
	var err error
	if tc, ok := dst.(*net.TCPConn); ok {
		n, err = tc.ReadFrom(src)
	} else {
		// 非 TCP 连接（理论上不会出现）：退化为用户态拷贝
		n, err = io.Copy(dst, src)
	}
	if download {
		sess.down.Add(n)
		if sess.stats != nil {
			sess.stats.BytesDown.Add(n)
		}
	} else {
		sess.up.Add(n)
		if sess.stats != nil {
			sess.stats.BytesUp.Add(n)
		}
	}
	return err
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
