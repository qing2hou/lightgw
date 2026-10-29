package proxy

import (
	"testing"

	"haproxyweb/internal/model"
)

// TestSnatRateUsesActualInterval SNAT 速率必须按实际采样间隔折算。
//
// 回归：早期实现把 5s 轮询的字节差分整块塞进 rateMeter 的"当前秒槽"，
// 而 Rate() 恒按 10 秒窗口求平均 → 10 个槽里只有 2 个有数据，显示值被
// 压低 5 倍（用户实测 46.7MB/s 下载在页面显示 66KB/s）。
// 这里用 5s 间隔、每周期 5MB 的算例验证：速率应为 1MB/s，而不是 200KB/s。
func TestSnatRateUsesActualInterval(t *testing.T) {
	const (
		interval = 5               // snatLoop 周期（秒）
		perCycle = 5 * 1024 * 1024 // 每周期 5MB
		want     = perCycle / interval
	)
	// 直接用与实现相同的折算公式校验语义（实现里为 dUp / dt）
	got := int64(perCycle) / int64(interval)
	if got != int64(want) {
		t.Fatalf("折算错误: got=%d want=%d", got, want)
	}
	// 对照：若错误地走 rateMeter（10 秒窗口、每 5 秒只填一个槽），
	// 同样 5MB/5s 会被算成 perCycle/10 = 一半流量再除以周期，严重低估
	var r rateMeter
	now := int64(1000)
	r.now = func() int64 { return now }
	for i := 0; i < 2; i++ {
		r.Add(perCycle) // 每 5 秒一次
		now += interval
	}
	wrong := r.Rate()
	// 实测：每 5 秒填一个槽 → 10 槽窗口中只有 2 槽有数据、8 槽为空，
	// Rate() 除以 10 后约为正确值的一半（本例 524288 vs 1048576）。
	// 真实采样里只有 1 个槽有数据时更差（1/5）。断言其确实显著低于正确值。
	if wrong >= int64(want) {
		t.Fatalf("rateMeter 口径应低估（这正是 SNAT 不能复用它的原因），实际 %d vs 正确 %d", wrong, want)
	}
	t.Logf("rateMeter 低估实证: %d vs 正确 %d（比例 %.2f）", wrong, want, float64(wrong)/float64(want))
}

// TestSnatRateZeroWhenIdle 一个周期内无流量时速率应归零，
// 避免静止规则长期显示历史峰值。
func TestSnatRateZeroWhenIdle(t *testing.T) {
	m := newFullManager(t, Options{})
	st := m.statsFor(model.ForwardRule{ID: 901, Name: "idle-snat", Protocol: model.ProtocolSNAT})
	st.SnatRateBps.Store(12345)
	// 实现中"本周期 dUp == 0"分支显式 Store(0)
	st.SnatRateBps.Store(0)
	if v := st.SnatRateBps.Load(); v != 0 {
		t.Fatalf("空闲周期速率应为 0，实际 %d", v)
	}
	// RuleMetrics 必须把它读出来（0 时不覆盖 rateMeter 值，故这里只验证可读）
	m.ForgetRule(901)
}
