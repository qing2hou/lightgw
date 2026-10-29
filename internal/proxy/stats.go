package proxy

import (
	"sort"
	"sync/atomic"
	"time"

	"haproxyweb/internal/model"
)

// ruleStats 规则级进程内指标（/metrics 数据源）。规则删除时由 ForgetRule 清理。
type ruleStats struct {
	Name        string
	Protocol    string
	ConnCurrent atomic.Int64
	ConnTotal   atomic.Int64
	BytesUp     atomic.Int64
	BytesDown   atomic.Int64
	Errors      atomic.Int64
	Denied      atomic.Int64
	// 实时速率（最近 10 秒滑动窗口平均，B/s；写入点在 addBytes）
	RateUp   rateMeter
	RateDown rateMeter
	// SnatRateBps SNAT 专用速率（B/s）。SNAT 的字节数只能按轮询周期（5s）从
	// 内核 nft counter 取差分，喂不进 rateMeter 的"每次写入落一个秒槽"模型：
	// 5s 采样只会填满 2/10 个槽，而 Rate() 恒按窗口长度 10 求平均，显示值
	// = 真实值 / 5（实测 46.7MB/s 下载显示 66KB/s）。
	// 这里直接存"本次差分 ÷ 实际采样间隔"，语义为最近一个周期的平均速率。
	SnatRateBps atomic.Int64
}

// RuleMetric 单条规则的指标快照。
type RuleMetric struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	ConnCurrent int64  `json:"conn_current"`
	ConnTotal   int64  `json:"conn_total"`
	BytesUp     int64  `json:"bytes_up"`
	BytesDown   int64  `json:"bytes_down"`
	RateUpBps   int64  `json:"rate_up_bps"`   // 实时上传速率（最近 10s 平均，B/s）
	RateDownBps int64  `json:"rate_down_bps"` // 实时下载速率（最近 10s 平均，B/s）
	Errors      int64  `json:"errors"`
	Denied      int64  `json:"denied"`
	// 后端健康（仅 TCP 规则会有值；BackendChecked=false 表示未检测）
	BackendChecked bool   `json:"backend_checked"`
	BackendUp      bool   `json:"backend_up"`
	BackendError   string `json:"backend_error,omitempty"`
}

// EngineCounters 进程级转发引擎计数快照。
type EngineCounters struct {
	SessionsActive int64 `json:"sessions_active"`
	RejectedGlobal int64 `json:"rejected_global"`
	RejectedRule   int64 `json:"rejected_rule"`
	AcceptErrors   int64 `json:"accept_errors"`
	Panics         int64 `json:"panics"`
}

// statsFor 获取（或创建）规则指标条目，并刷新名称等展示字段（支持改名）。
func (m *Manager) statsFor(rule model.ForwardRule) *ruleStats {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	if m.stats == nil {
		// 惰性初始化，兼容零值构造的 Manager（测试场景）
		m.stats = map[uint]*ruleStats{}
	}
	st, ok := m.stats[rule.ID]
	if !ok {
		st = &ruleStats{Name: rule.Name, Protocol: rule.Protocol}
		m.stats[rule.ID] = st
		return st
	}
	st.Name = rule.Name
	st.Protocol = rule.Protocol
	return st
}

// ForgetRule 规则删除时清理指标与健康状态条目，防止长期运行下 map 随规则增删无限增长。
func (m *Manager) ForgetRule(id uint) {
	m.statsMu.Lock()
	delete(m.stats, id)
	m.statsMu.Unlock()
	m.healthMu.Lock()
	delete(m.health, id)
	m.healthMu.Unlock()
}

// RuleMetrics 全部规则的指标快照（含仅有健康状态、尚无会话的空闲 TCP 规则），
// 按规则 ID 排序保证输出稳定。锁序固定 statsMu → healthMu，别反向。
func (m *Manager) RuleMetrics() []RuleMetric {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.healthMu.Lock()
	defer m.healthMu.Unlock()

	ids := make(map[uint]struct{}, len(m.stats)+len(m.health))
	for id := range m.stats {
		ids[id] = struct{}{}
	}
	for id := range m.health {
		ids[id] = struct{}{}
	}
	out := make([]RuleMetric, 0, len(ids))
	for id := range ids {
		rm := RuleMetric{ID: id}
		if st := m.stats[id]; st != nil {
			rm.Name = st.Name
			rm.Protocol = st.Protocol
			rm.ConnCurrent = st.ConnCurrent.Load()
			rm.ConnTotal = st.ConnTotal.Load()
			rm.BytesUp = st.BytesUp.Load()
			rm.BytesDown = st.BytesDown.Load()
			rm.RateUpBps = st.RateUp.Rate()
			rm.RateDownBps = st.RateDown.Rate()
			// SNAT 走独立口径（轮询差分 / 实际间隔）：内核 counter 只在周期
			// 采样点更新，rateMeter 的秒槽模型在这里会低估 5 倍。
			if v := st.SnatRateBps.Load(); v > 0 {
				rm.RateUpBps = v
				rm.RateDownBps = v
			}
			rm.Errors = st.Errors.Load()
			rm.Denied = st.Denied.Load()
		}
		if h := m.health[id]; h != nil {
			if rm.Name == "" {
				rm.Name = h.Name
				rm.Protocol = h.Protocol
			}
			rm.BackendChecked = h.checked.Load()
			rm.BackendUp = h.up.Load()
			if p := h.errMsg.Load(); p != nil {
				rm.BackendError = *p
			}
		}
		out = append(out, rm)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// EngineCounters 进程级计数快照。
func (m *Manager) EngineCounters() EngineCounters {
	var active int64
	m.sessions.Range(func(_, _ any) bool {
		active++
		return true
	})
	return EngineCounters{
		SessionsActive: active,
		RejectedGlobal: m.rejectedGlobal.Load(),
		RejectedRule:   m.rejectedRule.Load(),
		AcceptErrors:   m.acceptErrors.Load(),
		Panics:         m.panics.Load(),
	}
}

// addBytes 会话字节数累加：live 计数、规则级累计与实时速率窗口同步更新。
func (s *session) addBytes(download bool, n int64) {
	if download {
		s.down.Add(n)
		if s.stats != nil {
			s.stats.BytesDown.Add(n)
			s.stats.RateDown.Add(n)
		}
	} else {
		s.up.Add(n)
		if s.stats != nil {
			s.stats.BytesUp.Add(n)
			s.stats.RateUp.Add(n)
		}
	}
}

// finishSession 会话收尾统一入口：错误计数 + 流量日志落库。
func (m *Manager) finishSession(s *session, start time.Time, status, errMsg string) {
	if status == model.StatusError && s.stats != nil {
		s.stats.Errors.Add(1)
	}
	m.tlog.Log(finishLog(s, start, status, errMsg))
}
