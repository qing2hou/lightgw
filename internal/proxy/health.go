package proxy

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"haproxyweb/internal/model"
)

// healthWebhookClient 推送客户端：5 秒超时，翻转通知是尽力而为，不重试不阻塞探测。
var healthWebhookClient = &http.Client{Timeout: 5 * time.Second}

const (
	// backendProbeTimeout 单次后端探测的拨号超时。
	backendProbeTimeout = 5 * time.Second
	// HealthHistoryMaxPoints 时间范围查询返回的最大点数（超出按时间均匀降采样）。
	HealthHistoryMaxPoints = 1440
)

// HealthPoint 一次后端检测结果。
type HealthPoint struct {
	Ts int64 `json:"ts"` // unix 秒
	Up bool  `json:"up"`
}

// ruleHealth 规则后端当前健康状态（规则列表、运行监控与 /metrics 的数据源）。
// 历史检测记录持久化在 health_logs 表，这里只保留当前状态。
type ruleHealth struct {
	Name      string
	Protocol  string
	up        atomic.Bool
	checked   atomic.Bool
	lastCheck atomic.Int64 // unix 秒
	errMsg    atomic.Pointer[string]
}

// BackendHealth 对外暴露的后端健康快照。Checked=false 表示尚未检测过
// （新规则、检测关闭或 UDP 规则）。
type BackendHealth struct {
	Checked   bool   `json:"checked"`
	Up        bool   `json:"up"`
	LastCheck int64  `json:"last_check"`
	Error     string `json:"error,omitempty"`
}

// healthCheckOn 规则是否启用后端检测：HealthCheck 为 nil 表示默认开启（旧数据兼容）。
func healthCheckOn(rule model.ForwardRule) bool {
	return rule.HealthCheck == nil || *rule.HealthCheck
}

// StartHealthChecks 启动后端健康检查循环：每 HealthCheckInterval（默认 60s）对全部
// 运行中且未关闭检测的 TCP 规则做一次 TCP 连接探测。UDP 无握手语义，不检测。
// 启动时立即执行一轮，状态无需等满一个周期；进程退出由 StopAll 统一停止。
func (m *Manager) StartHealthChecks() {
	go m.healthLoop()
}

// healthLoop 每轮从运行参数读取最新周期——SIGHUP 热加载后立即生效；
// 周期被置 0（全局禁用）时暂停探测但保持循环，便于后续恢复。
func (m *Manager) healthLoop() {
	m.CheckBackendsNow()
	timer := time.NewTimer(m.opts().HealthCheckInterval)
	defer timer.Stop()
	pruneTicker := time.NewTicker(time.Hour)
	defer pruneTicker.Stop()
	for {
		select {
		case <-timer.C:
			if iv := m.opts().HealthCheckInterval; iv <= 0 {
				timer.Reset(5 * time.Second) // 已禁用：挂起，每 5s 查一次配置
				continue
			}
			m.CheckBackendsNow()
			timer.Reset(m.opts().HealthCheckInterval)
		case <-pruneTicker.C:
			m.pruneHealthLogs()
		case <-m.healthDone:
			return
		}
	}
}

// CheckBackendsNow 立即执行一轮后端健康检查（并发探测当前全部开启检测的 TCP 规则）。
// 上一轮尚未完成时跳过本轮，避免慢后端导致探测堆积。测试与手动触发也走这里。
func (m *Manager) CheckBackendsNow() {
	if !m.checking.CompareAndSwap(false, true) {
		return
	}
	defer m.checking.Store(false)

	type item struct {
		id   uint
		rule model.ForwardRule
	}
	// 评审 #11：锁内只摘轻量快照（id + dnat 位），DB 查询与判定在锁外——
	// 锁内做 IO 违反"阻塞操作不进锁"纪律
	// T104 + DEFECT-2 修复：dnat 探测集直接查 DB（启用中的 dnat 规则全集）。
	// 此前从 m.snatRules 注册表收集——健康下线会把注册表条目删除（down 语义），
	// 下轮探测集随之空掉 → 后端恢复后无人探测 → 发布永不重装（实测缺陷）。
	// DB 是唯一权威源：规则启用即在探测集，与装载状态无关。
	m.mu.Lock()
	items := make([]item, 0, len(m.tcpRules))
	for id, e := range m.tcpRules {
		rule := e.cfg.Load().rule
		if !healthCheckOn(rule) {
			continue
		}
		items = append(items, item{id: id, rule: rule})
	}
	m.mu.Unlock()
	var dnatRules []model.ForwardRule
	m.db.Where("protocol = ? AND enabled = ?", model.ProtocolDNAT, true).Find(&dnatRules)
	for _, r := range dnatRules {
		if !healthCheckOn(r) {
			continue // 评审 #11：显式关闭检测的发布规则不探测不卸载
		}
		items = append(items, item{rule: r})
	}

	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		go func(it item) {
			defer wg.Done()
			m.probeBackend(it.id, it.rule)
		}(it)
	}
	wg.Wait()

	// 清理已停用/下线/关闭检测规则的残留健康状态
	m.healthMu.Lock()
	live := make(map[uint]bool, len(items))
	for _, it := range items {
		live[it.id] = true
	}
	for id := range m.health {
		if !live[id] {
			delete(m.health, id)
		}
	}
	m.healthMu.Unlock()
}

// probeBackend 对规则目标做一次 TCP 连接探测：更新内存当前状态 + 入库历史。
// 状态翻转时记日志，稳态不刷屏（每分钟一次的重复结果不重复打印）。
func (m *Manager) probeBackend(id uint, rule model.ForwardRule) {
	conn, err := net.DialTimeout("tcp", rule.TargetAddr, backendProbeTimeout)
	now := time.Now()
	if err != nil {
		msg := err.Error()
		prevUp, prevChecked := m.recordProbe(id, rule, now, false, msg)
		m.persistHealth(id, now, false, msg)
		if !prevChecked || prevUp {
			logf("规则[%s#%d] 后端 %s 健康检查失败，标记为异常: %v", rule.Name, rule.ID, rule.TargetAddr, err)
			go m.notifyHealthWebhook(rule, false, msg)
			// T104 dnat 联动：后端不可达 → 卸载发布行（客户端连接拒绝由
			// dnat_reject_mode 决定：reject 模式的拒绝路径=发布行不在=超时/拒绝）
			if rule.Protocol == model.ProtocolDNAT {
				m.dnatHealthToggle(rule, false)
			}
		}
		return
	}
	_ = conn.Close()
	prevUp, prevChecked := m.recordProbe(id, rule, now, true, "")
	m.persistHealth(id, now, true, "")
	if prevChecked && !prevUp {
		logf("规则[%s#%d] 后端 %s 已恢复", rule.Name, rule.ID, rule.TargetAddr)
		go m.notifyHealthWebhook(rule, true, "")
		// T104 dnat 联动：恢复 → 重新装载发布
		if rule.Protocol == model.ProtocolDNAT {
			m.dnatHealthToggle(rule, true)
		}
	}
}

// recordProbe 在锁内更新内存中的当前健康状态，返回记录前的状态供翻转判断。
func (m *Manager) recordProbe(id uint, rule model.ForwardRule, now time.Time, up bool, errMsg string) (prevUp, prevChecked bool) {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()
	if m.health == nil {
		m.health = map[uint]*ruleHealth{}
	}
	h, ok := m.health[id]
	if !ok {
		h = &ruleHealth{}
		m.health[id] = h
	}
	h.Name = rule.Name
	h.Protocol = rule.Protocol
	prevUp = h.up.Load()
	prevChecked = h.checked.Load()
	h.up.Store(up)
	h.checked.Store(true)
	h.lastCheck.Store(now.Unix())
	if errMsg != "" {
		h.errMsg.Store(&errMsg)
	} else {
		h.errMsg.Store(nil)
	}
	return prevUp, prevChecked
}

// persistHealth 健康检测结果入库（health_logs）。每规则每分钟一条，量级很小，
// 直写即可；失败记日志不静默——丢一条历史可接受，但不能无声丢失。
func (m *Manager) persistHealth(id uint, now time.Time, up bool, errMsg string) {
	row := model.HealthLog{RuleID: id, Up: up, ErrorMsg: truncate(errMsg, 512), CheckedAt: now}
	if err := m.db.Create(&row).Error; err != nil {
		logf("规则#%d 健康检测记录入库失败: %v", id, err)
	}
}

// BackendHealthRange 查询指定规则时间范围内的检测历史（含窗口可用率）。
// 超过 maxPoints 时按时间均匀降采样，末点始终保留。
func (m *Manager) BackendHealthRange(id uint, start, end time.Time, maxPoints int) ([]HealthPoint, float64, error) {
	var rows []model.HealthLog
	err := m.db.Where("rule_id = ? AND checked_at >= ? AND checked_at <= ?", id, start, end).
		Order("checked_at ASC").Find(&rows).Error
	if err != nil {
		return nil, 0, err
	}
	if len(rows) == 0 {
		return []HealthPoint{}, 0, nil
	}
	step := 1
	if maxPoints > 0 && len(rows) > maxPoints {
		step = (len(rows) + maxPoints - 1) / maxPoints
	}
	pts := make([]HealthPoint, 0, len(rows)/step+1)
	up := 0
	for i, r := range rows {
		if i%step == 0 {
			pts = append(pts, HealthPoint{Ts: r.CheckedAt.Unix(), Up: r.Up})
		}
		if r.Up {
			up++
		}
	}
	last := len(rows) - 1
	if step > 1 && last%step != 0 {
		pts = append(pts, HealthPoint{Ts: rows[last].CheckedAt.Unix(), Up: rows[last].Up})
	}
	return pts, float64(up) / float64(len(rows)), nil
}

// pruneHealthLogs 清理超过保留天数的健康检测记录（保留期跟随流量日志）。
func (m *Manager) pruneHealthLogs() {
	if m.opts().HealthLogRetentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -m.opts().HealthLogRetentionDays)
	res := m.db.Where("checked_at < ?", cutoff).Delete(&model.HealthLog{})
	if res.Error != nil {
		logf("健康检测历史清理失败: %v", res.Error)
	} else if res.RowsAffected > 0 {
		logf("已清理 %d 条过期健康检测记录", res.RowsAffected)
	}
}

// BackendHealthOf 返回指定规则的后端健康快照；未检测过的规则返回零值。
func (m *Manager) BackendHealthOf(id uint) BackendHealth {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()
	h := m.health[id]
	if h == nil {
		return BackendHealth{}
	}
	out := BackendHealth{
		Checked:   h.checked.Load(),
		Up:        h.up.Load(),
		LastCheck: h.lastCheck.Load(),
	}
	if p := h.errMsg.Load(); p != nil {
		out.Error = *p
	}
	return out
}

// notifyHealthWebhook 健康状态翻转时向配置地址异步推送 JSON 通知。
// 尽力而为：失败仅记日志，不重试不阻塞探测循环。
func (m *Manager) notifyHealthWebhook(rule model.ForwardRule, up bool, errMsg string) {
	url := m.opts().HealthWebhookURL
	if url == "" {
		return
	}
	status := "down"
	if up {
		status = "up"
	}
	body, err := json.Marshal(map[string]any{
		"rule_id":     rule.ID,
		"rule_name":   rule.Name,
		"protocol":    rule.Protocol,
		"listen_addr": rule.ListenAddr,
		"target_addr": rule.TargetAddr,
		"status":      status,
		"error":       errMsg,
		"ts":          time.Now().Format(time.RFC3339),
	})
	if err != nil {
		logf("健康检测 webhook 序列化失败（规则[%s#%d]）: %v", rule.Name, rule.ID, err)
		return
	}
	resp, err := healthWebhookClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		logf("健康检测 webhook 推送失败（规则[%s#%d] -> %s）: %v", rule.Name, rule.ID, url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		logf("健康检测 webhook 返回异常状态码 %d（规则[%s#%d]）", resp.StatusCode, rule.Name, rule.ID)
	}
}

// BackendsDown 已检测且后端异常的规则数（/healthz 与 /metrics 告警口径）。
func (m *Manager) BackendsDown() int64 {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()
	var n int64
	for _, h := range m.health {
		if h.checked.Load() && !h.up.Load() {
			n++
		}
	}
	return n
}
