package proxy

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"haproxyweb/internal/model"
)

// 健康检查：后端可达 → up；目标变为不可达 → down 且带错误信息；恢复 → up。
// UDP 规则不检测；停用后状态清理；空闲 TCP 规则也出现在 RuleMetrics。
func TestBackendHealthCheck(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096, HealthCheckInterval: 100 * time.Millisecond})

	port := freePort(t)
	rule := model.ForwardRule{
		ID: 1, Name: "h", Protocol: model.ProtocolTCP,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		TargetAddr: echoServer(t), Enabled: true,
	}
	if err := m.Apply(rule); err != nil {
		t.Fatalf("应用规则失败: %v", err)
	}

	m.CheckBackendsNow()
	h := m.BackendHealthOf(rule.ID)
	if !h.Checked || !h.Up {
		t.Fatalf("后端可达时健康状态应为 up: %+v", h)
	}
	if h.LastCheck == 0 {
		t.Error("应记录检测时间")
	}
	if m.BackendsDown() != 0 {
		t.Error("无异常后端时 BackendsDown 应为 0")
	}

	// 目标切到已关闭端口（同一监听地址热更新）
	closed := freePort(t)
	rule.TargetAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(closed))
	if err := m.Apply(rule); err != nil {
		t.Fatalf("热更新规则失败: %v", err)
	}
	m.CheckBackendsNow()
	h = m.BackendHealthOf(rule.ID)
	if !h.Checked || h.Up {
		t.Fatalf("后端不可达时健康状态应为 down: %+v", h)
	}
	if h.Error == "" {
		t.Error("异常状态应携带错误信息")
	}
	if m.BackendsDown() != 1 {
		t.Errorf("BackendsDown 应为 1，实际 %d", m.BackendsDown())
	}

	// 恢复可达
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(closed)))
	if err != nil {
		t.Fatalf("起恢复后端失败: %v", err)
	}
	defer ln.Close()
	m.CheckBackendsNow()
	h = m.BackendHealthOf(rule.ID)
	if !h.Checked || !h.Up {
		t.Fatalf("后端恢复后健康状态应为 up: %+v", h)
	}
	if m.BackendsDown() != 0 {
		t.Errorf("恢复后 BackendsDown 应为 0，实际 %d", m.BackendsDown())
	}

	// UDP 规则不检测
	uport := freePort(t)
	urule := model.ForwardRule{
		ID: 2, Name: "u", Protocol: model.ProtocolUDP,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(uport)),
		TargetAddr: "127.0.0.1:1", Enabled: true,
	}
	if err := m.Apply(urule); err != nil {
		t.Fatalf("应用 UDP 规则失败: %v", err)
	}
	m.CheckBackendsNow()
	if uh := m.BackendHealthOf(urule.ID); uh.Checked {
		t.Errorf("UDP 规则不应有健康状态: %+v", uh)
	}

	// 空闲 TCP 规则（无会话）也应出现在 RuleMetrics 且带健康状态
	rms := m.RuleMetrics()
	found := false
	for _, rm := range rms {
		if rm.ID == rule.ID && rm.BackendChecked && rm.BackendUp && rm.Name == "h" {
			found = true
		}
	}
	if !found {
		t.Errorf("空闲规则应出现在 RuleMetrics 且含健康状态: %+v", rms)
	}

	// 停用后残留状态被清理
	m.Stop(rule)
	m.CheckBackendsNow()
	if h := m.BackendHealthOf(rule.ID); h.Checked {
		t.Errorf("规则停用后健康状态应被清理: %+v", h)
	}
}

// 规则级检测开关：HealthCheck=false 的规则不探测；nil（旧数据）默认开启。
func TestHealthCheckToggle(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096, HealthCheckInterval: 100 * time.Millisecond})
	off := false

	port := freePort(t)
	ruleOff := model.ForwardRule{
		ID: 3, Name: "off", Protocol: model.ProtocolTCP,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		TargetAddr: echoServer(t), HealthCheck: &off, Enabled: true,
	}
	if err := m.Apply(ruleOff); err != nil {
		t.Fatalf("应用规则失败: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // 留出（被跳过的）异步探测窗口
	m.CheckBackendsNow()
	if h := m.BackendHealthOf(3); h.Checked {
		t.Errorf("关闭检测的规则不应有健康状态: %+v", h)
	}

	// nil（旧数据）默认开启
	port2 := freePort(t)
	ruleNil := model.ForwardRule{
		ID: 4, Name: "legacy", Protocol: model.ProtocolTCP,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port2)),
		TargetAddr: echoServer(t), Enabled: true,
	}
	if err := m.Apply(ruleNil); err != nil {
		t.Fatalf("应用规则失败: %v", err)
	}
	m.CheckBackendsNow()
	if h := m.BackendHealthOf(4); !h.Checked || !h.Up {
		t.Errorf("nil 视为默认开启，应有健康状态: %+v", h)
	}
}

// 检测历史与窗口可用率：检测结果入库，时间范围查询、可用率与降采样生效。
func TestHealthHistory(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096, HealthCheckInterval: time.Minute})
	rule := model.ForwardRule{ID: 5, Name: "hist", Protocol: model.ProtocolTCP}

	base := time.Now().Add(-time.Hour).Round(time.Second)
	for i, up := range []bool{true, true, false, true} {
		m.recordProbe(5, rule, base.Add(time.Duration(i)*time.Minute), up, "")
		m.persistHealth(5, base.Add(time.Duration(i)*time.Minute), up, map[bool]string{true: "", false: "dial: refused"}[up])
	}

	// 全范围：4 个点，可用率 3/4
	pts, avail, err := m.BackendHealthRange(5, base.Add(-time.Minute), base.Add(5*time.Minute), 1440)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(pts) != 4 {
		t.Fatalf("应有 4 个点，实际 %d", len(pts))
	}
	if pts[2].Up || !pts[3].Up {
		t.Errorf("第 3 点应为异常、第 4 点应为正常: %+v", pts)
	}
	if avail != 0.75 {
		t.Errorf("可用率应为 0.75，实际 %v", avail)
	}

	// 时间过滤：只取异常点之后 → 1 个点
	pts2, avail2, _ := m.BackendHealthRange(5, base.Add(3*time.Minute), base.Add(5*time.Minute), 1440)
	if len(pts2) != 1 || !pts2[0].Up || avail2 != 1 {
		t.Errorf("时间过滤不符: %+v avail=%v", pts2, avail2)
	}

	// 降采样：插入 100 个点，限制 10 点
	for i := 0; i < 100; i++ {
		ts := base.Add(10*time.Minute + time.Duration(i)*time.Second)
		m.recordProbe(5, rule, ts, true, "")
		m.persistHealth(5, ts, true, "")
	}
	pts3, _, err := m.BackendHealthRange(5, base.Add(10*time.Minute), base.Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("降采样查询失败: %v", err)
	}
	// 均匀采样 10 点 + 末点保留（与采样点重合时不追加），因此 10~11 个均为正确行为
	if len(pts3) > 11 || len(pts3) < 10 {
		t.Errorf("降采样应输出 10~11 个点，实际 %d", len(pts3))
	}
	if last := pts3[len(pts3)-1]; last.Ts != base.Add(10*time.Minute+99*time.Second).Unix() {
		t.Errorf("末点应为最后一次检测: %+v", last)
	}
}

// 健康状态翻转时应向配置的 webhook 推送 JSON 通知（含 rule_id 与状态）。
func TestHealthWebhook(t *testing.T) {
	received := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- b
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := newFullManager(t, Options{
		BufferSize:          4096,
		HealthCheckInterval: 100 * time.Millisecond,
		HealthWebhookURL:    srv.URL,
	})
	closed := freePort(t)
	applyListen(t, m, model.ForwardRule{
		ID: 7, Name: "hook", Protocol: model.ProtocolTCP,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))),
		TargetAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(closed)),
	})

	select {
	case b := <-received:
		var payload map[string]any
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Fatalf("webhook 载荷非法: %v", err)
		}
		if payload["rule_id"].(float64) != 7 || payload["status"] != "down" || payload["error"] == "" {
			t.Errorf("webhook 载荷不符: %s", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到 webhook 通知")
	}
}

// ApplyOptions 热加载：参数原子替换，新建规则的运行时配置随之生效。
func TestApplyOptions(t *testing.T) {
	m := newFullManager(t, Options{BufferSize: 4096, TCPIdleTimeout: 100 * time.Second})
	listen := applyListen(t, m, model.ForwardRule{
		ID: 9, Name: "hot", Protocol: model.ProtocolTCP,
		ListenAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))),
		TargetAddr: echoServer(t),
	})
	_ = listen

	if got := m.buildRuleConfig(model.ForwardRule{Protocol: model.ProtocolTCP}).idleTimeout; got != 100*time.Second {
		t.Fatalf("初始空闲超时不符: %v", got)
	}
	if !m.globalBandwidth().Disabled() {
		t.Fatal("初始全局带宽应为不限")
	}

	// 热加载：空闲超时与整机带宽上限即时生效
	m.ApplyOptions(Options{
		BufferSize:         4096,
		TCPIdleTimeout:     5 * time.Second,
		GlobalUploadKBps:   1024,
		GlobalDownloadKBps: 1024,
	})
	if got := m.opts().TCPIdleTimeout; got != 5*time.Second {
		t.Errorf("热加载后空闲超时不符: %v", got)
	}
	if got := m.buildRuleConfig(model.ForwardRule{Protocol: model.ProtocolTCP}).idleTimeout; got != 5*time.Second {
		t.Errorf("热加载后新配置空闲超时不符: %v", got)
	}
	if m.globalBandwidth().Disabled() {
		t.Error("热加载后整机带宽上限应生效")
	}
}
