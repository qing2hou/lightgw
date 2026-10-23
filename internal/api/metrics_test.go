package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/audit"
	"haproxyweb/internal/config"
	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
	"haproxyweb/internal/trafficlog"
)

func newMetricsHandlers(t *testing.T) *handlers {
	t.Helper()
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "t.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.ForwardRule{}, &model.TrafficLog{}, &model.AuditLog{}, &model.HealthLog{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	tlog := trafficlog.New(db, trafficlog.Options{RetentionDays: 1})
	t.Cleanup(func() { tlog.Close() })
	auditW := audit.New(db, 90)
	t.Cleanup(func() { auditW.Close() })
	cfg := &config.Config{}
	cfg.Web.DataDir = dir
	mgr := proxy.NewManager(db, tlog, 0, proxy.Options{})
	return &handlers{Deps{DB: db, TLog: tlog, Audit: auditW, Mgr: mgr, Cfg: cfg, Version: "test"}}
}

// /api/metrics 应输出合法的 Prometheus 文本格式骨架。
func TestMetricsHandler(t *testing.T) {
	h := newMetricsHandlers(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	h.metrics(c)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type 不符: %q", ct)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# HELP haweb_uptime_seconds",
		"# TYPE haweb_build_info gauge",
		"haweb_build_info{version=\"test\"} 1",
		"haweb_rules_total 0",
		"haweb_engine_rejected_total{reason=\"global\"} 0",
		"haweb_log_dropped_total{kind=\"traffic\"} 0",
		"haweb_go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("指标输出缺少 %q", want)
		}
	}
}

// /api/observability 应返回运行监控页所需的 JSON 摘要。
func TestObservabilityHandler(t *testing.T) {
	h := newMetricsHandlers(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/observability", nil)
	h.observability(c)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"\"uptime_seconds\"",
		"\"db_size_bytes\"",
		"\"engine\"",
		"\"sessions_active\"",
		"\"goroutines\"",
		"\"logs\"",
		"\"traffic_dropped\"",
		"\"rule_metrics\"",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("observability 输出缺少 %q", want)
		}
	}
}

// pprof 转交后索引应可用（路径剥离 /api 前缀）。
func TestPprofHandler(t *testing.T) {
	h := newMetricsHandlers(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/debug/pprof/", nil)
	h.pprof(c)
	if w.Code != http.StatusOK {
		t.Fatalf("pprof 状态码 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "goroutine") {
		t.Error("pprof 索引应包含 goroutine profile")
	}
}

// 首次携带查询参数令牌访问 pprof 时应落一个仅限本路径的 Cookie，
// 供索引页内的相对链接（不带查询参数）继续通过鉴权。
func TestPprofHandlerSetsScopedCookie(t *testing.T) {
	h := newMetricsHandlers(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/debug/pprof/?pprof_token=abc", nil)
	h.pprof(c)

	setCookie := w.Header().Get("Set-Cookie")
	for _, want := range []string{"pprof_token=abc", "Path=/api/debug/pprof", "HttpOnly", "Max-Age=600"} {
		if !strings.Contains(setCookie, want) {
			t.Errorf("Set-Cookie 缺少 %q，实际: %q", want, setCookie)
		}
	}
	// 不带令牌的请求不应落 Cookie
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/api/debug/pprof/goroutine", nil)
	h.pprof(c2)
	if w2.Header().Get("Set-Cookie") != "" {
		t.Errorf("无查询令牌时不应设置 Cookie: %q", w2.Header().Get("Set-Cookie"))
	}
}

// 检测历史端点：返回该规则的检测点与可用率。
func TestRuleHealthHistoryHandler(t *testing.T) {
	h := newMetricsHandlers(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起后端失败: %v", err)
	}
	defer ln.Close()
	rule := model.ForwardRule{
		ID: 1, Name: "hh", Protocol: model.ProtocolTCP,
		ListenAddr: "127.0.0.1:18401", TargetAddr: ln.Addr().String(), Enabled: true,
	}
	if err := h.DB.Create(&rule).Error; err != nil {
		t.Fatalf("入库规则失败: %v", err)
	}
	if err := h.Mgr.Apply(rule); err != nil {
		t.Fatalf("应用规则失败: %v", err)
	}
	h.Mgr.CheckBackendsNow()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest(http.MethodGet, "/api/rules/1/health", nil)
	h.ruleHealthHistory(c)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", w.Code, w.Body.String())
	}
	var d struct {
		Checked      bool    `json:"checked"`
		Up           bool    `json:"up"`
		Availability float64 `json:"availability"`
		Points       []struct {
			Ts int64 `json:"ts"`
			Up bool  `json:"up"`
		} `json:"points"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatalf("响应非法: %v", err)
	}
	if !d.Checked || !d.Up || len(d.Points) < 1 || d.Availability != 1 {
		t.Errorf("历史详情不符: %+v", d)
	}

	// 不存在的规则 404
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Params = gin.Params{{Key: "id", Value: "999"}}
	c2.Request = httptest.NewRequest(http.MethodGet, "/api/rules/999/health", nil)
	h.ruleHealthHistory(c2)
	if w2.Code != http.StatusNotFound {
		t.Errorf("不存在的规则应 404，实际 %d", w2.Code)
	}
}
