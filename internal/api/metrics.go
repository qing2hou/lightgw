package api

import (
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/auth"
	"haproxyweb/internal/model"
)

// metricsStartTime 进程启动时间（包初始化时刻，误差可忽略），用于 uptime 指标。
var metricsStartTime = time.Now()

// metrics 输出 Prometheus 文本格式（0.0.4）指标。挂在 /api/metrics，需登录鉴权；
// 人类用户请在管理后台「运行监控」页查看，本端点面向程序化采集（如 Prometheus 带
// Bearer Token 抓取）。
func (h *handlers) metrics(c *gin.Context) {
	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	renderMetrics(h.Deps, c.Writer)
}

// metricsWithToken /api/metrics 的独立挂载版：普通会话 JWT 与长效监控采集令牌
// （scope=metrics，设置页签发）均可访问——Prometheus 无人值守抓取不必每天换 24h 令牌。
// 顺序：先试 Authorization 头里的监控令牌，不通过再走普通中间件校验。
func (h *handlers) metricsWithToken(c *gin.Context) {
	if tok := bearerToken(c); tok != "" {
		if _, err := h.Auth.ValidateMetricsToken(tok); err == nil {
			h.metrics(c)
			return
		}
	}
	h.Auth.Middleware()(c)
	if c.IsAborted() {
		return
	}
	h.metrics(c)
}

// bearerToken 取 Authorization: Bearer <token>（无则空串）。
func bearerToken(c *gin.Context) string {
	const prefix = "Bearer "
	if h := c.GetHeader("Authorization"); len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

// observability 运行监控页的数据源：进程、引擎、日志水位与逐规则指标的 JSON 摘要。
func (h *handlers) observability(c *gin.Context) {
	var ruleTotal, ruleEnabled, ruleFailed int64
	h.DB.Model(&model.ForwardRule{}).Count(&ruleTotal)
	h.DB.Model(&model.ForwardRule{}).Where("enabled = ?", true).Count(&ruleEnabled)
	h.DB.Model(&model.ForwardRule{}).Where("last_error <> ''").Count(&ruleFailed)

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	c.JSON(http.StatusOK, gin.H{
		"version":        h.Version,
		"uptime_seconds": int64(time.Since(metricsStartTime).Seconds()),
		"db_size_bytes":  dbSizeBytes(h.Cfg.Web.DataDir),
		"backends_down":  h.Mgr.BackendsDown(),
		"rules": gin.H{
			"total":   ruleTotal,
			"enabled": ruleEnabled,
			"failed":  ruleFailed,
		},
		"engine": h.Mgr.EngineCounters(),
		"runtime": gin.H{
			"goroutines":      runtime.NumGoroutine(),
			"mem_alloc_bytes": mem.Alloc,
			"fd_count":        fdCount(),
		},
		"logs": gin.H{
			"traffic_queued":         h.TLog.Queued(),
			"traffic_dropped":        h.TLog.Dropped(),
			"traffic_cleanup_failed": h.TLog.CleanupFailures(),
			"audit_queued":           h.Audit.Queued(),
			"audit_dropped":          h.Audit.Dropped(),
			"audit_cleanup_failed":   h.Audit.CleanupFailures(),
		},
		"rule_metrics": h.Mgr.RuleMetrics(),
	})
}

// pprof 性能分析端点（/api/debug/pprof/*），需登录鉴权。pprof 标准处理器
// 期望以 /debug/pprof 为前缀的路径，剥掉 /api 前缀后转交。
// 首次访问（URL 带短时令牌）时落一个仅限本路径的 Cookie：pprof 索引页内的
// 子链接（goroutine/heap 等）是相对链接，不会携带查询参数，Cookie 让它们
// 在令牌有效期内通过鉴权。
func (h *handlers) pprof(c *gin.Context) {
	if tok := c.Query("pprof_token"); tok != "" {
		c.SetSameSite(http.SameSiteStrictMode)
		c.SetCookie(auth.PprofCookieName, tok, int(auth.PprofTokenTTL/time.Second),
			"/api/debug/pprof", "", h.Cfg.TLSEnabled(), true)
	}
	c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, "/api")
	switch c.Request.URL.Path {
	case "/debug/pprof/cmdline":
		pprof.Cmdline(c.Writer, c.Request)
	case "/debug/pprof/profile":
		pprof.Profile(c.Writer, c.Request)
	case "/debug/pprof/symbol":
		pprof.Symbol(c.Writer, c.Request)
	case "/debug/pprof/trace":
		pprof.Trace(c.Writer, c.Request)
	default:
		pprof.Index(c.Writer, c.Request)
	}
}

// issuePprofToken 为浏览器打开 pprof 页面签发短时专用令牌（10 分钟，仅限
// pprof 路径，走查询参数）。浏览器新标签页无法携带 Authorization 头。
func (h *handlers) issuePprofToken(c *gin.Context) {
	token, err := h.Auth.IssuePprofToken(h.username(c))
	if err != nil {
		h.serverError(c, "签发分析令牌", err)
		return
	}
	h.Audit.Record(h.username(c), "pprof_token", "打开性能分析页面", h.clientIP(c))
	c.JSON(http.StatusOK, gin.H{"url": "/api/debug/pprof/?pprof_token=" + url.QueryEscape(token)})
}

type metricSample struct {
	labels string
	value  int64
}

// writeFamily 输出一个指标族（HELP/TYPE + 全部样本），标签串需已按 key 排序。
func writeFamily(w io.Writer, name, mtype, help string, samples []metricSample) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, mtype)
	for _, s := range samples {
		fmt.Fprintf(w, "%s%s %d\n", name, s.labels, s.value)
	}
}

// labelsStr 渲染 Prometheus 标签串 "{k=\"v\",...}"，按 key 排序保证输出稳定。
func labelsStr(kv map[string]string) string {
	if len(kv) == 0 {
		return ""
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := ""
	for i, k := range keys {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprintf("%s=%q", k, kv[k])
	}
	return "{" + s + "}"
}

// dbSizeBytes 数据库主文件与 WAL 的总字节数；读取失败按 0 处理。
func dbSizeBytes(dataDir string) int64 {
	var total int64
	for _, name := range []string{"haproxyweb.db", "haproxyweb.db-wal"} {
		if st, err := os.Stat(filepath.Join(dataDir, name)); err == nil {
			total += st.Size()
		}
	}
	return total
}

// fdCount 打开的文件描述符数（仅 Linux 提供 /proc，其他平台返回 0）。
func fdCount() int64 {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return int64(len(entries))
}

func renderMetrics(d Deps, w io.Writer) {
	// 进程与服务信息
	writeFamily(w, "haweb_build_info", "gauge", "构建版本信息", []metricSample{
		{labels: labelsStr(map[string]string{"version": d.Version}), value: 1},
	})
	writeFamily(w, "haweb_uptime_seconds", "gauge", "进程运行时长（秒）",
		[]metricSample{{value: int64(time.Since(metricsStartTime).Seconds())}})
	writeFamily(w, "haweb_db_size_bytes", "gauge", "数据库文件大小（含 WAL）",
		[]metricSample{{value: dbSizeBytes(d.Cfg.Web.DataDir)}})

	// 规则与引擎计数
	var ruleTotal, ruleEnabled, ruleFailed int64
	d.DB.Model(&model.ForwardRule{}).Count(&ruleTotal)
	d.DB.Model(&model.ForwardRule{}).Where("enabled = ?", true).Count(&ruleEnabled)
	d.DB.Model(&model.ForwardRule{}).Where("last_error <> ''").Count(&ruleFailed)
	writeFamily(w, "haweb_rules_total", "gauge", "转发规则总数",
		[]metricSample{{value: ruleTotal}})
	writeFamily(w, "haweb_rules_enabled", "gauge", "启用的转发规则数",
		[]metricSample{{value: ruleEnabled}})
	writeFamily(w, "haweb_rules_failed", "gauge", "启动失败的转发规则数",
		[]metricSample{{value: ruleFailed}})

	ec := d.Mgr.EngineCounters()
	writeFamily(w, "haweb_sessions_active", "gauge", "当前活跃会话数",
		[]metricSample{{value: ec.SessionsActive}})
	writeFamily(w, "haweb_engine_rejected_total", "counter", "连接被拒绝总数（并发上限）",
		[]metricSample{
			{labels: labelsStr(map[string]string{"reason": "global"}), value: ec.RejectedGlobal},
			{labels: labelsStr(map[string]string{"reason": "rule"}), value: ec.RejectedRule},
		})
	writeFamily(w, "haweb_engine_accept_errors_total", "counter", "accept 临时错误次数",
		[]metricSample{{value: ec.AcceptErrors}})
	writeFamily(w, "haweb_engine_panics_total", "counter", "转发路径被隔离的 panic 次数",
		[]metricSample{{value: ec.Panics}})

	// 每规则指标
	rules := d.Mgr.RuleMetrics()
	upSeries := make([]metricSample, 0, len(rules))
	downSeries := make([]metricSample, 0, len(rules))
	ruleUpRate := make([]metricSample, 0, len(rules))
	ruleDownRate := make([]metricSample, 0, len(rules))
	connCur := make([]metricSample, 0, len(rules))
	connTotal := make([]metricSample, 0, len(rules))
	errSeries := make([]metricSample, 0, len(rules))
	deniedSeries := make([]metricSample, 0, len(rules))
	for _, r := range rules {
		base := map[string]string{"rule_id": fmt.Sprint(r.ID), "rule": r.Name, "protocol": r.Protocol}
		up := map[string]string{"rule_id": fmt.Sprint(r.ID), "rule": r.Name, "protocol": r.Protocol, "direction": "up"}
		down := map[string]string{"rule_id": fmt.Sprint(r.ID), "rule": r.Name, "protocol": r.Protocol, "direction": "down"}
		connCur = append(connCur, metricSample{labels: labelsStr(base), value: r.ConnCurrent})
		connTotal = append(connTotal, metricSample{labels: labelsStr(base), value: r.ConnTotal})
		upSeries = append(upSeries, metricSample{labels: labelsStr(up), value: r.BytesUp})
		downSeries = append(downSeries, metricSample{labels: labelsStr(down), value: r.BytesDown})
		ruleUpRate = append(ruleUpRate, metricSample{labels: labelsStr(up), value: r.RateUpBps})
		ruleDownRate = append(ruleDownRate, metricSample{labels: labelsStr(down), value: r.RateDownBps})
		errSeries = append(errSeries, metricSample{labels: labelsStr(base), value: r.Errors})
		deniedSeries = append(deniedSeries, metricSample{labels: labelsStr(base), value: r.Denied})
	}
	writeFamily(w, "haweb_rule_connections_current", "gauge", "规则当前活跃连接数", connCur)
	writeFamily(w, "haweb_rule_connections_total", "counter", "规则累计接受的连接数", connTotal)
	writeFamily(w, "haweb_rule_bytes_total", "counter", "规则累计转发字节数", append(upSeries, downSeries...))
	// 实时速率（最近 10 秒滑动窗口平均）：ruleUpRate/ruleDownRate 在上面循环里已填
	writeFamily(w, "haweb_rule_rate_bytes_per_second", "gauge",
		"规则实时速率（最近 10 秒滑动窗口平均，B/s）", append(ruleUpRate, ruleDownRate...))
	writeFamily(w, "haweb_rule_errors_total", "counter", "规则累计出错的会话数", errSeries)
	writeFamily(w, "haweb_rule_denied_total", "counter", "规则累计被 ACL 拒绝的连接数", deniedSeries)

	// 后端健康（仅 TCP 规则检测；未检测过的不输出）
	backendSeries := make([]metricSample, 0, len(rules))
	for _, r := range rules {
		if !r.BackendChecked {
			continue
		}
		base := map[string]string{"rule_id": fmt.Sprint(r.ID), "rule": r.Name, "protocol": r.Protocol}
		v := int64(0)
		if r.BackendUp {
			v = 1
		}
		backendSeries = append(backendSeries, metricSample{labels: labelsStr(base), value: v})
	}
	writeFamily(w, "haweb_rule_backend_up", "gauge",
		"规则后端健康状态，1=正常 0=异常（仅 TCP 规则检测）", backendSeries)
	writeFamily(w, "haweb_backends_down", "gauge", "后端异常的规则数",
		[]metricSample{{value: d.Mgr.BackendsDown()}})

	// 日志写入器水位
	writeFamily(w, "haweb_log_dropped_total", "counter", "日志队列打满丢弃条数",
		[]metricSample{
			{labels: labelsStr(map[string]string{"kind": "traffic"}), value: d.TLog.Dropped()},
			{labels: labelsStr(map[string]string{"kind": "audit"}), value: d.Audit.Dropped()},
		})
	writeFamily(w, "haweb_log_cleanup_failures_total", "counter", "保留期清理失败次数",
		[]metricSample{
			{labels: labelsStr(map[string]string{"kind": "traffic"}), value: d.TLog.CleanupFailures()},
			{labels: labelsStr(map[string]string{"kind": "audit"}), value: d.Audit.CleanupFailures()},
		})
	writeFamily(w, "haweb_log_queue_depth", "gauge", "日志队列待落库条数",
		[]metricSample{
			{labels: labelsStr(map[string]string{"kind": "traffic"}), value: int64(d.TLog.Queued())},
			{labels: labelsStr(map[string]string{"kind": "audit"}), value: int64(d.Audit.Queued())},
		})

	// Go 运行时
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	writeFamily(w, "haweb_go_goroutines", "gauge", "goroutine 数量",
		[]metricSample{{value: int64(runtime.NumGoroutine())}})
	writeFamily(w, "haweb_go_mem_alloc_bytes", "gauge", "堆已分配字节数",
		[]metricSample{{value: int64(mem.Alloc)}})
	writeFamily(w, "haweb_fd_count", "gauge", "打开的文件描述符数（非 Linux 为 0）",
		[]metricSample{{value: fdCount()}})
}
