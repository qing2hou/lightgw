// 运行状态与能力快照（技术方案 §9.2 / D-12）。
//
// 两个接口的分工：
//   - GET /api/capabilities：能力快照 + 降级警告（前端轮询，轻量）
//   - GET /api/status      ：能力 + 计数 + 体积（运维面板，稍重）
//
// **都必须鉴权**（挂在 admin 分组下）。D-12：规则数、会话数、DB 大小
// 这些信息不能进无鉴权的 /healthz——那是信息泄露面。
package api

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/platform/caps"
)

// capabilities 返回能力快照与降级警告。
//
// 这是 DoD「tc 缺失时 UI 显示 unavailable」的数据源。
func (h *handlers) capabilities(c *gin.Context) {
	snap := h.capsSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"caps":     snap,
		"warnings": snap.Warnings(),
		"critical": snap.Critical() != nil,
	})
}

// status 返回完整运行状态。
func (h *handlers) status(c *gin.Context) {
	snap := h.capsSnapshot()
	// 规则数与会话数复用现有的统计口径（不新增查询路径）
	rules := 0
	if h.Mgr != nil {
		rules = len(h.Mgr.SnapshotSessions())
	}
	// 日志丢弃数是关键健康指标（技术方案 §7.3 第 4 条）：
	// 持续增长说明日志系统跟不上转发速率。
	var logDropped, logQueued, cleanupFails int64
	if h.TLog != nil {
		logDropped = h.TLog.Dropped()
		logQueued = int64(h.TLog.Queued())
		cleanupFails = h.TLog.CleanupFailures()
	}
	c.JSON(http.StatusOK, gin.H{
		"version":              h.Version,
		"caps":                 snap,
		"warnings":             snap.Warnings(),
		"db_bytes":             h.dbSizeBytes(),
		"log_dropped":          logDropped,
		"log_queued":           logQueued,
		"log_cleanup_failures": cleanupFails,
		"tls_enabled":          h.Cfg != nil && h.Cfg.TLSEnabled(),
		"rules":                rules,
	})
}

// capsSnapshot 返回能力快照；未注入时返回一个全 false 的快照。
//
// 为什么兜底而不是报错：能力探测在启动时必然跑过（platform/app.Run 里
// 强制调用），走到这里为 nil 只可能是测试或旧装配路径。
// 返回全 false 让 UI 显示「不可用」比 500 更有用——至少能看到是哪个缺失。
func (h *handlers) capsSnapshot() caps.Caps {
	if h.Caps != nil {
		return *h.Caps
	}
	return caps.Caps{
		Nftables:    caps.Status{Available: false, Detail: "能力探测未运行（启动路径异常）"},
		Conntrack:   caps.Status{Available: false, Detail: "能力探测未运行"},
		Tc:          caps.Status{Available: false, Detail: "能力探测未运行"},
		Ifb:         caps.Status{Available: false, Detail: "能力探测未运行"},
		CapNetAdmin: caps.Status{Available: false, Detail: "能力探测未运行"},
		SqliteWAL:   caps.Status{Available: false, Detail: "能力探测未运行"},
		PerSrcLimit: caps.Status{Available: false, Detail: "能力探测未运行"},
	}
}

// dbSizeBytes 返回配置库文件大小（字节）。读不到时返回 0。
func (h *handlers) dbSizeBytes() int64 {
	if h.Cfg == nil {
		return 0
	}
	// 用 os.Stat 而不是查 SQLite：库大小是文件属性，查库反而更慢。
	st, err := os.Stat(h.Cfg.Web.DataDir + "/config.db")
	if err != nil {
		return 0
	}
	return st.Size()
}
