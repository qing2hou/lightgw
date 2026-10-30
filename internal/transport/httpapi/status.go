package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/platform/caps"
)

// StatusProvider 提供运行状态快照。
//
// 抽成接口而不是直接依赖具体结构：status 的内容会随运维需求增长
// （DB 大小、会话数、TLS 状态……），用接口让本包不必跟着改。
type StatusProvider interface {
	// Status 返回状态快照（必须可 JSON 序列化）。
	Status() StatusSnapshot
}

// StatusSnapshot 是 `/api/status` 的返回内容。
//
// 与 `/healthz` 的分工（D-12）：
//   - `/healthz` **不鉴权**，只返回最小集（ok + 版本），供探活
//   - `/api/status` **需鉴权**，返回详细状态（能力、计数、体积）
//
// 把详细信息放 healthz 是信息泄露面：任何人都能探到规则数、会话数、DB 大小。
type StatusSnapshot struct {
	Version string `json:"version"`
	// Caps 是能力快照。**tc 缺失时这里必须显示 unavailable**（DoD 要求）。
	Caps caps.Caps `json:"caps"`
	// Rules 是已加载的规则数。
	Rules int `json:"rules"`
	// Sessions 是当前活跃会话数。
	Sessions int `json:"sessions"`
	// DBBytes 是配置库大小。
	DBBytes int64 `json:"db_bytes"`
	// LogDropped 是日志丢弃计数（持续增长说明日志系统跟不上）。
	LogDropped uint64 `json:"log_dropped"`
	// LogDropRate 是丢弃率（0..1）。
	LogDropRate float64 `json:"log_drop_rate"`
	// TLSEnabled 表示管理面是否启用 TLS。
	TLSEnabled bool `json:"tls_enabled"`
	// UptimeSec 是进程运行秒数。
	UptimeSec int64 `json:"uptime_sec"`
}

// status 返回详细状态（需鉴权，由路由分组上的中间件保证）。
func (h *Handler) status(c *gin.Context) {
	if h.Status == nil {
		fail(c, http.StatusServiceUnavailable, CodeUnavailable, "状态服务未就绪")
		return
	}
	ok(c, h.Status.Status())
}

// capsOnly 返回能力快照（轻量接口，供前端轮询降级状态）。
func (h *Handler) capsOnly(c *gin.Context) {
	if h.Status == nil {
		fail(c, http.StatusServiceUnavailable, CodeUnavailable, "状态服务未就绪")
		return
	}
	snap := h.Status.Status()
	ok(c, gin.H{
		"caps":     snap.Caps,
		"warnings": snap.Caps.Warnings(),
		// 是否有「无法启动」级别的缺失（正常情况下恒为 false，
		// 因为 Critical 会阻止启动；保留它是为了运行期人为改动后的可见性）
		"critical": snap.Caps.Critical() != nil,
	})
}
