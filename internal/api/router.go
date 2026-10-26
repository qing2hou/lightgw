package api

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"haproxyweb/internal/audit"
	"haproxyweb/internal/auth"
	"haproxyweb/internal/config"
	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
	"haproxyweb/internal/trafficlog"
)

type Deps struct {
	DB      *gorm.DB
	Auth    *auth.Service
	Audit   *audit.Writer
	TLog    *trafficlog.Writer
	Mgr     *proxy.Manager
	Cfg     *config.Config
	Version string
}

func NewRouter(d Deps, distFS fs.FS) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.LoggerWithFormatter(func(p gin.LogFormatterParams) string {
		// 访问日志带来源 IP 与 UA，安全事件可追溯到来源；UA 截断防刷屏
		ua := p.Request.UserAgent()
		if len(ua) > 128 {
			ua = ua[:128]
		}
		return fmt.Sprintf("[web] %s %s %s %d %s %s\n", p.ClientIP, p.Method, p.Path, p.StatusCode, p.Latency, ua)
	}), gin.Recovery())

	// 管理后台不允许被嵌入 iframe，禁止 MIME 嗅探；
	// TLS 部署下启用 HSTS（HTTP 部署不加，防止钉死明文访问）。
	// CSP 不覆盖 /api/debug/pprof：标准库 pprof 页面自带内联样式与
	// 相对链接脚本渲染，套 CSP 会破坏其展示。
	r.Use(func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		if c.Request.TLS != nil {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if !strings.HasPrefix(c.Request.URL.Path, "/api/debug/pprof") {
			c.Header("Content-Security-Policy",
				"default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
					"script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		}
		c.Next()
	})

	// 客户端 IP 只信真实连接来源；仅当显式配置可信代理网段时才解析 X-Forwarded-For，
	// 否则任何客户端都能伪造该头绕过登录失败锁定、污染审计日志
	if len(d.Cfg.Web.TrustedProxies) > 0 {
		if err := r.SetTrustedProxies(d.Cfg.Web.TrustedProxies); err != nil {
			return nil, fmt.Errorf("web.trusted_proxies 配置无效: %w", err)
		}
	} else if err := r.SetTrustedProxies(nil); err != nil {
		return nil, err
	}

	h := &handlers{Deps: d}

	apiGroup := r.Group("/api")
	// 请求体上限，防止超大 JSON 打爆内存
	apiGroup.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
		c.Next()
	})
	apiGroup.POST("/login", h.login)
	// 两步验证第二步：凭第一步返回的 pending 凭据 + 验证码换取正式令牌
	apiGroup.POST("/login/2fa", h.loginSecondFactor)

	// 监控采集：优先接受 Accepter Bearer 的长效监控令牌（供 Prometheus 无人值守抓取），
	// 普通会话 JWT 同样放行
	r.GET("/api/metrics", h.metricsWithToken)

	// 未修改默认密码前，仅允许访问改密相关接口
	authed := apiGroup.Group("", h.Auth.Middleware())
	{
		authed.POST("/logout", h.logout)
		authed.GET("/me", h.me)
		authed.PUT("/password", h.changePassword)
	}

	// 其余管理接口要求已完成初始改密
	admin := apiGroup.Group("", h.Auth.Middleware(), h.requirePasswordChanged())
	{
		admin.GET("/rules", h.listRules)
		admin.POST("/rules", h.createRule)
		admin.PUT("/rules/:id", h.updateRule)
		admin.DELETE("/rules/:id", h.deleteRule)
		admin.POST("/rules/:id/enable", h.enableRule)
		admin.POST("/rules/:id/disable", h.disableRule)
		admin.GET("/rules/:id/health", h.ruleHealthHistory)

		admin.GET("/stats", h.stats)
		admin.GET("/streams", h.streams)
		admin.GET("/rules/:id/live", h.ruleLiveStats)
		admin.GET("/traffic-logs", h.trafficLogs)
		admin.GET("/audit-logs", h.auditLogs)
		admin.GET("/rules/export", h.exportRules)
		admin.GET("/backup/db", h.backupDB)
		admin.GET("/observability", h.observability)
		admin.GET("/pprof-token", h.issuePprofToken)
		admin.GET("/debug/pprof/*any", h.pprof)

		// 名单组（白名单/黑名单组，规则引用）
		admin.GET("/acl-groups", h.listAclGroups)
		admin.POST("/acl-groups", h.createAclGroup)
		admin.PUT("/acl-groups/:id", h.updateAclGroup)
		admin.DELETE("/acl-groups/:id", h.deleteAclGroup)

		// 网卡列表（snat 规则表单下拉）
		admin.GET("/fw-policies", h.listFwPolicies)
		admin.POST("/fw-policies", h.createFwPolicy)
		admin.PUT("/fw-policies/:id", h.updateFwPolicy)
		admin.DELETE("/fw-policies/:id", h.deleteFwPolicy)
		admin.PUT("/fw-policies/reorder", h.reorderFwPolicies)
		admin.GET("/egresses", h.listEgresses)
		admin.POST("/egresses", h.createEgress)
		admin.PUT("/egresses/:id", h.updateEgress)
		admin.DELETE("/egresses/:id", h.deleteEgress)
		admin.POST("/egresses/:id/probe", h.probeEgress)

		admin.GET("/sessions", h.listSessions)
		admin.POST("/sessions/kill", h.killSession)

		admin.GET("/interfaces", h.listInterfaces)

		// 带宽包（多规则共享下载额度）
		admin.GET("/bandwidth-groups", h.listBWGroups)
		admin.POST("/bandwidth-groups", h.createBWGroup)
		admin.PUT("/bandwidth-groups/:id", h.updateBWGroup)
		admin.DELETE("/bandwidth-groups/:id", h.deleteBWGroup)

		// 两步验证 & 监控令牌（设置页）
		admin.GET("/2fa/status", h.totpStatus)
		admin.POST("/2fa/begin", h.totpBegin)
		admin.POST("/2fa/confirm", h.totpConfirm)
		admin.POST("/2fa/disable", h.totpDisable)
		admin.POST("/metrics-token", h.issueMetricsToken)
	}

	// 规则导入：请求体可能是大规则集，单独放宽 body 上限
	importGroup := r.Group("/api", h.Auth.Middleware(), h.requirePasswordChanged(), func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, importMaxBodyBytes)
		c.Next()
	})
	importGroup.POST("/rules/import", h.importRules)

	// 健康检查：不鉴权，供负载均衡器 / systemd / 探针使用
	r.GET("/healthz", h.healthz)

	if distFS != nil {
		r.NoRoute(spaHandler(distFS))
	}
	return r, nil
}

// healthz 进程与运行状态摘要：规则加载情况、日志丢弃计数与引擎拒绝/panic 计数
// （丢弃数非零说明日志队列打满，拒绝/panic 非零说明发生过资源防护或异常隔离）。
func (h *handlers) healthz(c *gin.Context) {
	var ruleTotal, ruleEnabled, ruleFailed int64
	h.DB.Model(&model.ForwardRule{}).Count(&ruleTotal)
	h.DB.Model(&model.ForwardRule{}).Where("enabled = ?", true).Count(&ruleEnabled)
	h.DB.Model(&model.ForwardRule{}).Where("last_error <> ''").Count(&ruleFailed)
	ec := h.Mgr.EngineCounters()

	// 出口状态摘要（M3/P2-2：AC-4.5 的 healthz 可见性）
	var egs []model.Egress
	h.DB.Where("enabled = ?", true).Find(&egs)
	egressUp, egressDown := 0, 0
	for _, e := range egs {
		if proxy.EgressUp(e.ID) {
			egressUp++
		} else {
			egressDown++
		}
	}

	c.JSON(200, gin.H{
		"egresses_up":            egressUp,
		"egresses_down":          egressDown,
		"status":                 "ok",
		"version":                h.Version,
		"tls":                    h.Cfg.TLSEnabled(),
		"uptime_seconds":         int64(time.Since(metricsStartTime).Seconds()),
		"db_size_bytes":          dbSizeBytes(h.Cfg.Web.DataDir),
		"backends_down":          h.Mgr.BackendsDown(),
		"rules_total":            ruleTotal,
		"rules_enabled":          ruleEnabled,
		"rules_failed":           ruleFailed,
		"active_sessions":        ec.SessionsActive,
		"rejected_global":        ec.RejectedGlobal,
		"rejected_rule":          ec.RejectedRule,
		"accept_errors":          ec.AcceptErrors,
		"panics":                 ec.Panics,
		"traffic_log_dropped":    h.TLog.Dropped(),
		"audit_log_dropped":      h.Audit.Dropped(),
		"traffic_cleanup_failed": h.TLog.CleanupFailures(),
		"audit_cleanup_failed":   h.Audit.CleanupFailures(),
		"traffic_log_rotated":    h.TLog.Rotated(), // 容量/水位自动轮转累计删除行数（非零=轮转已发生）
	})
}

// spaHandler 嵌入式前端静态资源，未命中的路径回退到 index.html（SPA 路由）。
func spaHandler(distFS fs.FS) gin.HandlerFunc {
	sub, err := fs.Sub(distFS, "web/dist")
	if err != nil {
		return func(c *gin.Context) { c.String(500, "前端资源目录无效") }
	}
	fileServer := http.FileServer(http.FS(sub))
	return func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "接口不存在"})
			return
		}
		p := strings.TrimPrefix(c.Request.URL.Path, "/")
		if p != "" {
			if st, err := fs.Stat(sub, p); err == nil && !st.IsDir() {
				fileServer.ServeHTTP(c.Writer, c.Request)
				return
			}
		}
		// SPA 回退
		if _, err := fs.Stat(sub, "index.html"); err != nil {
			c.String(http.StatusServiceUnavailable, "前端资源未构建：请先执行 make web")
			return
		}
		c.Request.URL.Path = "/"
		fileServer.ServeHTTP(c.Writer, c.Request)
	}
}

type handlers struct {
	Deps
}

// maxBodyBytes 管理 API 请求体上限（1MB），防止恶意超大请求耗尽内存。
const maxBodyBytes = 1 << 20

// requirePasswordChanged 拦截仍使用默认密码的会话，只放行改密相关接口。
func (h *handlers) requirePasswordChanged() gin.HandlerFunc {
	return func(c *gin.Context) {
		if v, ok := c.Get("must_change_password"); ok {
			if b, _ := v.(bool); b {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "请先修改默认密码再进行其他操作",
					"code":  "must_change_password",
				})
				return
			}
		}
		c.Next()
	}
}

func (h *handlers) clientIP(c *gin.Context) string { return c.ClientIP() }

func (h *handlers) username(c *gin.Context) string {
	v, _ := c.Get("username")
	s, _ := v.(string)
	return s
}

// ---------- 认证 ----------

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h *handlers) login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请输入用户名和密码"})
		return
	}
	ip := h.clientIP(c)
	token, err := h.Auth.Login(req.Username, req.Password, ip)
	if err != nil {
		if errors.Is(err, auth.ErrTOTPRequired) {
			// 第一步通过：返回待第二步使用的短时凭据（2 分钟有效）
			h.Audit.Record(req.Username, "login_2fa_pending", "密码通过，等待两步验证码", ip)
			c.JSON(401, gin.H{
				"error":         err.Error(),
				"code":          "totp_required",
				"pending_token": token,
			})
			return
		}
		h.Audit.Record(req.Username, "login_failed", "登录失败", ip)
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}
	h.Audit.Record(req.Username, "login", "登录成功", ip)

	var user model.User
	mustChange := false
	if h.DB.Where("username = ?", req.Username).First(&user).Error == nil {
		mustChange = user.MustChangePassword
	}
	c.JSON(200, gin.H{"token": token, "username": req.Username, "must_change_password": mustChange})
}

func (h *handlers) logout(c *gin.Context) {
	h.Audit.Record(h.username(c), "logout", "退出登录", h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}

func (h *handlers) me(c *gin.Context) {
	var user model.User
	if err := h.DB.Where("username = ?", h.username(c)).First(&user).Error; err != nil {
		c.JSON(404, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(200, gin.H{"username": user.Username, "must_change_password": user.MustChangePassword})
}

type passwordReq struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

func (h *handlers) changePassword(c *gin.Context) {
	var req passwordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请填写原密码和新密码"})
		return
	}
	token, err := h.Auth.ChangePassword(h.username(c), req.OldPassword, req.NewPassword)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.Audit.Record(h.username(c), "password_change", "修改密码", h.clientIP(c))
	c.JSON(200, gin.H{"ok": true, "token": token})
}

// ---------- 统计与会话 ----------

func (h *handlers) stats(c *gin.Context) {
	var ruleCount, enabledCount int64
	h.DB.Model(&model.ForwardRule{}).Count(&ruleCount)
	h.DB.Model(&model.ForwardRule{}).Where("enabled = ?", true).Count(&enabledCount)

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	var todayUp, todayDown, totalUp, totalDown struct{ Sum int64 }
	h.DB.Model(&model.TrafficLog{}).Select("COALESCE(SUM(upload_bytes),0) as sum").
		Where("started_at >= ? AND status != ?", today, model.StatusDenied).Scan(&todayUp)
	h.DB.Model(&model.TrafficLog{}).Select("COALESCE(SUM(download_bytes),0) as sum").
		Where("started_at >= ? AND status != ?", today, model.StatusDenied).Scan(&todayDown)
	h.DB.Model(&model.TrafficLog{}).Select("COALESCE(SUM(upload_bytes),0) as sum").
		Where("status != ?", model.StatusDenied).Scan(&totalUp)
	h.DB.Model(&model.TrafficLog{}).Select("COALESCE(SUM(download_bytes),0) as sum").
		Where("status != ?", model.StatusDenied).Scan(&totalDown)

	// 活跃会话的字节数单独返回：这些数据尚未落库，与落库统计分开口径，避免双重计数
	sessions := h.Mgr.ActiveSessions()
	var liveUp, liveDown int64
	for _, s := range sessions {
		liveUp += s.UploadBytes
		liveDown += s.DownloadBytes
	}

	c.JSON(200, gin.H{
		"rule_count":           ruleCount,
		"enabled_count":        enabledCount,
		"active_sessions":      len(sessions),
		"live_upload_bytes":    liveUp,
		"live_download_bytes":  liveDown,
		"today_upload_bytes":   todayUp.Sum,
		"today_download_bytes": todayDown.Sum,
		"total_upload_bytes":   totalUp.Sum,
		"total_download_bytes": totalDown.Sum,
	})
}

func (h *handlers) streams(c *gin.Context) {
	c.JSON(200, gin.H{"items": h.Mgr.ActiveSessions()})
}
