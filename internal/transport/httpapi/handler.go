// Package httpapi 是新版的 HTTP 传输层。
//
// 分层约束（技术方案 §8.1）：
//
//	本包         只做 DTO 转换 + 参数校验 + 调 app
//	app/*app     用例编排（业务规则在这里）
//	domain       纯函数
//
// **不许有业务判断**：在 handler 里按策略动作分支（例如判断「这条策略
// 是不是拒绝型以决定要不要踢会话」）就是错位——它会散落在各处，改一处
// 漏三处。这条边界的检查方式见 playbook §8.5，本包必须为 0 处。
//
// **错误返回格式定死** `{code, message, data}`（技术方案 §8.6）：
// 不为了「兼容旧版」保留旧的 `{error: "..."}` 结构。旧版前端由
// web/ 的 axios 拦截器统一适配。
package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/app/policyapp"
	"haproxyweb/internal/app/sessionapp"
)

// 错误码（前端按 code 分支，不按 message 文本）。
const (
	// CodeOK 是成功。
	CodeOK = 0
	// CodeBadRequest 是请求参数错误。
	CodeBadRequest = 40000
	// CodeNotFound 是资源不存在。
	CodeNotFound = 40400
	// CodeConflict 是状态冲突（如重复创建）。
	CodeConflict = 40900
	// CodeInternal 是服务端错误。
	CodeInternal = 50000
	// CodeUnavailable 是依赖不可用（如 conntrack 未就绪）。
	CodeUnavailable = 50300
)

// Response 是所有接口的统一返回结构。
type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// ok 返回成功响应。
func ok(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{Code: CodeOK, Message: "ok", Data: data})
}

// fail 返回错误响应。
//
// **message 必须是给用户看的中文**，不含 SQL、路径、栈等内部细节（§8.5）。
// 内部错误由调用方（app 层）记日志，handler 只负责把已经脱敏的原因
// 转成 HTTP 响应。
func fail(c *gin.Context, status, code int, message string) {
	c.JSON(status, Response{Code: code, Message: message})
}

// Actor 是从鉴权中间件注入的调用者信息。
//
// 抽成结构体而不是从 gin.Context 各处取：这样 handler 的签名能表明
// 「这个接口需要调用者身份」，且测试不需要构造完整的鉴权上下文。
type Actor struct {
	Username string
	ClientIP string
}

// actorOf 从上下文取调用者。鉴权中间件负责写入这两个 key。
//
// 取不到时返回空 Actor 而不是报错：审计记录会因此缺用户名，
// 但请求本身仍应被处理（鉴权由中间件负责，handler 不重复判断）。
func actorOf(c *gin.Context) Actor {
	return Actor{
		Username: c.GetString("username"),
		ClientIP: c.ClientIP(),
	}
}

// ctxOf 返回请求上下文。
//
// 用 c.Request.Context() 而不是 context.Background()：客户端断开时
// 下游的长操作（如批量踢 1000 条会话）必须能被取消。
func ctxOf(c *gin.Context) context.Context {
	if c.Request == nil {
		return context.Background()
	}
	return c.Request.Context()
}

// PolicyService 是策略用例的接口（app 层的投影，便于测试替身）。
type PolicyService interface {
	SetEnabled(ctx context.Context, id uint, enabled bool, actor, clientIP string) (*policyapp.EnableResult, error)
	Delete(ctx context.Context, id uint, actor, clientIP string) (int, error)
}

// SessionService 是会话用例的接口。
type SessionService interface {
	KillBatch(ctx context.Context, ids []string, actor, clientIP string) (*sessionapp.BatchResult, error)
	KillByACLGroup(ctx context.Context, groupID uint, prefixes []netip.Prefix, actor, clientIP string) (int, error)
}

// Handler 持有各用例服务。
type Handler struct {
	Policy  PolicyService
	Session SessionService
	// ACLGroupPrefixes 返回名单组的网段列表。
	//
	// 作为函数注入而不是让 handler 查库：handler 不许直接碰 db（§8.6）。
	ACLGroupPrefixes func(ctx context.Context, groupID uint) ([]netip.Prefix, error)
}

// Register 把路由挂到 gin 引擎。
//
// 路径按技术方案 §8.2 的接口清单：`/api/fw-policies/:id/enable|disable`、
// `/api/sessions/kill-batch`、`/api/acl-groups/:id/kick-sessions`。
//
// 调用方负责在这些路由外加鉴权中间件——**鉴权逻辑不写在本包**（§8.6）。
func (h *Handler) Register(r gin.IRouter) {
	g := r.Group("/api")
	// 策略启停（旧代码缺这两个接口，策略只能删不能停）
	g.POST("/fw-policies/:id/enable", h.enablePolicy)
	g.POST("/fw-policies/:id/disable", h.disablePolicy)
	g.DELETE("/fw-policies/:id", h.deletePolicy)
	// 批量清会话（旧代码只支持单条 {id}）
	g.POST("/sessions/kill-batch", h.killSessionsBatch)
	// 名单组变更后踢匹配会话
	g.POST("/acl-groups/:id/kick-sessions", h.kickACLGroupSessions)
}

// parseID 解析路径里的 uint 参数。
func parseID(c *gin.Context, what string) (uint, bool) {
	raw := c.Param("id")
	var id uint64
	if _, err := fmt.Sscanf(raw, "%d", &id); err != nil || id == 0 {
		fail(c, http.StatusBadRequest, CodeBadRequest, fmt.Sprintf("%s ID 无效", what))
		return 0, false
	}
	return uint(id), true
}

// SetEnabled 是启停的共用实现（enable / disable 只差一个布尔）。
//
// **不含业务判断**：是否踢会话、先改库还是先重装，全在 policyapp 里。
func (h *Handler) setEnabled(c *gin.Context, enabled bool) {
	id, okid := parseID(c, "策略")
	if !okid {
		return
	}
	if h.Policy == nil {
		fail(c, http.StatusServiceUnavailable, CodeUnavailable, "策略服务未就绪")
		return
	}
	a := actorOf(c)
	res, err := h.Policy.SetEnabled(ctxOf(c), id, enabled, a.Username, a.ClientIP)
	if err != nil {
		if isNotFound(err) {
			fail(c, http.StatusNotFound, CodeNotFound, "策略不存在")
			return
		}
		// app 层返回的已经是脱敏中文，直接透出
		fail(c, http.StatusInternalServerError, CodeInternal, publicMessage(err))
		return
	}
	ok(c, gin.H{
		"id":              res.ID,
		"enabled":         res.Enabled,
		"killed_sessions": res.KilledSessions,
	})
}

func (h *Handler) enablePolicy(c *gin.Context)  { h.setEnabled(c, true) }
func (h *Handler) disablePolicy(c *gin.Context) { h.setEnabled(c, false) }

// deletePolicy 删除策略（app 层会踢掉匹配会话）。
func (h *Handler) deletePolicy(c *gin.Context) {
	id, okid := parseID(c, "策略")
	if !okid {
		return
	}
	if h.Policy == nil {
		fail(c, http.StatusServiceUnavailable, CodeUnavailable, "策略服务未就绪")
		return
	}
	a := actorOf(c)
	killed, err := h.Policy.Delete(ctxOf(c), id, a.Username, a.ClientIP)
	if err != nil {
		if isNotFound(err) {
			fail(c, http.StatusNotFound, CodeNotFound, "策略不存在")
			return
		}
		fail(c, http.StatusInternalServerError, CodeInternal, publicMessage(err))
		return
	}
	ok(c, gin.H{"id": id, "killed_sessions": killed})
}

// killSessionsBatch 批量掐断会话。
//
// 请求体：`{"ids": ["...", "..."]}`
// 响应：`{"killed": [...], "failed": {id: reason}, "not_found": [...]}`
func (h *Handler) killSessionsBatch(c *gin.Context) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		fail(c, http.StatusBadRequest, CodeBadRequest, "请求体需为 JSON 且含 ids 数组")
		return
	}
	if h.Session == nil {
		fail(c, http.StatusServiceUnavailable, CodeUnavailable, "会话服务未就绪")
		return
	}
	a := actorOf(c)
	res, err := h.Session.KillBatch(ctxOf(c), in.IDs, a.Username, a.ClientIP)
	if err != nil {
		fail(c, http.StatusInternalServerError, CodeInternal, publicMessage(err))
		return
	}
	ok(c, gin.H{
		"killed":    res.Killed,
		"failed":    res.Failed,
		"not_found": res.NotFound,
	})
}

// kickACLGroupSessions 名单组变更后踢掉源地址落在组内的会话。
func (h *Handler) kickACLGroupSessions(c *gin.Context) {
	id, okid := parseID(c, "名单组")
	if !okid {
		return
	}
	if h.Session == nil {
		fail(c, http.StatusServiceUnavailable, CodeUnavailable, "会话服务未就绪")
		return
	}
	if h.ACLGroupPrefixes == nil {
		fail(c, http.StatusServiceUnavailable, CodeUnavailable, "名单组查询未就绪")
		return
	}
	ctx := ctxOf(c)
	prefixes, err := h.ACLGroupPrefixes(ctx, id)
	if err != nil {
		if isNotFound(err) {
			fail(c, http.StatusNotFound, CodeNotFound, "名单组不存在")
			return
		}
		fail(c, http.StatusInternalServerError, CodeInternal, publicMessage(err))
		return
	}
	a := actorOf(c)
	killed, err := h.Session.KillByACLGroup(ctx, id, prefixes, a.Username, a.ClientIP)
	if err != nil {
		fail(c, http.StatusInternalServerError, CodeInternal, publicMessage(err))
		return
	}
	ok(c, gin.H{"id": id, "killed_sessions": killed})
}

// isNotFound 判定「资源不存在」。
//
// 用字符串匹配而不是 errors.Is：app 层的 ErrNotFound 在 policyapp /
// sessionapp 是两个不同的值，本包不应 import 它们的错误变量来做判断
// （那会把 app 的内部表示泄漏到 transport 层）。
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "不存在")
}

// publicMessage 把错误转成可回传给客户端的中文消息。
//
// app 层已保证错误消息是中文且脱敏；这里只做「首字母大写」与
// 「去掉可能的换行」两件格式化的事，**不做内容改写**。
func publicMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "操作失败"
	}
	return msg
}
