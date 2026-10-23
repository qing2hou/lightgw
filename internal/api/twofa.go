package api

import (
	"encoding/base64"

	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"

	"haproxyweb/internal/auth"
)

// ---------- 两步验证登录 ----------

type login2FAReq struct {
	PendingToken string `json:"pending_token" binding:"required"`
	Code         string `json:"code" binding:"required"`
}

// loginSecondFactor 两步验证第二步：pending 凭据 + 验证码/恢复码 → 正式 JWT。
// 使用独立错误码 totp_required 之外的失败一律按凭证错误处理（401）。
func (h *handlers) loginSecondFactor(c *gin.Context) {
	var req login2FAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请填写两步验证凭据与验证码"})
		return
	}
	token, err := h.Auth.LoginSecondFactor(req.PendingToken, req.Code, h.clientIP(c))
	if err != nil {
		// 尽力解析用户名进审计（pending 凭据无效时为空）
		username, _, _ := h.Auth.ParseToken(req.PendingToken)
		h.Audit.Record(username, "login_2fa_failed", "两步验证失败", h.clientIP(c))
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}
	username, _, _ := h.Auth.ParseToken(token)
	var user struct {
		MustChangePassword bool
	}
	h.DB.Raw("SELECT must_change_password FROM users WHERE username = ?", username).Scan(&user)
	h.Audit.Record(username, "login_2fa", "两步验证登录成功", h.clientIP(c))
	c.JSON(200, gin.H{
		"token":                token,
		"username":             username,
		"must_change_password": user.MustChangePassword,
	})
}

// ---------- 两步验证设置 ----------

func (h *handlers) totpStatus(c *gin.Context) {
	c.JSON(200, h.Auth.TOTPStatus(h.username(c)))
}

// totpBegin 生成待扫码密钥。响应含 otpauth URL、二维码 PNG（base64）与
// 一次性展示的恢复码；Confirm 前两步验证不生效。
func (h *handlers) totpBegin(c *gin.Context) {
	secret, otpauthURL, codes, err := h.Auth.BeginTOTPSetup(h.username(c))
	if err != nil {
		h.serverError(c, "生成两步验证密钥", err)
		return
	}
	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, 240)
	if err != nil {
		h.serverError(c, "生成二维码", err)
		return
	}
	h.Audit.Record(h.username(c), "2fa_begin", "生成两步验证密钥（待确认）", h.clientIP(c))
	c.JSON(200, gin.H{
		"secret":        secret,
		"otpauth_url":   otpauthURL,
		"qr_png_base64": base64DataURI(png),
		"backup_codes":  codes,
	})
}

type totpConfirmReq struct {
	Code string `json:"code" binding:"required"`
}

func (h *handlers) totpConfirm(c *gin.Context) {
	var req totpConfirmReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请输入验证器显示的 6 位验证码"})
		return
	}
	if err := h.Auth.ConfirmTOTP(h.username(c), req.Code); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.Audit.Record(h.username(c), "2fa_enable", "启用两步验证", h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}

type totpDisableReq struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

func (h *handlers) totpDisable(c *gin.Context) {
	var req totpDisableReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "请填写密码与验证码"})
		return
	}
	if err := h.Auth.DisableTOTP(h.username(c), req.Password, req.Code); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	h.Audit.Record(h.username(c), "2fa_disable", "关闭两步验证", h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}

// ---------- 监控采集令牌 ----------

// issueMetricsToken 签发长效监控采集令牌（仅 /api/metrics）。
// 每次调用签发新令牌，改密后全部失效（token_version）。
func (h *handlers) issueMetricsToken(c *gin.Context) {
	token, err := h.Auth.IssueMetricsToken(h.username(c))
	if err != nil {
		h.serverError(c, "签发监控令牌", err)
		return
	}
	h.Audit.Record(h.username(c), "metrics_token", "签发监控采集令牌", h.clientIP(c))
	c.JSON(200, gin.H{
		"token":      token,
		"usage":      "curl -H 'Authorization: Bearer <token>' https://<host>/api/metrics",
		"expires_in": int(auth.MetricsTokenTTL.Seconds()),
	})
}

// base64DataURI PNG 转 base64 数据 URI（前端 <img> 直显）。
func base64DataURI(b []byte) string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b)
}
