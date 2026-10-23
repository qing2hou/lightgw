package api

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/auth"
	"haproxyweb/internal/model"
)

// new2FARouter 完整路由 + 真实认证服务的测试环境（登录/2FA/metrics 全链路）。
func new2FARouter(t *testing.T) (*gin.Engine, *handlers) {
	t.Helper()
	h := newMetricsHandlers(t)
	// metrics 测试基建没有 Auth 与 users 表；补迁移与真实认证服务
	if err := h.DB.AutoMigrate(&model.User{}, &model.LoginFail{}); err != nil {
		t.Fatal(err)
	}
	svc, err := auth.New(t.TempDir(), h.DB)
	if err != nil {
		t.Fatal(err)
	}
	h.Auth = svc
	r, err := NewRouter(h.Deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, h
}

// 两步验证端到端：登录第一步 → /api/login/2fa → 正式令牌可用；监控令牌端到端。
func TestTwoFactorAndMetricsTokenE2E(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r, h := new2FARouter(t)

	// 种子用户（密码 right）；默认管理员不走 seedAdmin，直接建
	hash, err := auth.BcryptHashForTest("right")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.Create(&model.User{Username: "admin", PasswordHash: hash}).Error; err != nil {
		t.Fatal(err)
	}

	do := func(method, path, token string, body any) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		var rd *strings.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = strings.NewReader(string(b))
		} else {
			rd = strings.NewReader("")
		}
		req := httptest.NewRequest(method, path, rd)
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		r.ServeHTTP(w, req)
		return w
	}

	// 未启用 2FA：普通登录直接成功
	w := do("POST", "/api/login", "", map[string]string{"username": "admin", "password": "right"})
	if w.Code != 200 {
		t.Fatalf("普通登录应成功: %d %s", w.Code, w.Body.String())
	}
	var login struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &login)
	adminTok := login.Token

	// Begin：拿密钥与二维码
	w = do("POST", "/api/2fa/begin", adminTok, nil)
	if w.Code != 200 {
		t.Fatalf("2fa begin 失败: %d %s", w.Code, w.Body.String())
	}
	var begin struct {
		Secret string   `json:"secret"`
		QR     string   `json:"qr_png_base64"`
		Codes  []string `json:"backup_codes"`
	}
	json.Unmarshal(w.Body.Bytes(), &begin)
	if begin.Secret == "" || !strings.HasPrefix(begin.QR, "data:image/png;base64,") || len(begin.Codes) != 10 {
		t.Fatalf("begin 响应不完整: %+v", begin)
	}

	// Confirm：错误码 400，正确码 200
	if w = do("POST", "/api/2fa/confirm", adminTok, map[string]string{"code": "000009"}); w.Code != 400 {
		t.Fatalf("错误验证码应 400: %d", w.Code)
	}
	code := auth.TOTPCodeForTest(begin.Secret)
	if w = do("POST", "/api/2fa/confirm", adminTok, map[string]string{"code": code}); w.Code != 200 {
		t.Fatalf("正确验证码应 200: %d %s", w.Code, w.Body.String())
	}

	// 下次登录：第一步返回 totp_required + pending
	w = do("POST", "/api/login", "", map[string]string{"username": "admin", "password": "right"})
	var step1 struct {
		Error        string `json:"error"`
		Code         string `json:"code"`
		PendingToken string `json:"pending_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &step1)
	if step1.Code != "totp_required" || step1.PendingToken == "" {
		t.Fatalf("第一步应返回 totp_required+pending: %s", w.Body.String())
	}

	// 第二步：错误码 401；恢复码兜底成功
	if w = do("POST", "/api/login/2fa", "", map[string]string{"pending_token": step1.PendingToken, "code": "000008"}); w.Code != 401 {
		t.Fatalf("错误验证码第二步应 401: %d", w.Code)
	}
	w = do("POST", "/api/login/2fa", "", map[string]string{"pending_token": step1.PendingToken, "code": begin.Codes[0]})
	if w.Code != 200 {
		t.Fatalf("恢复码第二步应 200: %d %s", w.Code, w.Body.String())
	}
	var step2 struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &step2)

	// 正式令牌可用（普通接口放行）
	if w = do("GET", "/api/rules", step2.Token, nil); w.Code != 200 {
		t.Fatalf("2FA 后正式令牌应可用: %d", w.Code)
	}

	// 监控令牌：签发 → 直接抓 /api/metrics 成功；不能访问普通接口
	w = do("POST", "/api/metrics-token", step2.Token, nil)
	if w.Code != 200 {
		t.Fatalf("签发监控令牌失败: %d %s", w.Code, w.Body.String())
	}
	var mt struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &mt)
	if w = do("GET", "/api/metrics", mt.Token, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "haweb_build_info") {
		t.Fatalf("监控令牌抓取 metrics 失败: %d", w.Code)
	}
	if w = do("GET", "/api/rules", mt.Token, nil); w.Code == 200 {
		t.Fatalf("监控令牌不应能访问普通接口: %d", w.Code)
	}
	// 普通 JWT 抓 metrics 仍可用；无令牌 401
	if w = do("GET", "/api/metrics", step2.Token, nil); w.Code != 200 {
		t.Fatalf("普通令牌抓 metrics 应可用: %d", w.Code)
	}
	if w = do("GET", "/api/metrics", "", nil); w.Code != 401 {
		t.Fatalf("无令牌抓 metrics 应 401: %d", w.Code)
	}
}

// 安全头：TLS 请求带 HSTS；HTTP 请求不带（防钉死明文）；pprof 路径无 CSP。
func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r, _ := new2FARouter(t)

	// 模拟 TLS 请求：gin 经 ServeHTTP 时 Request.TLS 会保留，
	// 造一个非 nil 的 TLS 状态验证 HSTS 分支
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/login", nil)
	req.TLS = &tls.ConnectionState{}
	r.ServeHTTP(w, req)
	if hsts := w.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Error("TLS 请求应携带 HSTS 头")
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Error("非 pprof 路径应携带 CSP")
	}

	// 明文请求：无 HSTS，有 CSP
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/api/login", nil))
	if hsts := w2.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Error("明文请求不应携带 HSTS（防钉死明文访问）")
	}
}
