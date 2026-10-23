package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/model"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "test.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.LoginFail{}); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("right"), bcrypt.MinCost)
	db.Create(&model.User{Username: "admin", PasswordHash: string(hash)})

	svc, err := New(t.TempDir(), db)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestLoginLockout(t *testing.T) {
	svc := newTestService(t)

	// 正确密码可登录
	if _, err := svc.Login("admin", "right", "1.2.3.4"); err != nil {
		t.Fatalf("正确密码应登录成功: %v", err)
	}
	// 错误用户名/密码
	if _, err := svc.Login("admin", "wrong", "1.2.3.4"); err != ErrBadCredentials {
		t.Fatalf("错误密码应返回 ErrBadCredentials, got %v", err)
	}

	// 前面已有 1 次失败，再失败 4 次达到阈值，第 5 次触发锁定
	for i := 0; i < 4; i++ {
		if _, err := svc.Login("admin", "wrong", "1.2.3.4"); err != ErrBadCredentials {
			t.Fatalf("第 %d 次失败应返回 ErrBadCredentials, got %v", i+2, err)
		}
	}
	if _, err := svc.Login("admin", "wrong", "1.2.3.4"); err != ErrLocked {
		t.Fatalf("第 5 次失败后应返回 ErrLocked, got %v", err)
	}
	if _, err := svc.Login("admin", "right", "1.2.3.4"); err != ErrLocked {
		t.Fatalf("锁定期间正确密码也应返回 ErrLocked, got %v", err)
	}

	// 其他 IP 不受影响
	if _, err := svc.Login("admin", "right", "5.6.7.8"); err != nil {
		t.Fatalf("其他 IP 应可正常登录: %v", err)
	}

	// 错误的用户名同样计入失败
	for i := 0; i < 5; i++ {
		_, _ = svc.Login("nobody", "x", "9.9.9.9")
	}
	if _, err := svc.Login("admin", "right", "9.9.9.9"); err != ErrLocked {
		t.Fatalf("用户名错误也应累计锁定该 IP, got %v", err)
	}
}

// pprof 短时令牌：查询参数在 pprof 路径可用；作用域令牌不可访问其他接口。
func TestPprofScopedToken(t *testing.T) {
	svc := newTestService(t)
	gin.SetMode(gin.TestMode)

	token, err := svc.IssuePprofToken("admin")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	normal, err := svc.Login("admin", "right", "1.2.3.4")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}

	run := func(path, queryToken, header, cookie string) int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if queryToken != "" {
			q := req.URL.Query()
			q.Set("pprof_token", queryToken)
			req.URL.RawQuery = q.Encode()
		}
		if header != "" {
			req.Header.Set("Authorization", "Bearer "+header)
		}
		if cookie != "" {
			req.Header.Set("Cookie", PprofCookieName+"="+cookie)
		}
		c.Request = req
		svc.Middleware()(c)
		return w.Code
	}

	// 查询参数令牌在 pprof 路径放行
	if code := run("/api/debug/pprof/", token, "", ""); code != http.StatusOK {
		t.Errorf("pprof 路径 + 查询参数短时令牌应放行，实际 %d", code)
	}
	// 索引页落下的 Cookie 在 pprof 子页面放行（相对链接不带查询参数）
	if code := run("/api/debug/pprof/goroutine?debug=1", "", "", token); code != http.StatusOK {
		t.Errorf("pprof 子页面 + Cookie 短时令牌应放行，实际 %d", code)
	}
	// 普通 JWT 在 pprof 路径（Authorization 头）放行
	if code := run("/api/debug/pprof/", "", normal, ""); code != http.StatusOK {
		t.Errorf("pprof 路径 + 正常令牌应放行，实际 %d", code)
	}
	// 普通 JWT 借道查询参数：拒绝（URL 通道只认作用域令牌）
	if code := run("/api/debug/pprof/", normal, "", ""); code != http.StatusUnauthorized {
		t.Errorf("普通令牌走查询参数应拒绝，实际 %d", code)
	}
	// 普通 JWT 借道 Cookie：拒绝
	if code := run("/api/debug/pprof/", "", "", normal); code != http.StatusUnauthorized {
		t.Errorf("普通令牌走 Cookie 应拒绝，实际 %d", code)
	}
	// 作用域令牌放在 Authorization 头访问其他接口：拒绝（防 URL 令牌重放）
	if code := run("/api/rules", "", token, ""); code != http.StatusUnauthorized {
		t.Errorf("作用域令牌访问其他接口应拒绝，实际 %d", code)
	}
	// 作用域令牌作为查询参数访问其他接口：拒绝（查询参数只在 pprof 路径被读取）
	if code := run("/api/rules", token, "", ""); code != http.StatusUnauthorized {
		t.Errorf("查询参数令牌访问非 pprof 接口应拒绝，实际 %d", code)
	}
	// Cookie 在非 pprof 路径不被读取
	if code := run("/api/rules", "", "", token); code != http.StatusUnauthorized {
		t.Errorf("Cookie 令牌访问非 pprof 接口应拒绝，实际 %d", code)
	}
	// 无令牌：拒绝
	if code := run("/api/debug/pprof/", "", "", ""); code != http.StatusUnauthorized {
		t.Errorf("无令牌应拒绝，实际 %d", code)
	}
	// 篡改的令牌：拒绝
	if code := run("/api/debug/pprof/", token+"x", "", ""); code != http.StatusUnauthorized {
		t.Errorf("篡改令牌应拒绝，实际 %d", code)
	}
	// 篡改的 Cookie：拒绝
	if code := run("/api/debug/pprof/goroutine", "", "", token+"x"); code != http.StatusUnauthorized {
		t.Errorf("篡改 Cookie 应拒绝，实际 %d", code)
	}
}

// 锁定状态持久化：换一个 Service 实例（模拟进程重启）后，锁定期仍然生效。
func TestLoginLockoutPersistsAcrossRestart(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "test.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.LoginFail{}); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("right"), bcrypt.MinCost)
	db.Create(&model.User{Username: "admin", PasswordHash: string(hash)})

	dataDir := t.TempDir()
	svc1, err := New(dataDir, db)
	if err != nil {
		t.Fatal(err)
	}
	// 5 次失败触发锁定
	for i := 0; i < maxLoginFails; i++ {
		if _, err := svc1.Login("admin", "wrong", "9.9.9.9"); err != ErrBadCredentials {
			t.Fatalf("第 %d 次失败应返回 ErrBadCredentials, got %v", i+1, err)
		}
	}
	if _, err := svc1.Login("admin", "right", "9.9.9.9"); err != ErrLocked {
		t.Fatalf("触发锁定后正确密码也应被拒: %v", err)
	}

	// 模拟重启：同一数据库、同一密钥目录，新建 Service 实例
	svc2, err := New(dataDir, db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc2.Login("admin", "right", "9.9.9.9"); err != ErrLocked {
		t.Fatalf("重启后锁定应仍生效，实际: %v", err)
	}
}

// 全局失败阈值：窗口内全网失败达到上限后，全新 IP 的登录（含正确密码）也被临时拒绝。
func TestLoginGlobalThreshold(t *testing.T) {
	svc := newTestService(t)
	for i := 0; i < globalFailThreshold; i++ {
		// 每个 IP 只失败一次，绕过按 IP 锁定，专测全网维度
		ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
		if _, err := svc.Login("admin", "wrong", ip); err != ErrBadCredentials {
			t.Fatalf("第 %d 次失败应返回 ErrBadCredentials, got %v", i+1, err)
		}
	}
	if _, err := svc.Login("admin", "right", "11.0.0.1"); err != ErrGlobalLocked {
		t.Fatalf("达到全网阈值后应返回 ErrGlobalLocked，实际: %v", err)
	}
}
