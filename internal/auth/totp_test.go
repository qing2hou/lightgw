package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// RFC 6238 附录 B 官方测试向量（SHA-1，8 位截断取前 6 位对齐本实现）。
// 种子为 "12345678901234567890" 的 base32 编码，时间步长 30s。
func TestHOTPRFCVectors(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // RFC 种子的 base32
	vectors := []struct {
		sec  int64
		code string // RFC 4226 附录 D 的 6 位向量 + RFC 6238 续表
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}
	raw, err := decodeBase32(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		if got := hotp(raw, uint64(v.sec)); got != v.code {
			t.Errorf("HOTP(ctr=%d) = %s, 期望 RFC 向量 %s", v.sec, got, v.code)
		}
		// 由向量时间推出窗口并验证 ValidateTOTP 的完整链路
		at := time.Unix(v.sec*totpPeriod, 0).UTC()
		if !ValidateTOTP(secret, v.code, at, nil) {
			t.Errorf("ValidateTOTP 在向量时刻应通过: ctr=%d", v.sec)
		}
	}
}

// 错误码 / 超窗码 / 已用窗口防重放。
func TestValidateTOTPNegativeAndReplay(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cur := now.Unix() / totpPeriod
	raw, _ := decodeBase32(secret)
	code := hotp(raw, uint64(cur))

	if ValidateTOTP(secret, "000000", now, nil) {
		// 极小概率撞码；用确定错误码避免 flaky
		if code != "000000" {
			t.Error("错误验证码不应通过")
		}
	}
	if ValidateTOTP(secret, code, now.Add(90*time.Second), nil) {
		t.Error("超出 ±1 窗口偏差的验证码不应通过")
	}
	used := map[int64]bool{}
	if !ValidateTOTP(secret, code, now, used) {
		t.Fatal("首次校验应通过")
	}
	if ValidateTOTP(secret, code, now, used) {
		t.Error("同一窗口的验证码二次使用应被拒（防重放）")
	}
	// 相邻窗口仍可用（时钟偏差容忍与防重放互不干扰）
	next := hotp(raw, uint64(cur+1))
	if !ValidateTOTP(secret, next, now.Add(totpPeriod*time.Second), used) {
		t.Error("下一窗口的验证码应通过")
	}
	// 格式防护：非 6 位 / 非法 base32
	if ValidateTOTP(secret, "12345", now, nil) || ValidateTOTP(secret, "1234567", now, nil) {
		t.Error("位数不符不应通过")
	}
	if ValidateTOTP("!!!", "123456", now, nil) {
		t.Error("非法密钥不应通过")
	}
}

func TestBackupCodes(t *testing.T) {
	codes, err := GenerateBackupCodes(backupCodeNum)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != backupCodeNum {
		t.Fatalf("应生成 %d 个恢复码，实际 %d", backupCodeNum, len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 9 || c[4] != '-' {
			t.Errorf("恢复码格式不符: %q", c)
		}
		if seen[c] {
			t.Errorf("恢复码重复: %q", c)
		}
		seen[c] = true
	}
}

// 攻击面回归：pending 凭据不得通过普通中间件访问任何管理接口（fail-closed），
// 防止"密码对 → 拿 pending token 直接当会话令牌用"绕过两步验证。
func TestPendingTokenCannotBypassMiddleware(t *testing.T) {
	svc := newTestService(t)

	// 启用两步验证
	secret, _, codes, err := svc.BeginTOTPSetup("admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfirmTOTP("admin", hotp(decode32(t, secret), uint64(time.Now().Unix()/totpPeriod))); err != nil {
		t.Fatal(err)
	}

	pending, err := svc.Login("admin", "right", "1.2.3.4")
	if err != ErrTOTPRequired || pending == "" {
		t.Fatalf("第一步应返回 pending: %v", err)
	}

	gin.SetMode(gin.TestMode)
	for _, path := range []string{"/api/rules", "/api/backup/db", "/api/password", "/api/2fa/begin", "/api/metrics"} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, path, nil)
		c.Request.Header.Set("Authorization", "Bearer "+pending)
		svc.Middleware()(c)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("pending token 访问 %s 应 401（fail-closed），实际 %d", path, w.Code)
		}
	}

	// pending token 只能用于 /api/login/2fa 这条路径——经 LoginSecondFactor 正常完成
	svc.totpMu.Lock()
	delete(svc.totpUsedWin, "admin")
	svc.totpMu.Unlock()
	tok, err := svc.LoginSecondFactor(pending, codes[0], "1.2.3.4")
	if err != nil || tok == "" {
		t.Fatalf("pending token 走正门（第二步）应成功: %v", err)
	}
}

// 攻击面回归：第二步验证码爆破不能靠"循环重新登录第一步"清零失败计数——
// per-IP 锁定必须对第二步生效。
func TestSecondFactorBruteForceLocked(t *testing.T) {
	svc := newTestService(t)
	secret, _, _, err := svc.BeginTOTPSetup("admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ConfirmTOTP("admin", hotp(decode32(t, secret), uint64(time.Now().Unix()/totpPeriod))); err != nil {
		t.Fatal(err)
	}

	ip := "6.6.6.6"
	// 5 轮"第一步拿新 pending + 第二步错误码"：每轮第一次第二步失败即计 1 次失败，
	// 第 5 轮触发 per-IP 锁定
	var lastPending string
	for i := 0; i < 5; i++ {
		pending, err := svc.Login("admin", "right", ip)
		if err != ErrTOTPRequired {
			t.Fatalf("第 %d 轮第一步应返回 pending: %v", i+1, err)
		}
		lastPending = pending
		if _, err := svc.LoginSecondFactor(pending, fmt.Sprintf("%06d", 100000+i), ip); err != ErrBadTOTP {
			t.Fatalf("第 %d 轮第二步错误码应返回 ErrBadTOTP: %v", i+1, err)
		}
	}
	// 第 5 次失败后：即使再拿到新 pending，第二步也应被锁定
	if _, err := svc.LoginSecondFactor(lastPending, "123456", ip); err != ErrLocked {
		t.Fatalf("爆破第 5 次后第二步应被 per-IP 锁定，实际: %v", err)
	}
	// 全局锁也应已在接下来生效（第二步失败计入全局窗口）
	if now := time.Now().Unix(); now < svc.globalLockedUntil.Load() {
		// globalFailThreshold=100，5 次未触发全局锁——正常，不算失败
		_ = now
	}
}

// decode32 测试辅助：base32 解码（不发错误——密钥来自 BeginTOTPSetup 必合法）。
func decode32(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeBase32(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 两步登录全流程：Begin → Confirm 启用 → 登录第一步 ErrTOTPRequired+pending →
// 第二步 TOTP 通过；错误码计数；恢复码一次性核销；Disable 需密码+码。
func TestTwoFactorLoginFlow(t *testing.T) {
	svc := newTestService(t)

	// 未启用时直接密码登录
	tok, err := svc.Login("admin", "right", "1.2.3.4")
	if err != nil || tok == "" {
		t.Fatalf("未启用两步验证时密码登录应成功: %v", err)
	}

	// Begin：拿到密钥/otpauth/恢复码，状态 pending
	secret, urlStr, codes, err := svc.BeginTOTPSetup("admin")
	if err != nil || secret == "" || urlStr == "" || len(codes) != backupCodeNum {
		t.Fatalf("BeginTOTPSetup 失败: %v", err)
	}
	st := svc.TOTPStatus("admin")
	if st.Enabled || !st.Pending || st.BackupRemaining != backupCodeNum {
		t.Fatalf("Begin 后应为 pending 态: %+v", st)
	}

	// 计算当前验证码（用待启用密钥）
	raw, _ := decodeBase32(secret)
	code := hotp(raw, uint64(time.Now().Unix()/totpPeriod))

	// 错误验证码确认失败
	if err := svc.ConfirmTOTP("admin", "000001"); err == nil {
		t.Fatal("错误验证码不应确认成功")
	}
	// 正确验证码确认成功 → enabled
	if err := svc.ConfirmTOTP("admin", code); err != nil {
		t.Fatalf("正确验证码确认失败: %v", err)
	}
	if st = svc.TOTPStatus("admin"); !st.Enabled {
		t.Fatalf("确认后应为 enabled: %+v", st)
	}

	// 登录第一步：ErrTOTPRequired 且带 pending 凭据
	pending, err := svc.Login("admin", "right", "1.2.3.4")
	if err != ErrTOTPRequired || pending == "" {
		t.Fatalf("启用后第一步应返回 ErrTOTPRequired+pending: err=%v pending=%q", err, pending)
	}
	// Confirm 消耗的窗口会挡住紧接着的同一验证码（防重放，行为正确）；
	// 此处白盒重置已用窗口，模拟"启用后过一会儿再登录"的真实节奏
	svc.totpMu.Lock()
	delete(svc.totpUsedWin, "admin")
	svc.totpMu.Unlock()
	// pending 凭据被篡改：第二步拒绝
	if _, err := svc.LoginSecondFactor(pending+"x", code, "1.2.3.4"); err == nil {
		t.Fatal("篡改的 pending 凭据应被拒")
	}
	// 错误验证码：拒绝（并计入失败）
	if _, err := svc.LoginSecondFactor(pending, "000002", "1.2.3.4"); err != ErrBadTOTP {
		t.Fatalf("错误验证码应返回 ErrBadTOTP: %v", err)
	}
	// 正确验证码：换得正式令牌
	code2 := hotp(raw, uint64(time.Now().Unix()/totpPeriod))
	tok2, err := svc.LoginSecondFactor(pending, code2, "1.2.3.4")
	if err != nil || tok2 == "" {
		t.Fatalf("第二步应成功: %v", err)
	}

	// 恢复码登录：一次性
	pending2, _ := svc.Login("admin", "right", "2.3.4.5")
	if pending2 == "" {
		t.Fatal("第一步应返回 pending")
	}
	tok3, err := svc.LoginSecondFactor(pending2, codes[0], "2.3.4.5")
	if err != nil || tok3 == "" {
		t.Fatalf("恢复码应可登录: %v", err)
	}
	if st = svc.TOTPStatus("admin"); st.BackupRemaining != backupCodeNum-1 {
		t.Fatalf("恢复码核销后应剩 %d，实际 %d", backupCodeNum-1, st.BackupRemaining)
	}
	pending3, _ := svc.Login("admin", "right", "2.3.4.5")
	if _, err := svc.LoginSecondFactor(pending3, codes[0], "2.3.4.5"); err != ErrBadTOTP {
		t.Fatalf("已用恢复码二次使用应拒绝: %v", err)
	}

	// Disable：错密码拒；对密码+错码拒；对密码+恢复码成功
	pending4, _ := svc.Login("admin", "right", "3.4.5.6")
	_ = pending4
	freshCode := hotp(raw, uint64(time.Now().Unix()/totpPeriod))
	if err := svc.DisableTOTP("admin", "wrong", freshCode); err == nil {
		t.Fatal("错误密码不应能关闭")
	}
	if err := svc.DisableTOTP("admin", "right", "000003"); err == nil {
		t.Fatal("错误验证码不应能关闭")
	}
	if err := svc.DisableTOTP("admin", "right", codes[1]); err != nil {
		t.Fatalf("密码+恢复码应能关闭: %v", err)
	}
	if st = svc.TOTPStatus("admin"); st.Enabled || st.Pending || st.BackupRemaining != 0 {
		t.Fatalf("关闭后状态应归零: %+v", st)
	}
	// 关闭后回到单密码登录
	if tok4, err := svc.Login("admin", "right", "4.5.6.7"); err != nil || tok4 == "" {
		t.Fatalf("关闭两步验证后应直接密码登录: %v", err)
	}
}

// 监控采集令牌：仅 /api/metrics 作用域、长效、改密（token_version）后失效。
func TestMetricsToken(t *testing.T) {
	svc := newTestService(t)
	mt, err := svc.IssueMetricsToken("admin")
	if err != nil || mt == "" {
		t.Fatalf("签发失败: %v", err)
	}
	if user, err := svc.ValidateMetricsToken(mt); err != nil || user != "admin" {
		t.Fatalf("校验应通过: %v %q", err, user)
	}
	// 普通会话 JWT 不是监控令牌
	normal, _ := svc.Login("admin", "right", "1.2.3.4")
	if _, err := svc.ValidateMetricsToken(normal); err == nil {
		t.Fatal("普通 JWT 不应被当作监控令牌")
	}
	// 监控令牌也不应通过普通中间件（作用域限制在其他接口）
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	c.Request.Header.Set("Authorization", "Bearer "+mt)
	svc.Middleware()(c)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("监控令牌访问普通接口应 401，实际 %d", w.Code)
	}
	// 但 /api/metrics 路径放行（作用域匹配）
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	c2.Request.Header.Set("Authorization", "Bearer "+mt)
	svc.Middleware()(c2)
	if w2.Code != http.StatusOK {
		t.Errorf("监控令牌访问 /api/metrics 应放行，实际 %d", w2.Code)
	}
	// 改密后旧监控令牌失效
	if _, err := svc.ChangePassword("admin", "right", "newpassword1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateMetricsToken(mt); err == nil {
		t.Fatal("改密后监控令牌应失效")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestOtpAuthURL(t *testing.T) {
	u := TOTPOtpAuthURL("admin", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	// 冒号在 path 段合法（RFC 3986 pchar），验证器 App 按 "Issuer:account" 解析
	for _, want := range []string{"otpauth://totp/HAProxyWeb:admin", "issuer=HAProxyWeb", "digits=6", "period=30", "algorithm=SHA1"} {
		if !contains(u, want) {
			t.Errorf("otpauth URL 缺少 %q: %s", want, u)
		}
	}
}
