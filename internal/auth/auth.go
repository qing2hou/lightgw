package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"haproxyweb/internal/model"
)

const (
	tokenTTL = 24 * time.Hour
	// PprofTokenTTL pprof 专用短时令牌的有效期（导出供 Cookie MaxAge 对齐）。
	PprofTokenTTL = 10 * time.Minute
	// PprofCookieName 索引页为子页面落下的作用域 Cookie 名（导出供 api 层使用）。
	PprofCookieName = "pprof_token"
	pprofTokenScope = "pprof"
	pprofPathPrefix = "/api/debug/pprof"
	// metricsTokenScope 监控采集令牌的作用域：仅 /api/metrics 可用，长效。
	MetricsTokenScope = "metrics"
	metricsPathPrefix = "/api/metrics"
	// MetricsTokenTTL 监控采集令牌有效期（一年）：给无人值守的 Prometheus 抓取用，
	// 泄漏可随时 IssueMetricsToken 重新签发覆盖 + 改密吊销全部。
	MetricsTokenTTL = 365 * 24 * time.Hour
	// totpPendingScope 两步验证第一步的短时凭据作用域：仅用于换取第二步。
	totpPendingScope = "totp-pending"
	// totpPendingTTL 第一步短时凭据有效期。
	totpPendingTTL    = 2 * time.Minute
	maxLoginFails     = 5
	lockoutDuration   = 10 * time.Minute
	minPasswordLength = 8
	// 全局失败阈值：按 IP 锁定只防单点爆破，这里加全网维度，
	// 防分布式/多 IP 慢速绕过。内存态即可——它是突发限流语义，重启归零无妨。
	globalFailWindowSec = 60
	globalFailThreshold = 100
	globalLockSeconds   = 300
)

// ErrTOTPRequired 密码已验证，还需 TOTP 验证码完成登录（两步验证第二步）。
var ErrTOTPRequired = errors.New("需要两步验证码")

type Service struct {
	secret []byte
	db     *gorm.DB

	// 全局失败窗口（突发限流，内存态）
	globalFailWindowStart atomic.Int64 // unix 秒，0 = 未开始
	globalFails           atomic.Int64
	globalLockedUntil     atomic.Int64 // unix 秒，0 = 未锁定

	// 每用户已用 TOTP 时间窗（防同一验证码重放），map[username]map[window]used
	totpUsedWin map[string]map[int64]bool
	totpMu      sync.Mutex
}

// New 创建认证服务，JWT 密钥持久化在 dataDir 下，重启不失效。
// 登录失败锁定状态持久化在数据库（login_fails 表），重启后仍然生效。
func New(dataDir string, db *gorm.DB) (*Service, error) {
	keyPath := filepath.Join(dataDir, "secret.key")
	secret, err := os.ReadFile(keyPath)
	if err == nil && len(secret) >= 32 {
		return &Service{secret: secret, db: db}, nil
	}
	if err == nil {
		log.Printf("[auth] 警告：%s 内容异常（长度 %d < 32），已重新生成，所有已签发的令牌将失效", keyPath, len(secret))
	} else if !os.IsNotExist(err) {
		log.Printf("[auth] 警告：读取 %s 失败（%v），已重新生成，所有已签发的令牌将失效", keyPath, err)
	}
	secret = make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, secret, 0600); err != nil {
		return nil, err
	}
	return &Service{secret: secret, db: db}, nil
}

// ErrLocked 登录失败次数过多，请 10 分钟后重试（锁定字面量进错误文案）。
var ErrLocked = errors.New("登录失败次数过多，请 10 分钟后重试")
var ErrGlobalLocked = errors.New("登录尝试过于频繁，请稍后再试")
var ErrBadCredentials = errors.New("用户名或密码错误")

// loginLocked 判断来源 IP 是否处于锁定期。锁定期已结束的记录会被清除，
// 失败计数从零重新开始（与旧内存版语义一致）。数据库异常时按未锁定处理——
// 后续的用户查询同样依赖数据库，不会放大风险。
func (s *Service) loginLocked(ip string) bool {
	var row model.LoginFail
	if err := s.db.Where("ip = ?", ip).First(&row).Error; err != nil {
		return false
	}
	if row.LockedUntil != nil && time.Now().Before(*row.LockedUntil) {
		return true
	}
	if row.LockedUntil != nil {
		_ = s.db.Delete(&row).Error
	}
	return false
}

// recordLoginFail 累计来源 IP 的失败次数；达到阈值写入锁定期并清零计数。
// 写失败记日志不静默——最坏情况是少记一次失败，不影响登录主流程。
func (s *Service) recordLoginFail(ip string) {
	now := time.Now()
	var row model.LoginFail
	err := s.db.Where("ip = ?", ip).First(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		row = model.LoginFail{IP: ip, FailCount: 1, LastFailAt: now}
		if err := s.db.Create(&row).Error; err != nil {
			log.Printf("[auth] 登录失败计数写入失败: %v", err)
		}
	case err != nil:
		log.Printf("[auth] 登录失败计数读取失败: %v", err)
		return
	default:
		row.FailCount++
		row.LastFailAt = now
		if row.FailCount >= maxLoginFails {
			until := now.Add(lockoutDuration)
			row.LockedUntil = &until
			row.FailCount = 0
		}
		if err := s.db.Model(&model.LoginFail{}).Where("ip = ?", ip).Updates(map[string]any{
			"fail_count":   row.FailCount,
			"locked_until": row.LockedUntil,
			"last_fail_at": row.LastFailAt,
		}).Error; err != nil {
			log.Printf("[auth] 登录失败计数更新失败: %v", err)
		}
	}
}

// clearLoginFails 登录成功后清除该 IP 的失败计数。失败仅记日志：残留计数
// 只会在后续登录失败时提前触发锁定，方向偏保守，可接受。
func (s *Service) clearLoginFails(ip string) {
	if err := s.db.Where("ip = ?", ip).Delete(&model.LoginFail{}).Error; err != nil {
		log.Printf("[auth] 登录失败记录清除失败: %v", err)
	}
}

// Login 校验用户名密码，成功返回 JWT；失败计数（持久化），达到阈值锁定来源 IP 十分钟，
// 锁定期内即使密码正确也拒绝。启用两步验证的用户返回 ErrTOTPRequired，
// 由 LoginSecondFactor 用第一步签发的短时凭据完成第二步。
func (s *Service) Login(username, password, ip string) (string, error) {
	if s.loginLocked(ip) {
		return "", ErrLocked
	}
	if now := time.Now().Unix(); now < s.globalLockedUntil.Load() {
		return "", ErrGlobalLocked
	}

	var user model.User
	err := s.db.Where("username = ?", username).First(&user).Error
	if err == nil && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) == nil {
		if user.TOTPEnabled && user.TOTPSecret != "" {
			// 第一步通过：签发仅限完成第二步的短时凭据，随错误信息返回。
			// 失败计数不在第一步清零——第二步完整通过才清（防"正确密码循环
			// 重置计数 + 第二步无限爆破验证码"的绕过）。
			pending, perr := s.issueTokenScoped(user.Username, user.TokenVersion, totpPendingTTL, totpPendingScope)
			if perr != nil {
				return "", perr
			}
			return pending, ErrTOTPRequired
		}
		s.clearLoginFails(ip)
		return s.issueToken(user.Username, user.TokenVersion)
	}

	s.recordLoginFail(ip)
	s.bumpGlobalFails()
	return "", ErrBadCredentials
}

// bumpGlobalFails 全网失败滑动窗口计数；达到阈值后锁定所有来源的登录一小段时间。
// 窗口与锁定都是内存态：突发限流语义，重启归零不影响按 IP 锁定的持久化防线。
// LoginSecondFactor 两步验证第二步：凭第一步返回的 pending 凭据 + TOTP 码
// （或一次性恢复码）换取正式会话令牌。验证码错误计入登录失败计数。
func (s *Service) LoginSecondFactor(pendingToken, code, ip string) (string, error) {
	username, err := s.parsePendingToken(pendingToken)
	if err != nil {
		return "", err
	}
	var user model.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return "", ErrBadCredentials
	}
	if s.loginLocked(ip) {
		return "", ErrLocked
	}
	// 全网锁定对第二步同样生效：第二步爆破（验证码空间仅 10^6）必须被
	// 与第一步同等级别的限流挡住
	if now := time.Now().Unix(); now < s.globalLockedUntil.Load() {
		return "", ErrGlobalLocked
	}
	code = strings.TrimSpace(code)
	// TOTP 校验与防重放标记整体在锁内（used map 的读写无锁并发会触发
	// Go runtime 的 fatal error，进程直接退出——绝不许在锁外碰它）
	s.totpMu.Lock()
	totpOK := ValidateTOTP(user.TOTPSecret, code, time.Now(), s.totpUsedWinLocked(username))
	s.totpMu.Unlock()
	if totpOK {
		s.clearLoginFails(ip)
		return s.issueToken(user.Username, user.TokenVersion)
	}
	if consumeBackupCode(&user, code) {
		if err := s.db.Model(&model.User{}).Where("id = ?", user.ID).
			Update("backup_codes", user.BackupCodes).Error; err != nil {
			// 核销落库失败即拒绝登录：否则该恢复码可无限重放
			log.Printf("[auth] 恢复码核销落库失败（拒绝本次登录）: %v", err)
			return "", ErrBadTOTP
		}
		s.clearLoginFails(ip)
		return s.issueToken(user.Username, user.TokenVersion)
	}
	s.recordLoginFail(ip)
	s.bumpGlobalFails()
	return "", ErrBadTOTP
}

// totpUsedWinLocked 在 s.totpMu 已持有的前提下取（或建）用户的已用窗口 map。
// 调用方必须持有 s.totpMu。
func (s *Service) totpUsedWinLocked(username string) map[int64]bool {
	if s.totpUsedWin == nil {
		s.totpUsedWin = map[string]map[int64]bool{}
	}
	m, ok := s.totpUsedWin[username]
	if !ok {
		m = map[int64]bool{}
		s.totpUsedWin[username] = m
	}
	return m
}

// consumeBackupCode 核销一个一次性恢复码（大小写不敏感、去连字符亦可）。
// 命中后从剩余列表移除并返回 true；调用方负责把剩余列表落库。
func consumeBackupCode(user *model.User, code string) bool {
	backup := unmarshalBackupCodes(user.BackupCodes)
	norm := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	for i, bc := range backup {
		if strings.ToUpper(strings.ReplaceAll(bc, "-", "")) == norm {
			user.BackupCodes = marshalBackupCodes(append(backup[:i:i], backup[i+1:]...))
			return true
		}
	}
	return false
}

// parsePendingToken 校验第一步签发的 totp-pending 作用域令牌。
func (s *Service) parsePendingToken(tokenStr string) (string, error) {
	claims, err := s.parseClaims(tokenStr)
	if err != nil {
		return "", err
	}
	if scope, _ := claims["pt"].(string); scope != totpPendingScope {
		return "", errors.New("无效的两步验证凭据")
	}
	sub, err := claims.GetSubject()
	if err != nil {
		return "", errors.New("无效的两步验证凭据")
	}
	return sub, nil
}

// TOTPSetupStatus 两步验证状态（设置页展示）。
type TOTPSetupStatus struct {
	Enabled bool `json:"enabled"`
	// Pending 已生成密钥但尚未确认启用（待扫码确认）
	Pending bool `json:"pending"`
	// BackupRemaining 剩余恢复码数量
	BackupRemaining int `json:"backup_remaining"`
}

// BeginTOTPSetup 生成待扫码密钥，返回 otpauth URL 与一次性展示的恢复码。
// 密钥暂存 user.TOTPSecret（此时尚未生效——启用前登录不校验），
// ConfirmTOTP 成功后才真正开启两步验证。已启用时调用视为重新初始化
// （覆盖旧密钥并作废旧恢复码）。
func (s *Service) BeginTOTPSetup(username string) (secret, otpauthURL string, backupCodes []string, err error) {
	secret, err = GenerateTOTPSecret()
	if err != nil {
		return "", "", nil, err
	}
	codes, err := GenerateBackupCodes(backupCodeNum)
	if err != nil {
		return "", "", nil, err
	}
	if err := s.db.Model(&model.User{}).Where("username = ?", username).
		Updates(map[string]any{
			"totp_secret":  secret,
			"backup_codes": marshalBackupCodes(codes),
		}).Error; err != nil {
		return "", "", nil, err
	}
	return secret, TOTPOtpAuthURL(username, secret), codes, nil
}

// ConfirmTOTP 校验用户扫码后输入的验证码，通过即正式启用两步验证。
func (s *Service) ConfirmTOTP(username, code string) error {
	var user model.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return errors.New("用户不存在")
	}
	if user.TOTPSecret == "" {
		return errors.New("请先生成两步验证密钥")
	}
	s.totpMu.Lock()
	ok := ValidateTOTP(user.TOTPSecret, code, time.Now(), s.totpUsedWinLocked(username))
	s.totpMu.Unlock()
	if !ok {
		return ErrBadTOTP
	}
	return s.db.Model(&model.User{}).Where("id = ?", user.ID).
		Update("totp_enabled", true).Error
}

// DisableTOTP 关闭两步验证：需密码 + 当前有效验证码（或恢复码），
// 防令牌被窃后攻击者直接关掉第二道门。同时清空密钥与恢复码。
func (s *Service) DisableTOTP(username, password, code string) error {
	var user model.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return errors.New("用户不存在")
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return errors.New("密码错误")
	}
	s.totpMu.Lock()
	totpOK := ValidateTOTP(user.TOTPSecret, code, time.Now(), s.totpUsedWinLocked(username))
	s.totpMu.Unlock()
	ok := totpOK || consumeBackupCode(&user, code)
	if !ok {
		return ErrBadTOTP
	}
	return s.db.Model(&model.User{}).Where("id = ?", user.ID).
		Updates(map[string]any{"totp_secret": "", "totp_enabled": false, "backup_codes": ""}).Error
}

// TOTPStatus 查询两步验证状态。
func (s *Service) TOTPStatus(username string) TOTPSetupStatus {
	var user model.User
	st := TOTPSetupStatus{}
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return st
	}
	st.Enabled = user.TOTPEnabled
	st.Pending = !user.TOTPEnabled && user.TOTPSecret != ""
	st.BackupRemaining = len(unmarshalBackupCodes(user.BackupCodes))
	return st
}

// marshalBackupCodes/unmarshalBackupCodes 恢复码列编解码（NULL/空串安全）。
func marshalBackupCodes(codes []string) string {
	if len(codes) == 0 {
		return ""
	}
	b, _ := json.Marshal(codes)
	return string(b)
}

func unmarshalBackupCodes(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var codes []string
	if err := json.Unmarshal([]byte(s), &codes); err != nil {
		return nil
	}
	return codes
}

// IssueMetricsToken 签发长效监控采集令牌（仅 /api/metrics 可用）。
// 重新签发即覆盖旧值（单槽），改密后随 token_version 一并吊销。
func (s *Service) IssueMetricsToken(username string) (string, error) {
	var user model.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return "", errors.New("用户不存在")
	}
	return s.issueTokenScoped(username, user.TokenVersion, MetricsTokenTTL, MetricsTokenScope)
}

// ValidateMetricsToken 校验监控令牌（作用域 + 用户令牌版本双查）。
func (s *Service) ValidateMetricsToken(tokenStr string) (string, error) {
	claims, err := s.parseClaims(tokenStr)
	if err != nil {
		return "", err
	}
	if scope, _ := claims["pt"].(string); scope != MetricsTokenScope {
		return "", errors.New("非监控采集令牌")
	}
	sub, err := claims.GetSubject()
	if err != nil {
		return "", err
	}
	var user model.User
	if err := s.db.Where("username = ?", sub).First(&user).Error; err != nil {
		return "", errors.New("登录已失效")
	}
	tv, _ := claims["tv"].(float64)
	if user.TokenVersion != int(tv) {
		return "", errors.New("密码已修改，请重新签发监控令牌")
	}
	return sub, nil
}

func (s *Service) bumpGlobalFails() {
	now := time.Now().Unix()
	start := s.globalFailWindowStart.Load()
	if start == 0 || now-start >= globalFailWindowSec {
		if s.globalFailWindowStart.CompareAndSwap(start, now) {
			s.globalFails.Store(0)
		}
	}
	if s.globalFails.Add(1) >= globalFailThreshold {
		s.globalLockedUntil.Store(now + globalLockSeconds)
		s.globalFails.Store(0)
		log.Printf("[auth] %d 秒内全网登录失败达到 %d 次，锁定所有登录 %d 秒", globalFailWindowSec, globalFailThreshold, globalLockSeconds)
	}
}

func (s *Service) issueToken(username string, tokenVersion int) (string, error) {
	return s.issueTokenScoped(username, tokenVersion, tokenTTL, "")
}

// issueTokenScoped 签发令牌；scope 非空时附加 pt 声明，限定令牌只能用于对应路径前缀。
func (s *Service) issueTokenScoped(username string, tokenVersion int, ttl time.Duration, scope string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": username,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"tv":  tokenVersion,
	}
	if scope != "" {
		claims["pt"] = scope
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

// IssuePprofToken 签发仅限性能分析页面的短时令牌。浏览器新标签页无法携带
// Authorization 头，改用查询参数携带，10 分钟过期且不能访问其他接口。
func (s *Service) IssuePprofToken(username string) (string, error) {
	var user model.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return "", errors.New("用户不存在")
	}
	return s.issueTokenScoped(user.Username, user.TokenVersion, PprofTokenTTL, pprofTokenScope)
}

// ParseToken 校验签名并返回用户名与令牌版本号（改密后旧令牌版本不匹配即失效）。
func (s *Service) ParseToken(tokenStr string) (string, int, error) {
	claims, err := s.parseClaims(tokenStr)
	if err != nil {
		return "", 0, err
	}
	sub, err := claims.GetSubject()
	if err != nil {
		return "", 0, errors.New("无效的令牌主体")
	}
	tv, _ := claims["tv"].(float64) // JSON 数字统一解码为 float64
	return sub, int(tv), nil
}

func (s *Service) parseClaims(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.secret, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("无效的令牌")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("无效的令牌载荷")
	}
	return claims, nil
}

// ChangePassword 修改密码、清除"必须修改密码"标记并递增令牌版本，
// 使所有已签发的旧令牌立即失效。成功返回按新版本签发的新令牌，当前会话可无缝续期。
func (s *Service) ChangePassword(username, oldPassword, newPassword string) (string, error) {
	var user model.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		return "", errors.New("用户不存在")
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)) != nil {
		return "", errors.New("原密码错误")
	}
	if len(newPassword) < minPasswordLength {
		return "", fmt.Errorf("新密码长度至少 %d 位", minPasswordLength)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	newVersion := user.TokenVersion + 1
	if err := s.db.Model(&user).Updates(map[string]interface{}{
		"password_hash":        string(hash),
		"must_change_password": false,
		"token_version":        newVersion,
	}).Error; err != nil {
		return "", err
	}
	return s.issueToken(username, newVersion)
}

// scopePrefix 作用域令牌允许的路径前缀（scope -> 前缀）。
// fail-closed：pt 非空且不在本表内的令牌在 Middleware 里一律拒绝——
// 新增作用域（如曾经的 totp-pending）若忘记登记，结果是拒之门外而非放行。
var scopePrefix = map[string]string{
	pprofTokenScope:   pprofPathPrefix,
	MetricsTokenScope: metricsPathPrefix,
}

// Middleware Gin JWT 校验中间件：验签、回查用户并核对令牌版本，
// 通过后把用户名与"必须改密"标记放入上下文。
// pprof 路径额外接受 URL/Cookie 携带的作用域短时令牌（浏览器新标签页及其页面内
// 相对链接都不带 Authorization 头）；URL/Cookie 通道只认 pprof 作用域令牌，
// 普通长效 JWT 经 URL 泄漏后在该通道不可用。
func (s *Service) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string
		fromURL := false
		if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tokenStr = strings.TrimPrefix(h, "Bearer ")
		} else if strings.HasPrefix(c.Request.URL.Path, pprofPathPrefix) {
			// 查询参数：新标签页首次打开；Cookie：索引页为页面内相对链接落下的
			tokenStr = c.Query("pprof_token")
			if tokenStr == "" {
				if ck, err := c.Cookie(PprofCookieName); err == nil {
					tokenStr = ck
				}
			}
			fromURL = tokenStr != ""
		}
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "未登录"})
			return
		}
		claims, err := s.parseClaims(tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "登录已失效"})
			return
		}
		scope, _ := claims["pt"].(string)
		if scope != "" {
			prefix, known := scopePrefix[scope]
			// fail-closed：未知作用域名一律拒绝（曾因此放过 totp-pending 绕过 2FA）
			if !known || !strings.HasPrefix(c.Request.URL.Path, prefix) {
				desc, hasDesc := scopePrefixDesc[scope]
				if !hasDesc {
					desc = "专用接口"
				}
				// 作用域令牌禁止访问前缀之外的接口，防止令牌被重放到其他端点
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "该令牌仅限" + desc + "使用",
				})
				return
			}
		}
		if fromURL && scope != pprofTokenScope {
			// URL/Cookie 中只接受 pprof 作用域令牌，防止普通 JWT 借道 URL 传播
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "该令牌仅限性能分析页面使用"})
			return
		}
		username, err := claims.GetSubject()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "登录已失效"})
			return
		}
		tokenVersion, _ := claims["tv"].(float64)
		var user model.User
		if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "登录已失效"})
			return
		}
		if user.TokenVersion != int(tokenVersion) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "密码已修改，请重新登录"})
			return
		}
		c.Set("username", username)
		c.Set("must_change_password", user.MustChangePassword)
		c.Next()
	}
}

// scopePrefixDesc 作用域文案（拒绝时说明令牌用途；未知作用域兜底文案）。
var scopePrefixDesc = map[string]string{
	pprofTokenScope:   "性能分析页面",
	MetricsTokenScope: "监控采集接口",
}

// SecretHex 返回当前 JWT 密钥的十六进制（调试用）。
func (s *Service) SecretHex() string {
	return hex.EncodeToString(s.secret)
}
