package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TOTP 两步验证（RFC 6238，SHA-1 / 6 位 / 30s 步长——与 Google Authenticator 等
// 主流验证器 App 的默认参数一致）。本文件为零依赖标准库实现，正确性由
// RFC 6238 附录 B 的官方测试向量覆盖（totp_test.go）。
const (
	totpPeriod    = 30
	totpSkew      = 1 // 容忍前后各 1 个时间窗的时钟偏差
	totpDigits    = 6
	totpIssuer    = "HAProxyWeb"
	backupCodeNum = 10 // 启用两步验证时生成的一次性恢复码数量
	// 恢复码 "xxxx-xxxx"：每段 4 字符，取自去混淆字母表（无 I/1/O/0）
	backupAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
)

// ErrBadTOTP 验证码错误（含已用过的恢复码）。每个验证码在其 30 秒有效窗内
// 只能用一次（防重放）——同一码立即二次使用也会得到本错误，属预期行为。
var ErrBadTOTP = errors.New("验证码错误或已失效")

// TOTPCodeForTest 返回密钥在当前时间窗的验证码（仅供测试使用，
// 与 ValidateTOTP 同一实现路径，避免测试复制算法造成漂移）。
func TOTPCodeForTest(secretB32 string) string {
	secret, err := decodeBase32(secretB32)
	if err != nil {
		return ""
	}
	return hotp(secret, uint64(time.Now().Unix()/totpPeriod))
}

// BcryptHashForTest 测试辅助：生成 bcrypt 哈希。
func BcryptHashForTest(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return string(b), err
}

// GenerateTOTPSecret 生成 160 位随机密钥并返回 base32 编码（无填充）。
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="), nil
}

// hotp RFC 4226 HOTP：计数器 ctr 的 6 位动态截断值。
func hotp(secret []byte, ctr uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], ctr)
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

// ValidateTOTP 校验 6 位验证码，容忍 ±1 个时间窗的时钟偏差。
// 每个时间窗的码只能用一次（防重放）：已用窗口记录在 used 中（unix 窗口号）。
func ValidateTOTP(secretB32, code string, now time.Time, used map[int64]bool) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	secret, err := decodeBase32(secretB32)
	if err != nil {
		return false
	}
	cur := now.Unix() / totpPeriod
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		w := cur + d
		if used != nil && used[w] {
			continue
		}
		if hmac.Equal([]byte(hotp(secret, uint64(w))), []byte(code)) {
			if used != nil {
				used[w] = true
			}
			return true
		}
	}
	return false
}

// decodeBase32 解码 base32 密钥（容忍大小写与填充差异）。
func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimRight(s, "=")
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// TOTPOtpAuthURL 生成验证器 App 扫码用的 otpauth:// 链接。
func TOTPOtpAuthURL(username, secretB32 string) string {
	label := url.PathEscape(totpIssuer + ":" + username)
	return fmt.Sprintf("otpauth://totp/%s?issuer=%s&secret=%s&algorithm=SHA1&digits=%d&period=%d",
		label, url.QueryEscape(totpIssuer), secretB32, totpDigits, totpPeriod)
}

// GenerateBackupCodes 生成 n 个 "xxxx-xxxx" 形式的一次性恢复码。
// 每码 4 字节熵（去混淆字母表 32^8 ≈ 1.1e12 组合），明文仅在生成时
// 展示一次，落库的是校验和哈希。
func GenerateBackupCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	buf := make([]byte, 4)
	for i := 0; i < n; i++ {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		codes = append(codes, chunk4(buf[:2], backupAlphabet)+"-"+chunk4(buf[2:], backupAlphabet))
	}
	return codes, nil
}

// chunk4 由 2 个随机字节（16 bit）确定性地导出 4 个字母表字符。
func chunk4(b []byte, alphabet string) string {
	v := binary.BigEndian.Uint16(b)
	var out [4]byte
	for i := 0; i < 4; i++ {
		out[i] = alphabet[int(v)%len(alphabet)]
		v /= uint16(len(alphabet))
	}
	return string(out[:])
}
