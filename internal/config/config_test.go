package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadForTest 以不存在的配置文件路径加载，避免读到仓库根目录的 config.yaml。
func loadForTest(t *testing.T) (*Config, error) {
	t.Helper()
	return Load(filepath.Join(t.TempDir(), "missing.yaml"))
}

func TestLoadDefaults(t *testing.T) {
	c, err := loadForTest(t)
	if err != nil {
		t.Fatalf("默认配置加载失败: %v", err)
	}
	if c.Web.Listen != "127.0.0.1:8080" || c.Web.DataDir != "./data" {
		t.Errorf("web 默认值不符: %+v", c.Web)
	}
	if c.Web.LogRetentionDays != 30 || c.Web.AuditRetentionDays != 90 {
		t.Errorf("保留天数默认值不符: %d / %d", c.Web.LogRetentionDays, c.Web.AuditRetentionDays)
	}
	if c.Tuning.MaxGlobalConns != 0 {
		t.Errorf("max_global_conns 默认应为 0（不限）")
	}
	if c.Tuning.TCPIdleTimeoutSec != 900 || c.Tuning.TCPDialTimeoutSec != 10 {
		t.Errorf("tcp 超时默认值不符: %+v", c.Tuning)
	}
	if c.Tuning.UDPSessionIdleSec != 60 || c.Tuning.UDPLimiterMaxWaitMs != 100 {
		t.Errorf("udp 默认值不符: %+v", c.Tuning)
	}
	if c.Tuning.BufferSize != 32768 || c.Tuning.Splice || c.Tuning.DrainTimeoutSec != 10 {
		t.Errorf("tuning 默认值不符: %+v", c.Tuning)
	}
}

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
web:
  listen: "127.0.0.1:9000"
  data_dir: "/var/lib/haweb"
  audit_retention_days: 0
tuning:
  max_global_conns: 20000
  tcp_idle_timeout_sec: 0
  buffer_size: 65536
  splice: true
  drain_timeout_sec: 5
  metrics_listen: ""
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("写配置文件失败: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if c.Web.Listen != "127.0.0.1:9000" || c.Web.DataDir != "/var/lib/haweb" {
		t.Errorf("web 覆盖不符: %+v", c.Web)
	}
	if c.Web.AuditRetentionDays != 0 {
		t.Errorf("audit_retention_days=0 应表示永久保留，实际 %d", c.Web.AuditRetentionDays)
	}
	if c.Tuning.MaxGlobalConns != 20000 || c.Tuning.TCPIdleTimeoutSec != 0 ||
		c.Tuning.BufferSize != 65536 || !c.Tuning.Splice || c.Tuning.DrainTimeoutSec != 5 {
		t.Errorf("tuning 覆盖不符: %+v", c.Tuning)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	t.Setenv("HAWEB_MAX_GLOBAL_CONNS", "5000")
	t.Setenv("HAWEB_TCP_IDLE_TIMEOUT_SEC", "60")
	t.Setenv("HAWEB_BUFFER_SIZE", "16384")
	t.Setenv("HAWEB_SPLICE", "true")
	t.Setenv("HAWEB_DRAIN_TIMEOUT_SEC", "0")
	c, err := loadForTest(t)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if c.Tuning.MaxGlobalConns != 5000 || c.Tuning.TCPIdleTimeoutSec != 60 ||
		c.Tuning.BufferSize != 16384 || !c.Tuning.Splice || c.Tuning.DrainTimeoutSec != 0 {
		t.Errorf("环境变量覆盖不符: %+v", c.Tuning)
	}
}

func TestLoadEnvInvalid(t *testing.T) {
	t.Setenv("HAWEB_BUFFER_SIZE", "abc")
	_, err := loadForTest(t)
	if err == nil || !strings.Contains(err.Error(), "HAWEB_BUFFER_SIZE") {
		t.Errorf("非法整数环境变量应启动报错，实际: %v", err)
	}
}

func TestLoadValidation(t *testing.T) {
	cases := []struct {
		name string
		mut  func(c *Config)
		want string
	}{
		{"全局连接上限为负", func(c *Config) { c.Tuning.MaxGlobalConns = -1 }, "max_global_conns"},
		{"空闲超时为负", func(c *Config) { c.Tuning.TCPIdleTimeoutSec = -5 }, "tcp_idle_timeout_sec"},
		{"拨号超时为零", func(c *Config) { c.Tuning.TCPDialTimeoutSec = 0 }, "tcp_dial_timeout_sec"},
		{"UDP 会话超时为零", func(c *Config) { c.Tuning.UDPSessionIdleSec = 0 }, "udp_session_idle_sec"},
		{"UDP 限速等待为零", func(c *Config) { c.Tuning.UDPLimiterMaxWaitMs = 0 }, "udp_limiter_max_wait_ms"},
		{"缓冲区过小", func(c *Config) { c.Tuning.BufferSize = 1024 }, "buffer_size"},
		{"缓冲区过大", func(c *Config) { c.Tuning.BufferSize = 1048576 }, "buffer_size"},
		{"排空超时为负", func(c *Config) { c.Tuning.DrainTimeoutSec = -1 }, "drain_timeout_sec"},
		{"审计保留为负", func(c *Config) { c.Web.AuditRetentionDays = -1 }, "audit_retention_days"},
		{"证书只配一半", func(c *Config) { c.Web.CertFile = "/tmp/a.crt" }, "cert_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := loadForTest(t)
			if err != nil {
				t.Fatalf("基准加载失败: %v", err)
			}
			tc.mut(c)
			if err := c.validate(); err == nil {
				t.Errorf("期望报错包含 %q，实际无错误", tc.want)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("期望报错包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}

// TLS 强制：非回环监听 + 明文 HTTP 启动即拒绝；回环放行；allow_insecure 显式放行。
func TestTLSEnforcedForNonLoopback(t *testing.T) {
	cases := []struct {
		listen   string
		tls      bool
		insecure bool
		wantErr  bool
	}{
		{":8080", false, false, true},            // 全网卡明文：拒绝
		{"0.0.0.0:8080", false, false, true},     // 显式全网卡明文：拒绝
		{"192.168.1.5:8080", false, false, true}, // 非回环 IP 明文：拒绝
		{"127.0.0.1:8080", false, false, false},  // 回环明文：放行（本机专用）
		{"localhost:8080", false, false, false},  // localhost 明文：放行
		{"[::1]:8080", false, false, false},      // IPv6 回环：放行
		{":8080", true, false, false},            // 全网卡 + TLS：放行
		{":8080", false, true, false},            // 全网卡明文 + allow_insecure：放行
	}
	for _, tc := range cases {
		c, err := loadForTest(t)
		if err != nil {
			t.Fatal(err)
		}
		c.Web.Listen = tc.listen
		if tc.tls {
			c.Web.CertFile = "/tmp/a.crt"
			c.Web.KeyFile = "/tmp/a.key"
		}
		c.Web.AllowInsecure = tc.insecure
		err = c.validate()
		if tc.wantErr && (err == nil || !strings.Contains(err.Error(), "TLS")) {
			t.Errorf("listen=%s tls=%v insecure=%v 期望拒绝，实际: %v", tc.listen, tc.tls, tc.insecure, err)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("listen=%s tls=%v insecure=%v 期望放行，实际: %v", tc.listen, tc.tls, tc.insecure, err)
		}
	}
	// 环境变量逃生口
	t.Setenv("HAWEB_ALLOW_INSECURE", "true")
	if _, err := loadForTest(t); err != nil {
		t.Fatalf("allow_insecure env 应放行非回环明文监听: %v", err)
	}
	t.Setenv("HAWEB_ALLOW_INSECURE", "bogus")
	if _, err := loadForTest(t); err == nil || !strings.Contains(err.Error(), "HAWEB_ALLOW_INSECURE") {
		t.Errorf("非法布尔值应报错，实际: %v", err)
	}
}

// 健康检测独立配置：默认 60s、-1 跟随保留期、0 禁用、负数报错、env 覆盖。
func TestLoadHealthCheckConfig(t *testing.T) {
	c, err := loadForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tuning.HealthCheckIntervalSec != 60 || c.Tuning.HealthLogRetentionDays != -1 {
		t.Fatalf("默认值不符: %+v", c.Tuning)
	}
	t.Setenv("HAWEB_HEALTH_CHECK_INTERVAL_SEC", "300")
	t.Setenv("HAWEB_HEALTH_LOG_RETENTION_DAYS", "7")
	c, err = loadForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tuning.HealthCheckIntervalSec != 300 || c.Tuning.HealthLogRetentionDays != 7 {
		t.Fatalf("env 覆盖不符: %+v", c.Tuning)
	}
	// yaml：0 = 全局禁用检测（env 优先级高于 yaml，本测试前一步设置过 env，需先清空）
	os.Setenv("HAWEB_HEALTH_CHECK_INTERVAL_SEC", "")
	os.Setenv("HAWEB_HEALTH_LOG_RETENTION_DAYS", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("tuning:\n  health_check_interval_sec: 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if c, err = Load(path); err != nil || c.Tuning.HealthCheckIntervalSec != 0 {
		t.Fatalf("0 应表示禁用: %+v err=%v", c.Tuning, err)
	}
	// 非法值
	t.Setenv("HAWEB_HEALTH_CHECK_INTERVAL_SEC", "-5")
	if _, err = loadForTest(t); err == nil || !strings.Contains(err.Error(), "health_check_interval_sec") {
		t.Errorf("负数周期应报错，实际: %v", err)
	}
}
