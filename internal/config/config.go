package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 应用配置，来源于 config.yaml 与环境变量（HAWEB_ 前缀优先）。
type Config struct {
	Web struct {
		Listen             string   `yaml:"listen"`               // Web 后台监听地址
		DataDir            string   `yaml:"data_dir"`             // 数据目录（SQLite、JWT 密钥）
		LogRetentionDays   int      `yaml:"log_retention_days"`   // 流量日志保留天数
		AuditRetentionDays int      `yaml:"audit_retention_days"` // 审计日志保留天数，0 = 永久保留
		CertFile           string   `yaml:"cert_file"`            // TLS 证书路径；与 key_file 同时配置时管理后台启用 HTTPS
		KeyFile            string   `yaml:"key_file"`             // TLS 私钥路径
		TrustedProxies     []string `yaml:"trusted_proxies"`      // 可信代理（IP/CIDR）；为空时不信任任何 X-Forwarded-For 头
		HealthWebhookURL   string   `yaml:"health_webhook_url"`   // 后端健康状态翻转时的通知地址（POST JSON）；空 = 关闭
		AllowInsecure      bool     `yaml:"allow_insecure"`       // 允许非回环监听 + 明文 HTTP（仅限隔离内网/临时调试，生产保持 false）
	} `yaml:"web"`
	// Tuning 转发面运行参数。所有时长/数量均支持 0 或特定值表达"禁用/不限"，
	// 语义见各字段注释；负数一律启动报错。
	Tuning struct {
		MaxGlobalConns         int  `yaml:"max_global_conns"`          // 进程级并发连接总上限（TCP+UDP），0 = 不限
		TCPIdleTimeoutSec      int  `yaml:"tcp_idle_timeout_sec"`      // TCP 空闲连接超时（无数据即断开），0 = 禁用
		TCPDialTimeoutSec      int  `yaml:"tcp_dial_timeout_sec"`      // TCP 后端拨号超时
		UDPSessionIdleSec      int  `yaml:"udp_session_idle_sec"`      // UDP 会话空闲回收时间
		UDPLimiterMaxWaitMs    int  `yaml:"udp_limiter_max_wait_ms"`   // UDP 限速单包最长等待，超时丢包
		BufferSize             int  `yaml:"buffer_size"`               // TCP 拷贝缓冲区字节数，[4096, 262144]
		Splice                 bool `yaml:"splice"`                    // 零拷贝快路径：仅对无限速规则生效，开启后传输期间实时字节统计不刷新
		DrainTimeoutSec        int  `yaml:"drain_timeout_sec"`         // 优雅关闭时等待存量连接结束的宽限，0 = 不等待
		HealthCheckIntervalSec int  `yaml:"health_check_interval_sec"` // 后端健康检查周期秒数，0 = 全局禁用
		HealthLogRetentionDays int  `yaml:"health_log_retention_days"` // 健康检测记录保留天数，-1 = 跟随 log_retention_days
		GlobalUploadKBps       int  `yaml:"global_upload_kbps"`        // 整机上传带宽上限 KB/s，0 = 不限
		GlobalDownloadKBps     int  `yaml:"global_download_kbps"`      // 整机下载带宽上限 KB/s，0 = 不限
	} `yaml:"tuning"`
}

func defaults() *Config {
	c := &Config{}
	// 默认仅绑回环：开箱即用且不暴露；对外监听必须显式配置，
	// 漏配 TLS 时 validate() 会给出带指引的硬失败。
	c.Web.Listen = "127.0.0.1:8080"
	c.Web.DataDir = "./data"
	c.Web.LogRetentionDays = 30
	c.Web.AuditRetentionDays = 90
	c.Tuning.MaxGlobalConns = 0
	c.Tuning.TCPIdleTimeoutSec = 900
	c.Tuning.TCPDialTimeoutSec = 10
	c.Tuning.UDPSessionIdleSec = 60
	c.Tuning.UDPLimiterMaxWaitMs = 100
	c.Tuning.BufferSize = 32768
	c.Tuning.Splice = false
	c.Tuning.DrainTimeoutSec = 10
	c.Tuning.HealthCheckIntervalSec = 60
	c.Tuning.HealthLogRetentionDays = -1
	c.Tuning.GlobalUploadKBps = 0
	c.Tuning.GlobalDownloadKBps = 0
	return c
}

// Load 依次加载默认值 -> 配置文件 -> 环境变量。
// 配置文件不存在视为使用默认值；存在但格式非法则报错，避免写错的配置被静默忽略。
func Load(path string) (*Config, error) {
	c := defaults()
	if path == "" {
		path = "config.yaml"
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, c); err != nil {
			return nil, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}

	if v := os.Getenv("HAWEB_LISTEN"); v != "" {
		c.Web.Listen = v
	}
	if v := os.Getenv("HAWEB_DATA_DIR"); v != "" {
		c.Web.DataDir = v
	}
	if v := os.Getenv("HAWEB_LOG_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Web.LogRetentionDays = n
		}
	}
	if v := os.Getenv("HAWEB_CERT_FILE"); v != "" {
		c.Web.CertFile = v
	}
	if v := os.Getenv("HAWEB_KEY_FILE"); v != "" {
		c.Web.KeyFile = v
	}
	if v := os.Getenv("HAWEB_TRUSTED_PROXIES"); v != "" {
		c.Web.TrustedProxies = strings.Split(v, ",")
		for i := range c.Web.TrustedProxies {
			c.Web.TrustedProxies[i] = strings.TrimSpace(c.Web.TrustedProxies[i])
		}
	}
	if v := os.Getenv("HAWEB_ALLOW_INSECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("环境变量 HAWEB_ALLOW_INSECURE 不是合法布尔值: %q", v)
		}
		c.Web.AllowInsecure = b
	}

	// 兼容既有语义：log_retention_days 的环境变量仅在 >0 时生效
	if v := os.Getenv("HAWEB_LOG_RETENTION_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("环境变量 HAWEB_LOG_RETENTION_DAYS 不是合法整数: %q", v)
		}
		if n > 0 {
			c.Web.LogRetentionDays = n
		}
	}
	// 其余数值型配置：非法值启动即失败，不静默忽略
	envInts := map[string]*int{
		"HAWEB_AUDIT_RETENTION_DAYS":      &c.Web.AuditRetentionDays,
		"HAWEB_MAX_GLOBAL_CONNS":          &c.Tuning.MaxGlobalConns,
		"HAWEB_TCP_IDLE_TIMEOUT_SEC":      &c.Tuning.TCPIdleTimeoutSec,
		"HAWEB_TCP_DIAL_TIMEOUT_SEC":      &c.Tuning.TCPDialTimeoutSec,
		"HAWEB_UDP_SESSION_IDLE_SEC":      &c.Tuning.UDPSessionIdleSec,
		"HAWEB_UDP_LIMITER_MAX_WAIT_MS":   &c.Tuning.UDPLimiterMaxWaitMs,
		"HAWEB_BUFFER_SIZE":               &c.Tuning.BufferSize,
		"HAWEB_DRAIN_TIMEOUT_SEC":         &c.Tuning.DrainTimeoutSec,
		"HAWEB_HEALTH_CHECK_INTERVAL_SEC": &c.Tuning.HealthCheckIntervalSec,
		"HAWEB_HEALTH_LOG_RETENTION_DAYS": &c.Tuning.HealthLogRetentionDays,
		"HAWEB_GLOBAL_UPLOAD_KBPS":        &c.Tuning.GlobalUploadKBps,
		"HAWEB_GLOBAL_DOWNLOAD_KBPS":      &c.Tuning.GlobalDownloadKBps,
	}
	for key, dst := range envInts {
		if v := os.Getenv(key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("环境变量 %s 不是合法整数: %q", key, v)
			}
			*dst = n
		}
	}
	if v := os.Getenv("HAWEB_SPLICE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("环境变量 HAWEB_SPLICE 不是合法布尔值: %q", v)
		}
		c.Tuning.Splice = b
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// validate 集中校验：非法配置启动即失败，不静默回退。
func (c *Config) validate() error {
	if c.Web.Listen == "" {
		return fmt.Errorf("web.listen 不能为空")
	}
	if c.Web.LogRetentionDays <= 0 {
		c.Web.LogRetentionDays = 30
	}
	if c.Web.AuditRetentionDays < 0 {
		return fmt.Errorf("web.audit_retention_days 不能为负数（0 表示永久保留）")
	}
	if (c.Web.CertFile == "") != (c.Web.KeyFile == "") {
		return fmt.Errorf("web.cert_file 与 web.key_file 必须同时配置才能启用 TLS")
	}
	// 安全底线：非回环监听 + 明文 HTTP 会把登录密码与 JWT 暴露在网络上，
	// 启动即拒绝（回环/localhost 不受限）；确属隔离内网或临时调试需显式放行。
	if !c.TLSEnabled() && !c.Web.AllowInsecure && !listenIsLoopback(c.Web.Listen) {
		return fmt.Errorf("监听 %s 为非回环地址且未启用 TLS（web.cert_file / web.key_file），生产环境必须启用 TLS；"+
			"确属隔离内网或临时调试可设 web.allow_insecure: true 或环境变量 HAWEB_ALLOW_INSECURE=1 显式放行", c.Web.Listen)
	}
	if u := c.Web.HealthWebhookURL; u != "" && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("web.health_webhook_url 必须以 http:// 或 https:// 开头")
	}
	for _, p := range c.Web.TrustedProxies {
		if !isValidIPOrCIDR(p) {
			return fmt.Errorf("web.trusted_proxies 中的 %q 不是合法的 IP 或 CIDR 网段", p)
		}
	}

	t := &c.Tuning
	if t.MaxGlobalConns < 0 {
		return fmt.Errorf("tuning.max_global_conns 不能为负数（0 表示不限）")
	}
	if t.TCPIdleTimeoutSec < 0 {
		return fmt.Errorf("tuning.tcp_idle_timeout_sec 不能为负数（0 表示禁用）")
	}
	if t.TCPDialTimeoutSec <= 0 {
		return fmt.Errorf("tuning.tcp_dial_timeout_sec 必须为正整数")
	}
	if t.UDPSessionIdleSec <= 0 {
		return fmt.Errorf("tuning.udp_session_idle_sec 必须为正整数")
	}
	if t.UDPLimiterMaxWaitMs <= 0 {
		return fmt.Errorf("tuning.udp_limiter_max_wait_ms 必须为正整数")
	}
	if t.BufferSize < 4096 || t.BufferSize > 262144 {
		return fmt.Errorf("tuning.buffer_size 必须在 [4096, 262144] 范围内，当前为 %d", t.BufferSize)
	}
	if t.DrainTimeoutSec < 0 {
		return fmt.Errorf("tuning.drain_timeout_sec 不能为负数（0 表示不等待）")
	}
	if t.HealthCheckIntervalSec < 0 {
		return fmt.Errorf("tuning.health_check_interval_sec 不能为负数（0 表示全局禁用）")
	}
	if t.HealthLogRetentionDays < -1 {
		return fmt.Errorf("tuning.health_log_retention_days 不能小于 -1（-1 表示跟随 log_retention_days）")
	}
	if t.GlobalUploadKBps < 0 || t.GlobalDownloadKBps < 0 {
		return fmt.Errorf("tuning.global_upload_kbps / global_download_kbps 不能为负数（0 表示不限）")
	}
	return nil
}

func isValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// listenIsLoopback 监听地址是否仅回环可达：空 host（全部网卡）与任何非回环
// IP 均视为对外暴露；localhost / 127.x / ::1 视为本机专用。
func listenIsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ListenPort 返回 Web 后台监听端口，用于转发规则端口冲突检测。
func (c *Config) ListenPort() int {
	_, port, err := net.SplitHostPort(c.Web.Listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}

// TLSEnabled 是否已配置管理后台 TLS。
func (c *Config) TLSEnabled() bool {
	return c.Web.CertFile != "" && c.Web.KeyFile != ""
}
