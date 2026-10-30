package app

import (
	"testing"
	"time"

	"haproxyweb/internal/config"
)

// TestOptionsZeroValue Options 零值不应 panic（Run 会因配置路径为空而报错）。
func TestOptionsZeroValue(t *testing.T) {
	err := Run(Options{})
	if err == nil {
		t.Fatal("空配置路径应报错")
	}
}

// TestBuildProxyOptions 引擎参数装配必须覆盖全部字段。
//
// 这是启动与 SIGHUP 热加载共用的函数，漏一个字段会导致「热加载后某项不生效」。
func TestBuildProxyOptions(t *testing.T) {
	cfg := &config.Config{}
	cfg.Tuning.MaxGlobalConns = 100
	cfg.Tuning.TCPIdleTimeoutSec = 900
	cfg.Tuning.TCPDialTimeoutSec = 10
	cfg.Tuning.UDPSessionIdleSec = 60
	cfg.Tuning.UDPLimiterMaxWaitMs = 50
	cfg.Tuning.BufferSize = 32768
	cfg.Tuning.Splice = true
	cfg.Tuning.DrainTimeoutSec = 10
	cfg.Tuning.HealthCheckIntervalSec = 60
	cfg.Tuning.GlobalUploadKBps = 1024
	cfg.Tuning.GlobalDownloadKBps = 2048
	cfg.Tuning.HealthLogRetentionDays = -1 // 跟随流量日志
	cfg.Web.LogRetentionDays = 30
	cfg.Web.HealthWebhookURL = "http://x/hook"

	o := BuildProxyOptions(cfg)
	if o.MaxGlobalConns != 100 {
		t.Fatalf("MaxGlobalConns 未传递: %d", o.MaxGlobalConns)
	}
	if o.TCPIdleTimeout != 900*time.Second {
		t.Fatalf("TCPIdleTimeout 错误: %v", o.TCPIdleTimeout)
	}
	if o.BufferSize != 32768 {
		t.Fatalf("BufferSize 未传递: %d", o.BufferSize)
	}
	if !o.Splice {
		t.Fatal("Splice 未传递")
	}
	if o.GlobalUploadKBps != 1024 || o.GlobalDownloadKBps != 2048 {
		t.Fatalf("全局带宽未传递: %d/%d", o.GlobalUploadKBps, o.GlobalDownloadKBps)
	}
	if o.HealthWebhookURL != "http://x/hook" {
		t.Fatalf("webhook 未传递: %q", o.HealthWebhookURL)
	}
	// -1 应跟随流量日志保留天数
	if o.HealthLogRetentionDays != 30 {
		t.Fatalf("HealthLogRetentionDays=-1 应跟随流量日志（30），实际 %d",
			o.HealthLogRetentionDays)
	}

	// 显式配置时应用自己的值
	cfg.Tuning.HealthLogRetentionDays = 7
	o = BuildProxyOptions(cfg)
	if o.HealthLogRetentionDays != 7 {
		t.Fatalf("显式配置应为 7，实际 %d", o.HealthLogRetentionDays)
	}
}

// TestSDNotifyNoopWithoutSocket 非 systemd 环境下 SDNotify 必须是无害的 no-op。
func TestSDNotifyNoopWithoutSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	// 不 panic、不阻塞即可
	SDNotify("READY=1")
}
