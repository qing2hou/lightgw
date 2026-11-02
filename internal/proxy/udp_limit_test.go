// UDP 限速的集成测试（2026-11-02）。
//
// 背景：UDP 路径有双向限速（udp.go:146 上传 TryWaitUpload / :268 下载
// TryWaitDownload），但此前**没有任何测试覆盖**。正因为缺测试，
// `ratelimit.Limiter.TryWaitUpload/TryWaitDownload` 在 shared 形态下
// （带宽包 NewSharedTotal）完全绕过限速的 bug 一直没被发现——
// 那两个方法直接读 l.upload/l.download，而 shared 形态下两者都是 nil，
// tryN 见 nil 即返回 true。
//
// 这些测试从外部观察行为（发 N 个包，看回显数量），不依赖内部实现细节。
package proxy

import (
	"bytes"
	"net"
	"testing"
	"time"

	"haproxyweb/internal/model"
)

// udpEchoBackend 起一个 UDP 回显后端，返回其地址。
func udpEchoBackend(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("启动 UDP 回显后端失败: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().String()
}

// countEchoes 向 listen 发 rounds 个包，统计 maxWait 内收到的回显数。
func countEchoes(t *testing.T, listen string, payload int, rounds int, maxWait time.Duration) int {
	t.Helper()
	c, err := net.Dial("udp", listen)
	if err != nil {
		t.Fatalf("UDP 拨号失败: %v", err)
	}
	defer func() { _ = c.Close() }()

	body := bytes.Repeat([]byte("x"), payload)
	deadline := time.Now().Add(maxWait)
	var got int
	buf := make([]byte, 65535)

	for i := 0; i < rounds; i++ {
		if _, err := c.Write(body); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
		if _, err := c.Read(buf); err == nil {
			got++
		}
		if time.Now().After(deadline) {
			break
		}
	}
	return got
}

// TestUDPUploadLimitDrops 上传限速：额度极低时大部分包应被丢弃。
//
// 判据不追求精确速率（CI 环境下计时不稳），只验证"限速确实生效"——
// 不限速时几乎 100% 回显，限速后应显著下降。
func TestUDPUploadLimitDrops(t *testing.T) {
	m := newFullManager(t, Options{UDPLimiterMaxWait: time.Millisecond})
	// 4KB/s 上传额度：发 20 个 1KB 包（共 20KB）远超额度
	listen := applyListen(t, m, model.ForwardRule{
		Name: "udp-up-limited", Protocol: model.ProtocolUDP,
		TargetAddr:      udpEchoBackend(t),
		UploadLimitKBps: 4,
	})

	got := countEchoes(t, listen, 1024, 20, 1500*time.Millisecond)
	t.Logf("上传限速 4KB/s，发 20×1KB 包，回显 %d 个", got)

	// 4KB/s 且 maxWait=1ms：首包可能过（桶初始满），后续基本全丢。
	// 放宽到"少于一半"即可证明限速生效，同时避免计时抖动导致偶发失败。
	if got >= 10 {
		t.Fatalf("★ 上传限速未生效：4KB/s 额度下 20 个 1KB 包回显了 %d 个", got)
	}
}

// TestUDPNoLimitPassesAll 不配限速时，所有包都应正常回显（对照组）。
//
// 这条测试的存在是为了防止另一种失败模式：把限速改得过严，
// 导致完全没配限速的规则也被误限。
func TestUDPNoLimitPassesAll(t *testing.T) {
	m := newFullManager(t, Options{UDPLimiterMaxWait: time.Millisecond})
	listen := applyListen(t, m, model.ForwardRule{
		Name: "udp-unlimited", Protocol: model.ProtocolUDP,
		TargetAddr: udpEchoBackend(t),
	})

	got := countEchoes(t, listen, 1024, 20, 1500*time.Millisecond)
	t.Logf("不限速，发 20×1KB 包，回显 %d 个", got)
	if got < 15 {
		t.Fatalf("★ 未配限速却大量丢包（回显 %d/20），说明限速器被误启用", got)
	}
}

// TestUDPSharedLimiterEnforced 回归：带宽包（shared 形态）必须真正限速。
//
// 这是本次修的 bug。NewSharedTotal 只设置 shared 桶，
// TryWaitUpload/TryWaitDownload 原来读 l.upload/l.download（nil）→ 直接放行。
// 通过奖励/惩罚测试：若 shared 被忽略，回显率会接近 100%。
func TestUDPSharedLimiterEnforced(t *testing.T) {
	m := newFullManager(t, Options{UDPLimiterMaxWait: time.Millisecond})
	// 直接给规则配"双向合计 4KB/s"的共享桶（模拟带宽包）
	rule := model.ForwardRule{
		Name: "udp-shared", Protocol: model.ProtocolUDP,
		TargetAddr: udpEchoBackend(t),
		BWGroupID:  1, // 触发 bwLimiter 查库；下面插入对应包
	}
	// newFullManager 只迁移了 TrafficLog/ForwardRule/HealthLog，
	// 带宽包表要自己建（不动共享辅助函数，避免影响其它测试的假设）
	if err := m.db.AutoMigrate(&model.BWGroup{}); err != nil {
		t.Fatalf("建带宽包表失败: %v", err)
	}
	if err := m.db.Create(&model.BWGroup{
		Name: "测试包", TotalKBps: 4, MinKBps: 1,
	}).Error; err != nil {
		t.Fatalf("插入带宽包失败: %v", err)
	}
	// 清掉缓存的限速器，让它按新包重建
	m.ResetBWLimiters()

	listen := applyListen(t, m, rule)
	got := countEchoes(t, listen, 1024, 20, 1500*time.Millisecond)
	t.Logf("带宽包 4KB/s 共享桶，发 20×1KB 包，回显 %d 个", got)

	if got >= 10 {
		t.Fatalf("★ shared 形态限速被绕过：4KB/s 额度下回显了 %d/20\n"+
			"（历史 bug：TryWaitUpload 读 l.upload 而 shared 形态下它是 nil）", got)
	}
}

// TestUDPDownloadLimitDrops 下载限速：后端回包方向也应受限。
func TestUDPDownloadLimitDrops(t *testing.T) {
	m := newFullManager(t, Options{UDPLimiterMaxWait: time.Millisecond})
	listen := applyListen(t, m, model.ForwardRule{
		Name: "udp-down-limited", Protocol: model.ProtocolUDP,
		TargetAddr:        udpEchoBackend(t),
		DownloadLimitKBps: 4,
	})

	got := countEchoes(t, listen, 1024, 20, 1500*time.Millisecond)
	t.Logf("下载限速 4KB/s，发 20×1KB 包，回显 %d 个", got)
	if got >= 10 {
		t.Fatalf("★ 下载限速未生效：4KB/s 额度下回显了 %d/20", got)
	}
}
