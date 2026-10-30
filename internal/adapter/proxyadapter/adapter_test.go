package proxyadapter

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"haproxyweb/internal/app/policyapp"
	"haproxyweb/internal/app/sessionapp"
)

// TestNilManagerSafe mgr 为 nil 时所有方法返回错误而非 panic。
func TestNilManagerSafe(t *testing.T) {
	k := NewSessionKiller(nil)
	r := NewReinstaller(nil)
	if _, err := k.KillByPolicy(context.Background(), policyapp.Policy{}); err == nil {
		t.Fatal("KillByPolicy 应报错")
	}
	if _, err := k.List(context.Background()); err == nil {
		t.Fatal("List 应报错")
	}
	if err := k.Kill(context.Background(), "x"); err == nil {
		t.Fatal("Kill 应报错")
	}
	if err := r.ReinstallPolicies(context.Background()); err == nil {
		t.Fatal("ReinstallPolicies 应报错")
	}
}

// TestCanceledContext 已取消的 ctx 必须被尊重（在有真实 manager 的前提下）。
//
// 注意检查顺序：nil manager 的检查**先于** ctx 检查——「引擎未就绪」是
// 更根本的配置错误，先报它比先报「操作被取消」对运维更有用。
// 所以这里用 nil manager 只能验证到「引擎未就绪」这一层。
func TestCanceledContext(t *testing.T) {
	k := NewSessionKiller(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// nil manager 优先报未就绪
	if _, err := k.KillByPolicy(ctx, policyapp.Policy{}); err == nil || !strings.Contains(err.Error(), "未就绪") {
		t.Fatalf("nil manager 应先报「未就绪」，实际: %v", err)
	}
	if _, err := k.List(ctx); err == nil || !strings.Contains(err.Error(), "未就绪") {
		t.Fatalf("nil manager 应先报「未就绪」，实际: %v", err)
	}
	if err := k.Kill(ctx, "x"); err == nil || !strings.Contains(err.Error(), "未就绪") {
		t.Fatalf("nil manager 应先报「未就绪」，实际: %v", err)
	}
}

// TestSplitHostPort 解析 v4 / v6 / 各种非法形式。
func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port uint16
		ok   bool
	}{
		{"192.168.10.152:51234", "192.168.10.152", 51234, true},
		{"[2001:db8::1]:443", "2001:db8::1", 443, true},
		{"172.16.30.10:9098", "172.16.30.10", 9098, true},
		{"10.0.0.1:65535", "10.0.0.1", 65535, true},
		// 非法
		{"", "", 0, false},
		{"1.2.3.4", "", 0, false},       // 无端口
		{"1.2.3.4:", "", 0, false},      // 端口为空
		{":80", "", 0, false},           // 主机为空
		{"1.2.3.4:99999", "", 0, false}, // 端口越界
		{"1.2.3.4:8o", "", 0, false},    // 端口非数字
	}
	for _, c := range cases {
		host, port, ok := splitHostPort(c.in)
		if ok != c.ok {
			t.Fatalf("%q 的 ok 应为 %v，实际 %v", c.in, c.ok, ok)
		}
		if ok && (host != c.host || port != c.port) {
			t.Fatalf("%q 解析为 (%q, %d)，期望 (%q, %d)", c.in, host, port, c.host, c.port)
		}
	}
}

// TestJoinList 列表拼接（旧模型的逗号分隔形式）。
func TestJoinList(t *testing.T) {
	if got := joinList(nil); got != "" {
		t.Fatalf("空列表应为空串，实际 %q", got)
	}
	if got := joinList([]string{"a", "b"}); got != "a,b" {
		t.Fatalf("应为 a,b，实际 %q", got)
	}
	// 空白项必须被过滤（否则 Manager 会把空串当一个 CIDR 解析）
	if got := joinList([]string{" a ", "", "  ", "b"}); got != "a,b" {
		t.Fatalf("应过滤空白项，实际 %q", got)
	}
}

// TestSessionKillerImplementsPorts 编译期断言：适配器必须同时满足
// policyapp 与 sessionapp 的端口。
func TestSessionKillerImplementsPorts(t *testing.T) {
	var _ policyapp.SessionKiller = NewSessionKiller(nil)
	var _ sessionapp.Lister = NewSessionKiller(nil)
	var _ sessionapp.Killer = NewSessionKiller(nil)
	var _ policyapp.Reinstaller = NewReinstaller(nil)
}

// TestValidAddrParsing 有效地址必须能解析成 netip.Addr（供 ACL 匹配用）。
func TestValidAddrParsing(t *testing.T) {
	host, port, ok := splitHostPort("192.168.10.152:51234")
	if !ok {
		t.Fatal("应解析成功")
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("应能解析成 netip.Addr: %v", err)
	}
	if !a.Is4() || port != 51234 {
		t.Fatalf("解析结果错误: %v:%d", a, port)
	}
}
