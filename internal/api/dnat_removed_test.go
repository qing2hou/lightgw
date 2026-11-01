package api

import (
	"strings"
	"testing"

	"haproxyweb/internal/model"
)

// TestDnatCreationRejected 锁住「端口发布（dnat）已下线」这个产品决定。
//
// 下线背景：产品只保留端口映射（tcp/udp 用户态转发）。dnat 走内核 nftables，
// 其 hairpin SNAT 会把后端看到的源地址改写为网关 IP，与「纯内网模拟公网访问、
// 需要看到真实源 IP」的诉求冲突（实测见 docs/poc-result.md §3.7 与本次排查记录）。
//
// 引擎代码（internal/proxy/dnat_nft.go、internal/proxy/fw/compile_dnat.go）
// **仍然完整保留**，恢复入口时：
//  1. 删掉 rules.go validate() 里 ProtocolDNAT 分支的 return
//  2. AdminLayout.vue 加回菜单项
//  3. router/index.js 加回 dnat-rules 路由
//  4. 本测试改成"应通过"
//
// 若这条测试红了，说明有人重新放开了 dnat 入口——请确认这是产品决定。
func TestDnatCreationRejected(t *testing.T) {
	h := &handlers{}

	in := &ruleInput{
		Name: "dnat-regress", Protocol: model.ProtocolDNAT,
		ListenAddr: "172.16.40.10:8080", TargetAddr: "192.168.10.152:8080",
	}
	err := in.validate(h)
	if err == nil {
		t.Fatal("★ 端口发布（dnat）已下线，validate 必须拒绝新建 dnat 规则，实际通过了")
	}
	if !strings.Contains(err.Error(), "已下线") {
		t.Fatalf("★ 拒绝理由应说明功能已下线，实际: %v", err)
	}
}

// TestDnatNotAdvertisedInProtocolError 断言协议枚举的错误消息里不再宣传 dnat。
//
// 用户传一个不存在的协议时，错误消息就是功能清单——列出 dnat 会让用户
// 以为能用，然后收到"已下线"的二次拒绝。
func TestDnatNotAdvertisedInProtocolError(t *testing.T) {
	h := &handlers{}
	in := &ruleInput{
		Name: "bogus", Protocol: "http",
		ListenAddr: ":8080", TargetAddr: "192.168.10.152:8080",
	}
	err := in.validate(h)
	if err == nil {
		t.Fatal("未知协议 http 应被拒绝")
	}
	if strings.Contains(err.Error(), "dnat") {
		t.Fatalf("★ 协议枚举错误消息不应再列出 dnat（功能已下线），实际: %v", err)
	}
	for _, want := range []string{"tcp", "udp", "snat"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("协议枚举错误消息应包含 %q，实际: %v", want, err)
		}
	}
}

// TestPortMappingStillWorks 确认下线 dnat 没有误伤端口映射（tcp/udp）。
//
// 这是本次改动的核心回归点：tcp/udp 规则必须仍然可建。
func TestPortMappingStillWorks(t *testing.T) {
	h := &handlers{}
	for _, proto := range []string{model.ProtocolTCP, model.ProtocolUDP} {
		in := &ruleInput{
			Name: "mapping-" + proto, Protocol: proto,
			ListenAddr: "192.168.10.171:18080", TargetAddr: "192.168.10.152:8080",
		}
		if err := in.validate(h); err != nil {
			t.Fatalf("端口映射（%s）应仍然可建，实际被拒: %v", proto, err)
		}
	}
}
