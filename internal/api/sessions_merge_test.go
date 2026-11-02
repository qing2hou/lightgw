// 会话表合并两个数据源的回归（2026-11-02）。
//
// 背景：端口映射由网关进程 accept 后重新 dial 后端，**不经过 netfilter 的
// conntrack 钩子**。实测重装后：端口映射正在传 1.7GB，`conntrack -L` 却返回
// "0 flow entries"，会话表因此永远显示"共 0 条"——用户以为功能没生效。
//
// 修复：会话表 = conntrack（内核转发）+ 进程内会话（端口映射）两部分。
package api

import (
	"testing"

	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
)

// TestAppendUserSessionsShowsPortMapping 端口映射的会话必须出现在会话表里。
func TestAppendUserSessionsShowsPortMapping(t *testing.T) {
	users := []model.SessionInfo{{
		ID: 1, RuleID: 6, RuleName: "perf2", Protocol: "tcp",
		SourceIP: "192.168.10.161", SourcePort: 45678,
		ListenIP: "172.16.40.10", ListenPort: 19000,
		TargetAddr: "192.168.10.151:19000",
	}}
	got := appendUserSessions(nil, users, "", "", 500)

	if len(got) != 1 {
		t.Fatalf("★ 端口映射会话未出现在会话表：期望 1 条，实际 %d 条", len(got))
	}
	v := got[0]
	if v.Backend != "192.168.10.151:19000" {
		t.Fatalf("后端应为 192.168.10.151:19000，实际 %q", v.Backend)
	}
	if v.Src != "192.168.10.161:45678" {
		t.Fatalf("客户端应为 192.168.10.161:45678，实际 %q", v.Src)
	}
	if v.Dst != "172.16.40.10:19000" {
		t.Fatalf("监听应为 172.16.40.10:19000，实际 %q", v.Dst)
	}
	if v.State != "ESTABLISHED" {
		t.Fatalf("进程内会话应视为 ESTABLISHED，实际 %q", v.State)
	}
	// ID 必须带 u: 前缀，掐断接口据此走用户态路径
	if v.ID[:2] != "u:" {
		t.Fatalf("★ 用户态会话 ID 必须带 u: 前缀（掐断依赖它），实际 %q", v.ID)
	}
}

// TestAppendUserSessionsFilters 协议与关键词筛选对合并进来的行同样生效。
func TestAppendUserSessionsFilters(t *testing.T) {
	users := []model.SessionInfo{
		{ID: 1, RuleID: 6, Protocol: "tcp", SourceIP: "10.0.0.1", SourcePort: 100,
			ListenIP: "10.0.0.2", ListenPort: 200, TargetAddr: "10.0.0.3:22"},
		{ID: 2, RuleID: 7, Protocol: "udp", SourceIP: "10.9.9.9", SourcePort: 300,
			ListenIP: "10.0.0.2", ListenPort: 400, TargetAddr: "10.0.0.4:53"},
	}

	if got := appendUserSessions(nil, users, "udp", "", 500); len(got) != 1 {
		t.Fatalf("proto=udp 应只剩 1 条，实际 %d", len(got))
	}
	if got := appendUserSessions(nil, users, "", "10.9.9.9", 500); len(got) != 1 {
		t.Fatalf("搜索 10.9.9.9 应只剩 1 条，实际 %d", len(got))
	}
	if got := appendUserSessions(nil, users, "", "10.0.0.4", 500); len(got) != 1 {
		t.Fatalf("搜索后端地址 10.0.0.4 应只剩 1 条，实际 %d", len(got))
	}
}

// TestAppendUserSessionsCoexistsWithConntrack 两部分能共存（SNAT 会话 + 端口映射会话）。
func TestAppendUserSessionsCoexistsWithConntrack(t *testing.T) {
	// 先有一条 conntrack 行（SNAT 穿越）
	ctItems := []ctSessionView{{
		ID: "ct1", Proto: "tcp", Src: "192.168.10.151:1000",
		Dst: "8.8.8.8:443", SrcAfter: "192.168.10.170:1000",
		Router: "snat:192.168.10.170", State: "ESTABLISHED",
	}}
	users := []model.SessionInfo{{
		ID: 1, RuleID: 6, Protocol: "tcp", SourceIP: "192.168.10.161", SourcePort: 2000,
		ListenIP: "172.16.40.10", ListenPort: 19000, TargetAddr: "192.168.10.151:19000",
	}}

	got := appendUserSessions(ctItems, users, "", "", 500)
	if len(got) != 2 {
		t.Fatalf("★ 应同时显示 conntrack 与端口映射两类会话，实际 %d 条", len(got))
	}
	var hasCT, hasUser bool
	for _, v := range got {
		if v.Router == "snat:192.168.10.170" {
			hasCT = true
		}
		if v.Router == "portmap" {
			hasUser = true
		}
	}
	if !hasCT || !hasUser {
		t.Fatalf("两类会话都必须出现: conntrack=%v portmap=%v", hasCT, hasUser)
	}
	_ = proxy.CTSnapshot{} // 保持 proxy 包引用
}

// TestAppendUserSessionsLimit limit 对合并后的总条数生效。
func TestAppendUserSessionsLimit(t *testing.T) {
	var users []model.SessionInfo
	for i := 0; i < 10; i++ {
		users = append(users, model.SessionInfo{
			ID: int64(i), RuleID: 1, Protocol: "tcp",
			SourceIP: "10.0.0.1", SourcePort: 1000 + i,
			ListenIP: "10.0.0.2", ListenPort: 2000, TargetAddr: "10.0.0.3:22",
		})
	}
	got := appendUserSessions(nil, users, "", "", 3)
	if len(got) != 3 {
		t.Fatalf("limit=3 应截断到 3 条，实际 %d", len(got))
	}
}
