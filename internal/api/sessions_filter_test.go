// 会话表过滤规则（产品决定 2026-11-01：只保留 ESTABLISHED）。
package api

import (
	"testing"

	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
)

// ct 造一条测试用会话快照。
func ct(id, proto, src, dst, state string) proxy.CTSnapshot {
	return proxy.CTSnapshot{
		ID: id, Proto: proto, Src: src, Dst: dst,
		SrcAfter: "192.168.10.170:0", Router: "snat:192.168.10.170", State: state,
	}
}

// TestSessionsOnlyEstablished 核心约定：非 ESTABLISHED 一律不出现在会话表。
//
// 生产实测（2026-11-01）：conntrack 9 条表项里 7 条是 TIME_WAIT，
// 会话表被它们淹没，"共 N 条"也因此失真。
func TestSessionsOnlyEstablished(t *testing.T) {
	in := []proxy.CTSnapshot{
		ct("1", "tcp", "172.16.30.10:1000", "192.168.10.152:80", "ESTABLISHED"),
		ct("2", "tcp", "172.16.30.10:1001", "192.168.10.152:80", "TIME_WAIT"),
		ct("3", "tcp", "172.16.30.10:1002", "192.168.10.152:80", "SYN_SENT"),
		ct("4", "tcp", "172.16.30.10:1003", "192.168.10.152:80", "SYN_RECV"),
		ct("5", "tcp", "172.16.30.10:1004", "192.168.10.152:80", "CLOSE_WAIT"),
		ct("6", "tcp", "172.16.30.10:1005", "192.168.10.152:80", "FIN_WAIT"),
		ct("7", "tcp", "172.16.30.10:1006", "192.168.10.152:80", "LAST_ACK"),
		ct("8", "udp", "172.16.30.10:1007", "192.168.10.152:53", "ESTABLISHED"),
		ct("9", "tcp", "172.16.30.10:1008", "192.168.10.152:80", ""),
		ct("10", "tcp", "172.16.30.10:1009", "192.168.10.152:80", "established"),
	}
	got := filterSessions(in, nil, "", "", 500)

	// 只有 id 1（tcp ESTABLISHED）与 id 8（udp ESTABLISHED）应保留。
	// id 10 是小写的 "established"——内核输出全大写，必须按字节比较判为不匹配。
	if len(got) != 2 {
		t.Fatalf("应只保留 2 条 ESTABLISHED，实际 %d 条: %+v", len(got), got)
	}
	for _, v := range got {
		if v.State != "ESTABLISHED" {
			t.Fatalf("★ 出现了非 ESTABLISHED 的行: state=%q", v.State)
		}
	}
	if got[0].ID != "1" || got[1].ID != "8" {
		t.Fatalf("保留的应是 id=1/8，实际 %q/%q", got[0].ID, got[1].ID)
	}
}

// TestSessionsStateFilterRunsBeforeLimit 断言状态过滤**先于** limit 截断。
//
// 若顺序反了（先截断再过滤），TIME_WAIT 占满前 500 条时真实会话会被挤掉，
// 表现为"有连接在跑但会话表是空的"。
func TestSessionsStateFilterRunsBeforeLimit(t *testing.T) {
	var in []proxy.CTSnapshot
	// 前 100 条全是 TIME_WAIT，最后 3 条才是真会话
	for i := 0; i < 100; i++ {
		in = append(in, ct("tw", "tcp", "10.0.0.1:1000", "192.168.10.152:80", "TIME_WAIT"))
	}
	for i := 0; i < 3; i++ {
		in = append(in, ct("live", "tcp", "10.0.0.2:2000", "192.168.10.152:80", "ESTABLISHED"))
	}
	got := filterSessions(in, nil, "", "", 10) // limit 远小于总数
	if len(got) != 3 {
		t.Fatalf("★ limit=10 也应保留全部 3 条真实会话（过滤先于截断），实际 %d 条", len(got))
	}
	for _, v := range got {
		if v.ID != "live" {
			t.Fatalf("★ 截断把 TIME_WAIT 留下了、真实会话被挤掉: id=%q state=%q", v.ID, v.State)
		}
	}
}

// TestSessionsProtoAndSearchStillWork 确认新增状态过滤没破坏原有筛选。
func TestSessionsProtoAndSearchStillWork(t *testing.T) {
	in := []proxy.CTSnapshot{
		ct("t1", "tcp", "172.16.30.10:1000", "192.168.10.152:80", "ESTABLISHED"),
		ct("u1", "udp", "172.16.30.10:1001", "192.168.10.152:53", "ESTABLISHED"),
		ct("t2", "tcp", "10.9.9.9:2000", "192.168.10.152:80", "ESTABLISHED"),
	}

	if got := filterSessions(in, nil, "udp", "", 500); len(got) != 1 || got[0].ID != "u1" {
		t.Fatalf("proto=udp 应只剩 u1，实际 %+v", got)
	}
	if got := filterSessions(in, nil, "", "10.9.9.9", 500); len(got) != 1 || got[0].ID != "t2" {
		t.Fatalf("搜索 10.9.9.9 应只剩 t2，实际 %+v", got)
	}
	// 搜一个只存在于 TIME_WAIT 行里的地址——必须返回空（状态过滤优先）
	in2 := append(in, ct("tw", "tcp", "10.7.7.7:3000", "192.168.10.152:80", "TIME_WAIT"))
	if got := filterSessions(in2, nil, "", "10.7.7.7", 500); len(got) != 0 {
		t.Fatalf("★ 搜索命中 TIME_WAIT 行时也应返回空，实际 %+v", got)
	}
}

// TestSessionsEmptyInput 空输入不应 panic，且返回非 nil 切片（JSON 序列化成 [] 而非 null）。
func TestSessionsEmptyInput(t *testing.T) {
	got := filterSessions(nil, nil, "", "", 500)
	if got == nil {
		t.Fatal("应返回空切片而非 nil（JSON 应序列化为 [] 而不是 null）")
	}
	if len(got) != 0 {
		t.Fatalf("空输入应返回 0 条，实际 %d", len(got))
	}
}

// TestSessionsShowRealBackend 端口映射的会话必须显示实际后端地址。
//
// 背景：conntrack 只有 NAT 前后四元组，端口映射是用户态重新 dial 后端，
// conntrack 里看起来只是「客户端 → 网关监听口」。后端地址只在进程内
// 会话表（ActiveSessions 的 TargetAddr）里，靠四元组关联。
//
// 生产实例：客户端 172.16.30.3:63886 → VIP 172.16.40.10:2222（规则 #33），
// 实际后端 172.16.30.20:22。
func TestSessionsShowRealBackend(t *testing.T) {
	snaps := []proxy.CTSnapshot{{
		ID: "s1", Proto: "tcp",
		Src: "172.16.30.3:63886", Dst: "172.16.40.10:2222",
		State: "ESTABLISHED",
	}}
	idx := buildBackendIndex([]model.SessionInfo{{
		SourceIP: "172.16.30.3", SourcePort: 63886,
		ListenIP: "172.16.40.10", ListenPort: 2222,
		TargetAddr: "172.16.30.20:22",
	}})
	got := filterSessions(snaps, idx, "", "", 500)
	if len(got) != 1 {
		t.Fatalf("应返回 1 条，实际 %d", len(got))
	}
	if got[0].Backend != "172.16.30.20:22" {
		t.Fatalf("★ 实际后端应为 172.16.30.20:22，实际 %q", got[0].Backend)
	}
}

// TestSessionsBackendEmptyWhenUnrelated 关联不上时 Backend 留空，不能串到别人的后端。
//
// 三类必须留空的场景：
//   - 内核转发的 snat 会话（本来就没有应用层后端）
//   - 端口号相同但客户端端口不同（不是同一条连接）
//   - 监听 IP 不同
func TestSessionsBackendEmptyWhenUnrelated(t *testing.T) {
	idx := buildBackendIndex([]model.SessionInfo{{
		SourceIP: "172.16.30.3", SourcePort: 63886,
		ListenIP: "172.16.40.10", ListenPort: 2222,
		TargetAddr: "172.16.30.20:22",
	}})

	cases := []struct {
		name, src, dst string
	}{
		{"源端口不同", "172.16.30.3:63887", "172.16.40.10:2222"},
		{"源 IP 不同", "172.16.30.4:63886", "172.16.40.10:2222"},
		{"监听 IP 不同", "172.16.30.3:63886", "172.16.40.11:2222"},
		{"监听端口不同", "172.16.30.3:63886", "172.16.40.10:2223"},
		{"完全无关的 snat 会话", "192.168.10.152:33668", "42.237.113.74:443"},
	}
	for _, c := range cases {
		if got := idx.lookupSession(c.src, c.dst); got != nil {
			t.Fatalf("★ %s 不应关联到后端，实际 %+v", c.name, got)
		}
	}
}

// TestSessionsBackendMalformedInput 畸形地址不能 panic、不能返回错误后端。
func TestSessionsBackendMalformedInput(t *testing.T) {
	idx := buildBackendIndex([]model.SessionInfo{{
		SourceIP: "172.16.30.3", SourcePort: 63886,
		ListenIP: "172.16.40.10", ListenPort: 2222,
		TargetAddr: "172.16.30.20:22",
	}})
	for _, c := range [][2]string{
		{"", ""},
		{"no-port", "172.16.40.10:2222"},
		{"172.16.30.3:abc", "172.16.40.10:2222"},
		{"172.16.30.3:63886", "bad"},
	} {
		if got := idx.lookupSession(c[0], c[1]); got != nil {
			t.Fatalf("畸形输入 %v 应返回空，实际 %+v", c, got)
		}
	}
}

// TestSessionsSkipSessionsWithoutTarget 无 target_addr 的会话不进索引
// （snat/dnat 走内核，没有 Redis 意义上的"后端"）。
func TestSessionsSkipSessionsWithoutTarget(t *testing.T) {
	idx := buildBackendIndex([]model.SessionInfo{
		{SourceIP: "10.0.0.1", SourcePort: 1, ListenIP: "10.0.0.2", ListenPort: 2},
	})
	if len(idx.byClient) != 0 {
		t.Fatalf("target_addr 为空的会话不应进索引，实际 %d 条", len(idx.byClient))
	}
}

// TestSessionsSearchMatchesBackend 搜索框要能按后端地址过滤——
// 排查"谁在连某台后端"是最常见用法。
func TestSessionsSearchMatchesBackend(t *testing.T) {
	snaps := []proxy.CTSnapshot{
		{ID: "a", Proto: "tcp", Src: "172.16.30.3:1000", Dst: "172.16.40.10:2222", State: "ESTABLISHED"},
		{ID: "b", Proto: "tcp", Src: "172.16.30.4:1001", Dst: "172.16.40.10:2222", State: "ESTABLISHED"},
	}
	idx := buildBackendIndex([]model.SessionInfo{
		{SourceIP: "172.16.30.3", SourcePort: 1000, ListenIP: "172.16.40.10", ListenPort: 2222,
			TargetAddr: "172.16.30.20:22"},
		{SourceIP: "172.16.30.4", SourcePort: 1001, ListenIP: "172.16.40.10", ListenPort: 2222,
			TargetAddr: "192.168.10.152:80"},
	})
	got := filterSessions(snaps, idx, "", "172.16.30.20", 500)
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("★ 搜后端 172.16.30.20 应只剩会话 a，实际 %+v", got)
	}
}

// TestSessionsMergeDialLeg 端口映射的一条逻辑连接在 conntrack 里是两段，
// 会话表必须合并成**一行**。
//
// 生产实例（规则 #33，VIP 172.16.40.10:2222 → 后端 172.16.30.20:22）：
//
//	入向段: src=172.16.30.3:63858 dst=172.16.40.10:2222
//	出向段: src=172.16.40.10:56191 dst=172.16.30.20:22   ← 网关 dial 的本地端口
//
// 两段本是同一条连接，用户之前反馈"这两个不是一条流量吗"。
func TestSessionsMergeDialLeg(t *testing.T) {
	snaps := []proxy.CTSnapshot{
		{ID: "client", Proto: "tcp",
			Src: "172.16.30.3:63858", Dst: "172.16.40.10:2222", State: "ESTABLISHED"},
		{ID: "dial", Proto: "tcp",
			Src: "172.16.40.10:56191", Dst: "172.16.30.20:22", State: "ESTABLISHED"},
	}
	idx := buildBackendIndex([]model.SessionInfo{{
		SourceIP: "172.16.30.3", SourcePort: 63858,
		ListenIP: "172.16.40.10", ListenPort: 2222,
		TargetAddr:    "172.16.30.20:22",
		DialLocalPort: 56191,
	}})

	got := filterSessions(snaps, idx, "", "", 500)
	if len(got) != 1 {
		t.Fatalf("★ 两段应合并成 1 行，实际 %d 行: %+v", len(got), got)
	}
	if got[0].ID != "client" {
		t.Fatalf("保留的应是入向段（client），实际 %q", got[0].ID)
	}
	if got[0].Backend != "172.16.30.20:22" {
		t.Fatalf("后端应为 172.16.30.20:22，实际 %q", got[0].Backend)
	}
}

// TestSessionsDialLegPortReuseGuard dial 端口会被内核复用，仅凭端口命中
// 不得把无关连接误判成出向段而隐藏掉——目的地址必须也匹配。
func TestSessionsDialLegPortReuseGuard(t *testing.T) {
	idx := buildBackendIndex([]model.SessionInfo{{
		SourceIP: "172.16.30.3", SourcePort: 63858,
		ListenIP: "172.16.40.10", ListenPort: 2222,
		TargetAddr:    "172.16.30.20:22",
		DialLocalPort: 56191,
	}})

	// 源端口撞上 56191，但目的地址不是该会话的后端 → 不是出向段，必须保留
	snaps := []proxy.CTSnapshot{
		{ID: "client", Proto: "tcp",
			Src: "172.16.30.3:63858", Dst: "172.16.40.10:2222", State: "ESTABLISHED"},
		{ID: "unrelated", Proto: "tcp",
			Src: "172.16.40.10:56191", Dst: "8.8.8.8:443", State: "ESTABLISHED"},
	}
	got := filterSessions(snaps, idx, "", "", 500)
	if len(got) != 2 {
		t.Fatalf("★ 目的地址不匹配时不得合并（端口复用保护），应保留 2 行，实际 %d", len(got))
	}
	var sawUnrelated bool
	for _, v := range got {
		if v.ID == "unrelated" {
			sawUnrelated = true
		}
	}
	if !sawUnrelated {
		t.Fatal("★ 无关连接被误判成出向段而隐藏了")
	}
}

// TestSessionsNoDialLocalPortKeepsBothLegs DialLocalPort=0（dial 未完成/失败）
// 时无法合并，两段各自显示——宁可多一行，不能凭空吞掉一条连接。
func TestSessionsNoDialLocalPortKeepsBothLegs(t *testing.T) {
	snaps := []proxy.CTSnapshot{
		{ID: "client", Proto: "tcp",
			Src: "172.16.30.3:63858", Dst: "172.16.40.10:2222", State: "ESTABLISHED"},
		{ID: "dial", Proto: "tcp",
			Src: "172.16.40.10:56191", Dst: "172.16.30.20:22", State: "ESTABLISHED"},
	}
	idx := buildBackendIndex([]model.SessionInfo{{
		SourceIP: "172.16.30.3", SourcePort: 63858,
		ListenIP: "172.16.40.10", ListenPort: 2222,
		TargetAddr: "172.16.30.20:22",
		// DialLocalPort 故意为 0
	}})
	got := filterSessions(snaps, idx, "", "", 500)
	if len(got) != 2 {
		t.Fatalf("★ 无 dial 端口时不应合并，应保留 2 行，实际 %d", len(got))
	}
	// 但入向段仍应拿到后端地址
	for _, v := range got {
		if v.ID == "client" && v.Backend != "172.16.30.20:22" {
			t.Fatalf("入向段仍应显示后端，实际 %q", v.Backend)
		}
	}
}
