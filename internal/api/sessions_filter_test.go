// 会话表过滤规则（产品决定 2026-11-01：只保留 ESTABLISHED）。
package api

import (
	"testing"

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
	got := filterSessions(in, "", "", 500)

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
	got := filterSessions(in, "", "", 10) // limit 远小于总数
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

	if got := filterSessions(in, "udp", "", 500); len(got) != 1 || got[0].ID != "u1" {
		t.Fatalf("proto=udp 应只剩 u1，实际 %+v", got)
	}
	if got := filterSessions(in, "", "10.9.9.9", 500); len(got) != 1 || got[0].ID != "t2" {
		t.Fatalf("搜索 10.9.9.9 应只剩 t2，实际 %+v", got)
	}
	// 搜一个只存在于 TIME_WAIT 行里的地址——必须返回空（状态过滤优先）
	in2 := append(in, ct("tw", "tcp", "10.7.7.7:3000", "192.168.10.152:80", "TIME_WAIT"))
	if got := filterSessions(in2, "", "10.7.7.7", 500); len(got) != 0 {
		t.Fatalf("★ 搜索命中 TIME_WAIT 行时也应返回空，实际 %+v", got)
	}
}

// TestSessionsEmptyInput 空输入不应 panic，且返回非 nil 切片（JSON 序列化成 [] 而非 null）。
func TestSessionsEmptyInput(t *testing.T) {
	got := filterSessions(nil, "", "", 500)
	if got == nil {
		t.Fatal("应返回空切片而非 nil（JSON 应序列化为 [] 而不是 null）")
	}
	if len(got) != 0 {
		t.Fatalf("空输入应返回 0 条，实际 %d", len(got))
	}
}
