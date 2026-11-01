// 会话强制断开的回归测试（两个线上问题，2026-11-01）。
//
// 背景一（掐断无效）：KillSessionByID 原来只做 `conntrack -D` 删内核表项。
// 端口映射是用户态转发，进程里有一对真实 socket，删表项后 copy 协程照常
// 搬数据、内核立刻重建条目——用户点"掐断"后 scp 速率不变。
//
// 背景二（白名单不生效）：ACL 只在 accept 时判定一次。改白名单只影响新连接，
// 正在跑的长传会传完——用户以为已经封禁，实际通道还开着。
package proxy

import (
	"sync/atomic"
	"testing"
	"time"

	"haproxyweb/internal/model"
)

// mkSession 造一条测试会话（直接塞进 manager 的 sessions 表）。
func mkSession(m *Manager, ruleID uint, proto, srcIP string, srcPort int,
	listenIP string, listenPort int) *session {
	s := &session{
		id:         m.sessionSeq.Add(1),
		rule:       model.ForwardRule{ID: ruleID, Protocol: proto, Name: "test"},
		srcIP:      srcIP,
		srcPort:    srcPort,
		listenIP:   listenIP,
		listenPort: listenPort,
		start:      time.Now(),
	}
	m.sessions.Store(s.id, s)
	return s
}

// TestForceCloseInvokesHook 基本契约：注册了钩子就能被 forceClose 调到。
func TestForceCloseInvokesHook(t *testing.T) {
	m := newTestManager(0, 60*time.Second)
	s := mkSession(m, 1, "tcp", "10.0.0.1", 1000, "10.0.0.2", 2000)

	var called atomic.Int32
	s.setCloser(func() { called.Add(1) })

	if !s.forceClose() {
		t.Fatal("注册了钩子，forceClose 应返回 true")
	}
	if called.Load() != 1 {
		t.Fatalf("钩子应被调用 1 次，实际 %d", called.Load())
	}
}

// TestForceCloseWithoutHook 未注册钩子（UDP 老路径/测试构造）时返回 false 且不 panic。
func TestForceCloseWithoutHook(t *testing.T) {
	m := newTestManager(0, 60*time.Second)
	s := mkSession(m, 1, "tcp", "10.0.0.1", 1000, "10.0.0.2", 2000)
	if s.forceClose() {
		t.Fatal("未注册钩子时 forceClose 应返回 false")
	}
}

// TestForceCloseIdempotent 掐断与 ACL 复核可能同时命中同一条会话，
// 钩子必须能被安全地重复调用（关闭已关闭的连接是安全的）。
func TestForceCloseIdempotent(t *testing.T) {
	m := newTestManager(0, 60*time.Second)
	s := mkSession(m, 1, "tcp", "10.0.0.1", 1000, "10.0.0.2", 2000)

	var called atomic.Int32
	s.setCloser(func() { called.Add(1) })
	s.forceClose()
	s.forceClose()
	s.forceClose()
	if called.Load() != 3 {
		t.Fatalf("钩子应被调用 3 次（幂等由钩子内部保证），实际 %d", called.Load())
	}
}

// TestKillUserSessionMatchesQuadruple 按入向段四元组精确命中。
//
// 用 approaching-but-different 的四元组验证"四个键都必须相等"：
// 只错一项就不能误杀别人的会话。
func TestKillUserSessionMatchesQuadruple(t *testing.T) {
	cases := []struct {
		name       string
		proto      string
		srcIP      string
		srcPort    int
		listenIP   string
		listenPort int
		wantHit    bool
	}{
		{"完全匹配", "tcp", "10.0.0.1", 1000, "10.0.0.2", 2000, true},
		{"协议不同", "udp", "10.0.0.1", 1000, "10.0.0.2", 2000, false},
		{"客户端 IP 不同", "tcp", "10.0.0.9", 1000, "10.0.0.2", 2000, false},
		{"客户端端口不同", "tcp", "10.0.0.1", 9999, "10.0.0.2", 2000, false},
		{"监听 IP 不同", "tcp", "10.0.0.1", 1000, "10.0.0.9", 2000, false},
		{"监听端口不同", "tcp", "10.0.0.1", 1000, "10.0.0.2", 9999, false},
	}
	for _, c := range cases {
		m := newTestManager(0, 60*time.Second)
		s := mkSession(m, 1, "tcp", "10.0.0.1", 1000, "10.0.0.2", 2000)
		var called atomic.Int32
		s.setCloser(func() { called.Add(1) })

		got := m.killUserSession(c.proto, c.srcIP, c.srcPort, c.listenIP, c.listenPort)
		if got != c.wantHit {
			t.Fatalf("%s：期望命中=%v，实际=%v", c.name, c.wantHit, got)
		}
		wantCalled := int32(0)
		if c.wantHit {
			wantCalled = 1
		}
		if called.Load() != wantCalled {
			t.Fatalf("%s：钩子应被调用 %d 次，实际 %d", c.name, wantCalled, called.Load())
		}
	}
}

// TestKillUserSessionNoMatch 会话表里没有对应会话时返回 false（不误报成功）。
func TestKillUserSessionNoMatch(t *testing.T) {
	m := newTestManager(0, 60*time.Second)
	mkSession(m, 1, "tcp", "10.0.0.1", 1000, "10.0.0.2", 2000)
	if m.killUserSession("tcp", "10.9.9.9", 8888, "10.0.0.2", 2000) {
		t.Fatal("无匹配会话时应返回 false")
	}
}

// TestCloseDeniedSessionsBreaksViolators ACL 收紧后，不在新名单内的存量会话
// 必须被断开，名单内的必须保留。
//
// 这是"白名单不生效"的直接回归：用户把白名单从「不限」改成只允许
// 27.222.18.154，正在跑的 scp（源 192.168.10.151）必须立刻断。
func TestCloseDeniedSessionsBreaksViolators(t *testing.T) {
	m := newTestManager(0, 60*time.Second)

	allowed := mkSession(m, 7, "tcp", "27.222.18.154", 1000, "10.0.0.2", 2222)
	violator1 := mkSession(m, 7, "tcp", "192.168.10.151", 1001, "10.0.0.2", 2222)
	violator2 := mkSession(m, 7, "tcp", "172.16.30.3", 1002, "10.0.0.2", 2222)
	otherRule := mkSession(m, 8, "tcp", "192.168.10.151", 1003, "10.0.0.3", 3333)

	var aOK, v1, v2, other atomic.Int32
	allowed.setCloser(func() { aOK.Add(1) })
	violator1.setCloser(func() { v1.Add(1) })
	violator2.setCloser(func() { v2.Add(1) })
	otherRule.setCloser(func() { other.Add(1) })

	acl, err := ParseACL(model.AclModeWhitelist, `["27.222.18.154"]`, "")
	if err != nil {
		t.Fatalf("构造 ACL 失败: %v", err)
	}
	m.closeDeniedSessions(7, acl)

	if aOK.Load() != 0 {
		t.Fatal("★ 白名单内的会话被误杀")
	}
	if v1.Load() != 1 || v2.Load() != 1 {
		t.Fatalf("★ 名单外的 2 条会话都应被断开，实际 v1=%d v2=%d", v1.Load(), v2.Load())
	}
	if other.Load() != 0 {
		t.Fatal("★ 断了别的规则的会话（规则隔离失效）")
	}
}

// TestCloseDeniedSessionsNoopWhenOff 改成「不限」时不主动断连接——
// 放宽限制不该切断正在跑的流量。
func TestCloseDeniedSessionsNoopWhenOff(t *testing.T) {
	m := newTestManager(0, 60*time.Second)
	s := mkSession(m, 7, "tcp", "192.168.10.151", 1000, "10.0.0.2", 2222)
	var called atomic.Int32
	s.setCloser(func() { called.Add(1) })

	acl, err := ParseACL(model.AclModeOff, "", "")
	if err != nil {
		t.Fatalf("构造 ACL 失败: %v", err)
	}
	m.closeDeniedSessions(7, acl)
	if called.Load() != 0 {
		t.Fatal("★ 改成不限时不应断开任何会话")
	}
}

// TestCloseDeniedSessionsNilACL nil ACL 不 panic（防御性：Apply 的某些路径可能传 nil）。
func TestCloseDeniedSessionsNilACL(t *testing.T) {
	m := newTestManager(0, 60*time.Second)
	mkSession(m, 7, "tcp", "192.168.10.151", 1000, "10.0.0.2", 2222)
	m.closeDeniedSessions(7, nil) // 不应 panic
}

// TestCloseDeniedSessionsBlacklist 黑名单模式同样生效：
// 命中黑名单的存量连接要断，未命中的保留。
func TestCloseDeniedSessionsBlacklist(t *testing.T) {
	m := newTestManager(0, 60*time.Second)
	denied := mkSession(m, 9, "tcp", "10.6.6.6", 1000, "10.0.0.2", 2222)
	ok := mkSession(m, 9, "tcp", "10.7.7.7", 1001, "10.0.0.2", 2222)
	var d, o atomic.Int32
	denied.setCloser(func() { d.Add(1) })
	ok.setCloser(func() { o.Add(1) })

	acl, err := ParseACL(model.AclModeBlacklist, "", `["10.6.6.0/24"]`)
	if err != nil {
		t.Fatalf("构造 ACL 失败: %v", err)
	}
	m.closeDeniedSessions(9, acl)
	if d.Load() != 1 {
		t.Fatal("★ 命中黑名单的存量会话应被断开")
	}
	if o.Load() != 0 {
		t.Fatal("★ 未命中黑名单的会话被误杀")
	}
}
