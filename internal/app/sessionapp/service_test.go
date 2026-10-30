package sessionapp

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

type fakeLister struct {
	sessions []Session
	err      error
}

func (l *fakeLister) List(ctx context.Context) ([]Session, error) {
	if l.err != nil {
		return nil, l.err
	}
	return l.sessions, nil
}

type fakeKiller struct {
	mu      sync.Mutex
	killed  []string
	missing map[string]bool
	fail    map[string]bool
}

func newFakeKiller() *fakeKiller {
	return &fakeKiller{missing: map[string]bool{}, fail: map[string]bool{}}
}

func (k *fakeKiller) Kill(ctx context.Context, id string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.missing[id] {
		return ErrNotFound
	}
	if k.fail[id] {
		return errors.New("netlink: 内部错误 at /proc/net/nf_conntrack line 42")
	}
	k.killed = append(k.killed, id)
	return nil
}

func (k *fakeKiller) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.killed)
}

type fakeAudit struct {
	mu      sync.Mutex
	actions []string
}

func (a *fakeAudit) Record(user, action, detail, clientIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.actions = append(a.actions, action)
}

func (a *fakeAudit) has(x string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, v := range a.actions {
		if v == x {
			return true
		}
	}
	return false
}

// TestKillBatchAllSucceed 批量全部成功。
func TestKillBatchAllSucceed(t *testing.T) {
	k := newFakeKiller()
	a := &fakeAudit{}
	svc := New(&fakeLister{}, k, a)
	res, err := svc.KillBatch(context.Background(), []string{"a", "b", "c"}, "admin", "10.0.0.1")
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	if len(res.Killed) != 3 {
		t.Fatalf("应成功 3 条，实际 %d", len(res.Killed))
	}
	if len(res.Failed) != 0 || len(res.NotFound) != 0 {
		t.Fatalf("不应有失败/不存在: %+v", res)
	}
	if !a.has("session_kill_batch") {
		t.Fatal("应记录审计")
	}
}

// TestKillBatchPartialFailure 单条失败不影响其它条（§8.2 的关键语义）。
func TestKillBatchPartialFailure(t *testing.T) {
	k := newFakeKiller()
	k.missing["gone"] = true
	k.fail["bad"] = true
	svc := New(&fakeLister{}, k, &fakeAudit{})

	res, err := svc.KillBatch(context.Background(), []string{"ok1", "gone", "bad", "ok2"}, "", "")
	if err != nil {
		t.Fatalf("批量失败不应整体报错: %v", err)
	}
	if len(res.Killed) != 2 {
		t.Fatalf("应成功 2 条，实际 %d: %v", len(res.Killed), res.Killed)
	}
	if len(res.NotFound) != 1 || res.NotFound[0] != "gone" {
		t.Fatalf("应把 gone 归入 NotFound，实际 %v", res.NotFound)
	}
	if len(res.Failed) != 1 || res.Failed["bad"] == "" {
		t.Fatalf("应把 bad 归入 Failed，实际 %v", res.Failed)
	}
}

// TestKillBatchErrorDoesNotLeakInternals 失败原因不能泄露内部细节（§8.5）。
func TestKillBatchErrorDoesNotLeakInternals(t *testing.T) {
	k := newFakeKiller()
	k.fail["bad"] = true
	svc := New(&fakeLister{}, k, &fakeAudit{})
	res, _ := svc.KillBatch(context.Background(), []string{"bad"}, "", "")
	reason := res.Failed["bad"]
	for _, leak := range []string{"/proc", "netlink", "line 42"} {
		if strings.Contains(reason, leak) {
			t.Fatalf("★ 失败原因泄露了内部细节 %q: %q", leak, reason)
		}
	}
	if reason == "" {
		t.Fatal("失败原因不应为空")
	}
}

// TestKillBatchDedup 重复 ID 只踢一次。
func TestKillBatchDedup(t *testing.T) {
	k := newFakeKiller()
	svc := New(&fakeLister{}, k, &fakeAudit{})
	res, err := svc.KillBatch(context.Background(), []string{"a", "a", "a", "b"}, "", "")
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	if k.count() != 2 {
		t.Fatalf("去重后应只踢 2 次，实际 %d", k.count())
	}
	if len(res.Killed) != 2 {
		t.Fatalf("应报告 2 条，实际 %d", len(res.Killed))
	}
}

// TestKillBatchEmpty 空列表不是错误。
func TestKillBatchEmpty(t *testing.T) {
	svc := New(&fakeLister{}, newFakeKiller(), &fakeAudit{})
	res, err := svc.KillBatch(context.Background(), nil, "", "")
	if err != nil {
		t.Fatalf("空列表不应报错: %v", err)
	}
	if len(res.Killed) != 0 {
		t.Fatalf("应为空，实际 %v", res.Killed)
	}
}

// TestKillBatchTooMany 超过上限必须拒绝（防误用）。
func TestKillBatchTooMany(t *testing.T) {
	svc := New(&fakeLister{}, newFakeKiller(), &fakeAudit{})
	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = "id"
	}
	if _, err := svc.KillBatch(context.Background(), ids, "", ""); err == nil {
		t.Fatal("★ 超过 1000 条必须拒绝（一次踢 10 万条会打爆 conntrack 与审计）")
	}
}

// TestKillByACLGroup 名单组踢会话：只踢源地址落在网段内的。
func TestKillByACLGroup(t *testing.T) {
	lister := &fakeLister{sessions: []Session{
		{ID: "s1", SrcAddr: netip.MustParseAddr("192.168.10.152")},
		{ID: "s2", SrcAddr: netip.MustParseAddr("192.168.10.151")},
		{ID: "s3", SrcAddr: netip.MustParseAddr("10.0.0.5")},
	}}
	k := newFakeKiller()
	a := &fakeAudit{}
	svc := New(lister, k, a)

	killed, err := svc.KillByACLGroup(context.Background(), 7,
		[]netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}, "admin", "10.0.0.1")
	if err != nil {
		t.Fatalf("失败: %v", err)
	}
	if killed != 2 {
		t.Fatalf("★ 应踢 2 条（192.168.10.x），实际 %d", killed)
	}
	if !a.has("acl_group_kick_sessions") {
		t.Fatal("应记录审计")
	}
}

// TestKillByACLGroupEmpty 空名单组不踢任何会话（清空名单是合法操作）。
func TestKillByACLGroupEmpty(t *testing.T) {
	lister := &fakeLister{sessions: []Session{
		{ID: "s1", SrcAddr: netip.MustParseAddr("192.168.10.152")},
	}}
	k := newFakeKiller()
	svc := New(lister, k, &fakeAudit{})
	killed, err := svc.KillByACLGroup(context.Background(), 1, nil, "", "")
	if err != nil {
		t.Fatalf("空组不应报错: %v", err)
	}
	if killed != 0 {
		t.Fatalf("空组不应踢会话，实际 %d", killed)
	}
}

// TestKillByACLGroupPartialFailure 单条踢失败继续处理其余（不整体失败）。
func TestKillByACLGroupPartialFailure(t *testing.T) {
	lister := &fakeLister{sessions: []Session{
		{ID: "s1", SrcAddr: netip.MustParseAddr("192.168.10.1")},
		{ID: "s2", SrcAddr: netip.MustParseAddr("192.168.10.2")},
		{ID: "s3", SrcAddr: netip.MustParseAddr("192.168.10.3")},
	}}
	k := newFakeKiller()
	k.fail["s2"] = true
	svc := New(lister, k, &fakeAudit{})
	killed, err := svc.KillByACLGroup(context.Background(), 1,
		[]netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}, "", "")
	if err != nil {
		t.Fatalf("单条失败不应让整体报错: %v", err)
	}
	if killed != 2 {
		t.Fatalf("应成功踢 2 条（s1、s3），实际 %d", killed)
	}
}

// TestKillByACLGroupListError 列出会话失败必须上报。
func TestKillByACLGroupListError(t *testing.T) {
	lister := &fakeLister{err: errors.New("conntrack 不可用")}
	svc := New(lister, newFakeKiller(), &fakeAudit{})
	if _, err := svc.KillByACLGroup(context.Background(), 1,
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, "", ""); err == nil {
		t.Fatal("列出会话失败应报错")
	}
}

// TestKillByACLGroupIPv6 IPv6 网段匹配。
func TestKillByACLGroupIPv6(t *testing.T) {
	lister := &fakeLister{sessions: []Session{
		{ID: "s1", SrcAddr: netip.MustParseAddr("2001:db8::1")},
		{ID: "s2", SrcAddr: netip.MustParseAddr("2001:dead::1")},
	}}
	k := newFakeKiller()
	svc := New(lister, k, &fakeAudit{})
	killed, _ := svc.KillByACLGroup(context.Background(), 1,
		[]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, "", "")
	if killed != 1 {
		t.Fatalf("v6 应只踢 1 条，实际 %d", killed)
	}
}

// TestKillBatchContextCancel ctx 取消必须中断。
func TestKillBatchContextCancel(t *testing.T) {
	k := newFakeKiller()
	svc := New(&fakeLister{}, k, &fakeAudit{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.KillBatch(ctx, []string{"a", "b"}, "", "")
	if err == nil {
		t.Fatal("已取消的 ctx 应返回错误")
	}
}
