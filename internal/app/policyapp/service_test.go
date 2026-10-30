package policyapp

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// ---- 测试替身 ----

type fakeStore struct {
	mu       sync.Mutex
	policies map[uint]*Policy
	nextID   uint
	// setEnabledCalls 记录每次启停调用（验证顺序：先改库再重装）
	setEnabledCalls []bool
	getErr          error
	setErr          error
}

func newFakeStore(ps ...Policy) *fakeStore {
	s := &fakeStore{policies: map[uint]*Policy{}, nextID: 1}
	for i := range ps {
		p := ps[i]
		if p.ID == 0 {
			p.ID = s.nextID
			s.nextID++
		}
		s.policies[p.ID] = &p
		if p.ID >= s.nextID {
			s.nextID = p.ID + 1
		}
	}
	return s
}

func (s *fakeStore) GetPolicy(ctx context.Context, id uint) (*Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return nil, s.getErr
	}
	p, ok := s.policies[id]
	if !ok {
		return nil, nil
	}
	cp := *p
	return &cp, nil
}

func (s *fakeStore) ListPolicies(ctx context.Context) ([]Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, *p)
	}
	return out, nil
}

func (s *fakeStore) SetEnabled(ctx context.Context, id uint, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return s.setErr
	}
	p, ok := s.policies[id]
	if !ok {
		return ErrNotFound
	}
	p.Enabled = enabled
	s.setEnabledCalls = append(s.setEnabledCalls, enabled)
	return nil
}

func (s *fakeStore) DeletePolicy(ctx context.Context, id uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, id)
	return nil
}

type fakeKiller struct {
	mu     sync.Mutex
	calls  []Policy
	result int
	err    error
}

func (k *fakeKiller) KillByPolicy(ctx context.Context, p Policy) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls = append(k.calls, p)
	if k.err != nil {
		return 0, k.err
	}
	return k.result, nil
}

func (k *fakeKiller) callCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.calls)
}

type fakeInstaller struct {
	mu    sync.Mutex
	calls int
	err   error
	// order 记录「重装」发生在什么操作之后（验证先改库再重装）
	store *fakeStore
	// storeStateAtInstall 是重装时看到的启停状态
	storeStateAtInstall []bool
}

func (i *fakeInstaller) ReinstallPolicies(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls++
	if i.store != nil {
		i.store.mu.Lock()
		i.storeStateAtInstall = append([]bool{}, i.store.setEnabledCalls...)
		i.store.mu.Unlock()
	}
	return i.err
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

func (a *fakeAudit) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.actions {
		if x == action {
			return true
		}
	}
	return false
}

// ---- 测试 ----

// TestDisableKillsSessions 「禁用策略 → 立即断开已建会话」。
//
// 这是验收文档「禁用策略后流量立即断开」的核心。旧实现只在
// action==drop 且显式要求时踢，已建会话最长存活 86400s，用例直接不通过。
func TestDisableKillsSessions(t *testing.T) {
	store := newFakeStore(Policy{Name: "p1", Action: "drop", Enabled: true})
	killer := &fakeKiller{result: 42}
	install := &fakeInstaller{}
	audit := &fakeAudit{}
	svc := New(store, killer, install, audit)

	res, err := svc.SetEnabled(context.Background(), 1, false, "admin", "10.0.0.1")
	if err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	// ★ 核心断言：必须踢会话
	if killer.callCount() != 1 {
		t.Fatalf("★ 禁用策略必须调用一次 KillByPolicy，实际 %d 次"+
			"（旧缺陷：只在 action==drop 且显式要求时才踢）", killer.callCount())
	}
	if res.KilledSessions != 42 {
		t.Fatalf("应报告踢掉 42 条，实际 %d", res.KilledSessions)
	}
	if res.Enabled {
		t.Fatal("操作后应为禁用状态")
	}
	// 必须重装规则
	if install.calls != 1 {
		t.Fatalf("必须重装规则，实际 %d 次", install.calls)
	}
	// 必须审计
	if !audit.has("fw_policy_disable") {
		t.Fatalf("应记录 fw_policy_disable 审计，实际 %v", audit.actions)
	}
}

// TestEnableDoesNotKill 启用策略不踢会话（放宽/收紧新连接，不该打断现有连接）。
func TestEnableDoesNotKill(t *testing.T) {
	store := newFakeStore(Policy{Name: "p1", Action: "drop", Enabled: false})
	killer := &fakeKiller{result: 99}
	svc := New(store, killer, &fakeInstaller{}, &fakeAudit{})

	res, err := svc.SetEnabled(context.Background(), 1, true, "admin", "10.0.0.1")
	if err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	if killer.callCount() != 0 {
		t.Fatalf("★ 启用策略不应踢会话，实际踢了 %d 次", killer.callCount())
	}
	if res.KilledSessions != 0 {
		t.Fatalf("启用时踢会话数应为 0，实际 %d", res.KilledSessions)
	}
}

// TestDisableOrderStoreThenInstall 必须先改库再重装。
//
// 顺序反了会出现「内核已无规则但库还标着启用」，重启后策略复活。
func TestDisableOrderStoreThenInstall(t *testing.T) {
	store := newFakeStore(Policy{Name: "p1", Action: "drop", Enabled: true})
	install := &fakeInstaller{store: store}
	svc := New(store, &fakeKiller{}, install, &fakeAudit{})

	if _, err := svc.SetEnabled(context.Background(), 1, false, "admin", ""); err != nil {
		t.Fatalf("失败: %v", err)
	}
	// 重装时库里应已经是「禁用」
	if len(install.storeStateAtInstall) != 1 || install.storeStateAtInstall[0] != false {
		t.Fatalf("★ 重装时库里应已是禁用状态，实际 %v（顺序反了会让策略重启后复活）",
			install.storeStateAtInstall)
	}
}

// TestDisableNotFound 不存在的策略返回 ErrNotFound。
func TestDisableNotFound(t *testing.T) {
	svc := New(newFakeStore(), &fakeKiller{}, &fakeInstaller{}, &fakeAudit{})
	if _, err := svc.SetEnabled(context.Background(), 999, false, "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("应返回 ErrNotFound，实际: %v", err)
	}
}

// TestDisableKillErrorReported 踢会话失败必须上报（但规则已撤，安全已达成）。
func TestDisableKillErrorReported(t *testing.T) {
	store := newFakeStore(Policy{Name: "p1", Action: "drop", Enabled: true})
	killer := &fakeKiller{err: errors.New("netlink 忙")}
	svc := New(store, killer, &fakeInstaller{}, &fakeAudit{})

	res, err := svc.SetEnabled(context.Background(), 1, false, "", "")
	if err == nil {
		t.Fatal("踢会话失败应返回错误")
	}
	// 但启停状态必须已经保存（安全优先于会话清理）
	if res == nil || res.Enabled {
		t.Fatal("启停状态应已保存为禁用")
	}
}

// TestDisableInstallErrorAborts 重装失败必须中止（不能继续踢会话）。
func TestDisableInstallErrorAborts(t *testing.T) {
	store := newFakeStore(Policy{Name: "p1", Action: "drop", Enabled: true})
	killer := &fakeKiller{result: 10}
	install := &fakeInstaller{err: errors.New("nft 失败")}
	svc := New(store, killer, install, &fakeAudit{})

	if _, err := svc.SetEnabled(context.Background(), 1, false, "", ""); err == nil {
		t.Fatal("重装失败应返回错误")
	}
	if killer.callCount() != 0 {
		t.Fatal("重装失败时不应继续踢会话（规则还没撤）")
	}
}

// TestStoreSetEnabledErrorAborts 保存启停失败必须中止。
func TestStoreSetEnabledErrorAborts(t *testing.T) {
	store := newFakeStore(Policy{Name: "p1", Action: "drop", Enabled: true})
	store.setErr = errors.New("disk full")
	install := &fakeInstaller{}
	svc := New(store, &fakeKiller{}, install, &fakeAudit{})

	if _, err := svc.SetEnabled(context.Background(), 1, false, "", ""); err == nil {
		t.Fatal("保存失败应返回错误")
	}
	if install.calls != 0 {
		t.Fatal("保存失败时不应重装规则")
	}
}

// TestDeleteKillsSessions 删策略也要踢会话（§8.3）。
func TestDeleteKillsSessions(t *testing.T) {
	store := newFakeStore(Policy{Name: "p1", Action: "accept", Enabled: true})
	killer := &fakeKiller{result: 7}
	audit := &fakeAudit{}
	svc := New(store, killer, &fakeInstaller{}, audit)

	killed, err := svc.Delete(context.Background(), 1, "admin", "10.0.0.1")
	if err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if killer.callCount() != 1 {
		t.Fatalf("★ 删策略必须踢会话，实际 %d 次", killer.callCount())
	}
	if killed != 7 {
		t.Fatalf("应报告踢掉 7 条，实际 %d", killed)
	}
	if !audit.has("fw_policy_delete") {
		t.Fatal("应记录删除审计")
	}
}

// TestDeleteNotFound 删除不存在的策略。
func TestDeleteNotFound(t *testing.T) {
	svc := New(newFakeStore(), &fakeKiller{}, &fakeInstaller{}, &fakeAudit{})
	if _, err := svc.Delete(context.Background(), 999, "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("应返回 ErrNotFound，实际: %v", err)
	}
}

// TestNeedsKick 穷举「哪些变更需要踢会话」的判定。
//
// 这是「禁用后立即断开」这条验收用例的可验证内核。
func TestNeedsKick(t *testing.T) {
	cases := []struct {
		name string
		old  *Policy
		next Policy
		want bool
	}{
		// 新策略
		{"新建 drop", nil, Policy{Action: "drop"}, true},
		{"新建 accept", nil, Policy{Action: "accept"}, false},
		{"新建 allow", nil, Policy{Action: "allow"}, false},
		// 旧是 drop
		{"drop→drop", &Policy{Action: "drop"}, Policy{Action: "drop"}, true},
		{"drop→accept", &Policy{Action: "drop"}, Policy{Action: "accept"}, true},
		// 新是 drop
		{"accept→drop", &Policy{Action: "accept"}, Policy{Action: "drop"}, true},
		{"allow→drop", &Policy{Action: "allow"}, Policy{Action: "drop"}, true},
		// accept 收紧
		{"accept→allow", &Policy{Action: "accept"}, Policy{Action: "allow"}, true},
		// 纯放宽
		{"accept→accept", &Policy{Action: "accept"}, Policy{Action: "accept"}, false},
		{"allow→accept", &Policy{Action: "allow"}, Policy{Action: "accept"}, false},
		{"allow→allow", &Policy{Action: "allow"}, Policy{Action: "allow"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := needsKick(c.old, c.next); got != c.want {
				t.Fatalf("needsKick = %v，期望 %v", got, c.want)
			}
		})
	}
}

// TestSaveKicksOnTighten 保存为更严格的策略时踢会话。
func TestSaveKicksOnTighten(t *testing.T) {
	store := newFakeStore(Policy{Name: "p1", Action: "accept", Enabled: true})
	killer := &fakeKiller{result: 5}
	svc := New(store, killer, &fakeInstaller{}, &fakeAudit{})

	killed, err := svc.Save(context.Background(), Policy{
		ID: 1, Name: "p1", Action: "drop", Enabled: true,
	}, "admin", "")
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if killer.callCount() != 1 || killed != 5 {
		t.Fatalf("accept→drop 应收紧并踢会话，实际调用 %d 次、踢 %d 条",
			killer.callCount(), killed)
	}
}

// TestSaveNoKickOnRelax 保存为纯放宽不踢会话。
func TestSaveNoKickOnRelax(t *testing.T) {
	store := newFakeStore(Policy{Name: "p1", Action: "accept", Enabled: true})
	killer := &fakeKiller{result: 5}
	svc := New(store, killer, &fakeInstaller{}, &fakeAudit{})

	_, err := svc.Save(context.Background(), Policy{
		ID: 1, Name: "p1", Action: "accept", Enabled: true,
	}, "admin", "")
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if killer.callCount() != 0 {
		t.Fatal("纯放宽不应踢会话")
	}
}
