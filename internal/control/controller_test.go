package control

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeNft 记录调用顺序并按注入的开关模拟失败。
type fakeNft struct {
	mu        sync.Mutex
	calls     []string
	loadErr   error
	verifyErr error
	commitErr error
	dropCalls int
	gcCalls   int
}

func (f *fakeNft) record(name string) {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	f.mu.Unlock()
}

func (f *fakeNft) order() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeNft) LoadShadow(ctx context.Context, p *NftPlanView) error {
	f.record("load")
	return f.loadErr
}
func (f *fakeNft) VerifyShadow(ctx context.Context, p *NftPlanView) error {
	f.record("verify")
	return f.verifyErr
}
func (f *fakeNft) CommitShadow(ctx context.Context) error {
	f.record("commit")
	return f.commitErr
}
func (f *fakeNft) DropShadow(ctx context.Context) error {
	f.record("drop")
	f.mu.Lock()
	f.dropCalls++
	f.mu.Unlock()
	return nil
}
func (f *fakeNft) GC(ctx context.Context) error {
	f.record("gc")
	f.mu.Lock()
	f.gcCalls++
	f.mu.Unlock()
	return nil
}

type fakeTc struct {
	calls int
	err   error
	lastP *TcPlanView
}

func (f *fakeTc) ApplyTc(ctx context.Context, p *TcPlanView) error {
	f.calls++
	f.lastP = p
	return f.err
}

func view(v uint64) *NftPlanView { return &NftPlanView{Version: v, RuleCount: 1} }
func tcview(v uint64) *TcPlanView {
	return &TcPlanView{Version: v, Qdiscs: 1, Classes: 2, Filters: 1}
}

// TestApplyHappyPath 成功路径：load → verify → commit → gc → tc。
func TestApplyHappyPath(t *testing.T) {
	nft := &fakeNft{}
	tc := &fakeTc{}
	c := New(nft, tc)
	if err := c.Apply(context.Background(), view(1), tcview(1)); err != nil {
		t.Fatalf("应成功: %v", err)
	}
	want := []string{"load", "verify", "commit", "gc"}
	got := nft.order()
	if len(got) != len(want) {
		t.Fatalf("调用序列应为 %v，实际 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("★ 调用顺序错误：第 %d 步应为 %q，实际 %q（顺序决定「先装后切」）",
				i+1, want[i], got[i])
		}
	}
	if tc.calls != 1 {
		t.Fatalf("tc 应被调用 1 次，实际 %d", tc.calls)
	}
	if c.AppliedVersion() != 1 {
		t.Fatalf("AppliedVersion 应为 1，实际 %d", c.AppliedVersion())
	}
	if c.LastError() != "" {
		t.Fatalf("成功时 LastError 应为空，实际 %q", c.LastError())
	}
}

// TestLoadShadowFailureKeepsOld 装载失败：必须 DropShadow 且不 commit。
func TestLoadShadowFailureKeepsOld(t *testing.T) {
	nft := &fakeNft{loadErr: errors.New("netlink 拒绝")}
	tc := &fakeTc{}
	c := New(nft, tc)
	err := c.Apply(context.Background(), view(2), tcview(2))
	if err == nil {
		t.Fatal("应返回错误")
	}
	if !strings.Contains(err.Error(), "旧规则继续生效") {
		t.Fatalf("错误消息必须说明旧规则仍在服务，实际: %v", err)
	}
	got := nft.order()
	// 不应有 commit
	for _, x := range got {
		if x == "commit" {
			t.Fatalf("★ 装载失败绝不能 commit（会切到不完整的影子链）: %v", got)
		}
	}
	// 必须清理半装内容
	if nft.dropCalls != 1 {
		t.Fatalf("★ 装载失败必须 DropShadow 清理半装内容，实际 %d 次", nft.dropCalls)
	}
	// tc 不应被调用（nft 都没成）
	if tc.calls != 0 {
		t.Fatal("nft 失败时不应应用 tc")
	}
	if c.AppliedVersion() != 0 {
		t.Fatal("失败时不应更新 AppliedVersion")
	}
	if c.LastError() == "" {
		t.Fatal("★ 失败必须记录 LastError（静默失败最难查）")
	}
}

// TestVerifyShadowFailureKeepsOld 自检失败：同样 DropShadow 且不 commit。
func TestVerifyShadowFailureKeepsOld(t *testing.T) {
	nft := &fakeNft{verifyErr: errors.New("规则数不符")}
	c := New(nft, &fakeTc{})
	err := c.Apply(context.Background(), view(3), tcview(3))
	if err == nil || !strings.Contains(err.Error(), "自检失败") {
		t.Fatalf("应返回自检失败: %v", err)
	}
	for _, x := range nft.order() {
		if x == "commit" {
			t.Fatalf("★ 自检失败绝不能 commit: %v", nft.order())
		}
	}
	if nft.dropCalls != 1 {
		t.Fatalf("自检失败必须 DropShadow，实际 %d 次", nft.dropCalls)
	}
}

// TestCommitShadowFailureKeepsOld 切换失败：DropShadow 且不 GC。
func TestCommitShadowFailureKeepsOld(t *testing.T) {
	nft := &fakeNft{commitErr: errors.New("batch 被拒")}
	c := New(nft, &fakeTc{})
	err := c.Apply(context.Background(), view(4), tcview(4))
	if err == nil || !strings.Contains(err.Error(), "切换失败") {
		t.Fatalf("应返回切换失败: %v", err)
	}
	if nft.gcCalls != 0 {
		t.Fatal("★ 切换失败不应 GC（旧链还在服务）")
	}
	if nft.dropCalls != 1 {
		t.Fatal("切换失败应 DropShadow")
	}
}

// TestTcFailureDoesNotRollbackNft tc 失败不回滚 nft（技术方案 §2.2）。
//
// 理由：规则已生效，回滚期间转发面为空，风险大于「限速暂时不生效」。
func TestTcFailureDoesNotRollbackNft(t *testing.T) {
	nft := &fakeNft{}
	tc := &fakeTc{err: errors.New("tc netlink 失败")}
	c := New(nft, tc)
	err := c.Apply(context.Background(), view(5), tcview(5))
	if err == nil {
		t.Fatal("应返回错误")
	}
	var pe *PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("★ 应返回 PartialError（表明 nft 已生效、tc 失败），实际 %T: %v", err, err)
	}
	if pe.Stage != "tc" {
		t.Fatalf("Stage 应为 tc，实际 %q", pe.Stage)
	}
	// nft 必须已完整应用（含 commit 与 gc）
	got := nft.order()
	var sawCommit bool
	for _, x := range got {
		if x == "commit" {
			sawCommit = true
		}
	}
	if !sawCommit {
		t.Fatalf("★ tc 失败不应阻止 nft 的 commit: %v", got)
	}
	if c.AppliedVersion() != 0 {
		t.Fatal("tc 失败时 AppliedVersion 不应更新（整体未成功）")
	}
	if c.LastError() == "" {
		t.Fatal("tc 失败必须记录 LastError")
	}
}

// TestEmptyTcPlanSkipsApply 空 tc 计划不调用 tc。
func TestEmptyTcPlanSkipsApply(t *testing.T) {
	tc := &fakeTc{}
	c := New(&fakeNft{}, tc)
	emptyTc := &TcPlanView{Version: 6, Empty: true}
	if err := c.Apply(context.Background(), view(6), emptyTc); err != nil {
		t.Fatalf("应成功: %v", err)
	}
	if tc.calls != 0 {
		t.Fatalf("★ 空 tc 计划不应调用 ApplyTc，实际 %d 次", tc.calls)
	}
}

// TestNilAppliersNilPlans 空计划报错；nil applier 不 panic。
func TestNilAppliers(t *testing.T) {
	c := New(nil, nil)
	// 两个计划都空 → 报错
	if err := c.Apply(context.Background(), nil, nil); err == nil {
		t.Fatal("空计划应报错")
	}
	// 只有 nft、applier 为 nil → 不 panic，视为成功（防御性）
	if err := c.Apply(context.Background(), view(7), nil); err != nil {
		t.Fatalf("nil nft applier 应安全跳过: %v", err)
	}
}

// TestSerializedApply 并发 Apply 必须串行（不交错）。
//
// 判据：任一次 Apply 的调用序列都必须是完整的 load→verify→commit，
// 不能出现 load(A) load(B) commit(A) 这种交错。
func TestSerializedApply(t *testing.T) {
	nft := &fakeNft{}
	c := New(nft, &fakeTc{})
	var wg sync.WaitGroup
	const n = 8
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			_ = c.Apply(context.Background(), view(uint64(v)), nil)
		}(i)
	}
	wg.Wait()
	// 每次成功 Apply 产生 4 次调用，共 4n 次
	got := nft.order()
	if len(got) != 4*n {
		t.Fatalf("应有 %d 次调用，实际 %d: %v", 4*n, len(got), got)
	}
	// 严格检查分组：每 4 个必须是 load,verify,commit,gc
	for i := 0; i < len(got); i += 4 {
		group := got[i : i+4]
		want := []string{"load", "verify", "commit", "gc"}
		for j := range want {
			if group[j] != want[j] {
				t.Fatalf("★ 并发 Apply 出现交错：第 %d 组为 %v（应为 %v）", i/4, group, want)
			}
		}
	}
}

// TestLastErrorClearedOnSuccess 成功一次后 LastError 必须清空。
func TestLastErrorClearedOnSuccess(t *testing.T) {
	nft := &fakeNft{loadErr: errors.New("首次失败")}
	c := New(nft, &fakeTc{})
	_ = c.Apply(context.Background(), view(8), nil)
	if c.LastError() == "" {
		t.Fatal("首次失败应记录错误")
	}
	nft.mu.Lock()
	nft.loadErr = nil
	nft.mu.Unlock()
	if err := c.Apply(context.Background(), view(9), nil); err != nil {
		t.Fatalf("第二次应成功: %v", err)
	}
	if c.LastError() != "" {
		t.Fatalf("★ 成功后必须清空 LastError（否则 UI 一直显示故障），实际 %q", c.LastError())
	}
	if c.AppliedVersion() != 9 {
		t.Fatalf("AppliedVersion 应为 9，实际 %d", c.AppliedVersion())
	}
}

// TestPartialErrorUnwrap PartialError 必须能 Unwrap 到原始错误。
func TestPartialErrorUnwrap(t *testing.T) {
	inner := errors.New("底层失败")
	pe := &PartialError{Stage: "tc", Err: inner}
	if !errors.Is(pe, inner) {
		t.Fatal("PartialError 应能 Unwrap 到原始错误")
	}
	if !strings.Contains(pe.Error(), "未回滚") {
		t.Fatalf("消息应说明未回滚，实际: %s", pe.Error())
	}
}
