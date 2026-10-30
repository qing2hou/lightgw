package nftables

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/nftables/expr"
)

// newTestEngine 建一个跑在内存 netlink 实现上的引擎。
//
// 用内存实现而不是真实连接的原因：S1 的 DoD 要求「连续切换 200 次」
// 与「并发 10 goroutine 切换」，在业务机上跑这些既慢又危险；而
// memConn 精确模拟了 netlink 的 batch 语义（提交失败整批回滚），
// 所以失败回滚逻辑得到了真实覆盖，不是自欺。
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(newMemConn())
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// newTestEngineWithConn 返回引擎与其底层内存连接（供注入 Flush 失败）。
func newTestEngineWithConn(t *testing.T) (*Engine, *memConn) {
	t.Helper()
	mc := newMemConn()
	e, err := NewEngine(mc)
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e, mc
}

// counterRule 返回一条最简单的规则（counter），用于填充工作链。
func counterRule() []expr.Any {
	return []expr.Any{&expr.Counter{}}
}

// setWith 构造「每个工作链 N 条 counter」的 WorkSet。
func setWith(n int) WorkSet {
	out := make(WorkSet, len(workChains))
	for _, work := range workChains {
		rules := make([][]expr.Any, n)
		for i := range rules {
			rules[i] = counterRule()
		}
		out[work] = rules
	}
	return out
}

// TestEngineStructure 初始化后必须存在 4 个锚点 + 8 个工作链 + 2 个固定链。
func TestEngineStructure(t *testing.T) {
	e := newTestEngine(t)
	chains, err := e.conn.ListChains()
	if err != nil {
		t.Fatalf("列出链失败: %v", err)
	}
	have := map[string]bool{}
	for _, c := range chains {
		if c.Table != nil && c.Table.Name == TableName {
			have[c.Name] = true
		}
	}
	want := []string{DispatchPre, DispatchDnat, DispatchFwd, DispatchSnat,
		ChainMSS, ChainInput}
	for _, work := range workChains {
		want = append(want, ChainName(work, SlotA), ChainName(work, SlotB))
	}
	for _, name := range want {
		if !have[name] {
			t.Fatalf("缺少链 %s（现有: %v）", name, have)
		}
	}
}

// TestNewEngineNilConn nil 连接必须报错而不是 panic。
func TestNewEngineNilConn(t *testing.T) {
	if _, err := NewEngine(nil); err == nil {
		t.Fatal("nil 连接应报错")
	}
}

// TestSlotOther 槽交替必须正确。
func TestSlotOther(t *testing.T) {
	if SlotA.Other() != SlotB || SlotB.Other() != SlotA {
		t.Fatal("槽交替错误")
	}
	if !SlotA.Valid() || !SlotB.Valid() || Slot("c").Valid() {
		t.Fatal("槽合法性判定错误")
	}
	if ChainName(WorkFwd, SlotA) != "fwd_a" {
		t.Fatalf("链名构造错误: %s", ChainName(WorkFwd, SlotA))
	}
}

// TestCommitShadowFirstTime 首次切换：从空 a 切到装满规则的 b。
func TestCommitShadowFirstTime(t *testing.T) {
	e := newTestEngine(t)
	if got := e.Active(); got != SlotA {
		t.Fatalf("初始 active 应为 a，实际 %s", got)
	}
	if got := e.Shadow(); got != SlotB {
		t.Fatalf("初始 shadow 应为 b，实际 %s", got)
	}

	res, err := e.CommitShadow(context.Background(), setWith(3))
	if err != nil {
		t.Fatalf("切换失败: %v", err)
	}
	if res.From != SlotA || res.To != SlotB {
		t.Fatalf("切换方向错误: %s -> %s", res.From, res.To)
	}
	if !res.Cleaned {
		t.Fatalf("旧链应被清理，实际清理错误: %v", res.CleanupErr)
	}
	if e.Active() != SlotB || e.Shadow() != SlotA {
		t.Fatalf("槽未互换: active=%s shadow=%s", e.Active(), e.Shadow())
	}
	// 每个工作链应有 3 条
	for _, work := range workChains {
		n, err := e.ChainRuleCount(ChainName(work, SlotB))
		if err != nil {
			t.Fatalf("读 %s 规则数失败: %v", work, err)
		}
		if n != 3 {
			t.Fatalf("%s_b 应有 3 条规则，实际 %d", work, n)
		}
	}
}

// TestCommitShadowTwiceSwapsBack 第二次切换必须切回 a，且旧内容被清空。
func TestCommitShadowTwiceSwapsBack(t *testing.T) {
	e := newTestEngine(t)
	if _, err := e.CommitShadow(context.Background(), setWith(2)); err != nil {
		t.Fatalf("第一次切换失败: %v", err)
	}
	res, err := e.CommitShadow(context.Background(), setWith(5))
	if err != nil {
		t.Fatalf("第二次切换失败: %v", err)
	}
	if res.From != SlotB || res.To != SlotA {
		t.Fatalf("第二次应 b -> a，实际 %s -> %s", res.From, res.To)
	}
	for _, work := range workChains {
		n, _ := e.ChainRuleCount(ChainName(work, SlotA))
		if n != 5 {
			t.Fatalf("%s_a 应有 5 条，实际 %d", work, n)
		}
		// 旧链（b）应被清空
		nb, _ := e.ChainRuleCount(ChainName(work, SlotB))
		if nb != 0 {
			t.Fatalf("%s_b 切换后应被清空，实际 %d 条", work, nb)
		}
	}
}

// TestCommitShadow200Times 连续 200 次切换后：
//   - 四个锚点各自恒为 1 条 jump
//   - a/b 槽不泄漏（每个工作链只有 1 个槽有规则）
//
// S1 DoD 明确要求这条。
func TestCommitShadow200Times(t *testing.T) {
	e := newTestEngine(t)
	for i := 0; i < 200; i++ {
		if _, err := e.CommitShadow(context.Background(), setWith(2)); err != nil {
			t.Fatalf("第 %d 次切换失败: %v", i+1, err)
		}
		counts, err := e.AllJumpCounts()
		if err != nil {
			t.Fatalf("第 %d 次读 jump 数失败: %v", i+1, err)
		}
		for disp, n := range counts {
			if n != 1 {
				t.Fatalf("第 %d 次切换后 %s 有 %d 条 jump（应恒为 1）", i+1, disp, n)
			}
		}
	}
	// 切换 200 次（偶数）后应回到 a
	if e.Active() != SlotA {
		t.Fatalf("200 次（偶数）后应回到 a，实际 %s", e.Active())
	}
	// 两个槽不能同时有规则
	for _, work := range workChains {
		na, _ := e.ChainRuleCount(ChainName(work, SlotA))
		nb, _ := e.ChainRuleCount(ChainName(work, SlotB))
		if na > 0 && nb > 0 {
			t.Fatalf("%s 两个槽同时有规则（a=%d, b=%d）——槽泄漏", work, na, nb)
		}
	}
}

// TestCommitShadowInstallFailureKeepsOld 装配失败时旧配置必须仍在服务。
//
// 这是 S1 DoD 第 3 条，也是 P0 Task C 没覆盖的那条（那次工作链只有 counter，
// 装什么都不会影响转发，无法覆盖异常路径）。
func TestCommitShadowInstallFailureKeepsOld(t *testing.T) {
	e := newTestEngine(t)

	// 先建立一份正常生效的配置（a 槽，3 条）
	if _, err := e.CommitShadow(context.Background(), setWith(3)); err != nil {
		t.Fatalf("首次切换失败: %v", err)
	}
	activeBefore := e.Active()
	countBefore := map[string]int{}
	for _, work := range workChains {
		countBefore[work], _ = e.ChainRuleCount(ChainName(work, activeBefore))
	}
	jumpsBefore, _ := e.AllJumpCounts()

	// 注入装配失败
	e.SetFailHooks(func(work string) error {
		if work == WorkFwd {
			return errors.New("模拟：装载 fwd 失败")
		}
		return nil
	}, nil)

	_, err := e.CommitShadow(context.Background(), setWith(9))
	if err == nil {
		t.Fatal("装配失败必须返回错误")
	}
	if !strings.Contains(err.Error(), "旧规则继续生效") {
		t.Fatalf("错误消息应明确说明旧规则仍生效，实际: %v", err)
	}

	// ★ 核心断言：旧配置完好
	if e.Active() != activeBefore {
		t.Fatalf("失败的切换不应改变 active 槽: %s -> %s", activeBefore, e.Active())
	}
	for _, work := range workChains {
		n, _ := e.ChainRuleCount(ChainName(work, activeBefore))
		if n != countBefore[work] {
			t.Fatalf("%s 的旧规则被破坏: %d -> %d", work, countBefore[work], n)
		}
	}
	jumpsAfter, _ := e.AllJumpCounts()
	for disp, n := range jumpsBefore {
		if jumpsAfter[disp] != n {
			t.Fatalf("%s 的 jump 被改动: %d -> %d", disp, n, jumpsAfter[disp])
		}
	}
}

// TestCommitShadowVerifyFailureKeepsOld 自检失败同样必须保留旧配置。
func TestCommitShadowVerifyFailureKeepsOld(t *testing.T) {
	e := newTestEngine(t)
	if _, err := e.CommitShadow(context.Background(), setWith(2)); err != nil {
		t.Fatalf("首次切换失败: %v", err)
	}
	activeBefore := e.Active()

	e.SetFailHooks(nil, func(work string) error {
		return errors.New("模拟：自检发现规则数不符")
	})
	_, err := e.CommitShadow(context.Background(), setWith(7))
	if err == nil {
		t.Fatal("自检失败必须返回错误")
	}
	if !strings.Contains(err.Error(), "自检失败") {
		t.Fatalf("错误消息应提到自检失败，实际: %v", err)
	}
	if e.Active() != activeBefore {
		t.Fatalf("自检失败不应改变 active 槽")
	}
	// 旧规则仍在
	for _, work := range workChains {
		n, _ := e.ChainRuleCount(ChainName(work, activeBefore))
		if n != 2 {
			t.Fatalf("%s 旧规则应保持 2 条，实际 %d", work, n)
		}
	}
	// 影子链必须被清干净（否则下次切换会把半装内容切上去）
	shadowName := ChainName(WorkFwd, e.Shadow())
	if n, _ := e.ChainRuleCount(shadowName); n != 0 {
		t.Fatalf("自检失败后影子链 %s 应被清空，实际 %d 条", shadowName, n)
	}
}

// TestCommitShadowCanceledContext context 取消必须中断且不破坏旧配置。
func TestCommitShadowCanceledContext(t *testing.T) {
	e := newTestEngine(t)
	if _, err := e.CommitShadow(context.Background(), setWith(2)); err != nil {
		t.Fatalf("首次切换失败: %v", err)
	}
	activeBefore := e.Active()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消
	if _, err := e.CommitShadow(ctx, setWith(5)); err == nil {
		t.Fatal("已取消的 context 必须返回错误")
	}
	if e.Active() != activeBefore {
		t.Fatal("取消不应改变 active 槽")
	}
}

// TestCommitShadowConcurrent 10 个 goroutine 并发切换必须被串行化。
//
// 判据：不 panic、不出错、每次切换后 jump 数恒为 1。
func TestCommitShadowConcurrent(t *testing.T) {
	e := newTestEngine(t)
	const workers = 10
	const rounds = 20

	errs := make(chan error, workers*rounds)
	done := make(chan struct{}, workers)
	for w := 0; w < workers; w++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for r := 0; r < rounds; r++ {
				if _, err := e.CommitShadow(context.Background(), setWith(1+id%3)); err != nil {
					errs <- fmt.Errorf("worker %d round %d: %w", id, r, err)
					return
				}
			}
		}(w)
	}
	for i := 0; i < workers; i++ {
		<-done
	}
	close(errs)
	for err := range errs {
		t.Fatalf("并发切换失败: %v", err)
	}

	// 最终状态必须自洽
	counts, err := e.AllJumpCounts()
	if err != nil {
		t.Fatalf("读 jump 数失败: %v", err)
	}
	for disp, n := range counts {
		if n != 1 {
			t.Fatalf("并发切换后 %s 有 %d 条 jump（应恒为 1）", disp, n)
		}
	}
}

// TestJumpTarget jump 目标提取必须只认 VerdictJump。
func TestJumpTarget(t *testing.T) {
	jump := []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: "fwd_a"}}
	if got := jumpTarget(jump); got != "fwd_a" {
		t.Fatalf("应提取 fwd_a，实际 %q", got)
	}
	accept := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	if got := jumpTarget(accept); got != "" {
		t.Fatalf("accept 不是 jump，应返回空串，实际 %q", got)
	}
	drop := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	if got := jumpTarget(drop); got != "" {
		t.Fatalf("drop 不是 jump，应返回空串，实际 %q", got)
	}
	none := []expr.Any{&expr.Counter{}}
	if got := jumpTarget(none); got != "" {
		t.Fatalf("无 verdict 应返回空串，实际 %q", got)
	}
}

// TestCtxCheckNilContext nil context 不应 panic（向后兼容）。
func TestCtxCheckNilContext(t *testing.T) {
	if err := ctxCheck(nil); err != nil {
		t.Fatalf("nil context 应返回 nil，实际: %v", err)
	}
}

// TestDispatchOfCoversAllWorkChains 每个工作链都必须有对应的锚点。
//
// 漏一个会导致该 hook 的规则永远不生效（静默）。
func TestDispatchOfCoversAllWorkChains(t *testing.T) {
	for _, work := range workChains {
		if _, ok := dispatchOf[work]; !ok {
			t.Fatalf("工作链 %s 没有对应的 dispatch 锚点", work)
		}
		if _, ok := hookOf[work]; !ok {
			t.Fatalf("工作链 %s 没有对应的 hook 规格", work)
		}
	}
	if len(dispatchOf) != len(workChains) || len(hookOf) != len(workChains) {
		t.Fatalf("映射数量不匹配: %d 个工作链 / %d 个锚点 / %d 个 hook",
			len(workChains), len(dispatchOf), len(hookOf))
	}
}

// TestCloseTwice Close 必须幂等（不能二次关闭 netlink 连接）。
func TestCloseTwice(t *testing.T) {
	e := newTestEngine(t)
	if err := e.Close(); err != nil {
		t.Fatalf("首次 Close 失败: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("二次 Close 应幂等，实际: %v", err)
	}
}

// TestCommitAfterClose 关闭后调用必须返回 ErrNotReady 而不是 panic。
func TestCommitAfterClose(t *testing.T) {
	e := newTestEngine(t)
	_ = e.Close()
	if _, err := e.CommitShadow(context.Background(), setWith(1)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("关闭后应返回 ErrNotReady，实际: %v", err)
	}
}

// TestCommitShadowFlushFailureRollsBack 内核拒绝整批时，暂存内容必须全部丢弃。
//
// 这验证 memConn 的 batch 回滚语义与真实 netlink 一致，进而验证
// 「装配失败不会把半装内容留在影子链里」这条保护。
func TestCommitShadowFlushFailureRollsBack(t *testing.T) {
	e, mc := newTestEngineWithConn(t)

	// 先建立一份正常生效的配置
	if _, err := e.CommitShadow(context.Background(), setWith(2)); err != nil {
		t.Fatalf("首次切换失败: %v", err)
	}
	activeBefore := e.Active()
	shadowBefore := e.Shadow()

	// 让下一次 Flush 失败（模拟内核拒绝 batch）
	mc.setFailNextFlush(errors.New("模拟：内核拒绝整批（ENOMEM）"))

	_, err := e.CommitShadow(context.Background(), setWith(6))
	if err == nil {
		t.Fatal("Flush 失败必须返回错误")
	}
	if !strings.Contains(err.Error(), "旧规则继续生效") {
		t.Fatalf("错误消息应说明旧规则仍生效，实际: %v", err)
	}

	// 旧配置完好
	if e.Active() != activeBefore {
		t.Fatalf("active 槽不应改变: %s -> %s", activeBefore, e.Active())
	}
	for _, work := range workChains {
		n, _ := e.ChainRuleCount(ChainName(work, activeBefore))
		if n != 2 {
			t.Fatalf("%s 旧规则应保持 2 条，实际 %d", work, n)
		}
	}
	// 影子链不能残留半装内容
	for _, work := range workChains {
		name := ChainName(work, shadowBefore)
		n, _ := e.ChainRuleCount(name)
		if n != 0 {
			t.Fatalf("影子链 %s 残留 %d 条（batch 未回滚）", name, n)
		}
	}
	// 恢复后应能正常切换
	if _, err := e.CommitShadow(context.Background(), setWith(6)); err != nil {
		t.Fatalf("恢复后切换应成功，实际: %v", err)
	}
}

// TestActiveShadowNeverSame 任何时刻 active 与 shadow 必须是不同槽。
func TestActiveShadowNeverSame(t *testing.T) {
	e := newTestEngine(t)
	for i := 0; i < 10; i++ {
		if e.Active() == e.Shadow() {
			t.Fatalf("第 %d 轮：active 与 shadow 相同（%s）——下一轮会覆盖正在服务的工作链",
				i, e.Active())
		}
		if _, err := e.CommitShadow(context.Background(), setWith(1)); err != nil {
			t.Fatalf("切换失败: %v", err)
		}
	}
}
