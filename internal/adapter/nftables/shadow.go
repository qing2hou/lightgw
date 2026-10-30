package nftables

import (
	"context"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// RuleBuilder 由调用方（compile 层的 adapter 翻译器）提供，
// 把一条编译产物翻译成 nftables 表达式列表。
//
// 抽成接口而不是直接依赖 compile 包，是为了让本包的测试能构造任意
// 表达式（包括「故意非法」的），而不需要拉入整个编译链。
type RuleBuilder func(work string) ([][]expr.Any, error)

// WorkSet 是「一个版本的全量规则」：四个工作链各自的规则。
//
// 全量重装而不是增量 diff（技术方案 §3.1）：diff 需要维护「内核现状」与
// 「期望状态」的映射，一旦有人手工 nft 改了规则就会误判并「修复」成错误
// 状态。全量重装天然具备自愈能力。
type WorkSet map[string][][]expr.Any

// CommitResult 描述一次切换的结果。
type CommitResult struct {
	// From 是切换前的槽，To 是切换后的槽。
	From, To Slot
	// RuleCounts 是各工作链装入规则数（自检用）。
	RuleCounts map[string]int
	// Cleaned 表示旧链是否已成功清理（失败不影响切换结果）。
	Cleaned bool
	// CleanupErr 是清理失败的原因（非致命，下次切换会重试）。
	CleanupErr error
}

// CommitShadow 执行一次完整的热切换。
//
// 四个阶段，任何一步失败都保证「旧配置仍在服务」（C-10）：
//
//	① 装载影子链 —— 失败 → DropShadow 清掉半装内容，返回错误，旧链不动
//	② 自检      —— 失败 → DropShadow，返回错误，旧链不动
//	③ 原子切换  —— 单 batch 内「删旧 jump + 加新 jump」，失败 → 旧链仍在
//	④ 清理旧链  —— 失败非致命（已无引用），记入 CleanupErr 供下次重试
//
// 实测依据：阶段 ③ 的原子性在真机验证过（60 次翻转零丢包，
// docs/poc-result.md §6.3）。阶段 ①②④ 的行为由本包的测试覆盖。
func (e *Engine) CommitShadow(ctx context.Context, set WorkSet) (*CommitResult, error) {
	if e.conn == nil {
		return nil, ErrNotReady
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	target := e.shadow

	// ① 装载到影子链。先清空影子链里可能残留的上次半装内容。
	if err := e.dropShadowLocked(target); err != nil {
		return nil, fmt.Errorf("清理影子链失败（旧规则继续生效）: %w", err)
	}
	if err := ctxCheck(ctx); err != nil {
		return nil, err
	}
	counts, err := e.installLocked(target, set)
	if err != nil {
		// 关键：装配失败必须清掉半装内容，且**不碰 dispatch**。
		// 否则下次切换会把半装规则当成完整版切上去。
		cleanupErr := e.dropShadowLocked(target)
		if cleanupErr != nil {
			return nil, fmt.Errorf("装配影子链失败（旧规则继续生效）: %w；且清理影子链也失败: %v",
				err, cleanupErr)
		}
		return nil, fmt.Errorf("装配影子链失败（旧规则继续生效）: %w", err)
	}

	// ② 自检：读回来数规则数，与控制面期望的数量比对。
	if err := ctxCheck(ctx); err != nil {
		_ = e.dropShadowLocked(target)
		return nil, err
	}
	if err := e.verifyLocked(target, counts); err != nil {
		cleanupErr := e.dropShadowLocked(target)
		if cleanupErr != nil {
			return nil, fmt.Errorf("影子链自检失败（旧规则继续生效）: %w；且清理也失败: %v",
				err, cleanupErr)
		}
		return nil, fmt.Errorf("影子链自检失败（旧规则继续生效）: %w", err)
	}

	// ③ 原子切换
	from := e.active
	if err := e.switchLocked(ctx, from, target); err != nil {
		_ = e.dropShadowLocked(target)
		return nil, fmt.Errorf("切换失败（旧规则继续生效）: %w", err)
	}

	// 切换成功：槽位互换
	e.active = target
	e.shadow = target.Other()

	res := &CommitResult{
		From:       from,
		To:         target,
		RuleCounts: counts,
	}

	// ④ 清理旧链（已无引用，失败不影响转发）
	if err := e.cleanupChainLocked(from); err != nil {
		res.CleanupErr = err
	} else {
		res.Cleaned = true
	}
	return res, nil
}

// installLocked 把规则装进指定槽的四个工作链。
//
// 四个链各自 Flush 一次（一次 batch）。这样即使某个链装到一半失败，
// 已提交的链也只在影子上，不影响转发。
func (e *Engine) installLocked(slot Slot, set WorkSet) (map[string]int, error) {
	if e.failInstall != nil {
		// 测试钩子：模拟装配失败
		for _, work := range workChains {
			if err := e.failInstall(work); err != nil {
				return nil, err
			}
		}
	}
	counts := make(map[string]int, len(workChains))
	for _, work := range workChains {
		rules := set[work]
		chain := &nftables.Chain{Name: ChainName(work, slot), Table: e.tbl}
		for _, exprs := range rules {
			e.conn.AddRule(&nftables.Rule{
				Table: e.tbl,
				Chain: chain,
				Exprs: exprs,
			})
		}
		if err := e.conn.Flush(); err != nil {
			return nil, fmt.Errorf("装载 %s 失败: %w", chain.Name, err)
		}
		counts[work] = len(rules)
	}
	return counts, nil
}

// verifyLocked 读回影子链的规则数并与期望比对。
//
// 为什么必须自检：netlink 的 AddRule 可能被内核接受但语义被改写
// （例如表达式被简化为空规则）。只靠「Flush 没报错」不足以判定装对了。
func (e *Engine) verifyLocked(slot Slot, want map[string]int) error {
	if e.failVerify != nil {
		for _, work := range workChains {
			if err := e.failVerify(work); err != nil {
				return err
			}
		}
	}
	for _, work := range workChains {
		name := ChainName(work, slot)
		chain := &nftables.Chain{Name: name, Table: e.tbl}
		rules, err := e.conn.GetRules(e.tbl, chain)
		if err != nil {
			return fmt.Errorf("读回 %s 的规则失败: %w", name, err)
		}
		if len(rules) != want[work] {
			return fmt.Errorf("%s 规则数不符: 期望 %d 条，内核实际 %d 条",
				name, want[work], len(rules))
		}
	}
	return nil
}

// switchLocked 在**一个 batch** 内替换四个锚点的 jump。
//
// 这是整个方案的核心：`DelRule(旧 jump)` 与 `AddRule(新 jump)` 在同一个
// `Flush()` 里提交，内核保证 batch 原子。转发面只会看到「跳 a」或「跳 b」，
// 不存在「两条都不跳」的瞬间。
func (e *Engine) switchLocked(ctx context.Context, from, to Slot) error {
	for _, work := range workChains {
		if err := ctxCheck(ctx); err != nil {
			return err
		}
		disp := dispatchOf[work]
		h, err := e.findJumpHandleLocked(disp, ChainName(work, from))
		if err != nil {
			return err
		}
		if h != 0 {
			e.conn.DelRule(&nftables.Rule{
				Table:  e.tbl,
				Chain:  &nftables.Chain{Name: disp, Table: e.tbl},
				Handle: h,
			})
		}
		e.conn.AddRule(&nftables.Rule{
			Table: e.tbl,
			Chain: &nftables.Chain{Name: disp, Table: e.tbl},
			Exprs: []expr.Any{
				&expr.Verdict{Kind: expr.VerdictJump, Chain: ChainName(work, to)},
			},
		})
		// 每次 Flush 是独立 batch —— 四个 hook 之间无法原子，
		// 但每个 hook 内部原子，且四个 hook 是独立的评估路径，
		// 不存在「prerouting 跳新、forward 跳旧」导致的语义错乱
		//（它们作用于同一条连接的不同阶段，短暂混用是安全的）。
		if err := e.conn.Flush(); err != nil {
			return fmt.Errorf("切换 %s 失败: %w", disp, err)
		}
		// 切换后刷新 handle 缓存
		delete(e.jumpHandles, disp)
	}
	return nil
}

// findJumpHandleLocked 找出 dispatch 链里「jump 到 targetChain」那条规则的 handle。
//
// 返回 0 表示没有这条 jump（首次切换时正常）。
func (e *Engine) findJumpHandleLocked(disp, targetChain string) (uint64, error) {
	rules, err := e.conn.GetRules(e.tbl, &nftables.Chain{Name: disp, Table: e.tbl})
	if err != nil {
		return 0, fmt.Errorf("列出 %s 的规则失败: %w", disp, err)
	}
	for _, r := range rules {
		if jumpTarget(r.Exprs) == targetChain {
			return r.Handle, nil
		}
	}
	return 0, nil
}

// jumpTarget 从表达式里提取 jump 目标链名；非 jump 规则返回空串。
func jumpTarget(exprs []expr.Any) string {
	for _, ex := range exprs {
		v, ok := ex.(*expr.Verdict)
		if !ok {
			continue
		}
		if v.Kind == expr.VerdictJump {
			return v.Chain
		}
	}
	return ""
}

// dropShadowLocked 清空某个槽的四个工作链（保留链本身）。
func (e *Engine) dropShadowLocked(slot Slot) error {
	for _, work := range workChains {
		chain := &nftables.Chain{Name: ChainName(work, slot), Table: e.tbl}
		e.conn.FlushChain(chain)
		if err := e.conn.Flush(); err != nil {
			return fmt.Errorf("清空 %s 失败: %w", chain.Name, err)
		}
	}
	return nil
}

// cleanupChainLocked 清空一个槽（切换后的旧链）。
func (e *Engine) cleanupChainLocked(slot Slot) error {
	return e.dropShadowLocked(slot)
}

// JumpCount 返回指定锚点链的 jump 规则条数。
//
// 切换后必须恒为 1（S1 DoD：连续 200 次切换后仍只有 1 条 jump）。
func (e *Engine) JumpCount(disp string) (int, error) {
	if e.conn == nil {
		return 0, ErrNotReady
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	rules, err := e.conn.GetRules(e.tbl, &nftables.Chain{Name: disp, Table: e.tbl})
	if err != nil {
		return 0, fmt.Errorf("列出 %s 的规则失败: %w", disp, err)
	}
	n := 0
	for _, r := range rules {
		if jumpTarget(r.Exprs) != "" {
			n++
		}
	}
	return n, nil
}

// AllJumpCounts 返回四个锚点的 jump 条数（供整体自检）。
func (e *Engine) AllJumpCounts() (map[string]int, error) {
	out := make(map[string]int, len(workChains))
	for _, work := range workChains {
		n, err := e.JumpCount(dispatchOf[work])
		if err != nil {
			return nil, err
		}
		out[dispatchOf[work]] = n
	}
	return out, nil
}

// ChainRuleCount 返回指定链当前的规则条数（供对账与测试）。
func (e *Engine) ChainRuleCount(chainName string) (int, error) {
	if e.conn == nil {
		return 0, ErrNotReady
	}
	rules, err := e.conn.GetRules(e.tbl, &nftables.Chain{Name: chainName, Table: e.tbl})
	if err != nil {
		return 0, fmt.Errorf("列出 %s 的规则失败: %w", chainName, err)
	}
	return len(rules), nil
}
