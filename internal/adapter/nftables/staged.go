// 分阶段应用接口：把 CommitShadow 内部的一体化流程拆开导出。
//
// 为什么要拆（技术方案 §2.2 / C-10）：
//
// `CommitShadow` 把「装载 → 自检 → 切换 → 清理」做成一体，调用方只能在
// 全部成功或全部失败之间二选一。但控制平面需要在**每个阶段之间**做判断
// （比如自检失败时要不要重试、切换超时时怎么告警），一个不透明的
// CommitShadow 做不到。
//
// 本节导出的四个方法让调用方可以按阶段推进，并在任意阶段失败时
// 明确知道「旧版仍在服务」。`CommitShadow` 保留不变（它内部就是调这四个），
// 两种用法共存：
//
//	简单场景      → CommitShadow（一次调用，内部已按顺序执行四阶段）
//	需要细粒度控制 → StageLoad / StageVerify / StageCommit / StageCleanup
package nftables

import (
	"context"
	"fmt"
)

// StagedApplier 是分阶段应用的会话状态。
//
// 不变量：
//   - 同一时刻只允许一个 StagedApplier 处于活跃状态（由 Engine.mu 保证）
//   - StageCommit 之前任何一步失败，调用方必须调 StageAbort 清理
//   - StageCommit 成功后，target 槽成为新的 active
type StagedApplier struct {
	engine *Engine
	target Slot
	from   Slot
	// counts 是装载时记录的规则数（自检用）
	counts map[string]int
	// loaded 表示装载已完成（未装载时不允许 verify/commit）
	loaded bool
	// committed 表示已切换（防止重复切换）
	committed bool
}

// BeginStage 开始一次分阶段应用，返回会话。
//
// 调用方必须在结束时（无论成败）调用 StageAbort 或 StageCleanup 之一。
func (e *Engine) BeginStage() (*StagedApplier, error) {
	if e.conn == nil {
		return nil, ErrNotReady
	}
	e.mu.Lock()
	target := e.shadow
	from := e.active
	// 先清空目标槽里可能残留的上次半装内容
	err := e.dropShadowLocked(target)
	e.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("清理影子链失败（旧规则继续生效）: %w", err)
	}
	return &StagedApplier{engine: e, target: target, from: from}, nil
}

// StageLoad 把规则装进影子链。
func (s *StagedApplier) StageLoad(ctx context.Context, set WorkSet) error {
	if s.committed {
		return fmt.Errorf("装载失败: 本次会话已提交，不能重复装载")
	}
	e := s.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	counts, err := e.installLocked(s.target, set)
	if err != nil {
		return fmt.Errorf("装配影子链失败（旧规则继续生效）: %w", err)
	}
	s.counts = counts
	s.loaded = true
	return nil
}

// StageVerify 读回影子链并比对规则数。
func (s *StagedApplier) StageVerify(ctx context.Context) error {
	if !s.loaded {
		return fmt.Errorf("自检失败: 影子链尚未装载")
	}
	e := s.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.verifyLocked(s.target, s.counts); err != nil {
		return fmt.Errorf("影子链自检失败（旧规则继续生效）: %w", err)
	}
	return nil
}

// StageCommit 原子切换（单 batch：删旧 jump + 加新 jump）。
func (s *StagedApplier) StageCommit(ctx context.Context) error {
	if !s.loaded {
		return fmt.Errorf("切换失败: 影子链尚未装载")
	}
	if s.committed {
		return fmt.Errorf("切换失败: 已提交过")
	}
	e := s.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.switchLocked(ctx, s.from, s.target); err != nil {
		return fmt.Errorf("切换失败（旧规则继续生效）: %w", err)
	}
	// 槽位互换
	e.active = s.target
	e.shadow = s.target.Other()
	s.committed = true
	return nil
}

// StageCleanup 清理旧链（切换成功后调用）。失败非致命。
func (s *StagedApplier) StageCleanup(ctx context.Context) error {
	if !s.committed {
		return fmt.Errorf("清理失败: 尚未提交")
	}
	e := s.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cleanupChainLocked(s.from)
}

// StageAbort 丢弃影子链（任何失败路径都必须调用）。
//
// 幂等：已提交时是 no-op（不能把正在服务的槽清掉）。
func (s *StagedApplier) StageAbort(ctx context.Context) error {
	if s.committed {
		return nil
	}
	e := s.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	s.loaded = false
	s.counts = nil
	return e.dropShadowLocked(s.target)
}

// Target 返回本次会话的影子槽（供日志）。
func (s *StagedApplier) Target() Slot { return s.target }

// From 返回切换前的活动槽（供日志）。
func (s *StagedApplier) From() Slot { return s.from }

// Committed 报告本次会话是否已提交。
func (s *StagedApplier) Committed() bool { return s.committed }
