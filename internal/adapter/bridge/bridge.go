// Package adapterbridge 把真实 adapter 接到 control 的端口上。
//
// 本包只做「接口形状转换 + 分阶段编排」，不含业务逻辑：
//
//	control.Applier   ←  nftables.Engine（经 StagedApplier 分阶段）
//	control.TcApplier ←  tcnetlink.Engine
//
// 为什么单独一个包而不让 control 直接 import adapter：
// control 的测试必须能在无 CAP_NET_ADMIN 的环境跑。一旦 control import 了
// nftables/tcnetlink，它就只能「有内核才能测」。本包是唯一同时认识
// 「控制平面端口」与「内核 adapter」的地方，也是唯一需要真机才测得了的地方。
package adapterbridge

import (
	"context"
	"fmt"

	"haproxyweb/internal/adapter/nftables"
	"haproxyweb/internal/adapter/tcnetlink"
	"haproxyweb/internal/compile"
	"haproxyweb/internal/control"
)

// NftBridge 把 nftables.Engine 适配成 control.Applier。
//
// 关键设计：**用 StagedApplier 真实执行四阶段**，而不是调一体化的
// CommitShadow 再假装分阶段。前者让 control 能在每阶段之间做判断与告警，
// 后者会让 control 的失败回滚语义形同虚设。
type NftBridge struct {
	engine *nftables.Engine
	// plan 是本次要应用的完整计划。
	//
	// 为什么不从 control 的 NftPlanView 取：那个视图不含规则细节
	// （它是给「不需要翻译的测试实现」用的）。真实翻译必须要 compile.Plan。
	// 调用方（装配层）负责把同一个 plan 同时交给 control 与 bridge。
	plan *compile.Plan
	// session 是当前分阶段会话（LoadShadow 时创建，Commit/Abort 时结束）。
	session *nftables.StagedApplier
}

// NewNftBridge 创建桥接。
func NewNftBridge(engine *nftables.Engine) *NftBridge {
	return &NftBridge{engine: engine}
}

// SetPlan 设置本次要应用的完整计划（在 control.Apply 之前调用）。
func (b *NftBridge) SetPlan(p *compile.Plan) { b.plan = p }

// LoadShadow 翻译计划并装载影子链。
func (b *NftBridge) LoadShadow(ctx context.Context, view *control.NftPlanView) error {
	if b.engine == nil {
		return fmt.Errorf("装载影子链失败: nftables 引擎未初始化")
	}
	if b.plan == nil {
		return fmt.Errorf("装载影子链失败: 未设置编译计划（装配层需先调 SetPlan）")
	}
	set, fixed, err := nftables.TranslatePlan(b.plan)
	if err != nil {
		return fmt.Errorf("翻译编译计划失败: %w", err)
	}
	// 固定链（MSS）不参与版本化：每次重装即可，失败不影响业务规则
	if err := b.engine.ApplyFixed(fixed); err != nil {
		return fmt.Errorf("装载固定链失败: %w", err)
	}
	sess, err := b.engine.BeginStage()
	if err != nil {
		return err
	}
	if err := sess.StageLoad(ctx, set); err != nil {
		// 装载失败：清理半装内容，不碰 dispatch
		_ = sess.StageAbort(ctx)
		return err
	}
	b.session = sess
	return nil
}

// VerifyShadow 读回影子链并比对规则数。
func (b *NftBridge) VerifyShadow(ctx context.Context, view *control.NftPlanView) error {
	if b.session == nil {
		return fmt.Errorf("自检失败: 没有活跃的分阶段会话")
	}
	return b.session.StageVerify(ctx)
}

// CommitShadow 原子切换（单 batch）。
func (b *NftBridge) CommitShadow(ctx context.Context) error {
	if b.session == nil {
		return fmt.Errorf("切换失败: 没有活跃的分阶段会话")
	}
	return b.session.StageCommit(ctx)
}

// DropShadow 丢弃影子链（任何失败路径调用）。
func (b *NftBridge) DropShadow(ctx context.Context) error {
	if b.session == nil {
		return nil
	}
	err := b.session.StageAbort(ctx)
	b.session = nil
	return err
}

// GC 清理旧链（切换成功后调用，失败非致命）。
func (b *NftBridge) GC(ctx context.Context) error {
	if b.session == nil {
		return nil
	}
	err := b.session.StageCleanup(ctx)
	b.session = nil
	return err
}

// TcBridge 把 tcnetlink.Engine 适配成 control.TcApplier。
type TcBridge struct {
	engine *tcnetlink.Engine
	plan   *compile.Plan
}

// NewTcBridge 创建桥接。
func NewTcBridge(engine *tcnetlink.Engine) *TcBridge {
	return &TcBridge{engine: engine}
}

// SetPlan 设置本次要应用的完整计划。
func (b *TcBridge) SetPlan(p *compile.Plan) { b.plan = p }

// ApplyTc 把 tc 段落到内核。
//
// tc 无事务，Engine.Apply 内部已做校验与补偿；失败由 control 包装成
// PartialError（nft 不回滚）。
func (b *TcBridge) ApplyTc(ctx context.Context, view *control.TcPlanView) error {
	if b.engine == nil {
		return fmt.Errorf("应用限速失败: tc 引擎未初始化")
	}
	if b.plan == nil {
		return fmt.Errorf("应用限速失败: 未设置编译计划（装配层需先调 SetPlan）")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("应用限速被取消: %w", err)
	}
	return b.engine.Apply(b.plan.Tc)
}
