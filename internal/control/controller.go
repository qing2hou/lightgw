// Package control 是控制平面：把 compile 产物装配到内核面。
//
// 分层（技术方案 §2）：
//
//	domain/compile   纯函数，State → Plan
//	本包             Plan → 内核（通过注入的 Applier 端口）
//	adapter/*        真正的 netlink/exec 实现
//
// 本包**不 import 任何 adapter**：它只认 Applier 接口。这样：
//   - 装配顺序、失败回滚、影子链语义可以在 CI 里完整单测（不需要 CAP_NET_ADMIN）
//   - adapter 换实现（nftables 换后端、tc 换 CLI）时控制平面一行不改
//
// 提交语义（技术方案 §2.2）：先装后切，任何一步失败前面都不生效（C-10）。
package control

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

// Applier 是内核面应用端口。
//
// 拆成三段而不是一个 Apply，是为了让控制平面能按「先装后切」的顺序编排，
// 并在每个阶段之间做自检——一个不透明的 Apply(Plan) 无法在中途失败时
// 保证「旧配置仍在服务」。
type Applier interface {
	// LoadShadow 把新版全貌装进影子（旧的仍在服务）。
	LoadShadow(ctx context.Context, p *NftPlanView) error
	// VerifyShadow 自检：读回来核对规则数/关键规则存在性。
	VerifyShadow(ctx context.Context, p *NftPlanView) error
	// CommitShadow 原子切换（单 batch：删旧 jump + 加新 jump）。
	CommitShadow(ctx context.Context) error
	// DropShadow 丢弃影子（失败清理，不影响正在服务的旧版）。
	DropShadow(ctx context.Context) error
	// GC 清理旧版链（切换成功后调用；失败无影响，下次重试）。
	GC(ctx context.Context) error
}

// NftPlanView 是控制平面传给 Applier 的 nft 段视图。
//
// 不直接传 compile.NftPlan：那会让 Applier 依赖 compile 包的全部类型，
// 而各 adapter 只需要「规则集合 + 链布局」这两样。
type NftPlanView struct {
	// Version 是本版配置的版本号（用于日志与自检对账）。
	Version uint64
	// RuleCount 是规则总数（自检用）。
	RuleCount int
	// BackendTargets 是默认拒绝作用域用的后端地址（已排序去重）。
	BackendTargets []string
}

// TcApplier 是 tc 应用端口。
//
// tc 没有事务，只能补偿式应用：失败时按逆序回滚（技术方案 §2.2 的
// TcPlan.Inverses）。所以接口给的是 Apply + 由调用方决定是否回滚。
type TcApplier interface {
	ApplyTc(ctx context.Context, p *TcPlanView) error
}

// TcPlanView 是 tc 段视图。
type TcPlanView struct {
	Version uint64
	Qdiscs  int
	Classes int
	Filters int
	// Empty 表示本次不需要任何限速（调用方据此跳过 tc 应用）。
	Empty bool
}

// PartialError 表示「nft 已生效但 tc 失败」。
//
// 关键语义（技术方案 §2.2）：tc 失败**不回滚 nft**——规则已生效，
// 回滚风险更大（回滚期间转发面为空）。但必须显式告警，不能静默。
type PartialError struct {
	Stage string
	Err   error
}

func (e *PartialError) Error() string {
	return fmt.Sprintf("%s 阶段失败（此前阶段已生效，未回滚）: %v", e.Stage, e.Err)
}

func (e *PartialError) Unwrap() error { return e.Err }

// Applier 是控制平面：串行编排一次配置变更。
//
// 串行性保证：同一时刻只有一次 Apply 在跑。并发请求排队——
// 两次并发切换会互相覆盖影子链（与 nftables.Engine 内部的 mu 是两道防线，
// 这里是「跨阶段」的，那里是「单引擎内」的）。
type Controller struct {
	mu      sync.Mutex
	nft     Applier
	tc      TcApplier
	version atomic.Uint64

	// applied 是最近一次成功应用的版本（供 UI 显示与幂等判断）。
	applied atomic.Uint64
	// lastErr 是最近一次失败原因（供 /api/status）。
	lastErr atomic.Pointer[string]
}

// New 创建控制平面。
//
// nft 与 tc 都可以为 nil：
//   - nft 为 nil 表示「本环境无 nftables」（能力探测已拒绝启动，这里只是防御）
//   - tc 为 nil 表示「不做限速」（能力缺失时降级，必须已在 UI 可见）
func New(nft Applier, tc TcApplier) *Controller {
	return &Controller{nft: nft, tc: tc}
}

// Apply 执行一次完整配置变更。
//
// 顺序不可换（技术方案 §2.2）：
//
//	① LoadShadow   影子装载失败 → DropShadow → 返回（旧配置继续服务）
//	② VerifyShadow 自检失败     → DropShadow → 返回（旧配置继续服务）
//	③ CommitShadow 切换失败     → DropShadow → 返回（旧配置继续服务）
//	④ GC           清理失败     → 忽略（已无引用，下次重试）
//	⑤ ApplyTc      失败         → 返回 PartialError（nft 不回滚）
//
// 每一步失败都保证「旧版仍在服务」（C-10）。
func (c *Controller) Apply(ctx context.Context, nftPlan *NftPlanView, tcPlan *TcPlanView) error {
	if nftPlan == nil && tcPlan == nil {
		return fmt.Errorf("应用配置失败: 计划为空")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	version := uint64(0)
	if nftPlan != nil {
		version = nftPlan.Version
	} else if tcPlan != nil {
		version = tcPlan.Version
	}
	c.version.Store(version)

	// ①-④ nft 段
	if nftPlan != nil && c.nft != nil {
		if err := c.applyNft(ctx, nftPlan); err != nil {
			c.setErr(err)
			return err
		}
	}

	// ⑤ tc 段（补偿式，失败不回滚 nft）
	if tcPlan != nil && !tcPlan.Empty && c.tc != nil {
		if err := c.tc.ApplyTc(ctx, tcPlan); err != nil {
			pe := &PartialError{Stage: "tc", Err: err}
			c.setErr(pe)
			return pe
		}
	}

	c.applied.Store(version)
	c.clearErr()
	return nil
}

// applyNft 是 nft 段的四阶段编排。
func (c *Controller) applyNft(ctx context.Context, p *NftPlanView) error {
	// ① 影子装载
	if err := c.nft.LoadShadow(ctx, p); err != nil {
		// 清理半装内容：不清会让下次切换把半装当完整版切上去
		_ = c.nft.DropShadow(ctx)
		return fmt.Errorf("规则装配失败（旧规则继续生效）: %w", err)
	}
	// ② 自检
	if err := c.nft.VerifyShadow(ctx, p); err != nil {
		_ = c.nft.DropShadow(ctx)
		return fmt.Errorf("规则自检失败（旧规则继续生效）: %w", err)
	}
	// ③ 原子切换
	if err := c.nft.CommitShadow(ctx); err != nil {
		_ = c.nft.DropShadow(ctx)
		return fmt.Errorf("规则切换失败（旧规则继续生效）: %w", err)
	}
	// ④ 清理旧链（失败无影响）
	_ = c.nft.GC(ctx)
	return nil
}

// AppliedVersion 返回最近一次成功应用的版本。
func (c *Controller) AppliedVersion() uint64 { return c.applied.Load() }

// LastError 返回最近一次失败原因（nil 表示上次成功）。
//
// 供 /api/status 显示「配置应用失败」——静默失败是最难查的故障。
func (c *Controller) LastError() string {
	if p := c.lastErr.Load(); p != nil {
		return *p
	}
	return ""
}

func (c *Controller) setErr(err error) {
	s := err.Error()
	c.lastErr.Store(&s)
}

func (c *Controller) clearErr() {
	c.lastErr.Store(nil)
}
