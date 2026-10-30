// Package policyapp 是防火墙策略的用例编排层。
//
// 分层约束（技术方案 §8.1）：
//
//	transport/httpapi  只做 DTO 转换 + 参数校验 + 调 app
//	app/*app           用例编排，可以有事务边界，**不许 import gin**
//	domain/compile     纯函数
//
// 本包存在的理由：把「禁用策略必须立即断开已建会话」这类业务规则
// 从 handler 里搬出来，让它可以被单测覆盖，而不是只能靠 HTTP 集成测试。
package policyapp

import (
	"context"
	"errors"
	"fmt"
)

// Policy 是本包需要的策略视图。
//
// 不复用 internal/model 的类型：app 层不应该被持久化模型绑死，
// 由调用方（transport 或 store adapter）负责转换。
// 这样 app 层的测试不需要建数据库。
type Policy struct {
	ID      uint
	Name    string
	Action  string // "accept" / "allow" / "drop"
	Enabled bool
	// 匹配维度（用于判定哪些会话应被踢掉）
	Proto     string
	PortRange string
	SrcList   []string
	DstList   []string
	Order     int
}

// Store 是策略持久化端口。
//
// 接口而非具体实现：app 层不 import gorm。真实实现在 adapter/sqlite。
type Store interface {
	GetPolicy(ctx context.Context, id uint) (*Policy, error)
	ListPolicies(ctx context.Context) ([]Policy, error)
	// SetEnabled 只改启停位，不碰其它字段（避免「启停」意外覆盖用户刚改的内容）。
	SetEnabled(ctx context.Context, id uint, enabled bool) error
	DeletePolicy(ctx context.Context, id uint) error
}

// SessionKiller 是「踢掉匹配会话」端口。
//
// 由 proxy.Manager（旧实现：读 /proc/net/nf_conntrack）或
// ctnl.Engine（新实现：事件订阅 + KillSession）实现。
type SessionKiller interface {
	// KillByPolicy 掐断匹配该策略的存量会话，返回掐断条数。
	KillByPolicy(ctx context.Context, p Policy) (int, error)
}

// Reinstaller 是「重装内核规则」端口。
type Reinstaller interface {
	ReinstallPolicies(ctx context.Context) error
}

// Auditor 是审计端口。
type Auditor interface {
	Record(user, action, detail, clientIP string)
}

// ErrNotFound 表示策略不存在。
var ErrNotFound = errors.New("策略不存在")

// Service 是策略用例。
type Service struct {
	store   Store
	killer  SessionKiller
	install Reinstaller
	audit   Auditor
}

// New 创建服务。依赖全部以接口注入，便于测试与替换实现。
func New(store Store, killer SessionKiller, install Reinstaller, audit Auditor) *Service {
	return &Service{store: store, killer: killer, install: install, audit: audit}
}

// EnableResult 是启停操作的结果。
type EnableResult struct {
	ID uint
	// Enabled 是操作后的状态。
	Enabled bool
	// KilledSessions 是本次踢掉的会话数。
	//
	// **禁用时必然踢会话**（技术方案 §8.3）：这是「禁用策略后流量立即断开」
	// 这条验收用例的核心。旧实现只在 action==drop 且显式要求时才踢，
	// 已建会话最长存活 86400s，用例直接不通过。
	KilledSessions int
}

// SetEnabled 启停一条策略，并在禁用时立即断开已建会话。
//
// 语义（与验收用例一一对应）：
//   - 启用：只重装规则（新连接按新策略评估），不踢现有会话
//     （启用是放宽或收紧新连接，没有理由打断已经在跑的连接）
//   - 禁用：重装规则 **+ 立即踢掉所有匹配该策略的会话**
//     （否则「禁用」只是对新连接生效，旧连接会继续跑满 conntrack 超时）
//
// 无论启用还是禁用，先改库再重装——顺序反了会出现「内核已无规则但库还
// 标着启用」的不一致状态，重启后会「复活」。
func (s *Service) SetEnabled(ctx context.Context, id uint, enabled bool, actor, clientIP string) (*EnableResult, error) {
	p, err := s.store.GetPolicy(ctx, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, ErrNotFound
	}
	if err := s.store.SetEnabled(ctx, id, enabled); err != nil {
		return nil, fmt.Errorf("保存策略启停状态失败: %w", err)
	}
	if err := s.install.ReinstallPolicies(ctx); err != nil {
		return nil, fmt.Errorf("重装策略失败: %w", err)
	}

	res := &EnableResult{ID: id, Enabled: enabled}
	// ★ 禁用时立即断开已建会话
	if !enabled {
		killed, err := s.killer.KillByPolicy(ctx, *p)
		if err != nil {
			// 踢会话失败不回滚启停（规则已撤，安全性已达成；
			// 残留会话靠 conntrack 超时自然消亡）。但必须上报。
			return res, fmt.Errorf("策略已禁用，但断开存量会话失败（将随超时自然消亡）: %w", err)
		}
		res.KilledSessions = killed
	}
	action := "fw_policy_disable"
	if enabled {
		action = "fw_policy_enable"
	}
	if s.audit != nil {
		s.audit.Record(actor, action,
			fmt.Sprintf("策略#%d %s（断开会话 %d）", id, p.Name, res.KilledSessions), clientIP)
	}
	return res, nil
}

// Delete 删除一条策略，并立即断开其匹配的会话。
//
// 删除也要踢会话（技术方案 §8.3）：删掉策略后，原本被它的 accept/drop
// 影响的连接必须立刻按新规则集重新判定，否则会「幽灵放行/幽灵拒绝」。
// 踢掉之后，同一五元组的新包会重新走完整评估链。
func (s *Service) Delete(ctx context.Context, id uint, actor, clientIP string) (int, error) {
	p, err := s.store.GetPolicy(ctx, id)
	if err != nil {
		return 0, err
	}
	if p == nil {
		return 0, ErrNotFound
	}
	if err := s.store.DeletePolicy(ctx, id); err != nil {
		return 0, fmt.Errorf("删除策略失败: %w", err)
	}
	if err := s.install.ReinstallPolicies(ctx); err != nil {
		return 0, fmt.Errorf("重装策略失败: %w", err)
	}
	killed, kerr := s.killer.KillByPolicy(ctx, *p)
	if s.audit != nil {
		s.audit.Record(actor, "fw_policy_delete",
			fmt.Sprintf("删除策略#%d %s（断开会话 %d）", id, p.Name, killed), clientIP)
	}
	if kerr != nil {
		return killed, fmt.Errorf("策略已删除，但断开存量会话失败: %w", kerr)
	}
	return killed, nil
}

// Save 保存（新建或更新）一条策略。
//
// 与旧实现的差异：旧实现只在「action==drop 且调用方显式要求」时踢会话，
// 本实现按「策略影响面变化」判定——**任何会让某些连接从「被允许」变成
// 「被拒绝」的变更都要踢**。
//
// 判定规则（保守，宁可多踢）：
//   - 新策略或旧策略是 drop → 踢（拒绝面可能扩大）
//   - 旧策略是 accept 且新策略不是 accept → 踢（允许面缩小）
//   - 其余情况不踢（纯放宽，无需打断现有连接）
func (s *Service) Save(ctx context.Context, p Policy, actor, clientIP string) (int, error) {
	var old *Policy
	if p.ID != 0 {
		got, err := s.store.GetPolicy(ctx, p.ID)
		if err != nil {
			return 0, err
		}
		old = got
	}
	if err := s.install.ReinstallPolicies(ctx); err != nil {
		return 0, fmt.Errorf("重装策略失败: %w", err)
	}
	if !needsKick(old, p) {
		if s.audit != nil {
			s.audit.Record(actor, "fw_policy_apply", fmt.Sprintf("保存策略 %s", p.Name), clientIP)
		}
		return 0, nil
	}
	killed, err := s.killer.KillByPolicy(ctx, p)
	if s.audit != nil {
		s.audit.Record(actor, "fw_policy_apply",
			fmt.Sprintf("保存策略 %s（断开会话 %d）", p.Name, killed), clientIP)
	}
	if err != nil {
		return killed, fmt.Errorf("策略已保存，但断开存量会话失败: %w", err)
	}
	return killed, nil
}

// needsKick 判定策略变更是否需要踢掉存量会话。
//
// 分离成独立函数是为了让它可被穷举单测——这是「禁用后立即断开」这条
// 验收用例的可验证内核。
func needsKick(old *Policy, next Policy) bool {
	if old == nil {
		// 新策略：只有 drop 会立即拒绝别人
		return next.Action == "drop"
	}
	if old.Action == "drop" || next.Action == "drop" {
		// 任一版本是 drop：拒绝面可能变化
		return true
	}
	if old.Action == "accept" && next.Action != "accept" {
		// 从「打标放行」收紧：原本通行的连接现在可能不通
		return true
	}
	return false
}
