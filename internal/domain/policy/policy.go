// Package policy 提供防火墙策略的展开、排序与三态语义判断。
//
// 纯函数层：零 IO。不 import os/net/os-exec/netlink/database-sql（C-12）。
package policy

import (
	"fmt"
	"net/netip"
	"sort"

	"haproxyweb/internal/domain/model"
)

// Sorted 返回按 Order 升序排序的副本。
//
// 排序必要性：内核规则的下发顺序必须稳定且符合语义——Order 小的先评估，
// 首个终结动作（allow/drop）生效。若顺序不稳定，同一配置每次 Apply 都会
// 产生不同规则序列，导致无意义的全量重装。
//
// Order 相同时按 ID 兜底，保证结果确定。
func Sorted(policies []model.Policy) []model.Policy {
	out := make([]model.Policy, len(policies))
	copy(out, policies)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// EnabledSorted 返回已启用且按 Order 排序的策略。
func EnabledSorted(policies []model.Policy) []model.Policy {
	enabled := make([]model.Policy, 0, len(policies))
	for _, p := range policies {
		if p.Enabled {
			enabled = append(enabled, p)
		}
	}
	return Sorted(enabled)
}

// Validate 校验一组策略，并检测 Order 冲突。
//
// Order 冲突只在「协议与端口区间重叠」时算错——两条策略作用于不同端口时，
// 顺序无所谓。这里按 (proto, port) 精确判重：同一 proto+port 上 Order 必须唯一。
func Validate(policies []model.Policy) error {
	seen := make(map[string]uint, len(policies))
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("校验策略[%s#%d] 失败: %w", p.Name, p.ID, err)
		}
		if !p.Enabled {
			continue
		}
		key := fmt.Sprintf("%s|%d", string(p.Proto), p.Port)
		if prevID, dup := seen[key]; dup {
			return fmt.Errorf("校验策略失败: 策略#%d 与策略#%d 在 %s/%d 上的优先级相同，评估顺序不确定",
				prevID, p.ID, protoLabel(p.Proto), p.Port)
		}
		seen[key] = p.ID
	}
	return nil
}

func protoLabel(p model.Proto) string {
	if p == "" {
		return "全部协议"
	}
	return string(p)
}

// ExpandedSources 返回策略的源网段；空表示「匹配所有源」。
//
// 与 rule.ExpandedSources 的语义一致：返回 nil 时编译层**不生成**源匹配条件。
func ExpandedSources(p model.Policy) []netip.Prefix {
	if len(p.Sources) == 0 {
		return nil
	}
	return p.Sources
}

// Verdict 是一次策略评估的结论。
type Verdict struct {
	// Action 是命中的动作；零值表示没有策略命中。
	Action model.PolicyAction
	// PolicyID 是命中的策略 ID（Action 为零值时无意义）。
	PolicyID uint
	// Terminates 表示评估是否可以停止（allow/drop 为 true，accept 为 false）。
	Terminates bool
}

// Evaluate 按顺序评估策略，返回首个**终结**动作。
//
// 语义（D-14，技术方案 §3.6）：
//   - accept：打标记，**继续**评估后续策略，且仍需规则白名单命中（AND）
//   - allow ：终结放行
//   - drop  ：终结拒绝
//
// 如果只命中 accept 而没有 allow/drop，返回 Action=accept 且 Terminates=false
// ——调用方据此继续查规则白名单。
//
// 没有任何策略命中时返回零值 Verdict（Action=""），语义是「策略层不干预」。
func Evaluate(policies []model.Policy, proto model.Proto, port uint16, src netip.Addr) Verdict {
	var accepted *model.Policy
	for i := range policies {
		p := policies[i]
		if !p.Enabled || !p.MatchesPort(proto, port) {
			continue
		}
		if !matchesSource(p.Sources, src) {
			continue
		}
		switch p.Action {
		case model.ActionDrop:
			return Verdict{Action: model.ActionDrop, PolicyID: p.ID, Terminates: true}
		case model.ActionAllow:
			return Verdict{Action: model.ActionAllow, PolicyID: p.ID, Terminates: true}
		case model.ActionAccept:
			if accepted == nil {
				cp := p
				accepted = &cp
			}
			// 继续评估——accept 不终结
		}
	}
	if accepted != nil {
		return Verdict{Action: model.ActionAccept, PolicyID: accepted.ID, Terminates: false}
	}
	return Verdict{}
}

// matchesSource 报告 src 是否落在 sources 内；空 sources 匹配一切。
func matchesSource(sources []netip.Prefix, src netip.Addr) bool {
	if len(sources) == 0 {
		return true
	}
	for _, p := range sources {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

// AllowsForwarding 综合策略评估结论与规则白名单命中情况，判断是否放行。
//
// 这是 accept 语义最容易搞错的一处（D-14）：accept **不等于**放行，
// 它只打标记，仍需规则白名单命中（AND 语义）。
//
//	命中 allow         → 放行（不再看白名单）
//	命中 drop          → 拒绝
//	命中 accept        → 看 ruleMatched
//	没命中任何策略      → 看 ruleMatched
func AllowsForwarding(v Verdict, ruleMatched bool) bool {
	switch v.Action {
	case model.ActionAllow:
		return true
	case model.ActionDrop:
		return false
	case model.ActionAccept:
		return ruleMatched
	default:
		return ruleMatched
	}
}

// NeedRuleWhitelist 报告在给定策略结论下，是否还需要检查规则白名单。
//
// 编译层用它决定是否生成「规则白名单命中」的前置条件：命中 allow 的策略
// 已经终结放行，不必再依赖白名单打标。
func NeedRuleWhitelist(v Verdict) bool {
	return v.Action != model.ActionAllow
}
