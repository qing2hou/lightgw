// Package session 提供会话状态机与超时判定。
//
// 纯函数层：零 IO。不 import os/net/os-exec/netlink/database-sql（C-12）。
package session

import (
	"fmt"
	"time"

	"haproxyweb/internal/domain/model"
)

// Transition 校验一次状态迁移是否合法，返回新状态。
//
// 合法迁移：
//
//	new         → established, closed
//	established → closed
//	closed      → （终态，不可再迁移）
//
// 幂等：同状态到同状态视为合法（conntrack 会重复上报 UPDATE 事件）。
func Transition(from, to model.SessionState) (model.SessionState, error) {
	if from == to {
		return to, nil
	}
	switch from {
	case model.SessionNew:
		if to == model.SessionEstablished || to == model.SessionClosed {
			return to, nil
		}
	case model.SessionEstablished:
		if to == model.SessionClosed {
			return to, nil
		}
	case model.SessionClosed:
		return from, fmt.Errorf("会话状态迁移失败: closed 是终态，不能再迁移到 %q", string(to))
	}
	return from, fmt.Errorf("会话状态迁移失败: 不允许 %q → %q", string(from), string(to))
}

// Expired 报告会话是否已超过空闲超时。
//
// idle 为负表示该规则未配置超时（0）——此时用 fallback 兜底；两者都 <= 0
// 时返回 false（不因超时关闭，交给 conntrack 自己的 timeout）。
func Expired(lastSeen time.Time, now time.Time, idle, fallback time.Duration) bool {
	limit := idle
	if limit <= 0 {
		limit = fallback
	}
	if limit <= 0 {
		return false
	}
	return now.Sub(lastSeen) > limit
}

// ShouldDrop 判定会话是否应被主动踢掉。
//
// 用于「禁用策略/删规则后立即断开已建会话」这条验收用例——旧代码只拦
// `ct state new`，已建会话最长存活 86400s，导致「禁用后流量立即断开」不通过。
//
// interpreter：策略动作 drop，或规则已不存在/已禁用，都返回 true。
func ShouldDrop(action model.PolicyAction, ruleExists, ruleEnabled bool) bool {
	if action == model.ActionDrop {
		return true
	}
	if !ruleExists || !ruleEnabled {
		return true
	}
	return false
}
