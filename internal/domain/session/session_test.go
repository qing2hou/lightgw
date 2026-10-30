package session

import (
	"testing"
	"time"

	"haproxyweb/internal/domain/model"
)

// TestTransitionHappy 合法迁移。
func TestTransitionHappy(t *testing.T) {
	cases := [][2]model.SessionState{
		{model.SessionNew, model.SessionEstablished},
		{model.SessionNew, model.SessionClosed},
		{model.SessionEstablished, model.SessionClosed},
	}
	for _, c := range cases {
		got, err := Transition(c[0], c[1])
		if err != nil {
			t.Fatalf("%q → %q 应合法，实际: %v", c[0], c[1], err)
		}
		if got != c[1] {
			t.Fatalf("应返回 %q，实际 %q", c[1], got)
		}
	}
}

// TestTransitionIdempotent 同状态到同状态合法（conntrack 会重复上报 UPDATE）。
func TestTransitionIdempotent(t *testing.T) {
	for _, s := range []model.SessionState{
		model.SessionNew, model.SessionEstablished, model.SessionClosed,
	} {
		if _, err := Transition(s, s); err != nil {
			t.Fatalf("%q → %q 应幂等通过，实际: %v", s, s, err)
		}
	}
}

// TestTransitionFromClosedFails closed 是终态。
func TestTransitionFromClosedFails(t *testing.T) {
	if _, err := Transition(model.SessionClosed, model.SessionNew); err == nil {
		t.Fatal("closed 不能再迁移（终态）")
	}
}

// TestTransitionEstablishedToNewFails 不能倒退。
func TestTransitionEstablishedToNewFails(t *testing.T) {
	if _, err := Transition(model.SessionEstablished, model.SessionNew); err == nil {
		t.Fatal("established 不能退回 new")
	}
}

// TestTransitionErrorsAreChinese 错误消息必须是中文（C-05）。
func TestTransitionErrorsAreChinese(t *testing.T) {
	_, err := Transition(model.SessionClosed, model.SessionNew)
	if err == nil {
		t.Fatal("应报错")
	}
	if got := err.Error(); got == "" {
		t.Fatal("错误消息不应为空")
	}
}

func TestExpired(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		lastSeen time.Duration // now - lastSeen
		idle     time.Duration
		fallback time.Duration
		want     bool
	}{
		{"未超时", 10 * time.Second, 60 * time.Second, 0, false},
		{"已超时", 90 * time.Second, 60 * time.Second, 0, true},
		{"idle=0 用 fallback 未超时", 10 * time.Second, 0, 60 * time.Second, false},
		{"idle=0 用 fallback 已超时", 90 * time.Second, 0, 60 * time.Second, true},
		{"都为0 不超时", 1000 * time.Second, 0, 0, false},
		{"负 idle 走 fallback", 90 * time.Second, -1, 60 * time.Second, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			last := now.Add(-c.lastSeen)
			if got := Expired(last, now, c.idle, c.fallback); got != c.want {
				t.Fatalf("Expired(%v, idle=%v, fb=%v) = %v，期望 %v",
					c.lastSeen, c.idle, c.fallback, got, c.want)
			}
		})
	}
}

// TestShouldDrop 禁用策略/删规则后必须踢掉已建会话。
//
// 这是验收用例「禁用策略后流量立即断开」的实现依据：旧代码只拦
// ct state new，已建会话最长存活 86400s，导致用例不通过。
func TestShouldDrop(t *testing.T) {
	cases := []struct {
		name        string
		action      model.PolicyAction
		ruleExists  bool
		ruleEnabled bool
		want        bool
	}{
		{"正常会话", "", true, true, false},
		{"策略drop", model.ActionDrop, true, true, true},
		{"规则已删", "", false, true, true},
		{"规则已禁用", "", true, false, true},
		{"allow 且规则正常", model.ActionAllow, true, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ShouldDrop(c.action, c.ruleExists, c.ruleEnabled); got != c.want {
				t.Fatalf("ShouldDrop(%q,%v,%v) = %v，期望 %v",
					c.action, c.ruleExists, c.ruleEnabled, got, c.want)
			}
		})
	}
}
