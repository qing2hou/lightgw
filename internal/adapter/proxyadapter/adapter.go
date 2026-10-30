// Package proxyadapter 把旧的 proxy.Manager 适配成 S4 定义的应用层端口。
//
// 为什么需要这一层（技术方案 §8.1）：
//
//	app/policyapp   定义 ports（Store / SessionKiller / Reinstaller / Auditor）
//	app/sessionapp  定义 ports（Lister / Killer）
//	本包            把 proxy.Manager 的方法翻译成这些端口
//
// 适配层存在的意义是**让 app 层不认识 proxy.Manager**：
// 将来数据面换成 ctnl.Engine（事件订阅）时，只要写一个新的适配器，
// app 层与 transport 层一行都不用改。
package proxyadapter

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"haproxyweb/internal/app/policyapp"
	"haproxyweb/internal/app/sessionapp"
	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
)

// SessionKiller 实现 policyapp.SessionKiller 与 sessionapp.Lister/Killer。
//
// 同时满足两个包的端口：policyapp 要「按策略踢」，sessionapp 要
// 「列表 + 按 ID 踢」。同一个底层（proxy.Manager）提供全部三种能力。
type SessionKiller struct {
	mgr *proxy.Manager
}

// NewSessionKiller 创建适配器。mgr 为 nil 时所有方法安全返回错误（不 panic）。
func NewSessionKiller(mgr *proxy.Manager) *SessionKiller {
	return &SessionKiller{mgr: mgr}
}

// KillByPolicy 实现 policyapp.SessionKiller。
//
// 把 app 层的 Policy 视图转回 model.FwPolicy，再调 Manager 的实现。
// 转换是「字段逐个搬运」——不传整对象，避免 app 层的类型被 proxy 感知。
func (k *SessionKiller) KillByPolicy(ctx context.Context, p policyapp.Policy) (int, error) {
	if k.mgr == nil {
		return 0, fmt.Errorf("踢会话失败: 转发引擎未就绪")
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("踢会话被取消: %w", err)
	}
	mp := model.FwPolicy{
		ID:        p.ID,
		Name:      p.Name,
		Action:    p.Action,
		Proto:     p.Proto,
		PortRange: p.PortRange,
		SrcList:   joinList(p.SrcList),
		DstList:   joinList(p.DstList),
	}
	return k.mgr.KillPolicySessions(mp), nil
}

// List 实现 sessionapp.Lister。
func (k *SessionKiller) List(ctx context.Context) ([]sessionapp.Session, error) {
	if k.mgr == nil {
		return nil, fmt.Errorf("列出会话失败: 转发引擎未就绪")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("列出会话被取消: %w", err)
	}
	snaps := k.mgr.SnapshotSessions()
	out := make([]sessionapp.Session, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, convertSnapshot(s))
	}
	return out, nil
}

// Kill 实现 sessionapp.Killer。
//
// 区分「不存在」与「真失败」：前者让 app 层归入 not_found（不是错误），
// 后者归入 failed。Manager 用 killed==0 表示不存在。
func (k *SessionKiller) Kill(ctx context.Context, id string) error {
	if k.mgr == nil {
		return fmt.Errorf("掐断会话失败: 转发引擎未就绪")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("掐断会话被取消: %w", err)
	}
	killed, err := k.mgr.KillSessionByID(id)
	if err != nil {
		return fmt.Errorf("掐断会话失败: %w", err)
	}
	if killed == 0 {
		return sessionapp.ErrNotFound
	}
	return nil
}

// Reinstaller 实现 policyapp.Reinstaller。
type Reinstaller struct {
	mgr *proxy.Manager
}

// NewReinstaller 创建适配器。
func NewReinstaller(mgr *proxy.Manager) *Reinstaller { return &Reinstaller{mgr: mgr} }

// ReinstallPolicies 实现 policyapp.Reinstaller。
func (r *Reinstaller) ReinstallPolicies(ctx context.Context) error {
	if r.mgr == nil {
		return fmt.Errorf("重装策略失败: 转发引擎未就绪")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("重装策略被取消: %w", err)
	}
	return r.mgr.ReinstallPolicies()
}

// convertSnapshot 把 proxy.CTSnapshot 转成 sessionapp.Session。
//
// 源地址解析失败时返回零值 Addr（IsValid()==false）——app 层的
// KillByACLGroup 会跳过它（matchAnyPrefix 对无效地址返回 false）。
// **不在这里返回错误**：一条脏数据不该让整个会话列表失败。
func convertSnapshot(s proxy.CTSnapshot) sessionapp.Session {
	out := sessionapp.Session{
		ID:    s.ID,
		Proto: s.Proto,
	}
	if host, port, ok := splitHostPort(s.Src); ok {
		if a, err := netip.ParseAddr(host); err == nil {
			out.SrcAddr = a
		}
		out.SrcPort = port
	}
	if host, port, ok := splitHostPort(s.Dst); ok {
		if a, err := netip.ParseAddr(host); err == nil {
			out.DstAddr = a
		}
		out.DstPort = port
	}
	return out
}

// splitHostPort 解析 "ip:port" 形式（兼容 v4 与 [v6]:port）。
//
// 不用 net.SplitHostPort：对 "1.2.3.4:80" 与 "[::1]:80" 都适用，但
// 对缺端口的裸 IP 会报错——而 snapshot 的字段理论上可能只有 IP。
// 这里做成「尽力而为」：解析失败返回 ok=false。
func splitHostPort(s string) (host string, port uint16, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, false
	}
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", 0, false
	}
	host = strings.Trim(s[:i], "[]")
	var p int
	for _, c := range s[i+1:] {
		if c < '0' || c > '9' {
			return "", 0, false
		}
		p = p*10 + int(c-'0')
		if p > 65535 {
			return "", 0, false
		}
	}
	return host, uint16(p), true
}

// joinList 把 []string 拼成旧模型的逗号分隔形式。
//
// 旧 model.FwPolicy 的 SrcList/DstList 是逗号分隔的字符串（历史设计）。
// 空列表返回空串——Manager 的实现把空串解释为「不限制」。
func joinList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	cleaned := make([]string, 0, len(items))
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s != "" {
			cleaned = append(cleaned, s)
		}
	}
	return strings.Join(cleaned, ",")
}
