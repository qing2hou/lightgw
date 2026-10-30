package model

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Rule 是一条转发规则（DNAT：把 VIP:port 转到 backend:port）。
//
// 不变量：
//   - 构造后不可变；修改一律返回新值（见 WithXxx 方法）
//   - Validate 通过后：Proto 有效、后端非空、端口合法、CIDR 合法
//   - SameTarget 判定两条规则是否指向同一后端（用于「无改动」快速路径）
type Rule struct {
	ID       uint
	Name     string
	Proto    Proto
	ListenAt netip.AddrPort // VIP + 监听端口
	Backend  netip.AddrPort // 真实后端
	Pool     Pool           // SNAT 池（若该规则做 SNAT）
	Enabled  bool

	// 源名单：ACLMode + 展开后的 CIDR 列表
	ACLMode ACLMode
	ACL     []netip.Prefix

	// SNAT 目标限制名单（第二处引用位，与 ACL 独立）
	DstACLMode ACLMode
	DstACL     []netip.Prefix

	// 带宽包（0 = 不限速）
	BWGroupID      uint
	MaxConns       int
	IdleTimeoutSec int
}

// Validate 校验规则的所有字段。
//
// 错误消息为中文，格式「<做什么>失败: <原因>」（C-05）。
func (r Rule) Validate() error {
	if !r.Proto.Valid() {
		return fmt.Errorf("校验规则失败: 协议 %q 无效（只支持 tcp/udp）", string(r.Proto))
	}
	if !r.ListenAt.IsValid() {
		return fmt.Errorf("校验规则失败: 监听地址无效")
	}
	if r.ListenAt.Port() == 0 {
		return fmt.Errorf("校验规则失败: 监听端口不能为 0")
	}
	if !r.Backend.IsValid() {
		return fmt.Errorf("校验规则失败: 后端地址无效")
	}
	if r.Backend.Port() == 0 {
		return fmt.Errorf("校验规则失败: 后端端口不能为 0")
	}
	if r.ListenAt.Addr().Is4() != r.Backend.Addr().Is4() {
		return fmt.Errorf("校验规则失败: 监听地址族 %s 与后端地址族 %s 不一致",
			r.ListenAt.Addr(), r.Backend.Addr())
	}
	if err := validatePrefixes("源名单", r.ACLMode, r.ACL); err != nil {
		return err
	}
	if err := validatePrefixes("SNAT 目标名单", r.DstACLMode, r.DstACL); err != nil {
		return err
	}
	if r.MaxConns < 0 {
		return fmt.Errorf("校验规则失败: 最大连接数不能为负（%d）", r.MaxConns)
	}
	if r.IdleTimeoutSec < 0 {
		return fmt.Errorf("校验规则失败: 空闲超时不能为负（%d）", r.IdleTimeoutSec)
	}
	if err := r.Pool.Validate(); err != nil {
		return fmt.Errorf("校验规则失败: %w", err)
	}
	return nil
}

func validatePrefixes(what string, mode ACLMode, prefixes []netip.Prefix) error {
	// 零值 "" 按 off 处理：旧数据里未配置名单的规则 ACLMode 就是空串
	// （AGENTS.md「空模式是旧数据兼容语义」）。不能因此判非法——否则
	// 所有历史规则都校验不过。
	if mode == "" {
		mode = ACLOff
	}
	if !mode.Valid() {
		return fmt.Errorf("校验规则失败: %s模式 %q 无效", what, string(mode))
	}
	if mode == ACLOff && len(prefixes) > 0 {
		return fmt.Errorf("校验规则失败: %s为空但配置了 %d 条网段", what, len(prefixes))
	}
	if mode != ACLOff && len(prefixes) == 0 {
		return fmt.Errorf("校验规则失败: %s模式为 %q 但没有任何网段（会匹配不到任何流量）", what, string(mode))
	}
	for _, p := range prefixes {
		if !p.IsValid() {
			return fmt.Errorf("校验规则失败: %s含无效网段", what)
		}
		// 网络地址必须归零，否则内核 set 语义与用户预期不符
		if p.Masked() != p {
			return fmt.Errorf("校验规则失败: %s网段 %s 未归零（应为 %s）", what, p, p.Masked())
		}
	}
	return nil
}

// SameTarget 报告两条规则是否指向同一后端与同一监听端点（协议 + 地址 + 端口）。
// 用于热更新时判定「后端没变，可零中断」。
func (r Rule) SameTarget(o Rule) bool {
	return r.Proto == o.Proto &&
		r.ListenAt == o.ListenAt &&
		r.Backend == o.Backend &&
		r.Enabled == o.Enabled
}

// WithBackend 返回把后端替换为新值的规则副本（保持不可变语义）。
func (r Rule) WithBackend(b netip.AddrPort) Rule {
	r.Backend = b
	return r
}

// WithEnabled 返回启停状态被替换的规则副本。
func (r Rule) WithEnabled(v bool) Rule {
	r.Enabled = v
	return r
}

// ListenerKey 是该规则的监听端点标识，用于同 (proto, listen_port) 冲突检测。
type ListenerKey struct {
	Proto Proto
	Addr  netip.Addr
	Port  uint16
}

// ListenerKey 返回该规则的监听端点标识。
func (r Rule) ListenerKey() ListenerKey {
	return ListenerKey{Proto: r.Proto, Addr: r.ListenAt.Addr(), Port: r.ListenAt.Port()}
}

// Pool 是 SNAT 地址池。
//
// 不变量（重要）：一旦构造完成即不可变。任何「修改」都返回新 Pool。
// Members 恒为非空、去重、且地址族一致；构造必须走 NewPool。
type Pool struct {
	members []netip.Addr
}

// NewPool 校验并构造一个地址池。
//
// 空池是合法的（表示「不做 SNAT」）；非空池要求全部同族且去重。
func NewPool(members []netip.Addr) (Pool, error) {
	if len(members) == 0 {
		return Pool{}, nil
	}
	seen := make(map[netip.Addr]struct{}, len(members))
	out := make([]netip.Addr, 0, len(members))
	v4 := members[0].Is4()
	for i, m := range members {
		if !m.IsValid() {
			return Pool{}, fmt.Errorf("构造 SNAT 池失败: 第 %d 个成员地址无效", i+1)
		}
		if m.Is4() != v4 {
			return Pool{}, fmt.Errorf("构造 SNAT 池失败: 成员 %s 与 %s 地址族不一致", members[0], m)
		}
		if _, dup := seen[m]; dup {
			continue // 去重而非报错：导入的历史数据常有重复
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return Pool{members: out}, nil
}

// Members 返回池成员的副本（调用方无法修改内部状态）。
func (p Pool) Members() []netip.Addr {
	if len(p.members) == 0 {
		return nil
	}
	return slices.Clone(p.members)
}

// Len 返回池成员数。
func (p Pool) Len() int { return len(p.members) }

// IsEmpty 报告池是否为空（等价于「不做 SNAT」）。
func (p Pool) IsEmpty() bool { return len(p.members) == 0 }

// Validate 校验池的内部一致性。
func (p Pool) Validate() error {
	if len(p.members) == 0 {
		return nil
	}
	v4 := p.members[0].Is4()
	seen := make(map[netip.Addr]struct{}, len(p.members))
	for i, m := range p.members {
		if !m.IsValid() {
			return fmt.Errorf("SNAT 池第 %d 个成员地址无效", i+1)
		}
		if m.Is4() != v4 {
			return fmt.Errorf("SNAT 池成员地址族不一致: %s 与 %s", p.members[0], m)
		}
		if _, dup := seen[m]; dup {
			return fmt.Errorf("SNAT 池含重复成员 %s", m)
		}
		seen[m] = struct{}{}
	}
	return nil
}

// String 便于日志输出。
func (p Pool) String() string {
	if p.IsEmpty() {
		return "(空池)"
	}
	parts := make([]string, len(p.members))
	for i, m := range p.members {
		parts[i] = m.String()
	}
	return strings.Join(parts, ",")
}

// Egress 是一个出口（网卡 + 可选网关 + 可选源 IP）。
type Egress struct {
	ID       uint
	Name     string
	IfName   string
	Gateway  netip.Addr // 可选
	SourceIP netip.Addr // 可选：SNAT 源地址
	Enabled  bool
}

// Validate 校验出口字段。
func (e Egress) Validate() error {
	if strings.TrimSpace(e.IfName) == "" {
		return fmt.Errorf("校验出口失败: 网卡名不能为空")
	}
	if e.Gateway.IsValid() && e.SourceIP.IsValid() && e.Gateway.Is4() != e.SourceIP.Is4() {
		return fmt.Errorf("校验出口失败: 网关 %s 与源地址 %s 地址族不一致", e.Gateway, e.SourceIP)
	}
	return nil
}

// BWGroup 是带宽包：总额 + 每源保底。
//
// 实测约束（ADR-15）：htb 的 parent.rate 不是硬上限，实际总量约为
// max(parent.rate, Σ(成员 rate))。所以「总额」要靠**禁止超额订阅**来保证：
// Σ(成员 MinKBps) 必须 ≤ TotalKBps。见 bandwidth.CheckOversubscription。
type BWGroup struct {
	ID        uint
	Name      string
	TotalKBps int64 // 带宽包总额（KB/s）
	MinKBps   int64 // 每源保底（KB/s）；0 表示用默认值
	Enabled   bool
}

// Validate 校验带宽包字段。
func (g BWGroup) Validate() error {
	if g.TotalKBps <= 0 {
		return fmt.Errorf("校验带宽包失败: 总额必须为正（%d KB/s）", g.TotalKBps)
	}
	if g.MinKBps < 0 {
		return fmt.Errorf("校验带宽包失败: 保底不能为负（%d KB/s）", g.MinKBps)
	}
	if g.MinKBps > g.TotalKBps {
		return fmt.Errorf("校验带宽包失败: 每源保底 %d KB/s 大于总额 %d KB/s", g.MinKBps, g.TotalKBps)
	}
	return nil
}

// EffectiveMinKBps 返回生效的每源保底：配置值 > 0 用之，否则用默认值。
func (g BWGroup) EffectiveMinKBps(def int64) int64 {
	if g.MinKBps > 0 {
		return g.MinKBps
	}
	return def
}

// AclGroup 是名单组。
type AclGroup struct {
	ID   uint
	Name string
	Kind AclGroupKind
	// CIDRs 是展开后的网段（已归一化）
	CIDRs   []netip.Prefix
	Enabled bool
}

// Validate 校验名单组字段。
func (g AclGroup) Validate() error {
	if !g.Kind.Valid() {
		return fmt.Errorf("校验名单组失败: 类型 %q 无效", string(g.Kind))
	}
	for _, p := range g.CIDRs {
		if !p.IsValid() {
			return fmt.Errorf("校验名单组失败: 含无效网段")
		}
		if p.Masked() != p {
			return fmt.Errorf("校验名单组失败: 网段 %s 未归零（应为 %s）", p, p.Masked())
		}
	}
	return nil
}

// Policy 是一条防火墙策略。
//
// 不变量：Order 越小越先评估；同一 (proto, port) 上 Order 必须唯一。
type Policy struct {
	ID      uint
	Name    string
	Order   int
	Proto   Proto
	Port    uint16 // 0 = 所有端口
	Action  PolicyAction
	Sources []netip.Prefix // 空 = 匹配所有源
	Enabled bool
}

// Validate 校验策略字段。
func (p Policy) Validate() error {
	if !p.Action.Valid() {
		return fmt.Errorf("校验策略失败: 动作 %q 无效（accept/allow/drop）", string(p.Action))
	}
	if p.Proto != "" && !p.Proto.Valid() {
		return fmt.Errorf("校验策略失败: 协议 %q 无效", string(p.Proto))
	}
	if p.Order < 0 {
		return fmt.Errorf("校验策略失败: 优先级不能为负（%d）", p.Order)
	}
	for _, c := range p.Sources {
		if !c.IsValid() {
			return fmt.Errorf("校验策略失败: 含无效源网段")
		}
		if c.Masked() != c {
			return fmt.Errorf("校验策略失败: 源网段 %s 未归零（应为 %s）", c, c.Masked())
		}
	}
	return nil
}

// MatchesPort 报告策略是否覆盖给定协议与端口。
func (p Policy) MatchesPort(proto Proto, port uint16) bool {
	if p.Proto != "" && p.Proto != proto {
		return false
	}
	return p.Port == 0 || p.Port == port
}

// SessionState 是会话状态机的状态。
type SessionState string

const (
	SessionNew         SessionState = "new"
	SessionEstablished SessionState = "established"
	SessionClosed      SessionState = "closed"
)

// Session 是会话值对象（只读快照，运行时状态由 adapter 提供）。
type Session struct {
	Key      CtKey
	State    SessionState
	RuleID   uint
	BytesIn  uint64
	BytesOut uint64
}
