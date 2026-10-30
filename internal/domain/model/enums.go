// Package model 定义网关的领域实体与值对象。
//
// 本包是纯领域层：零 IO、零外部依赖（不 import os/net/database/sql/gin/gorm）。
// 所有实体都以「不可变值语义」为设计目标——修改一律返回新值，不就地变更，
// 这样上一版快照可以被并发读取而不加锁（RCU 语义，见技术方案 §1.2）。
package model

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Proto 是规则的四层协议。
type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// Valid 报告 p 是否为受支持的协议。
func (p Proto) Valid() bool {
	return p == ProtoTCP || p == ProtoUDP
}

// PolicyAction 是防火墙策略的动作。
//
// 三档语义（技术方案 §3.6，D-14）：
//   - ActionAccept：只打标记（MarkPolicyOK），**仍需规则白名单命中**（AND 语义）
//   - ActionAllow：终结放行，不再查规则白名单
//   - ActionDrop：终结拒绝
//
// Accept 与 Allow 的区别是最容易搞错的一处：把 accept 当 allow 用，会出现
// 「配了 accept 反而不通」——因为规则白名单没命中。
type PolicyAction string

const (
	ActionAccept PolicyAction = "accept"
	ActionAllow  PolicyAction = "allow"
	ActionDrop   PolicyAction = "drop"
)

// Valid 报告 a 是否为受支持的动作。
func (a PolicyAction) Valid() bool {
	switch a {
	case ActionAccept, ActionAllow, ActionDrop:
		return true
	}
	return false
}

// Terminates 报告该动作是否终结链评估（allow / drop 终结，accept 不终结）。
func (a PolicyAction) Terminates() bool {
	return a == ActionAllow || a == ActionDrop
}

// DenyScope 是默认拒绝的作用域。
//
// ScopeDnatTarget 是默认值：只拒绝「目标属于本产品后端集」的未打标流量，
// 这样同机的 Docker（172.17.0.0/16）、K8s pod 网段等其他转发不受影响。
// ScopeInterface 会拒绝整个入口网卡——即旧行为，**危险**（D-13）。
type DenyScope string

const (
	// ScopeOff 不安装默认拒绝。
	ScopeOff DenyScope = "off"
	// ScopeDnatTarget 只拒「目标 ∈ 本产品后端集」的未打标流量。默认档。
	ScopeDnatTarget DenyScope = "dnat_target"
	// ScopeInterface 拒整个入口网段/网卡。危险，仅为向下兼容保留。
	ScopeInterface DenyScope = "interface"
)

// Valid 报告 s 是否为受支持的作用域。
func (s DenyScope) Valid() bool {
	switch s {
	case ScopeOff, ScopeDnatTarget, ScopeInterface:
		return true
	}
	return false
}

// ACLMode 是名单匹配模式。
type ACLMode string

const (
	// ACLOff 未配置名单（全部放行）。
	ACLOff ACLMode = "off"
	// ACLWhitelist 仅名单内放行。
	ACLWhitelist ACLMode = "whitelist"
	// ACLBlacklist 名单内拒绝。
	ACLBlacklist ACLMode = "blacklist"
)

// Valid 报告 m 是否为受支持的模式。
func (m ACLMode) Valid() bool {
	switch m {
	case ACLOff, ACLWhitelist, ACLBlacklist:
		return true
	}
	return false
}

// AclGroupKind 是名单组的类型。
//
// 兼容判据统一走 AclGroupMatchesMode：同类型组或中性 ip 组可用于该模式。
// 这条规则有**两处**引用位（规则源名单、SNAT 目标限制），新增引用位时必须同步。
type AclGroupKind string

const (
	// GroupWhitelist 白名单组。
	GroupWhitelist AclGroupKind = "whitelist"
	// GroupBlacklist 黑名单组。
	GroupBlacklist AclGroupKind = "blacklist"
	// GroupIP 中性 IP 组，两种模式都可用。
	GroupIP AclGroupKind = "ip"
)

// Valid 报告 k 是否为受支持的组类型。
func (k AclGroupKind) Valid() bool {
	switch k {
	case GroupWhitelist, GroupBlacklist, GroupIP:
		return true
	}
	return false
}

// AclGroupMatchesMode 报告某类型的名单组能否用于指定模式。
//
// 判据：同类型组，或中性 GroupIP 组。
func AclGroupMatchesMode(kind AclGroupKind, mode ACLMode) bool {
	if kind == GroupIP {
		return mode == ACLWhitelist || mode == ACLBlacklist
	}
	switch mode {
	case ACLWhitelist:
		return kind == GroupWhitelist
	case ACLBlacklist:
		return kind == GroupBlacklist
	}
	return false
}

// Validate 校验模式与组类型是否匹配。
func (m ACLMode) Validate(kind AclGroupKind) error {
	if !m.Valid() {
		return fmt.Errorf("名单模式 %q 无效", string(m))
	}
	if m == ACLOff {
		return nil
	}
	if !kind.Valid() {
		return fmt.Errorf("名单组类型 %q 无效", string(kind))
	}
	if !AclGroupMatchesMode(kind, m) {
		return fmt.Errorf("名单组类型 %q 不能用于 %q 模式", string(kind), string(m))
	}
	return nil
}

// CtKey 是 conntrack 五元组值对象，用于精确踢会话。
//
// 不变量：构造后不可变；String 与 Parse 互为逆运算（Parse(String(x)) == x）。
type CtKey struct {
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   Proto
}

// String 输出 "proto src:port -> dst:port" 形式，便于日志与踢会话接口。
func (k CtKey) String() string {
	return fmt.Sprintf("%s %s:%d -> %s:%d",
		string(k.Proto), k.SrcAddr, k.SrcPort, k.DstAddr, k.DstPort)
}

// ParseCtKey 解析 CtKey.String 的输出。
func ParseCtKey(s string) (CtKey, error) {
	var k CtKey
	fields := strings.Fields(s)
	if len(fields) != 4 || fields[2] != "->" {
		return k, fmt.Errorf("解析会话键 %q 失败: 期望 \"proto src:port -> dst:port\"", s)
	}
	proto := Proto(fields[0])
	if !proto.Valid() {
		return k, fmt.Errorf("解析会话键 %q 失败: 协议 %q 无效", s, fields[0])
	}
	src, sport, err := splitHostPort(fields[1])
	if err != nil {
		return k, fmt.Errorf("解析会话键 %q 的源地址失败: %w", s, err)
	}
	dst, dport, err := splitHostPort(fields[3])
	if err != nil {
		return k, fmt.Errorf("解析会话键 %q 的目的地址失败: %w", s, err)
	}
	k = CtKey{SrcAddr: src, DstAddr: dst, SrcPort: sport, DstPort: dport, Proto: proto}
	if err := k.Validate(); err != nil {
		return CtKey{}, err
	}
	return k, nil
}

func splitHostPort(s string) (netip.Addr, uint16, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 {
		return netip.Addr{}, 0, fmt.Errorf("缺少端口: %q", s)
	}
	addr, err := netip.ParseAddr(s[:i])
	if err != nil {
		return netip.Addr{}, 0, err
	}
	p, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("端口 %q 无效: %w", s[i+1:], err)
	}
	return addr, uint16(p), nil
}

// Validate 校验五元组的完整性。
func (k CtKey) Validate() error {
	if !k.Proto.Valid() {
		return fmt.Errorf("会话键协议 %q 无效", string(k.Proto))
	}
	if !k.SrcAddr.IsValid() {
		return fmt.Errorf("会话键源地址无效")
	}
	if !k.DstAddr.IsValid() {
		return fmt.Errorf("会话键目的地址无效")
	}
	if k.SrcAddr.Is4() != k.DstAddr.Is4() {
		return fmt.Errorf("会话键源/目的地址族不一致: %s 与 %s", k.SrcAddr, k.DstAddr)
	}
	return nil
}
