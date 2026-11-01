// SNAT 独立规则的编译（方案 A：独立类型）。
//
// 背景（docs/equivcheck-result.md 缺口 3）：
//
// `compile.Rule` 是为 **DNAT**（端口转发：Proto + ListenAt + Backend）设计的。
// 而生产环境的 SNAT 规则是**独立规则**，形态完全不同：
//
//	DNAT 规则：谁（源白名单）能访问 我的 VIP:端口 → 转发到后端:端口
//	SNAT 规则：谁（源白名单）能穿过我出去 → 源地址改写成 出口IP
//
// 共用一个结构的结果是：`rule.Validate` 要求 `Proto ∈ {tcp,udp}`，
// 而 SNAT 没有协议概念（作用于所有协议的穿越流量），
// 现网规则#30 的 protocol 字段值是 `"snat"` —— 校验直接失败：
//
//	校验规则[test#30] 失败: 协议 "" 无效（只支持 tcp/udp）
//
// 所以这里引入 `SnatRule`：它只含 SNAT 真正需要的字段，
// 不借用 DNAT 的形状。两条编译路径互不干扰。
package compile

import (
	"fmt"
	"net/netip"

	"haproxyweb/internal/domain/model"
)

// SnatRule 是一条独立的 SNAT 规则（穿越流量出口改写）。
//
// 与 `Rule`（DNAT）的区别：
//
//	Rule      有 Proto / ListenAt / Backend —— 面向「转发到后端」
//	SnatRule  有 SourceNets / OutIP / MetaMarkExempt —— 面向「穿出去」
//
// 不变量：构造后不可变；`Validate` 通过后 SourceNets 非空、OutIP 有效。
type SnatRule struct {
	// ID 是规则主键（进 ct mark 的 rule_id 位段，也进 comment）。
	ID uint
	// Name 用于日志与错误消息。
	Name string
	// SourceNets 是允许穿越的源网段（白名单，已展开并归零）。
	SourceNets []netip.Prefix
	// OutIP 是改写后的源地址（SNAT 目标）。
	OutIP netip.Addr
	// OutPort 是出口端口范围（可选；0 表示不改写端口）。
	//
	// 当前生产全部是「只改地址不改端口」，保留字段是为了将来需要时不用改结构。
	OutPort uint16
	// IfIn / IfOut 是入口/出口网卡。
	//
	// 单臂网关下两者相同。用于生成 `iifname` / `oifname` 前置条件。
	IfIn  string
	IfOut string
	// MetaMarkExempt 非零时生成 `meta mark & <值> == 0` 前置条件。
	//
	// 生产用途（AGENTS.md 记录）：`0x4` 是 MarkDNAT —— 发布流量（DNAT 会话）
	// 必须**豁免** SNAT，否则回程包会被错误改写、发布直接断。
	// 漏掉这个条件等于让发布流量也被 SNAT。
	MetaMarkExempt uint32
	// Enabled 为 false 时跳过（不生成规则）。
	Enabled bool
	// Counter 为 true 时带计数器。
	Counter bool
}

// Validate 校验 SNAT 规则。
//
// 与 `rule.Validate` 的区别：**不检查协议**（SNAT 没有协议概念）。
func (r SnatRule) Validate() error {
	if r.OutIP.IsValid() && r.OutIP.Is6() {
		// 现网全是 IPv4；IPv6 的 SNAT 需要不同的表达式族，暂不支持。
		return fmt.Errorf("校验 SNAT 规则失败: 出口地址 %s 是 IPv6（当前只支持 IPv4）", r.OutIP)
	}
	if len(r.SourceNets) == 0 {
		return fmt.Errorf("校验 SNAT 规则失败: 没有源网段（规则会匹配不到任何流量）")
	}
	for _, p := range r.SourceNets {
		if !p.IsValid() {
			return fmt.Errorf("校验 SNAT 规则失败: 含无效网段")
		}
		if p.Masked() != p {
			return fmt.Errorf("校验 SNAT 规则失败: 网段 %s 未归零（应为 %s）", p, p.Masked())
		}
		if p.Addr().Is6() {
			return fmt.Errorf("校验 SNAT 规则失败: 源网段 %s 是 IPv6（当前只支持 IPv4）", p)
		}
	}
	if !r.OutIP.IsValid() {
		return fmt.Errorf("校验 SNAT 规则失败: 出口地址无效")
	}
	return nil
}

// CompileSnatRules 把独立 SNAT 规则编译成 nft 规则段。
//
// 每条 SnatRule 生成**两条**规则（与 AGENTS.md 的「SNAT counter 必须覆盖双向」一致）：
//
//	① 放行 + 改写行（每个源网段一条，因为 u32/nft 的单网段匹配）：
//	     iifname <IfIn> oifname <IfOut> meta mark & <exempt> == 0 \
//	     saddr ∈ <源网段> counter snat ip to <OutIP>
//	② 回程计数行（目的地址 = 源网段，无 verdict）：
//	     iifname <IfIn> oifname <IfOut> meta mark & <exempt> == 0 \
//	     daddr ∈ <源网段> counter
//
// 为什么必须有 ②：只装上行的计数会让页面速率只反映 ACK 小包。
// 回程包（源=服务器、目的=客户端）不经过 ① 的 `saddr=白名单` 条件，
// 必须靠 ② 单独计数。实测过 3.54MB/s 显示成 68.9KB/s。
//
// 返回的规则 `Chain` 都是 `ChainSnat`，`WorkChain` 都是 `"snat"`。
func CompileSnatRules(rules []SnatRule) ([]Rule, error) {
	var out []Rule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("编译 SNAT 规则[%s#%d] 失败: %w", r.Name, r.ID, err)
		}
		for i, net := range r.SourceNets {
			// ① 放行 + 改写
			rule := Rule{
				Chain:     ChainSnat,
				WorkChain: "snat",
				Comment:   fmt.Sprintf("%s%d:%d", snatRuleCommentPrefix, r.ID, i),
				Src:       AddrMatch{Prefixes: []netip.Prefix{net}},
				SnatTo:    r.OutIP,
				Counter:   r.Counter,
			}
			if r.MetaMarkExempt != 0 {
				m := r.MetaMarkExempt
				rule.MetaMarkNotSet = &m
			}
			if r.IfIn != "" {
				rule.IfIn = r.IfIn
			}
			if r.IfOut != "" {
				rule.IfOut = r.IfOut
			}
			out = append(out, rule)

			// ② 回程计数（daddr = 源，无 verdict）
			ret := Rule{
				Chain:     ChainSnat,
				WorkChain: "snat",
				Comment:   fmt.Sprintf("%s%d:%d:return", snatRuleCommentPrefix, r.ID, i),
				Dst:       AddrMatch{Prefixes: []netip.Prefix{net}},
				Counter:   true,
			}
			if r.MetaMarkExempt != 0 {
				m := r.MetaMarkExempt
				ret.MetaMarkNotSet = &m
			}
			if r.IfIn != "" {
				ret.IfIn = r.IfIn
			}
			if r.IfOut != "" {
				ret.IfOut = r.IfOut
			}
			out = append(out, ret)
		}
	}
	return out, nil
}

// snatRuleCommentPrefix 是独立 SNAT 规则的 comment 前缀。
//
// 与 DNAT 配套的 SNAT（`snatCommentPrefix`）分开，
// 两者来源不同、生命周期不同，混在一起会让对账难以区分。
const snatRuleCommentPrefix = "haweb:snatrule:"

// SnatRuleCommentPrefix 暴露前缀供 adapter 对账使用。
func SnatRuleCommentPrefix() string { return snatRuleCommentPrefix }

// SnatRulesFromModel 把 domain 的 SNAT 意图转成 SnatRule。
//
// 抽成函数而不是让调用方自己拼：源网段必须归零、出口地址必须校验，
// 这些不变量应该在一处保证。
func SnatRulesFromModel(id uint, name string, srcs []netip.Prefix, outIP netip.Addr,
	ifIn, ifOut string, metaMarkExempt uint32) (SnatRule, error) {
	// 归零（10.1.2.3/8 → 10.0.0.0/8）
	clean := make([]netip.Prefix, 0, len(srcs))
	for _, p := range srcs {
		if !p.IsValid() {
			return SnatRule{}, fmt.Errorf("构造 SNAT 规则[%s#%d] 失败: 含无效网段", name, id)
		}
		clean = append(clean, p.Masked())
	}
	r := SnatRule{
		ID:             id,
		Name:           name,
		SourceNets:     clean,
		OutIP:          outIP,
		IfIn:           ifIn,
		IfOut:          ifOut,
		MetaMarkExempt: metaMarkExempt,
		Enabled:        true,
		Counter:        true,
	}
	if err := r.Validate(); err != nil {
		return SnatRule{}, err
	}
	return r, nil
}

// PoolsFromModel 是 domain.Pool → []netip.Addr 的便捷转换。
func PoolsFromModel(p model.Pool) []netip.Addr {
	return p.Members()
}
