package compile

import (
	"fmt"
	"net/netip"

	"haproxyweb/internal/domain/model"
	"haproxyweb/internal/domain/policy"
	domainrule "haproxyweb/internal/domain/rule"
)

// dnatCommentPrefix 是 DNAT 规则 comment 前缀。
const dnatCommentPrefix = "haweb:dnat:"

// CompileDnat 把转发规则编译成 DNAT 段。
//
// 每条 domain.Rule 生成**两条** nft 规则：
//
//	① prerouting/mangle (-150)  pre_mark：
//	     ct state new <proto> dport <port> [saddr ∈ 白名单]
//	     → ct mark set <ruleID<<8 | DNAT>  ;  meta mark |= FWD_OK  ;  counter
//	② prerouting/dstnat (-100)  dnat：
//	     ct mark and 0xFFFFFF00 == <ruleID<<8>  →  dnat ip to <backend>
//
// 为什么必须两条：DNAT 链本身不做「是否允许」的判断，它只按 ct mark 无条件
// 改写地址。判定（源白名单）必须在更早的 pre_mark 完成，否则会出现「未授权
// 源也被 DNAT 到后端」——地址改了但后续 forward 链才 drop，后端已经看到包了。
//
// 不变量：同一 ruleID 在 ct mark 的 rule_id 位段内唯一（由调用方保证）。
func CompileDnat(rules []model.Rule) ([]Rule, error) {
	enabled := domainrule.Enabled(domainrule.SortByID(rules))
	out := make([]Rule, 0, len(enabled)*2)

	for _, r := range enabled {
		mark, err := MakeCtMark(uint32(r.ID), CtFlagDnat)
		if err != nil {
			return nil, fmt.Errorf("编译 DNAT 规则[%s#%d] 失败: %w", r.Name, r.ID, err)
		}
		fwdOK := MarkFwdOK

		// ① pre_mark：判定 + 打标
		pre := Rule{
			Chain:          ChainDnat,
			WorkChain:      "pre", // 判定阶段：打 ct mark + FWD_OK
			Comment:        fmt.Sprintf("%s%d:mark", dnatCommentPrefix, r.ID),
			Proto:          string(r.Proto),
			DstPort:        r.ListenAt.Port(),
			CtStateNew:     true,
			SetCtMark:      &mark,
			SetMetaMark:    &fwdOK,
			Counter:        true,
			MetaMarkNotSet: nil,
		}
		if srcs := domainrule.ExpandedSources(r); len(srcs) > 0 {
			pre.Src = AddrMatch{Prefixes: srcs}
		}
		// 只对「目标是本规则 VIP」的流量生效，避免把去往其他地址的同端口流量
		// 也打上本规则的 ct mark。
		pre.Dst = AddrMatch{Prefixes: []netip.Prefix{
			netip.PrefixFrom(r.ListenAt.Addr(), r.ListenAt.Addr().BitLen()),
		}}
		out = append(out, pre)

		// ② dnat：按 ct mark 改写（不再判断源——判定已在 ① 完成）
		ruleMark := mark & CtRuleMask
		out = append(out, Rule{
			Chain:     ChainDnat,
			WorkChain: "dnat", // 改写阶段：按 ct mark 做 DNAT
			Comment:   fmt.Sprintf("%s%d:apply", dnatCommentPrefix, r.ID),
			Proto:     string(r.Proto),
			// VIP 侧端口作为「传输层上下文锚点」：内核要求协议匹配后紧跟
			// 一个传输层字段，否则 `tcp ct mark ...` 报 syntax error（实测）。
			// 注意这里匹配的是 **VIP 端口**（DNAT 之前），不是后端端口。
			DstPort:  r.ListenAt.Port(),
			CtMarkEq: &ruleMark,
			DnatTo:   r.Backend,
			Counter:  true,
		})
	}
	return out, nil
}

// snatCommentPrefix 是 SNAT 规则 comment 前缀。
const snatCommentPrefix = "haweb:snat:"

// SnatSpec 是编译 SNAT 所需的输入。
type SnatSpec struct {
	Rule   model.Rule
	Egress model.Egress
}

// CompileSnat 把出口与池编译成 SNAT 段。
//
// 语义：只对「命中本规则 DNAT」的连接做 SNAT，源地址改成出口的 SourceIP
// （未配置则用池分配）。判据是 ct mark 的 rule_id 位段，与 DNAT 侧共用同一
// 个 mark——这就是用 ct mark 取代 meta mark 的核心收益：回程包自动带 mark，
// 不需要额外的「回程计数行」去兜。
func CompileSnat(specs []SnatSpec) ([]Rule, error) {
	out := make([]Rule, 0, len(specs))
	for _, s := range specs {
		r := s.Rule
		if !r.Enabled {
			continue
		}
		if err := s.Egress.Validate(); err != nil {
			return nil, fmt.Errorf("编译 SNAT 规则[%s#%d] 失败: %w", r.Name, r.ID, err)
		}
		ruleMark, err := MakeCtMark(uint32(r.ID), 0)
		if err != nil {
			return nil, fmt.Errorf("编译 SNAT 规则[%s#%d] 失败: %w", r.Name, r.ID, err)
		}
		masked := ruleMark & CtRuleMask

		// 固定源地址优先；否则用池（池的成员选择在 domain/snat 里算，
		// 这里只生成「按 ct mark 做 snat to <addr>」的规则）
		snatTo := s.Egress.SourceIP
		if !snatTo.IsValid() && r.Pool.Len() > 0 {
			members := r.Pool.Members()
			snatTo = members[0] // 单成员退化；多成员由 adapter 用 map/numgen 展开
		}
		if !snatTo.IsValid() {
			// 没配源地址也没配池：不做 SNAT（源地址保持客户端原样）。
			// 这是合法配置（纯 DNAT 场景），不报错。
			continue
		}
		out = append(out, Rule{
			Chain:     ChainSnat,
			WorkChain: "snat",
			Comment:   fmt.Sprintf("%s%d", snatCommentPrefix, r.ID),
			Proto:     string(r.Proto),
			// DstPort 在这里是「传输层上下文锚点」，不是匹配条件：
			// 内核要求协议匹配后紧跟一个传输层字段，否则 `tcp ct mark ...`
			// 会报 syntax error（实测）。用规则自身的监听端口即可。
			DstPort:  r.ListenAt.Port(),
			CtMarkEq: &masked,
			SnatTo:   snatTo,
			Counter:  true,
		})
	}
	return out, nil
}

// policyCommentPrefix 是策略规则 comment 前缀。
const policyCommentPrefix = "haweb:policy:"

// CompilePolicies 把策略编译成 nft 规则。
//
// 三态语义（D-14，技术方案 §3.6）：
//
//	accept → meta mark |= POLICY_OK，**不终结**（仍需规则白名单命中）
//	allow  → verdict accept（终结放行）
//	drop   → verdict drop（终结拒绝）+ 带 counter 供拒绝日志用
//
// 顺序必须由 policy.Sorted 决定（Order 升序，同 Order 按 ID），否则评估
// 语义与用户预期不符。
func CompilePolicies(policies []model.Policy) ([]Rule, error) {
	if err := policy.Validate(policies); err != nil {
		return nil, err
	}
	sorted := policy.EnabledSorted(policies)
	out := make([]Rule, 0, len(sorted))
	for _, p := range sorted {
		mark := MarkPolicyOK
		rule := Rule{
			Chain:   ChainWorkA, // 策略段应挂在工作链，由 adapter 决定具体链
			Comment: fmt.Sprintf("%s%d", policyCommentPrefix, p.ID),
			Proto:   string(p.Proto),
			DstPort: p.Port,
			Counter: true,
		}
		if srcs := policy.ExpandedSources(p); len(srcs) > 0 {
			rule.Src = AddrMatch{Prefixes: srcs}
		}
		switch p.Action {
		case model.ActionAccept:
			rule.SetMetaMark = &mark
		case model.ActionAllow:
			rule.Verdict = "accept"
		case model.ActionDrop:
			rule.Verdict = "drop"
		}
		out = append(out, rule)
	}
	return out, nil
}

// denyCommentPrefix 是默认拒绝行 comment 前缀。
const denyCommentPrefix = "haweb:deny:"

// IcmpExempt 是必须豁免的 ICMP 类型（IPv4 的 3/11，IPv6 的 1/2/3）。
//
// 为什么必须豁免（技术方案 §3.3(c)）：路径 MTU 发现依赖 ICMP
// destination-unreachable（含 frag-needed）与 time-exceeded。若默认拒绝无条件
// drop 所有未打标流量，这些差错报文也被 drop，结果是「大包黑洞」——
// ping 小包通、大包不通，且极难排查。
var IcmpExempt = []struct {
	Family string
	Types  []uint8
}{
	{"ipv4", []uint8{3, 11}},   // destination-unreachable, time-exceeded
	{"ipv6", []uint8{1, 2, 3}}, // unreachable, packet-too-big, time-exceeded
}

// CompileDefaultDeny 编译默认拒绝段。
//
// 三档作用域（技术方案 §3.6）：
//
//	off          → 不生成任何规则
//	dnat_target  → 只拒「目标 ∈ backendTargets」的未打标流量 【默认档】
//	interface    → 拒整个入口（现有行为，危险，D-13）
//
// dnat_target 是默认档的理由：只影响「目标是本产品后端但源不在白名单」的
// 流量，同机的 Docker（172.17.0.0/16）、K8s pod 网段等其他转发完全不受影响。
// interface 档会误杀这些，正是因为旧实现按 iifname 判范围（D-13）。
func CompileDefaultDeny(scope model.DenyScope, backendTargets []netip.Addr) ([]Rule, error) {
	if scope == "" {
		scope = model.ScopeDnatTarget
	}
	if !scope.Valid() {
		return nil, fmt.Errorf("编译默认拒绝失败: 作用域 %q 无效", string(scope))
	}
	if scope == model.ScopeOff {
		return nil, nil
	}

	mark := MarkFwdOK
	var out []Rule

	// ICMP 差错报文豁免必须排在 drop **之前**——否则差错报文先被 drop，
	// 后面的豁免规则永远看不到它们。
	for _, ex := range IcmpExempt {
		out = append(out, Rule{
			Chain:      ChainDnat,
			WorkChain:  "fwd",
			Comment:    fmt.Sprintf("%sicmp:%s", denyCommentPrefix, ex.Family),
			Proto:      "", // ICMP 不是 tcp/udp
			IcmpFamily: ex.Family,
			IcmpTypes:  ex.Types,
			Verdict:    "accept",
		})
	}

	drop := Rule{
		Chain:          ChainDnat,
		Comment:        denyCommentPrefix + string(scope),
		CtStateNew:     true,
		MetaMarkNotSet: &mark,
		Counter:        true,
		Verdict:        "drop",
	}
	switch scope {
	case model.ScopeDnatTarget:
		if len(backendTargets) == 0 {
			// 没有后端目标 → 拒绝范围为空 → 不生成 drop 行。
			// 这是正确的：没有 DNAT 规则时不该拒绝任何转发。
			return out, nil
		}
		prefixes := make([]netip.Prefix, 0, len(backendTargets))
		for _, a := range backendTargets {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
		drop.Dst = AddrMatch{Prefixes: SortedPrefixes(prefixes)}
	case model.ScopeInterface:
		// 不设 Dst 条件 → 作用于该链覆盖的全部转发流量
	}
	out = append(out, drop)
	return out, nil
}

// forwardCommentPrefix 是规则白名单行 comment 前缀。
const forwardCommentPrefix = "haweb:fwd:"

// CompileForward 编译规则白名单段。
//
// 语义：命中「某条启用规则的后端 + 源在白名单内」的流量 → meta mark |= FWD_OK。
// 默认拒绝行只认 FWD_OK 这一位，所以这段是所有放行判断的基础。
//
// 回程包（established/related）不需要额外规则——ct mark 贯穿连接双向，
// 由 pre_mark 链的 established 规则统一打标（见 CompileEstablished）。
func CompileForward(rules []model.Rule) ([]Rule, error) {
	enabled := domainrule.Enabled(domainrule.SortByID(rules))
	out := make([]Rule, 0, len(enabled))
	fwdOK := MarkFwdOK
	for _, r := range enabled {
		rule := Rule{
			Chain: fmt.Sprintf("%s%d", forwardCommentPrefix, r.ID),
			// comment 用规则 ID 而非名称：名称可能含空格/冒号，且允许重名，
			// 而 Applier 靠 comment 精确删除，必须唯一稳定。
			Comment:     fmt.Sprintf("%s%d", forwardCommentPrefix, r.ID),
			Proto:       string(r.Proto),
			DstPort:     r.Backend.Port(),
			CtStateNew:  true,
			SetMetaMark: &fwdOK,
			Counter:     true,
			Dst: AddrMatch{Prefixes: []netip.Prefix{
				netip.PrefixFrom(r.Backend.Addr(), r.Backend.Addr().BitLen()),
			}},
		}
		if srcs := domainrule.ExpandedSources(r); len(srcs) > 0 {
			rule.Src = AddrMatch{Prefixes: srcs}
		}
		out = append(out, rule)
	}
	return out, nil
}

// establishedComment 是回程放行规则的 comment。
const establishedComment = "haweb:established"

// CompileEstablished 生成回程放行规则。
//
//	ct state established,related → meta mark |= FWD_OK
//
// 为什么需要它：DNAT 后回程包（后端→客户端）的方向与去程相反，源白名单
// 匹配不上（源是后端而非客户端）。靠 conntrack 状态判定才是正确的做法。
//
// 这条规则必须在 pre_mark 链**最先**执行，否则已经处于 established 状态的
// 连接在配置重载瞬间会被默认拒绝误杀。
func CompileEstablished() []Rule {
	fwdOK := MarkFwdOK
	return []Rule{{
		Chain:       ChainDnat,
		WorkChain:   "pre", // 显式：回程放行属于 pre_mark 阶段
		Comment:     establishedComment,
		SetMetaMark: &fwdOK,
		// 由 adapter 翻译成 ct state established,related
		CtStateNew: false,
		Counter:    true,
	}}
}

// EstablishedComment 暴露 comment 常量供测试与 adapter 使用。
func EstablishedComment() string { return establishedComment }
