// Package compile 把领域对象编译成内核操作的中间表示。
//
// 本包是纯编译层：输入是 domain 的不可变值，输出是不可变的 Plan。
// **没有任何函数参数或返回值是 *netlink.Conn、*sql.DB 之类的外部句柄。**
// 这让单测不需要任何特权、不需要内核、不需要数据库（C-12）。
//
// 三层职责划分：
//
//	domain   实体 + 纯业务判断（能否放行、池选谁）
//	compile  实体 → NftPlan / TcPlan（编译产物，可完整单测）
//	adapter  编译产物 → 内核（唯一碰 netlink/exec 的层）
package compile

import (
	"fmt"
	"net/netip"
	"sort"
)

// Ct mark 位布局（技术方案 §3.2）。
//
// 用 ct mark 而非 meta mark 存规则身份，是因为 meta mark 只有 32 位且旧实现
// 已占用 3 位做状态位，最多容纳 16 条源就会耗尽。ct mark 是 conntrack 条目上
// 的标记，贯穿连接双向：prerouting 写入、postrouting 读取，同一个值。
//
// 实测依据（docs/poc-result.md §6.3 的前置 PoC）：prerouting priority -160 写
// 0x1200，postrouting priority 100 用 `ct mark and 0x0000ff00 == 0x00001200`
// 读回，两条 counter 的字节数完全相等（196,451 / 196,451）→ 跨链可读且位域提取生效。
const (
	// CtRuleShift 是 rule_id 在 ct mark 中的位移。低 8 位留给标志。
	CtRuleShift = 8
	// CtFlagDnat 表示本连接经过 DNAT。
	CtFlagDnat uint32 = 0x1
	// CtFlagHairpin 表示本连接做了 hairpin 改写。
	CtFlagHairpin uint32 = 0x2
	// CtFlagPolicyDrop 表示本连接命中了一条 drop 策略（供拒绝日志区分）。
	CtFlagPolicyDrop uint32 = 0x4

	// CtRuleMask 是提取 rule_id 的掩码。
	CtRuleMask uint32 = 0xFFFFFF00
	// CtFlagMask 是提取标志位的掩码。
	CtFlagMask uint32 = 0x000000FF
)

// Meta mark 位布局：只留两个布尔语义位，默认拒绝只查 bit0。
const (
	// MarkFwdOK 表示命中规则白名单（默认拒绝只认这一位）。
	MarkFwdOK uint32 = 0x1
	// MarkPolicyOK 表示命中策略 accept（仅计数，不参与放行判断）。
	MarkPolicyOK uint32 = 0x2
)

// MakeCtMark 合成 ct mark 值：rule_id << 8 | flags。
//
// ruleID 必须在 24 位内（1,677 万条），否则溢出会被静默截断——
// 这里显式检查而不是让它悄悄出错。
func MakeCtMark(ruleID uint32, flags uint32) (uint32, error) {
	const maxRuleID = (1 << 24) - 1
	if ruleID > maxRuleID {
		return 0, fmt.Errorf("合成 ct mark 失败: 规则 ID %d 超过 24 位上限 %d", ruleID, maxRuleID)
	}
	if flags&^CtFlagMask != 0 {
		return 0, fmt.Errorf("合成 ct mark 失败: 标志位 0x%x 超出低 8 位掩码", flags)
	}
	return ruleID<<CtRuleShift | flags, nil
}

// SplitCtMark 拆解 ct mark 为 (ruleID, flags)。
func SplitCtMark(v uint32) (ruleID uint32, flags uint32) {
	return (v & CtRuleMask) >> CtRuleShift, v & CtFlagMask
}

// Chain 是链名常量。dispatch 是稳定锚点，w_a/w_b 是版本化工作链。
const (
	ChainDispatch = "dispatch"
	ChainWorkA    = "w_a"
	ChainWorkB    = "w_b"
	ChainDnat     = "dnat"
	ChainSnat     = "snat"
	ChainMss      = "mss"
	ChainInput    = "input"
)

// Hook 是一条链挂载的 netfilter hook。
type Hook string

const (
	HookPrerouting  Hook = "prerouting"
	HookForward     Hook = "forward"
	HookPostrouting Hook = "postrouting"
)

// ChainSpec 描述一条链的挂载方式。
//
// Priority 的取值有一个实测约束：同一 hook 上不同 priority 的链**都会被执行**，
// 前序链的 policy accept **不会**短路后续链（四探针链各 72,029 包，完全相等，
// 见 docs/poc-result.md §6.3.1）。但 `drop` 会终结。
type ChainSpec struct {
	Name     string
	Hook     Hook
	Priority int32
	// Type 为空表示普通链（只能被 jump 进入，不挂 hook）。
	Type string
}

// AddrMatch 描述一个地址匹配条件。
//
// Negated 为 true 表示「不匹配」。编译层据此生成 `!=` 比较而不是另建一条规则——
// 后者会在规则数量上翻倍，且让 `nft list` 难以人工核对。
type AddrMatch struct {
	// Prefixes 为空表示「匹配所有」——此时**不生成**任何匹配表达式。
	Prefixes []netip.Prefix
	Negated  bool
}

// Empty 报告该条件是否为空（不需要生成匹配表达式）。
func (m AddrMatch) Empty() bool { return len(m.Prefixes) == 0 }

// Rule 是一条**已完全展开**的 nft 规则。
//
// 与 domain.Rule 的区别：domain.Rule 是业务实体（含带宽包、连接数等与内核
// 无关的字段）；compile.Rule 只保留下发内核必需的信息，且所有多值字段都已
// 展开成可逐条下发的形态。
type Rule struct {
	Chain string
	// Comment 用于 `nft list` 人工核对与精确删除（按 comment 匹配）。
	// 必须唯一且稳定。
	Comment string

	Proto   string // "tcp" / "udp" / ""（不限）
	DstPort uint16 // 0 = 不限
	Src     AddrMatch
	Dst     AddrMatch

	// CtMarkEq 非 nil 时生成 `ct mark and 0xFFFFFF00 == <值>` 条件。
	CtMarkEq *uint32
	// CtStateNew 为 true 时生成 `ct state new` 条件。
	CtStateNew bool
	// MetaMarkNotSet 非空时生成 `meta mark & <mask> == 0` 条件。
	MetaMarkNotSet *uint32

	// DnatTo 非零时生成 dnat 语句。
	DnatTo netip.AddrPort
	// SnatTo 非零时生成 snat 语句。
	SnatTo netip.Addr
	// SetCtMark 非零时生成 `ct mark set <值>`。
	SetCtMark *uint32
	// SetMetaMark 非零时生成 `meta mark set meta mark | <值>`（OR 语义）。
	SetMetaMark *uint32

	// Counter 为 true 时该规则带计数器。
	Counter bool
	// Verdict 是终结动作：""（无）/ "accept" / "drop"。
	Verdict string
	// JumpTo 非空时生成 jump（与 Verdict 互斥）。
	JumpTo string

	// MSSValue 非零时该规则是 MSS clamping：`tcp flags syn tcp option maxseg
	// size set <MSSValue>`。MSSFamily 决定挂 v4 还是 v6 匹配（"ipv4"/"ipv6"）。
	//
	// 用专用字段而非复用 DnatTo 之类，是为了让 adapter 明确知道这条规则要
	// 生成 exthdr + payload-write 表达式，而不是地址改写。
	MSSValue  uint16
	MSSFamily string
}

// String 输出人类可读的单行描述（供日志与测试断言）。
func (r Rule) String() string {
	return fmt.Sprintf("%s|%s", r.Chain, r.Comment)
}

// NftPlan 表达「内核上应有的全貌」，而非 diff。
//
// 不变量：构造完成后不可变。Applier 负责与内核现状比对后决定最小操作集。
type NftPlan struct {
	Chains []ChainSpec
	// Forward / Policy / Dnat / Snat / Mss / Deny 按评估顺序排列。
	Forward []Rule
	Policy  []Rule
	Dnat    []Rule
	Snat    []Rule
	Mss     []Rule
	Deny    []Rule
	// BackendTargets 是 dnat_target 默认拒绝作用域的地址集合（已排序去重）。
	BackendTargets []netip.Addr
}

// RuleCount 返回计划中的规则总数（供自检用）。
func (p NftPlan) RuleCount() int {
	return len(p.Forward) + len(p.Policy) + len(p.Dnat) +
		len(p.Snat) + len(p.Mss) + len(p.Deny)
}

// TcClassSpec 是 htb 类规格。
//
// 单位约束（D-07，最容易错的一处）：**Rate/Ceil 是 bytes/sec**，
// 而 `tc` CLI 的 kbit/mbit 是 bit/sec。换算错 8 倍是这块的经典 bug。
type TcClassSpec struct {
	ClassID uint32 // 如 0x10000 表示 1:100；1:NNN 用 0x10000|NNN
	// ParentClassID 为 0 表示直接挂在 qdisc 根下。
	ParentClassID uint32
	RateBytes     uint64 // bytes/sec（= bps / 8）
	CeilBytes     uint64 // bytes/sec
	BurstBytes    uint32
	CburstBytes   uint32
	// IsLeaf 为 true 表示该 class 应挂 fq_codel。
	//
	// 这个标记的存在理由（实测，docs/poc-result.md §3.2）：
	//   - 内层 class 挂 fq_codel 会直接失败：`RTNETLINK answers: Invalid argument`
	//   - 叶子 class 不挂 fq_codel 时该 class 无队列，落进去的包会走 direct 绕过
	// 所以「是不是叶子」必须由编译层显式决定，不能靠 adapter 猜测。
	IsLeaf bool
}

// TcFilterSpec 是 u32 分类过滤器规格。
//
// **方向约束（C-17 / D-16）**：MatchSrc 为 true 时用 `match ip src`，
// false 时用 `match ip dst`。两个方向严禁照抄：
//   - 下载（出口网卡）：回程包 daddr=客户端 → MatchSrc=false
//   - 上传（ifb）：包进 ifb 后 daddr 是公网服务器、saddr 才是客户端 → MatchSrc=true
//
// 写反的后果是静默的：filter 永不命中 → 全部走 default → 实测 8MB/s 配置
// 跑出 118.51MB/s（14.8 倍）。
type TcFilterSpec struct {
	// Device 是挂载设备（出口网卡，或 ifb-<bwID>）。
	Device string
	// Parent 是 qdisc handle，如 "1:"。
	Parent string
	// Pref 必须按方向分段派生，不许写死 10（D-17）。
	Pref     uint16
	MatchSrc bool
	// Match 是展开后的地址/网段（v4 归一化由 adapter 负责）。
	Match netip.Prefix
	// FlowID 是目标 class，如 "1:208"。
	FlowID string
}

// Dir 返回该过滤器方向的字符串表示（"src" / "dst"），供日志与断言。
func (f TcFilterSpec) Dir() string {
	if f.MatchSrc {
		return "src"
	}
	return "dst"
}

// TcQdiscSpec 是一条 qdisc 规格。
type TcQdiscSpec struct {
	Device string
	Parent string // "root" 或 class handle
	Handle string
	Kind   string // "htb" / "fq_codel" / "ingress"
	// Default 仅对 htb 根 qdisc 有意义：必须是**叶子** class 的 minor。
	//
	// 实测约束（docs/poc-result.md §3.2）：default 指向挂了子类的内层 class
	// 时，未命中 filter 的包进不了任何队列，内核走 direct queue 绕过整棵树
	// （2828.79 MB/s vs 配置 8）。所以这个字段的合法性由 Validate 强制检查。
	Default uint32
}

// TcPlan 是补偿式应用的 tc 计划（tc 无事务，只能靠逆操作回滚）。
type TcPlan struct {
	Qdiscs  []TcQdiscSpec
	Classes []TcClassSpec
	Filters []TcFilterSpec
	// Inverses 按逆序执行以回滚。
	Inverses []TcOp
}

// TcOp 是一次可逆的 tc 操作记录。
type TcOp struct {
	Kind   string // "qdisc-del" / "class-del" / "filter-del"
	Device string
	Target string
}

// Empty 报告该计划是否为空（无任何限速需求）。
func (p TcPlan) Empty() bool {
	return len(p.Qdiscs) == 0 && len(p.Classes) == 0 && len(p.Filters) == 0
}

// Validate 校验 tc 计划的硬约束。任何一条不满足都返回错误——
// 这些约束一旦静默破坏，限速会「看起来配了但完全不生效」。
func (p TcPlan) Validate() error {
	classes := make(map[uint32]TcClassSpec, len(p.Classes))
	for _, c := range p.Classes {
		classes[c.ClassID] = c
	}
	hasChildren := make(map[uint32]bool, len(p.Classes))
	for _, c := range p.Classes {
		if c.ParentClassID != 0 {
			hasChildren[c.ParentClassID] = true
		}
	}
	// 硬约束 1：htb 的 default 必须指向叶子 class
	for _, q := range p.Qdiscs {
		if q.Kind != "htb" || q.Default == 0 {
			continue
		}
		for _, c := range p.Classes {
			if classMinor(c.ClassID) != q.Default {
				continue
			}
			if hasChildren[c.ClassID] {
				return fmt.Errorf(
					"校验 tc 计划失败: %s 的 default 指向 1:%d，但该类有子类（内层类）。"+
						"未分类流量会走 direct queue 绕过整棵限速树",
					q.Device, q.Default)
			}
			if !c.IsLeaf {
				return fmt.Errorf(
					"校验 tc 计划失败: %s 的 default 指向 1:%d，但该类未标记 IsLeaf（无队列）。"+
						"落进去的包会走 direct queue 绕过限速",
					q.Device, q.Default)
			}
		}
	}
	// 硬约束 2：内层 class 不能标 IsLeaf（挂 fq_codel 会 EINVAL）
	for _, c := range p.Classes {
		if c.IsLeaf && hasChildren[c.ClassID] {
			return fmt.Errorf(
				"校验 tc 计划失败: class 1:%d 既标了 IsLeaf 又有子类。"+
					"内层类挂 fq_codel 会返回 RTNETLINK answers: Invalid argument",
				classMinor(c.ClassID))
		}
	}
	// 硬约束 3：filter 的 flowid 必须存在且是叶子
	for _, f := range p.Filters {
		var minor uint32
		if _, err := fmt.Sscanf(f.FlowID, "1:%d", &minor); err != nil {
			return fmt.Errorf("校验 tc 计划失败: filter 的 flowid %q 格式无效", f.FlowID)
		}
		id := uint32(0x10000) | minor
		c, ok := classes[id]
		if !ok {
			return fmt.Errorf("校验 tc 计划失败: filter 的 flowid %q 没有对应的 class", f.FlowID)
		}
		if hasChildren[id] {
			return fmt.Errorf(
				"校验 tc 计划失败: filter 的 flowid %q 指向内层类（有子类）。"+
					"实测该情况下流量会落到 default 而不是该 class", f.FlowID)
		}
		_ = c
	}
	// 硬约束 4：pref 不许为 0（0 是 tc 的保留值），且下载/上传必须分段
	for _, f := range p.Filters {
		if f.Pref == 0 {
			return fmt.Errorf("校验 tc 计划失败: %s 上的 filter pref 为 0（保留值）", f.Device)
		}
	}
	return nil
}

// classMinor 提取 class major:minor 中的 minor。
func classMinor(classID uint32) uint32 { return classID & 0xFFFF }

// Plan 是一次配置变更的完整内核操作计划。不可变。
type Plan struct {
	Version uint64
	Nft     NftPlan
	Tc      TcPlan
	// Warnings 是编译期发现但不致命的问题（如 tc 不可用导致限速降级）。
	// **必须**上报给 UI，不能静默丢弃。
	Warnings []string
}

// Validate 校验整份计划的硬约束。
func (p Plan) Validate() error {
	if err := p.Tc.Validate(); err != nil {
		return err
	}
	// comment 必须唯一——Applier 靠它精确删除规则
	seen := make(map[string]struct{}, p.Nft.RuleCount())
	for _, group := range [][]Rule{p.Nft.Forward, p.Nft.Policy, p.Nft.Dnat,
		p.Nft.Snat, p.Nft.Mss, p.Nft.Deny} {
		for _, r := range group {
			if r.Comment == "" {
				return fmt.Errorf("校验计划失败: %s 链有一条规则没有 comment，无法精确删除", r.Chain)
			}
			if _, dup := seen[r.Comment]; dup {
				return fmt.Errorf("校验计划失败: comment %q 重复（必须唯一）", r.Comment)
			}
			seen[r.Comment] = struct{}{}
		}
	}
	return nil
}

// SortedPrefixes 返回去重、排序、归零后的网段列表。
//
// 三个动作都必要：
//   - 去重：多次出现的同一网段会让内核 set 报重复元素
//   - 排序：顺序不稳定会导致每次 Apply 生成不同的规则文本，产生无意义 diff
//   - 归零：10.1.2.3/8 与 10.0.0.0/8 在 nft 里语义不同，前者只匹配一个地址
func SortedPrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		m := p.Masked()
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() != out[j].Addr() {
			return out[i].Addr().Less(out[j].Addr())
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}
