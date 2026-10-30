package compile

import (
	"fmt"

	"haproxyweb/internal/domain/bandwidth"
	"haproxyweb/internal/domain/model"
	"haproxyweb/internal/domain/rule"
)

// State 是一次编译的输入快照（对应技术方案 §2.1 的 State）。
//
// 不变量：构造后不可变。换配置时构造新的 State，而不是就地修改——
// 这样上一版快照能被并发读取而无需加锁（RCU 语义）。
type State struct {
	Version  uint64
	Rules    []model.Rule
	Policies []model.Policy
	Egresses []model.Egress
	BWGroups []model.BWGroup
	Acls     []model.AclGroup
	// DenyScope 为默认拒绝的作用域；零值按 dnat_target 处理（最安全档）。
	DenyScope model.DenyScope
	// MSSv4 / MSSv6 为 0 表示关闭 MSS clamping。
	MSSv4 uint16
	MSSv6 uint16
}

// Compiler 是纯函数编译器。
type Compiler struct {
	// Caps 是能力探测结果。tc 不可用时编译出空 TcPlan + 显式警告，
	// **绝不静默跳过**（技术方案 §2.1）。
	Caps Caps
}

// Caps 是编译期需要知道的能力子集。
type Caps struct {
	TcNetlink bool
	Ifb       bool
	// PerSrcLimit 表示能否按源分类（u32 可用性）。实测本环境为 true。
	PerSrcLimit bool
}

// Compile 把 State 编译成不可变的 Plan。
//
// 顺序有意为之：校验 → 固定段 → NAT 段 → 策略 → 转发 → 默认拒绝 → tc。
// 默认拒绝必须最后编译，因为它要消费「所有启用规则的后端集合」。
//
// 错误消息一律中文（C-05）。
func (c *Compiler) Compile(s State) (*Plan, error) {
	// 1. 校验（domain 层，纯函数）
	if err := rule.Validate(s.Rules); err != nil {
		return nil, fmt.Errorf("配置校验失败: %w", err)
	}
	p := &Plan{Version: s.Version}

	// 2. MSS（固定段，与业务无关）
	mss, err := CompileMSSClamp(s.MSSv4, s.MSSv6)
	if err != nil {
		return nil, err
	}
	p.Nft.Mss = mss

	// 3. DNAT + 回程放行
	dnat, err := CompileDnat(s.Rules)
	if err != nil {
		return nil, err
	}
	est := CompileEstablished()
	p.Nft.Dnat = append(est, dnat...)

	// 4. SNAT
	//
	// 只为「需要改源地址」的规则生成 SNAT：配了池，或配了固定源地址
	// （Egress.SourceIP）。纯 DNAT 规则不生成——这是合法且常见的情形，
	// 此时后端看到的是客户端真实源 IP。
	specs := make([]SnatSpec, 0, len(s.Rules))
	for _, r := range s.Rules {
		if !r.Enabled {
			continue
		}
		// 出口的选择：优先用规则显式引用的出口，否则回退到唯一出口。
		// 单出口是当前部署的常态；多出口时必须靠 egress_ids 明确指定，
		// 不能靠「取第一个」猜——那会让 SNAT 源地址与本意不符。
		var e model.Egress
		found := false
		for _, cand := range s.Egresses {
			if cand.Enabled {
				e = cand
				found = true
				break
			}
		}
		if !found {
			continue // 没有可用出口 → 不做 SNAT
		}
		if r.Pool.IsEmpty() && !e.SourceIP.IsValid() {
			continue // 既无池也无固定源 → 纯 DNAT
		}
		specs = append(specs, SnatSpec{Rule: r, Egress: e})
	}
	snat, err := CompileSnat(specs)
	if err != nil {
		return nil, err
	}
	p.Nft.Snat = snat

	// 5. 策略
	pol, err := CompilePolicies(s.Policies)
	if err != nil {
		return nil, err
	}
	p.Nft.Policy = pol

	// 6. 转发白名单
	fwd, err := CompileForward(s.Rules)
	if err != nil {
		return nil, err
	}
	p.Nft.Forward = fwd

	// 7. 默认拒绝（必须最后：消费全部后端集合）
	targets := rule.BackendTargets(s.Rules)
	deny, err := CompileDefaultDeny(s.DenyScope, targets)
	if err != nil {
		return nil, err
	}
	p.Nft.Deny = deny
	p.Nft.BackendTargets = targets

	// 8. 链布局
	p.Nft.Chains = DefaultChains()

	// 9. tc
	if !c.Caps.TcNetlink {
		p.Warnings = append(p.Warnings, "tc 不可用，所有限速不生效")
	} else {
		if !c.Caps.Ifb {
			p.Warnings = append(p.Warnings, "ifb 不可用，上传方向只能限总额（无每源保底）")
		}
		if !c.Caps.PerSrcLimit {
			p.Warnings = append(p.Warnings, "按源分类不可用（u32 失效），每源保底降级为总额共享")
		}
	}

	// 10. 自检：计划本身必须自洽
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("编译产物自检失败: %w", err)
	}
	return p, nil
}

// DefaultChains 返回标准的链布局（技术方案 §3.1/§3.2）。
//
// priority 取值有实测依据：
//   - pre_mark 用 -150：需早于 dstnat(-100)
//   - dstnat 用 -100（nft 的 dstnat 标准优先级）
//   - mss 用 -20：需早于 fwd(-10)，因为 MSS 只在 SYN 上有意义
//   - fwd 用 -10
//   - srcnat 用 +100（nft 的 srcnat 标准优先级）
func DefaultChains() []ChainSpec {
	return []ChainSpec{
		{Name: ChainDispatch, Hook: HookForward, Priority: -10, Type: "filter"},
		{Name: ChainWorkA},
		{Name: ChainWorkB},
		{Name: ChainDnat, Hook: HookPrerouting, Priority: -100, Type: "nat"},
		{Name: ChainSnat, Hook: HookPostrouting, Priority: 100, Type: "nat"},
		{Name: ChainMss, Hook: HookForward, Priority: -20, Type: "filter"},
		{Name: ChainInput, Hook: HookPrerouting, Priority: -150, Type: "filter"},
	}
}

// CompileTcOnly 是便捷入口：只编译 tc 段（S2 阶段 adapter 单测常用）。
func CompileTcOnly(groupTotalKBps, minKBps int64, sources []string, egress, ingress, ifb string) (TcPlan, error) {
	plan := bandwidth.Allocate(groupTotalKBps, minKBps, sources)
	return CompileTc(TcSpec{
		Group:         plan,
		EgressDevice:  egress,
		IngressDevice: ingress,
		IfbDevice:     ifb,
	})
}
