// 防火墙策略 → nftables 规则编译（US3/T106）。
//
// 顺序语义：FwPolicy.Order 升序 = fwd 链评估序。装载为整段重装（策略任一
// 变更 → 清 haweb-nft:pol 全部标记行 → 按 Order 序重装；与规则装载的
// "尾追加即评估序"一致——段内有序，段前后位置由装载顺序决定：策略段装在
// 规则放行段【之前】需要 order 语义上的全局位置——v1 语义：策略先评估
// （PRD 3.7 拒绝优先）由【装配时先装策略段】保证（reinstall 顺序：snat/dnat
// 规则装载各自独立，策略段装在其前需 fwd 链内位置控制——AddCompiled 只有
// 追加；实现方式：策略重装时连带重装规则段？代价高。v1 简化：策略 DROP
// 行同时是"终结"语义，accept 行打标放行——两条都会先于"链尾默认拒绝"；
// 与规则放行行的相对顺序：装载时序决定，语义上"策略与规则白名单 AND
// 语义"（策略 accept + 规则白名单都过才通）由默认拒绝行兜底达成——
// 策略 drop 命中即终结（无论规则）；策略 accept 只打标不终结，规则段
// 不匹配仍由默认拒绝拒——等价 AND 语义，顺序无关。这个设计让顺序问题消失）。
package fw

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"haproxyweb/internal/nft"
)

// PolicySpec 单条策略的内核面参数。
type PolicySpec struct {
	ID        uint
	Order     int
	Action    string // accept / drop
	SrcList   []string
	DstList   []string
	Proto     string // tcp / udp / icmp / any
	PortRange string // "80,443,1000-2000"（逗号分隔端口/范围）
}

// CompilePolicies 编译全部启用策略（Order 升序；内部先做 src×dst×port 展开）。
// accept 行：匹配 → counter + mark（不终结——与规则白名单 AND 语义）；
// drop 行：匹配 → counter + drop（终结）。
func CompilePolicies(ps []PolicySpec) ([]Rule, error) {
	var out []Rule
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: nft.Table}
	for _, p0 := range ps {
		expanded, err := ExpandPolicySpec(p0)
		if err != nil {
			return nil, fmt.Errorf("策略#%d 展开失败: %w", p0.ID, err)
		}
		for _, p := range expanded {
			rule, err := compilePolicyRow(tbl, p)
			if err != nil {
				return nil, fmt.Errorf("策略#%d 编译失败: %w", p.ID, err)
			}
			out = append(out, rule)
		}
	}
	return out, nil
}

// compilePolicyRow 单行策略编译（已展开：每条件至多一条目）。
func compilePolicyRow(tbl *nftables.Table, p PolicySpec) (Rule, error) {
	{
		exprs, err := policyMatchExprs(p)
		if err != nil {
			return Rule{}, err
		}
		ud := nft.Comment(nft.KindPolicy, p.ID)
		if p.Action == "drop" {
			exprs = append(exprs, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
		} else {
			// accept：打标放行（counter + mark；不终结——链尾默认拒绝兜底 AND 语义）
			exprs = withCounterMark(exprs)
		}
		return Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
			Table: tbl, UserData: []byte(ud), Exprs: exprs,
		}}, nil
	}
}

// policyMatchExprs 策略匹配序列：源/目的列表（每方向的列表展开为
// 多行由上层做？——不：策略的列表内多条目是 OR 语义，nftables 无 OR，
// 单列表多条件需展开为多条规则。此处限定单条目列表进单行；
// 多条目时返回多行由 CompilePolicies 上层展开——v1 简化：
// 每策略每（src×dst）一行（笛卡尔积，OR 语义），实现如下。
func policyMatchExprs(p PolicySpec) ([]expr.Any, error) {
	var ex []expr.Any
	// 源匹配（单条目；列表多条件由上层笛卡尔展开）
	if len(p.SrcList) > 1 || len(p.DstList) > 1 {
		return nil, fmt.Errorf("多条目列表需上层笛卡尔展开（编译层只接单条目行）")
	}
	if len(p.SrcList) == 1 {
		ex = append(ex, srcMatchPayloadOnly(p.SrcList[0])...)
	}
	if len(p.DstList) == 1 {
		ex = append(ex, dstMatchExprs(p.DstList[0])...)
	}
	switch p.Proto {
	case "tcp", "udp":
		proto := byte(unix.IPPROTO_TCP)
		if p.Proto == "udp" {
			proto = unix.IPPROTO_UDP
		}
		ex = append(ex,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		)
		ports, err := parsePortGroups(p.PortRange)
		if err != nil {
			return nil, err
		}
		// 端口条件是 OR 组（80,443）——同样需多行展开；单端口/单范围进单行
		if len(ports) > 1 {
			return nil, fmt.Errorf("多端口组需上层展开")
		}
		if len(ports) == 1 {
			ex = append(ex, ports[0]...)
		}
	case "icmp":
		ex = append(ex,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMP}},
		)
		if p.PortRange != "" {
			return nil, fmt.Errorf("icmp 策略不支持端口条件")
		}
	case "any", "":
	default:
		return nil, fmt.Errorf("协议 %q 无效（tcp/udp/icmp/any）", p.Proto)
	}
	return ex, nil
}

// parsePortGroups 端口串 → 每组的 dport 匹配序列（单端口=Cmp、范围=Range）。
// "80,443,1000-2000" → 3 组。空串 → 空（不限端口）。
func parsePortGroups(s string) ([][]expr.Any, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out [][]expr.Any
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, err1 := strconv.Atoi(strings.TrimSpace(lo))
			h, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
				return nil, fmt.Errorf("端口范围 %q 无效", part)
			}
			out = append(out, []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offDport, Len: 2},
				&expr.Range{Op: expr.CmpOpGte, Register: 1,
					FromData: binaryutil.BigEndian.PutUint16(uint16(l)),
					ToData:   binaryutil.BigEndian.PutUint16(uint16(h))},
			})
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("端口 %q 无效", part)
		}
		out = append(out, []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offDport, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(port))},
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("端口串 %q 未解析出有效条件", s)
	}
	return out, nil
}

// ExpandPolicySpec 多条目策略的笛卡尔展开（src×dst×port 单条件行集，OR 语义）。
// 展开后的每一行 Spec 单独编译；它们的 Order/ID 相同（同策略，计数各行合计）。
func ExpandPolicySpec(p PolicySpec) ([]PolicySpec, error) {
	srcs := p.SrcList
	if len(srcs) == 0 {
		srcs = []string{""}
	}
	dsts := p.DstList
	if len(dsts) == 0 {
		dsts = []string{""}
	}
	portGroups, err := parsePortGroups(p.PortRange)
	if err != nil {
		return nil, err
	}
	var out []PolicySpec
	for _, s := range srcs {
		for _, d := range dsts {
			n := p
			if s != "" {
				n.SrcList = []string{s}
			} else {
				n.SrcList = nil
			}
			if d != "" {
				n.DstList = []string{d}
			} else {
				n.DstList = nil
			}
			// 端口维度：每组一行（把 PortRange 重写为单组形态的串——编译层
			// parsePortGroups 再解析一次；省 структура 改动，直接传 spec 串）
			if len(portGroups) <= 1 {
				out = append(out, n)
				continue
			}
			for _, g := range splitPortGroups(p.PortRange) {
				ng := n
				ng.PortRange = g
				out = append(out, ng)
			}
		}
	}
	return out, nil
}

// splitPortGroups 端口串按逗号拆组（展开维度用；与 parsePortGroups 同语法）。
func splitPortGroups(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

var _ = net.ParseIP // 保 net import（dstMatchExprs 在 compile.go）
