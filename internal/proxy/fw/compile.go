// snat 规则 → nftables 规则序列编译（链形态见 design-fwgateway.md 总体架构）。
package fw

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"haproxyweb/internal/nft"
)

// Rule 编译产物：目标链 + 规则（含标记）。
type Rule struct {
	Chain string // nft.Chain* 常量名
	Rule  *nftables.Rule
}

// CompileSNAT 把一条 snat 规则编译为 nftables 规则集。
//
// 形态（沿承 iptables 时代语义，AC-1.1 等价迁移）：
//   - fwd 链：目标黑名单行（blacklist，先于放行命中）→ 源匹配放行行
//     （whitelist 空态=黑洞行）→ established 打标行（pre_mark）
//   - pre_mark 链：ct established → set mark（旧 conntrack 回程放行的等价物）
//   - srcnat 链：iif in + saddr ∈ 白名单 → snat OutIP（无名单=无 -s 形态）
func CompileSNAT(s Spec) ([]Rule, error) {
	if v4(s.OutIP) == nil && s.OutIP != "" {
		return nil, fmt.Errorf("SNAT 源 %s 不是合法 IPv4", s.OutIP)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: nft.Table}
	ud := nft.Comment(nft.KindSNAT, s.ID)
	var out []Rule

	// ① pre_mark：established/related 打放行标记（回程与后续包的短路）。
	out = append(out, Rule{Chain: nft.ChainPreMark, Rule: &nftables.Rule{
		Table: tbl, UserData: []byte(ud),
		Exprs: append([]expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:  binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		}, nft.SetMarkExprs(nft.MarkFwdOK)...),
	}})

	srcs := s.AllowSrcs
	noSrc := len(srcs) == 0 // 无名单形态：穿越不加源限制（off 模式全放行语义）

	// ② fwd：目标黑名单 DROP（每目标×源一行；无源黑名单语义黑洞化在上游处理的名单条件下）
	if s.DstMode == "blacklist" {
		for _, d := range s.DstDeny {
			dst := v4(d)
			if dst == nil {
				return nil, fmt.Errorf("目标黑名单 %s 不是合法 IPv4", d)
			}
			exprs := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(s.IfIn)},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offDaddr, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: dst},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictDrop},
			}
			out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
				Table: tbl, UserData: []byte(ud), Exprs: exprs,
			}})
		}
	}

	// ③ fwd：源白名单放行（白名单各源一行 OR 语义；whitelist 空=上游黑洞化不进此分支）
	if s.DstMode == "whitelist" && len(s.DstAllow) > 0 {
		for _, src := range srcs {
			for _, d := range s.DstAllow {
				dst := v4(d)
				if dst == nil {
					return nil, fmt.Errorf("目标白名单 %s 不是合法 IPv4", d)
				}
				out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
					Table: tbl, UserData: []byte(ud),
					Exprs: withCounterMark(srcMatchExprs(s.IfIn, src)),
				}})
				_ = dst
			}
		}
	}

	// ④ fwd：目标无限制（off / 空白名单）的源放行 + 非白名单兜底拒绝
	//   （承旧"链尾 policy DROP"语义 → 自有 fwd 链尾"入口命中且未标记 → DROP"，
	//    仅对本规则源集之外流量；标记=已放行短路）
	if s.DstMode != "whitelist" || len(s.DstAllow) == 0 {
		for _, src := range srcs {
			ex := srcMatchExprs(s.IfIn, src)
			out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
				Table: tbl, UserData: []byte(ud),
				Exprs: withCounterMark(ex),
			}})
		}
		if noSrc {
			// off 且无源：仅入口网卡维度的放行（旧形态"无 -s ACCEPT"等价）
			out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
				Table: tbl, UserData: []byte(ud),
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(s.IfIn)},
					&expr.Counter{},
				},
			}})
		}
	}

	// ⑤ srcnat：SNAT 源改写（每源一行）
	if s.OutIP != "" {
		srcList := srcs
		if noSrc {
			srcList = []string{""}
		}
		for _, src := range srcList {
			nat := []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(s.IfIn)},
			}
			if src != "" {
				nat = append(nat, srcMatchExprs(s.IfIn, src)...)
			}
			nat = append(nat,
				&expr.Immediate{Register: 1, Data: v4(s.OutIP)},
				&expr.NAT{Type: expr.NATTypeSourceNAT, Family: unix.AF_INET,
					RegAddrMin: 1, RegAddrMax: 1},
			)
			out = append(out, Rule{Chain: nft.ChainSrcNAT, Rule: &nftables.Rule{
				Table: tbl, UserData: []byte(ud), Exprs: nat,
			}})
		}
	}
	return out, nil
}

// srcMatchExprs 入口网卡 + 源 IP/CIDR 匹配序列（nil CIDR 走单 IP 精确匹配）。
func srcMatchExprs(ifin, src string) []expr.Any {
	ex := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(ifin)},
	}
	ip, ipn, err := net.ParseCIDR(src)
	if err == nil && ipn != nil {
		_ = ip
		// CIDR：saddr & mask == network（Bitwise + Cmp）
		mask := make([]byte, 4)
		copy(mask, ipn.Mask)
		network := ipn.IP.To4()
		return append(ex,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offSaddr, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: mask, Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
		)
	}
	if ip := v4(src); ip != nil {
		return append(ex,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offSaddr, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		)
	}
	// 非法源：永不匹配（防御——上游已校验）
	return append(ex, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 0}})
}

// withCounterMark 放行行尾随：counter + 打放行标记（不修改入参切片）。
func withCounterMark(ex []expr.Any) []expr.Any {
	out := make([]expr.Any, 0, len(ex)+4)
	out = append(out, ex...)
	out = append(out, &expr.Counter{})
	out = append(out, nft.SetMarkExprs(nft.MarkFwdOK)...)
	return out
}

// ifnameBytes 网卡名定长编码（nft meta iifname 要求 16 字节含 NUL）。
func ifnameBytes(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}
