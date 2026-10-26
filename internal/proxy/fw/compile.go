// snat 规则 → nftables 规则序列编译（链形态见 design-fwgateway.md 总体架构；
// 旧 iptables 形态对照见 snat.go iptablesArgs 注释——两处形态必须逐行对齐）。
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
// 形态（与旧 iptables 形态逐行等价，AC-1.1）：
//   - fwd 链：② 目标黑名单 DROP（每 源×目标 一行，带 -s 维度）→
//     ③④ 源匹配放行行（off 无源=仅入口网卡行）——全部带 iif+oif 双维度
//   - pre_mark 链：① established/related → set mark（旧 conntrack 放行行等价）
//   - srcnat 链：⑤ iif+oif(+源) → snat OutIP
//
// 编译失败返回错误（fail-fast，绝不产出残缺序列）。
func CompileSNAT(s Spec) ([]Rule, error) {
	if s.OutIP == "" {
		// 旧 installSnat 的 fail-fast 语义沿承：空 SNAT 源装出去就是单向黑洞
		// （出去的包源是私网地址、回程必丢）——宁可拒绝安装
		return nil, fmt.Errorf("出口网卡 %s 无 IP 地址（SNAT 源为空）", s.IfOut)
	}
	if v4(s.OutIP) == nil && v4OrV6(s.OutIP) == nil {
		return nil, fmt.Errorf("SNAT 源 %s 不是合法 IP", s.OutIP)
	}
	for _, d := range s.DstDeny {
		if !validDst(d) {
			return nil, fmt.Errorf("目标黑名单 %s 不是合法 IPv4/CIDR", d)
		}
	}
	for _, d := range s.DstAllow {
		if !validDst(d) {
			return nil, fmt.Errorf("目标白名单 %s 不是合法 IPv4/CIDR", d)
		}
	}

	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: nft.Table}
	ud := nft.Comment(nft.KindSNAT, s.ID)
	var out []Rule

	// ① pre_mark：established/related 打放行标记（回程与后续包的短路）。
	// 每规则一条（无 counter，无计数影响；Review-Nit：跨规则冗余但无害，
	// 全局去重需要共享生命周期管理，M3 随多出口重构再收敛）。
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

	// ② fwd：目标黑名单 DROP（每 源×目标 一行，必须带源匹配——无源 DROP 会
	// 误伤同网卡其他规则的源，v2 事故同型；与旧形态 -s 逐字段对齐）
	if s.DstMode == "blacklist" {
		srcList := srcs
		if noSrc {
			// off + 黑名单：buildSnatSpec 已把源黑洞化为 0.0.0.0/32（不匹配任何
			// 真实源），此处仍按无源单行展开与旧形态一致（永不命中，防御形态）
			srcList = []string{""}
		}
		for _, src := range srcList {
			for _, d := range s.DstDeny {
				var ex []expr.Any
				if src != "" {
					ex = srcMatchExprs(s.IfIn, s.IfOut, src)
				} else {
					ex = iifOifExprs(s.IfIn, s.IfOut)
				}
				ex = append(ex, dstMatchExprs(d)...)
				ex = append(ex,
					&expr.Counter{},
					&expr.Verdict{Kind: expr.VerdictDrop},
				)
				out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
					Table: tbl, UserData: []byte(ud), Exprs: ex,
				}})
			}
		}
	}

	// ③ fwd：目标白名单放行（每 源×目标 一行 OR 语义——旧形态 -s/-d 笛卡尔积；
	// 无源形态归一 srcList=[""]——旧 iptablesArgs 对该组合产出
	// "-i in -o out -d <d> ACCEPT" 行，漏归一则 vanilla 宿主目标白名单失效
	// 全放行/有 deny 宿主全拒绝——复审 N4）
	if s.DstMode == "whitelist" && len(s.DstAllow) > 0 {
		srcList := srcs
		if noSrc {
			srcList = []string{""}
		}
		for _, src := range srcList {
			for _, d := range s.DstAllow {
				var ex []expr.Any
				if src != "" {
					ex = srcMatchExprs(s.IfIn, s.IfOut, src)
				} else {
					ex = iifOifExprs(s.IfIn, s.IfOut)
				}
				ex = append(ex, dstMatchExprs(d)...)
				out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
					Table: tbl, UserData: []byte(ud), Exprs: withCounterMark(ex),
				}})
			}
		}
	}

	// ④ fwd：目标无限制（off / 空白名单）的源放行（每源一行；off 无源=仅出入口行）
	if s.DstMode != "whitelist" || len(s.DstAllow) == 0 {
		if noSrc {
			// off 且无源：仅入口/出口网卡维度放行（旧形态"无 -s -i in -o out ACCEPT"等价）
			out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
				Table: tbl, UserData: []byte(ud),
				Exprs: withCounterMark(iifOifExprs(s.IfIn, s.IfOut)),
			}})
		} else {
			for _, src := range srcs {
				out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
					Table: tbl, UserData: []byte(ud),
					Exprs: withCounterMark(srcMatchExprs(s.IfIn, s.IfOut, src)),
				}})
			}
		}
	}

	// ⑤ srcnat：SNAT 源改写（每源一行；off 无源=仅出入口行——均带 oif 出口维度）。
	// 池模式（T207）：每源的改写目标 = Pool 按源确定性映射（同源恒同 IP）
	srcList := srcs
	if noSrc {
		srcList = []string{""}
	}
	for _, src := range srcList {
		var nat []expr.Any
		if src != "" {
			nat = srcMatchExprs(s.IfIn, s.IfOut, src)
		} else {
			nat = iifOifExprs(s.IfIn, s.IfOut)
		}
		outIP := s.OutIP
		if len(s.Pool) > 0 && src != "" {
			if m := PoolMemberOf(src, s.Pool); m != "" {
				outIP = m
			}
		}
		// B8：v6 SNAT（NAT66）——地址族由改写目标推断（v4 4B AF_INET；v6 16B AF_INET6）
		var natIP net.IP
		if ip := v4(outIP); ip != nil {
			natIP = ip
		} else if ip := v4OrV6(outIP); ip != nil {
			natIP = ip
		} else {
			return nil, fmt.Errorf("SNAT 源 %q 不是合法 IP", outIP)
		}
		natFamily := uint32(unix.AF_INET)
		if len(natIP) == 16 {
			natFamily = unix.AF_INET6
		}
		nat = append(nat,
			&expr.Immediate{Register: 1, Data: natIP},
			&expr.NAT{Type: expr.NATTypeSourceNAT, Family: natFamily,
				RegAddrMin: 1, RegAddrMax: 1},
		)
		out = append(out, Rule{Chain: nft.ChainSrcNAT, Rule: &nftables.Rule{
			Table: tbl, UserData: []byte(ud), Exprs: nat,
		}})
	}
	return out, nil
}

// CompileDefaultDeny "范围内默认拒绝"全局尾行（fwd 链链尾，全局一条而非 per-rule：
// per-rule 尾行会把别家未打标的源误杀——v2 事故同型；全局行只按"入口 ∈ 本产品
// 入口集 且 未被任何规则放行打标"判拒，多规则天然兼容）。
//
//	gwd 链尾：iifname ∈ <入口网卡集> && mark & 0x1 == 0 → counter + drop
//
// ifaces 为空返回 nil（无启用规则时无默认拒绝——vanilla 语义回到全通）。
// 这是设计承诺"gateway-firewall.sh 机器级基线废弃、默认拒绝由 fwd 链承担"
// 的实现，比机器级 FORWARD policy DROP 更精确（只管本产品入口网卡的穿越）。
func CompileDefaultDeny(ruleID uint, ifaces []string) []Rule {
	if len(ifaces) == 0 {
		return nil
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: nft.Table}
	ud := nft.Comment(nft.KindDefaultDeny, ruleID)
	var out []Rule
	for _, ifn := range ifaces {
		out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
			Table: tbl, UserData: []byte(ud),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(ifn)},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: binaryutil.NativeEndian.PutUint32(nft.MarkFwdOK),
					Xor:  binaryutil.NativeEndian.PutUint32(0)},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		}})
	}
	return out
}

// iifOifExprs 入口+出口双维度匹配（旧形态 -i in -o out 的等价；防多网卡机器上
// 从第三块网卡出的包被误改写/误放行——评审 M2）。
// DEFECT-4：前提 DNAT 位（mark&0x4≠0）不匹配——DNAT 发布的后端流量不走 SNAT
// （发布流量直达后端，源不该被改写；若源恰在 snat 白名单且出口策略路由在场，
//
//	无此前提会把直连后端流量误 SNAT 成出口 IP）。
func iifOifExprs(ifin, ifout string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(ifin)},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(ifout)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(nft.MarkDNAT),
			Xor:  binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}
}

// srcMatchExprs 入口+出口+源 IP/CIDR 匹配序列（T210：v4/v6 双栈按族分支）。
func srcMatchExprs(ifin, ifout, src string) []expr.Any {
	return append(iifOifExprs(ifin, ifout), addrMatchExprsSrc(src)...)
}

// addrMatchExprsSrc 源地址匹配（v4 offset12/4B；v6 offset8/16B）。
func addrMatchExprsSrc(src string) []expr.Any {
	if ip := v4(src); ip != nil {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offSaddr, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		}
	}
	if ip := v4OrV6(src); ip != nil {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offSaddr6, Len: 16},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		}
	}
	if _, ipn, err := net.ParseCIDR(src); err == nil && ipn != nil {
		off := uint32(offSaddr)
		if ipn.IP.To4() == nil {
			off = offSaddr6
		}
		return cidrMatchExprs(ipn, off)
	}
	// 非法源：永不匹配（防御——上游已校验）
	return []expr.Any{&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 0}}}
}

// cidrMatchExprs CIDR 网段匹配（Bitwise+网络序；v4/v6 由 ipn 派生长度与偏移）。
func cidrMatchExprs(ipn *net.IPNet, offset uint32) []expr.Any {
	// 族归一（B2：v4 的 To16() 是 v4-in-v6 映射 [::ffff:a.b.c.d]——前 4 字节全零，
	// Cmp Data 若按 To16 切片会全零把网段匹配退化为 ==0.0.0.0——v4 一律 To4）
	isV4 := ipn.IP.To4() != nil
	var mask, network []byte
	if isV4 {
		if len(ipn.Mask) == net.IPv6len {
			mask = ipn.Mask[12:] // v6 长度掩码表示 v4：取尾 4 字节
		} else {
			mask = ipn.Mask
		}
		network = ipn.IP.To4()
	} else {
		mask = ipn.Mask // 16B v6 掩码
		network = ipn.IP.To16()
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(mask))},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(mask)),
			Mask: mask, Xor: make([]byte, len(mask))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
	}
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

// dstMatchExprs 目标地址匹配序列（单 IP 精确 / CIDR Bitwise 展开——与
// 源匹配同构；旧形态 -d 支持网段，此处等价）。
func dstMatchExprs(dst string) []expr.Any {
	if ip := v4(dst); ip != nil {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offDaddr, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		}
	}
	if _, ipn, err := net.ParseCIDR(dst); err == nil && ipn != nil {
		mask := make([]byte, 4)
		copy(mask, ipn.Mask)
		network := ipn.IP.To4()
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offDaddr, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: mask, Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
		}
	}
	return nil // 非法目标（调用方已校验——防御）
}

// validDst 目标条目合法（单 IP 或 CIDR）。
func validDst(d string) bool {
	if v4(d) != nil {
		return true
	}
	_, ipn, err := net.ParseCIDR(d)
	return err == nil && ipn != nil && ipn.IP.To4() != nil
}

// CompileDefaultDenyEx 默认拒绝尾行的完整形态（dnat 后端 IP 辖区维度）。
// dnat 的辖区 = 后端 IP：DNAT 在 prerouting(-100) 已把 daddr 改写为后端，
// fwd 链(-10) 看到的目的即后端 IP。snat 的辖区内聚在上面的 ifaces 版
// （CompileDefaultDeny）——两版本并存，snat_nft.go 之后统一到 Ex。
func CompileDefaultDenyEx(ruleID uint, ifaces, dnatBackends []string) []Rule {
	if len(ifaces) == 0 && len(dnatBackends) == 0 {
		return nil
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: nft.Table}
	ud := nft.Comment(nft.KindDefaultDeny, ruleID)
	dropTail := func() []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(nft.MarkFwdOK),
				Xor:  binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictDrop},
		}
	}
	var out []Rule
	for _, ifn := range ifaces {
		ex := append([]expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(ifn)},
		}, dropTail()...)
		out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
			Table: tbl, UserData: []byte(ud), Exprs: ex,
		}})
	}
	for _, b := range dnatBackends {
		// B7：v6 后端同样有辖区行（此前 v4-only continue——v6 发布的名单外
		// 拒绝失效，vanilla 宿主下直接放行到 v6 后端）
		m := dstMatchExprsD(b)
		if m == nil {
			continue
		}
		ex := append(m, dropTail()...)
		out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
			Table: tbl, UserData: []byte(ud), Exprs: ex,
		}})
	}
	return out
}
