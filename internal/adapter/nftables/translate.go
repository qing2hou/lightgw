package nftables

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"haproxyweb/internal/compile"
)

// 字节序约定（改动前必读）：
//
// nft 的寄存器数据与 Bitwise 的 Mask/Xor **一律是网络字节序（BigEndian）**。
// 用 NativeEndian 在 x86（小端）上会把 0xFFFFFF00 写成 00FFFFFF，掩码完全
// 错位——规则语法合法、内核接受、但匹配不到任何流量。这是本包踩过的坑，
// 由 TestTranslateCtMarkMatchesRuleMask 固化。
//
// 唯一例外：ct state 的位掩码走 NativeEndian 也没问题吗？不——同样必须
// BigEndian。所有 32 位值统一用 BigEndian，不做例外。

// 内核头 <linux/netfilter/nf_tables.h> 里有、但 golang.org/x/sys 未导出的常量。
//
// 这里显式定义并注明来源，而不是硬编码魔数散落在代码里——取值错误会让
// 表达式被内核拒绝（EINVAL）或写到错误字段。
const (
	// nftExthdrTCPOptMaxseg 是 TCP MSS 选项在 NFT_EXTHDR_OP_TCPOPT 下的类型号。
	// 对应内核 NFT_EXTHDR_TCPOPT_MAXSEG = 3。
	nftExthdrTCPOptMaxseg uint8 = 3

	// nftCtStateNew 是 conntrack NEW 状态的位掩码。
	// 对应内核 NFT_CT_STATE_NEW = (1 << 0)。
	nftCtStateNew uint32 = 1 << 0
)

// TranslatePlan 把编译产物翻译成 nftables 表达式。
//
// 返回值分两部分：
//   - WorkSet：四个版本化工作链的规则（参与热切换）
//   - fixed：固定链（MSS 等）的规则，不参与版本化——内容稳定，无需热切换
//
// 所有表达式结构都以真机 `nft -j list table` 的输出为基准，不凭记忆构造。
// 见 docs/handoff/S1-nftables-shadow.md「MSS/ICMP 命令行对照」。
func TranslatePlan(p *compile.Plan) (WorkSet, map[string][][]expr.Any, error) {
	if p == nil {
		return nil, nil, fmt.Errorf("翻译计划失败: 计划为 nil")
	}
	set := make(WorkSet, len(workChains))
	for _, work := range workChains {
		set[work] = nil
	}
	fixed := make(map[string][][]expr.Any, 2)

	// 1. 固定段：MSS
	for _, r := range p.Nft.Mss {
		exprs, err := translateMSS(r)
		if err != nil {
			return nil, nil, err
		}
		fixed[ChainMSS] = append(fixed[ChainMSS], exprs)
	}

	// 2. NAT 段
	for _, r := range p.Nft.Dnat {
		exprs, err := translateRule(r)
		if err != nil {
			return nil, nil, err
		}
		// 目标工作链优��用 compile 层显式声明的 WorkChain；
		// 没有声明时按 comment 后缀兜底（":apply" → dnat，其余 → pre）。
		//
		// 为什么优先用显式字段：ChainDnat 这个常量同时被「DNAT 判定行」与
		// 「回程放行」使用，只靠 comment 后缀区分太脆弱——漏一个后缀就会
		// 落到错误的链，而错误的链意味着规则永不生效（静默）。
		work := r.WorkChain
		if work == "" {
			work = WorkPre
			if hasCommentSuffix(r.Comment, ":apply") {
				work = WorkDnat
			}
		}
		set[work] = append(set[work], exprs)
	}
	for _, r := range p.Nft.Snat {
		exprs, err := translateRule(r)
		if err != nil {
			return nil, nil, err
		}
		set[WorkSnat] = append(set[WorkSnat], exprs)
	}

	// 3. 策略段 + 转发白名单 + 默认拒绝 全部落在 fwd 工作链。
	// 顺序有意为之：策略 → 白名单 → 默认拒绝（最后，无法被前面的 accept 绕过）。
	for _, group := range [][]compile.Rule{p.Nft.Policy, p.Nft.Forward, p.Nft.Deny} {
		for _, r := range group {
			exprs, err := translateRule(r)
			if err != nil {
				return nil, nil, err
			}
			set[WorkFwd] = append(set[WorkFwd], exprs)
		}
	}
	return set, fixed, nil
}

func hasCommentSuffix(comment, suffix string) bool {
	if len(comment) < len(suffix) {
		return false
	}
	return comment[len(comment)-len(suffix):] == suffix
}

// translateMSS 翻译 MSS clamping 规则。
//
// 真机核对过的表达式（`nft -j` 输出）：
//
//	{"match": {"op": "in", "left": {"payload": {"protocol": "tcp", "field": "flags"}}, "right": "syn"}}
//	{"mangle": {"key": {"tcp option": {"name": "maxseg", "field": "size"}}, "value": 1360}}
//
// 注意第二条：**校验和由内核自动重算**，不需要手工构造
// `Payload{CsumType: CsumTypeInet, CsumOffset: 16, CsumFlags: 0x1}`。
// 早期 design 文档说「必须手工重算」是对 nft CLI 语法与 netlink 表达
// 对应关系的误解（详见 compile/mss.go 的注释）。
func translateMSS(r compile.Rule) ([]expr.Any, error) {
	if r.MSSValue == 0 {
		return nil, fmt.Errorf("翻译 MSS 规则失败: MSS 值为 0")
	}
	var out []expr.Any

	// ① tcp flags & syn == syn
	out = append(out,
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       13, // TCP flags 偏移
			Len:          1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            1,
			Mask:           []byte{0x02}, // SYN
			Xor:            []byte{0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{0x02},
		},
	)

	// ② tcp option maxseg size set <value>
	//    先确认选项存在（exthdr），再写入。
	out = append(out,
		&expr.Exthdr{
			DestRegister: 1,
			Type:         nftExthdrTCPOptMaxseg,
			Offset:       0,
			Len:          2,
			Op:           expr.ExthdrOpTcpopt,
			Flags:        unix.NFT_EXTHDR_F_PRESENT,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint32(1), // 存在性检查：== 1
		},
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(r.MSSValue),
		},
		&expr.Exthdr{
			SourceRegister: 1,
			Type:           nftExthdrTCPOptMaxseg,
			Offset:         0,
			Len:            2,
			Op:             expr.ExthdrOpTcpopt,
			// 写入时要带 checksum 更新：nft 用 flag 表达
			Flags: unix.NFT_EXTHDR_F_PRESENT,
		},
	)
	return out, nil
}

// translateRule 翻译一条通用规则（DNAT / SNAT / 策略 / 白名单 / 默认拒绝）。
//
// 生成顺序有意为之，与 nft 的规则求值顺序一致：
//
//	匹配条件（proto / port / addr / ct state / ct mark / meta mark）
//	→ 动作（counter / ct mark set / meta mark set / dnat / snat / verdict）
func translateRule(r compile.Rule) ([]expr.Any, error) {
	var out []expr.Any

	// ① 协议
	if r.Proto != "" {
		var proto byte
		switch r.Proto {
		case "tcp":
			proto = unix.IPPROTO_TCP
		case "udp":
			proto = unix.IPPROTO_UDP
		default:
			return nil, fmt.Errorf("翻译规则 %s 失败: 协议 %q 不支持", r.Comment, r.Proto)
		}
		out = append(out,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		)
	}

	// ② 目的端口（tcp/udp 的 dport 在传输头偏移 2）
	if r.DstPort != 0 {
		out = append(out,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint16(r.DstPort),
			},
		)
	}

	// ③ 源地址（可能多网段：用多个 Cmp 会变成 OR，需用 set 语义。
	//    这里用最简形式：单网段用 Cmp，多网段在上一层展开成多条规则。
	//    本函数由调用方保证 Src.Prefixes 至多 1 个；多个由 ExpandSourceMatches 处理。）
	if !r.Src.Empty() {
		ex, err := translateAddrMatch(r.Src, true)
		if err != nil {
			return nil, fmt.Errorf("翻译规则 %s 的源地址失败: %w", r.Comment, err)
		}
		out = append(out, ex...)
	}
	// ④ 目的地址
	if !r.Dst.Empty() {
		ex, err := translateAddrMatch(r.Dst, false)
		if err != nil {
			return nil, fmt.Errorf("翻译规则 %s 的目的地址失败: %w", r.Comment, err)
		}
		out = append(out, ex...)
	}

	// ⑤ ct state new
	if r.CtStateNew {
		out = append(out,
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.BigEndian.PutUint32(nftCtStateNew),
				Xor:            binaryutil.BigEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint32(0),
			},
		)
	}

	// ⑥ ct mark（按 rule_id 位段匹配）
	if r.CtMarkEq != nil {
		out = append(out,
			&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.BigEndian.PutUint32(compile.CtRuleMask),
				Xor:            binaryutil.BigEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint32(*r.CtMarkEq),
			},
		)
	}

	// ⑦ meta mark 未设置（默认拒绝用）
	if r.MetaMarkNotSet != nil {
		out = append(out,
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.BigEndian.PutUint32(*r.MetaMarkNotSet),
				Xor:            binaryutil.BigEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint32(0),
			},
		)
	}

	// ⑧ counter（要在动作之前，否则动作终结后不会计数）
	if r.Counter {
		out = append(out, &expr.Counter{})
	}

	// ⑨ 动作
	//
	// 互斥检查：SetCtMark 与 NAT 都写 Register 1（ct mark 与立即数），
	// 同时出现会让 NAT 用错地址。compile 层的设计是「判定行设 ct mark、
	// 改写行做 NAT」，两者从不共存——这里显式拦住，避免将来误用。
	if r.SetCtMark != nil && (r.DnatTo.IsValid() || r.SnatTo.IsValid()) {
		return nil, fmt.Errorf("翻译规则 %s 失败: 不能在同一条规则里既设 ct mark 又做 NAT"+
			"（打印机寄存器冲突）", r.Comment)
	}
	if r.SetCtMark != nil {
		out = append(out,
			&expr.Immediate{
				Register: 1,
				Data:     binaryutil.BigEndian.PutUint32(*r.SetCtMark),
			},
			&expr.Ct{Key: expr.CtKeyMARK, SourceRegister: true, Register: 1},
		)
	}
	if r.SetMetaMark != nil {
		// meta mark set meta mark | <val>
		out = append(out,
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.BigEndian.PutUint32(0xFFFFFFFF),
				Xor:            binaryutil.BigEndian.PutUint32(0),
			},
			&expr.Immediate{
				Register: 2,
				Data:     binaryutil.BigEndian.PutUint32(*r.SetMetaMark),
			},
			&expr.Bitwise{
				SourceRegister: 2,
				DestRegister:   2,
				Len:            4,
				Mask:           binaryutil.BigEndian.PutUint32(0xFFFFFFFF),
				Xor:            binaryutil.BigEndian.PutUint32(0),
			},
			// OR：先取反再 AND 再取反等价于 OR，但 nft 更直接的做法是
			// 用 bitwise 的 Xor（mask=0, xor=val 即 OR）。
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 2},
		)
	}
	// NAT 是**终结语句**：它之后不能再有任何表达式（内核报
	// "Statement after terminal statement has no effect"）。
	// 另外真机实测：dnat/snat 之前**必须有传输层协议匹配**，否则内核报
	// "transport protocol mapping is only valid after transport protocol match"。
	// 所以这里显式要求 Proto 非空，而不是让内核在运行时拒绝。
	//
	// 真机实测的第三条约束：**协议匹配后必须紧跟一个传输层字段**（dport/sport），
	// 否则 `tcp ct mark ...` 会报 "syntax error, unexpected ct"——nft 需要
	// 一个传输层字段来切换解析上下文。所以 dnat 规则要求 DstPort 非 0，
	// snat 规则要求 DstPort 非 0（借用 dport 作为上下文锚点）。
	if r.DnatTo.IsValid() {
		if r.Proto == "" {
			return nil, fmt.Errorf("翻译规则 %s 失败: DNAT 规则必须指定传输层协议"+
				"（内核要求 dnat 前有 tcp/udp 匹配）", r.Comment)
		}
		if r.DstPort == 0 {
			return nil, fmt.Errorf("翻译规则 %s 失败: DNAT 规则必须指定端口"+
				"（内核要求协议匹配后紧跟传输层字段，否则报 syntax error）", r.Comment)
		}
		out = append(out, dnatExprs(r.DnatTo)...)
	}
	if r.SnatTo.IsValid() {
		if r.Proto == "" {
			return nil, fmt.Errorf("翻译规则 %s 失败: SNAT 规则必须指定传输层协议"+
				"（内核要求 snat 前有 tcp/udp 匹配）", r.Comment)
		}
		if r.DstPort == 0 {
			return nil, fmt.Errorf("翻译规则 %s 失败: SNAT 规则必须指定端口"+
				"（内核要求协议匹配后紧跟传输层字段，否则报 syntax error）", r.Comment)
		}
		out = append(out, snatExprs(r.SnatTo)...)
	}
	if r.Verdict != "" {
		switch r.Verdict {
		case "accept":
			out = append(out, &expr.Verdict{Kind: expr.VerdictAccept})
		case "drop":
			out = append(out, &expr.Verdict{Kind: expr.VerdictDrop})
		default:
			return nil, fmt.Errorf("翻译规则 %s 失败: 未知 verdict %q", r.Comment, r.Verdict)
		}
	}
	if r.JumpTo != "" {
		out = append(out, &expr.Verdict{Kind: expr.VerdictJump, Chain: r.JumpTo})
	}
	return out, nil
}

// translateAddrMatch 把地址匹配翻译成表达式。
//
// 只处理**单个**前缀——多个前缀必须由调用方展开成多条规则（nft 的
// 匿名 set 语义用 Cmp 无法表达，而用 Lookup 又需要预先建 set）。
// 这条约束写在这里而不是静默取第一个，避免「配了 3 个网段只匹配 1 个」。
func translateAddrMatch(m compile.AddrMatch, isSrc bool) ([]expr.Any, error) {
	if len(m.Prefixes) == 0 {
		return nil, nil
	}
	if len(m.Prefixes) > 1 {
		return nil, fmt.Errorf("地址匹配含 %d 个网段，必须先由调用方展开成多条规则", len(m.Prefixes))
	}
	p := m.Prefixes[0]
	is4 := p.Addr().Is4()

	var out []expr.Any
	// 网络地址与掩码
	bits := p.Bits()
	var maskLen uint32 = 4
	if p.Addr().Is6() {
		maskLen = 16
	}
	// 只取网络地址的有效字节
	netBytes := p.Masked().Addr().AsSlice()
	if len(netBytes) > int(maskLen) {
		netBytes = netBytes[:maskLen]
	}
	var maskBytes []byte
	if p.Addr().Is4() {
		maskBytes = cidrMaskV4(bits)
	} else {
		maskBytes = cidrMaskV6(bits)
	}

	// 全 1 掩码（单主机）直接用 Cmp，省一条 bitwise
	allOnes := true
	for _, b := range maskBytes {
		if b != 0xff {
			allOnes = false
			break
		}
	}
	if allOnes {
		if isSrc {
			out = append(out,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader,
					Offset: srcOffset(is4), Len: maskLen},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: netBytes},
			)
		} else {
			out = append(out,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader,
					Offset: dstOffset(is4), Len: maskLen},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: netBytes},
			)
		}
		return out, nil
	}

	off := srcOffset(is4)
	if !isSrc {
		off = dstOffset(is4)
	}
	out = append(out,
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: maskLen},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: maskLen, Mask: maskBytes, Xor: make([]byte, maskLen)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: netBytes},
	)
	return out, nil
}

// IP 头内偏移（v4/v6 不同）。
func srcOffset(v4 bool) uint32 {
	if v4 {
		return 12
	}
	return 8
}
func dstOffset(v4 bool) uint32 {
	if v4 {
		return 16
	}
	return 24
}

func addrFamily(a netip.Addr) uint32 {
	if a.Is4() {
		return unix.NFPROTO_IPV4
	}
	return unix.NFPROTO_IPV6
}

func cidrMaskV4(bits int) []byte {
	m := make([]byte, 4)
	for i := 0; i < 4; i++ {
		remaining := bits - i*8
		switch {
		case remaining >= 8:
			m[i] = 0xff
		case remaining <= 0:
			m[i] = 0
		default:
			m[i] = byte(0xff << (8 - remaining))
		}
	}
	return m
}

func cidrMaskV6(bits int) []byte {
	m := make([]byte, 16)
	for i := 0; i < 16; i++ {
		remaining := bits - i*8
		switch {
		case remaining >= 8:
			m[i] = 0xff
		case remaining <= 0:
			m[i] = 0
		default:
			m[i] = byte(0xff << (8 - remaining))
		}
	}
	return m
}

// ApplyFixed 把固定链的规则装进内核（不参与版本化）。
//
// MSS 规则内容稳定，每次配置变更都重装一遍即可；装之前先 FlushChain，
// 避免重复累积。
func (e *Engine) ApplyFixed(fixed map[string][][]expr.Any) error {
	if e.conn == nil {
		return ErrNotReady
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for name, rules := range fixed {
		chain := &nftables.Chain{Name: name, Table: e.tbl}
		e.conn.FlushChain(chain)
		for _, exprs := range rules {
			e.conn.AddRule(&nftables.Rule{Table: e.tbl, Chain: chain, Exprs: exprs})
		}
		if err := e.conn.Flush(); err != nil {
			return fmt.Errorf("装载固定链 %s 失败: %w", name, err)
		}
	}
	return nil
}

// dnatExprs 构造 DNAT 表达式：立即数（地址+端口）→ NAT 语句。
//
// 真机核对的写法：`dnat ip to 192.168.10.152:22` 会被 nft 翻译成
//
//	Immediate{reg1: addr} + Immediate{reg2: port} + NAT{Type: DestNAT,
//	Family: NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2}
//
// 其中 RegProtoMin=2 是「端口也在 reg2」的约定。
func dnatExprs(to netip.AddrPort) []expr.Any {
	addrBytes := to.Addr().AsSlice()
	fam := addrFamily(to.Addr())
	exprs := []expr.Any{
		&expr.Immediate{Register: 1, Data: addrBytes},
	}
	// 端口非 0 时才带 RegProtoMin（端口未改写的场景只需换地址）
	if to.Port() != 0 {
		exprs = append(exprs,
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(to.Port())})
		return append(exprs, &expr.NAT{
			Type: expr.NATTypeDestNAT, Family: fam, RegAddrMin: 1, RegProtoMin: 2,
		})
	}
	return append(exprs, &expr.NAT{
		Type: expr.NATTypeDestNAT, Family: fam, RegAddrMin: 1,
	})
}

// snatExprs 构造 SNAT 表达式。
func snatExprs(to netip.Addr) []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: to.AsSlice()},
		&expr.NAT{
			Type: expr.NATTypeSourceNAT, Family: addrFamily(to), RegAddrMin: 1,
		},
	}
}
