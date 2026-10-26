// dnat 规则 → nftables 规则编译（M2/US2，链形态见 design-fwgateway.md）。
//
// 源白名单的执行位（与 iptables 时代 DNAT@PREROUTING + FORWARD filter 同构）：
// DNAT 对全部到发布地址的包执行（prerouting 阶段无过滤语义，非白名单源被
// DNAT 后由 fwd 行拒绝——conntrack 不建立即无回程）；白名单真正拦截在 fwd 行。
//
// 一条 dnat 规则编译为（全部 haweb-nft:dnat:<id> 标记）：
//   - pre_mark：发布命中打标（daddr=公网IP && dport=发布端口 → set mark）
//   - dstnat：DNAT（同匹配 → 改写目的为后端 addr+port）
//   - fwd：入向放行（每源一行：daddr=后端 && saddr∈白名单 → counter+mark；
//     名单外由默认拒绝尾行/宿主 policy 拒——无放行行即无 mark 即拒）
package fw

import (
	"fmt"
	"net"
	"strconv"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"haproxyweb/internal/nft"
)

// DNatSpec dnat 规则的内核面参数。
type DNatSpec struct {
	ID          uint
	IfIn        string   // 发布地址所在网卡名（展示用）
	HairpinIP   string   // hairpin SNAT 源（入口网卡 IP；DEFECT-5——空则不装）
	ListenIP    string   // 发布公网 IP（v4）
	ListenPort  int      // 发布端口
	BackendIP   string   // 内网后端 IP（v4）
	BackendPort int      // 后端端口
	AllowSrcs   []string // 源白名单（IP/CIDR；空 = 无限制——上游 API 已强制白名单语义）
	RejectMode  string   // reject/timeout（不可达时的行为由 Manager 健康联动控制规则装拆实现）
}

// CompileDNAT 编译 dnat 规则。
func CompileDNAT(s DNatSpec) ([]Rule, error) {
	// T210 双栈：发布/后端地址族由地址形态推断；两者必须同族（无 NAT64）
	lip, bip := v4OrV6(s.ListenIP), v4OrV6(s.BackendIP)
	if lip == nil {
		return nil, fmt.Errorf("发布 IP %s 不是合法 IP", s.ListenIP)
	}
	if bip == nil {
		return nil, fmt.Errorf("后端 IP %s 不是合法 IP", s.BackendIP)
	}
	if (len(lip) == 4) != (len(bip) == 4) {
		return nil, fmt.Errorf("发布与后端地址族不一致（v1 不做 NAT64）: %s → %s", s.ListenIP, s.BackendIP)
	}
	natFamily := unix.AF_INET
	daddrOff, daddrLen := uint32(offDaddr), uint32(4)
	if len(lip) == 16 {
		natFamily = unix.AF_INET6
		daddrOff, daddrLen = offDaddr6, 16
	}
	if s.ListenPort < 1 || s.ListenPort > 65535 || s.BackendPort < 1 || s.BackendPort > 65535 {
		return nil, fmt.Errorf("端口无效：发布 %d 后端 %d", s.ListenPort, s.BackendPort)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: nft.Table}
	ud := nft.Comment(nft.KindDNAT, s.ID)
	var out []Rule

	// 发布匹配序列（三处共用）：daddr=公网IP && TCP/UDP dport=发布端口
	match := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: daddrOff, Len: daddrLen},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lip},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offDport, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(s.ListenPort))},
	}

	// ① pre_mark：命中发布地址 → 打 FwdOK|DNAT 位（DEFECT-4：DNAT 位豁免策略路由与
	// srcnat——否则源在 snat 白名单内的客户端访问发布地址时，改写后的后端流量被该源的
	// 出口策略路由拉去外网网卡绕行并误 SNAT）。
	// 新包同样打 DNAT 位（首包路由决策就需要豁免）；FwdOK 的白名单裁决仍在 fwd 行——
	// 名单外新包 DNAT 位在但 FwdOK 无 → 默认拒绝行照拒（白名单语义不变）。
	both := nft.MarkFwdOK | nft.MarkDNAT
	out = append(out, Rule{Chain: nft.ChainPreMark, Rule: &nftables.Rule{
		Table: tbl, UserData: []byte(ud),
		Exprs: append(append([]expr.Any{}, match...), nft.SetMarkExprs(both)...),
	}})

	// ② dstnat：DNAT 到后端（NAT 链仅每连接首包求值——counter 计连接而非包）
	dnat := append(append([]expr.Any{}, match...),
		&expr.Immediate{Register: 1, Data: bip},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(uint16(s.BackendPort))},
		&expr.NAT{Type: expr.NATTypeDestNAT, Family: uint32(natFamily),
			RegAddrMin: 1, RegAddrMax: 1, RegProtoMin: 2, RegProtoMax: 2},
	)
	out = append(out, Rule{Chain: nft.ChainDstNAT, Rule: &nftables.Rule{
		Table: tbl, UserData: []byte(ud), Exprs: dnat,
	}})

	// ②b srcnat：hairpin SNAT（DEFECT-5）：DNAT 改写后的流量源改写为【后端出口网卡 IP】——
	// 强制回程经本网关（对端与本网关不同段/回程直连路由绕过网关时，反 DNAT 失配，
	// 客户端收到陌生五元组的 SYN-ACK 直接 RST——发布不可用）。
	// 匹配：mark 含 DNAT 位（① 已对发布命中流打标）→ snat to <后端出口网卡 IP>。
	if ifIP := v4(s.HairpinIP); ifIP != nil {
		out = append(out, Rule{Chain: nft.ChainSrcNAT, Rule: &nftables.Rule{
			Table: tbl, UserData: []byte(ud),
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
					Mask: binaryutil.NativeEndian.PutUint32(nft.MarkDNAT),
					Xor:  binaryutil.NativeEndian.PutUint32(0)},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
				&expr.Immediate{Register: 1, Data: ifIP},
				&expr.NAT{Type: expr.NATTypeSourceNAT, Family: uint32(natFamily),
					RegAddrMin: 1, RegAddrMax: 1},
			},
		}})
	}

	// ③ fwd：入向放行（每源一行：daddr=后端（DNAT 改写后 fwd 看到的目的）+
	// dport=后端端口 + saddr∈白名单 → counter + mark）
	backendMatch := func() []expr.Any {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: daddrOff, Len: daddrLen},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: bip},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offDport, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(s.BackendPort))},
		}
	}
	srcs := s.AllowSrcs
	if len(srcs) == 0 {
		srcs = []string{""} // 无名单：不限源（API 语义当前不会走到——防御形态）
	}
	for _, src := range srcs {
		ex := backendMatch()
		if src != "" {
			ex = append(ex, srcMatchPayloadOnly(src)...)
		}
		out = append(out, Rule{Chain: nft.ChainFwd, Rule: &nftables.Rule{
			Table: tbl, UserData: []byte(ud), Exprs: withCounterMark(ex),
		}})
	}
	return out, nil
}

// srcMatchPayloadOnly 仅源匹配的 payload 序列（无 iif/oif 维度——dnat 无网卡语义）。
func srcMatchPayloadOnly(src string) []expr.Any {
	if ip := v4(src); ip != nil {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offSaddr, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		}
	}
	if _, ipn, err := net.ParseCIDR(src); err == nil && ipn != nil {
		mask := make([]byte, 4)
		copy(mask, ipn.Mask)
		network := ipn.IP.To4()
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offSaddr, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: mask, Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
		}
	}
	return []expr.Any{&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 0, 0, 0}}}
}

// dstMatchExprsD 目的地址匹配（v4 offset16/4B；v6 offset24/16B）。
func dstMatchExprsD(dst string) []expr.Any {
	if ip := v4(dst); ip != nil {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offDaddr, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		}
	}
	if ip := v4OrV6(dst); ip != nil {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offDaddr6, Len: 16},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ip},
		}
	}
	if _, ipn, err := net.ParseCIDR(dst); err == nil && ipn != nil {
		off := uint32(offDaddr)
		if ipn.IP.To4() == nil {
			off = offDaddr6
		}
		return cidrMatchExprs(ipn, off)
	}
	return nil
}

// ParseAddrPort "IP:port" → (ip, port, err)（dnat spec 构建用）。
func ParseAddrPort(s string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("地址 %q 必须是 IP:端口 形式: %w", s, err)
	}
	if net.ParseIP(host) == nil {
		return "", 0, fmt.Errorf("地址 %q 的 IP 部分不合法", s)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("端口 %q 无效", portStr)
	}
	return host, port, nil
}

// CompileDnatSilentDrop timeout 模式的"静默丢弃"行（评审 #9）：后端不可达
// 时发布已卸载，SYN 进本机 INPUT 无监听会回 RST（=reject 表现）；timeout
// 语义要求静默丢弃——在 input 方向补 drop 行让包被丢弃（客户端超时）。
// 行形态：iif 任意、daddr=发布IP、dport=发布端口 → counter + drop。
func CompileDnatSilentDrop(s DNatSpec) []Rule {
	lip := v4(s.ListenIP)
	if lip == nil {
		return nil
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: nft.Table}
	ud := nft.Comment(nft.KindDnatDrop, s.ID)
	return []Rule{{
		Chain: nft.ChainInput,
		Rule: &nftables.Rule{Table: tbl, UserData: []byte(ud),
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offDaddr, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lip},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offDport, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(uint16(s.ListenPort))},
				&expr.Counter{},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		},
	}}
}

// ---------- T207-T209：SNAT 源池（US6；v1 直落方案） ----------
//
// ADR-13 原定的 jhash 槽位标记在 google/nftables v0.3.0 的 Hash 原语上
// 未经内核验证（concat 多字段表达式支持面不明）。v1 落地为**源确定性映射**：
//   每个白名单源 → pool[hash(源IP) mod N]（同源恒同出口 IP——天然满足
//   AC-6.1 的 sticky 语义；rotate 的"按会话轮换"调整为"按源轮换"，
//   语义修订已记任务表）。
// 形态：⑤ srcnat 行每白名单源一行的 Immediate 用各自映射成员——
// CompileSNAT 的 OutIP 按池在-spec 层展开（每源一行不同 snat IP），
// 编译层零改动，本层仅提供映射函数。

// PoolMemberOf 源 IP → 池成员（确定性：同源恒同 IP；成员增减的重排影响面
// ≈ |ΔN|/N——AC-6.4 边界内）。
func PoolMemberOf(src string, pool []string) string {
	if len(pool) == 0 {
		return ""
	}
	ip := net.ParseIP(src)
	if ip == nil {
		return pool[0]
	}
	b := ip.To4()
	if b == nil {
		b = ip.To16()
	}
	h := 0
	for _, v := range b {
		h = h*131 + int(v)
	}
	if h < 0 {
		h = -h
	}
	return pool[h%len(pool)]
}
