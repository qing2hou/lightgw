// Package ctnl 通过 **原生 nfnetlink** 订阅 conntrack 事件并维护内存会话表。
//
// 为什么不用 `ti-mo/conntrack`：`docs/poc-nftables.md` 已验证「conntrack dump
// 原生 NETLINK_NETFILTER 通道可用，不引第三方库也行」。少一个依赖面，
// 且事件订阅只需 NFNLGRP_CONNTRACK_{NEW,UPDATE,DESTROY} 三个多播组。
//
// 为什么不用 `exec.Command("conntrack", ...)`（旧实现）：
//   - 每次查询全量 dump，10 万会话单次约 200ms，占满控制平面
//   - CLI 不存在时静默返回零值，统计面板全零且无告警（D-08）
//   - `conntrack -D -p tcp -s ... -d ...` 拼参数既慢又有失败静默
//
// 本包的三块职责：
//
//	codec.go    nfnetlink 消息编解码（纯函数，无特权可测 ★覆盖率主要来源）
//	table.go    32 分片会话表 + 快照（原子发布）
//	engine.go   事件订阅循环 + 60s 全量对账 + KillSession
//
// 零 IO 的部分严格分离：codec.go 只依赖 encoding/binary 与 net/netip。
package ctnl

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// nfnetlink 协议常量（摘自 <linux/netfilter/nfnetlink.h> 与
// <linux/netfilter/nfnetlink_conntrack.h>）。
//
// 这些常量 golang.org/x/sys 未导出，显式定义并注明来源，避免魔数散落。
const (
	// NFNL_SUBSYS_CTNETLINK 是 conntrack 的 nfnetlink 子系统号。
	NFNLSubsysCtnetlink = 1

	// nfnetlink 消息类型（低 8 位是子系统内的消息号）。
	// 完整消息类型 = subsys<<8 | msgtype
	IPCTNLMsgNew    = 0
	IPCTNLMsgDelete = 1
	IPCTNLMsgGet    = 2
	IPCTNLMsgDump   = 3
	// IPCTNLMsgGetCtnl 与消息类型 GET 同值，语义由子系统决定。
	IPCTNLMsgGetCtnl = IPCTNLMsgGet

	// 多播组（NFNLGRP_CONNTRACK_*）。
	// 注意：netlink 的组号从 1 开始，0 表示不订阅。
	NFNLGrpConntrackNew     = 1
	NFNLGrpConntrackUpdate  = 2
	NFNLGrpConntrackDestroy = 3

	// nfgenmsg：每个 nfnetlink 消息固定 4 字节头（family + version + res_id）。
	NFGenMsgSize = 4
	// NFNETLINK_V0 是当前唯一版本。
	NFNetlinkV0 = 0

	// 属性嵌套标志。
	NLAFNested = 0x8000

	// CTA_* 属性类型（conntrack attribute）。
	//
	// ⚠️ 这组值必须与内核头 <linux/netfilter/nfnetlink_conntrack.h> 的
	// enum ctattr_type **逐项对齐**。曾经按记忆写过一版（STATUS=4、
	// COUNTERS=7、TIMEOUT=8），全部错位，后果是：status 读到的是
	// CTA_PROTOINFO 的值 → 所有会话都显示未建立；counters 读到的是
	// CTA_TIMEOUT → 所有字节数都是 0。**这个错误在编译与单测里都发现不了**
	//（自造消息用自造常量，往返一致），只有真机 dump 才能暴露。
	//
	// 现在的值经真机 `nft`/netlink dump 原始字节逐项核对：
	//   0x0001 CTA_TUPLE_ORIG (nested)
	//   0x0002 CTA_TUPLE_REPLY (nested)
	//   0x0003 CTA_STATUS
	//   0x0007 CTA_TIMEOUT
	//   0x0008 CTA_PROTOINFO
	//   0x000b CTA_USE
	//   0x000c CTA_ID
	CTAUnspec         = 0
	CTAATupleOrig     = 1
	CTAATupleReply    = 2
	CTAAStatus        = 3
	CTAAProtoinfo     = 4
	CTAAHelp          = 5
	CTAANatSrc        = 6
	CTAATimeout       = 7
	CTAAMark          = 8
	CTAACountersOrig  = 9
	CTAACountersReply = 10
	CTAAUse           = 11
	CTAAID            = 12
	CTAANatDst        = 13
	CTAATupleMaster   = 14

	// 兼容别名：旧代码/文档里写的 CTAACounters 指原始方向计数。
	CTAACounters = CTAACountersOrig

	// CTA_TUPLE_* 嵌套属性（enum ctattr_tuple，从 1 开始）。
	CTATupleUnspec = 0
	CTATupleIP     = 1
	CTATupleProto  = 2
	// CTA_TUPLE_SRC/DST/ZONE 是「带元组的源/目的」（用于 NAT 后的地址），
	// 与 CTA_TUPLE_IP 里的 IPv4/IPv6 源目的不是一回事。
	CTATupleSrc   = 3
	CTATupleDst   = 4
	CTATupleSport = 5
	CTATupleDport = 6
	CTATupleZone  = 7

	// CTA_TUPLE_IP 嵌套属性（enum ctattr_ip，从 1 开始）。
	CTATupleIPV4Src = 1
	CTATupleIPV4Dst = 2
	CTATupleIPV6Src = 3
	CTATupleIPV6Dst = 4

	// CTA_TUPLE_PROTO 嵌套属性（enum ctattr_l4proto，从 1 开始）。
	CTATupleProtoNum      = 1
	CTATupleProtoSrcPort  = 2
	CTATupleProtoDstPort  = 3
	CTATupleProtoIcmpID   = 4
	CTATupleProtoIcmpType = 5
	CTATupleProtoIcmpCode = 6

	// CTA_COUNTERS_* 嵌套属性（enum ctattr_counters，从 1 开始）。
	CTAACountersPackets = 1
	CTAACountersBytes   = 2

	// nf_conntrack 状态位（<linux/netfilter/nf_conntrack_common.h>）。
	// 注意：这是 IPS_* 位，不是 nft 的 NFT_CT_STATE_*（后者的 NEW 是 0x8）。
	IPSExpected  = 1 << 0
	IPSSeenReply = 1 << 1
	IPSAssured   = 1 << 2
	IPSConfirmed = 1 << 3
	IPSSrcNAT    = 1 << 4
	IPSDstNAT    = 1 << 5
	IPSTemplate  = 1 << 6
)

// 每个 conntrack 事件的类型。
type EventType uint8

const (
	// EventNew 表示新建连接。
	EventNew EventType = iota
	// EventUpdate 表示连接状态更新（如 seen_reply、assured）。
	EventUpdate
	// EventDestroy 表示连接销毁。
	EventDestroy
)

func (t EventType) String() string {
	switch t {
	case EventNew:
		return "new"
	case EventUpdate:
		return "update"
	case EventDestroy:
		return "destroy"
	}
	return "unknown"
}

// Flow 是一条 conntrack 表项（本包的精简表示）。
//
// 只保留会话表与 UI 需要的字段。**IPv4 与 IPv6 都支持**（地址用 netip.Addr，
// 天然区分族）。
type Flow struct {
	// Orig 是原始方向的五元组。
	Orig Tuple
	// Reply 是应答方向的五元组（NAT 后）。
	Reply Tuple
	// Status 是 IPS_* 位掩码。
	Status uint32
	// Timeout 是剩余存活秒数。
	Timeout uint32
	// Packets / Bytes 是原始方向的计数。
	Packets uint64
	Bytes   uint64
}

// Tuple 是 conntrack 五元组。
type Tuple struct {
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// IsNatted 报告该连接是否经过 NAT（源或目的被改写）。
func (f Flow) IsNatted() bool {
	return f.Status&(IPSSrcNAT|IPSDstNAT) != 0
}

// IsEstablished 报告是否已完成双向握手（seen_reply）。
func (f Flow) IsEstablished() bool {
	return f.Status&IPSSeenReply != 0
}

// IsAssured 报告是否被内核标记为 assured（不需要再经过 helper 检查）。
func (f Flow) IsAssured() bool {
	return f.Status&IPSAssured != 0
}

// netlink 属性（NLA）。
//
// 手写解析而不是用 netlink 包的 AttributeDecoder：conntrack 的属性是
// **多层嵌套**（CTA_TUPLE_ORIG → CTA_TUPLE_IP → CTA_TUPLE_IPV4_SRC），
// 且同一层级里既有嵌套属性又有普通属性，通用解码器处理起来反而更绕。
type attr struct {
	typ   uint16
	value []byte
}

// parseAttrs 解析一段 NLA 序列。
//
// NLA 布局：len(uint16) | type(uint16) | payload...（4 字节对齐）
// 长度非法（0 或超出剩余 buffer）时停止解析——避免恶意/损坏消息导致死循环。
func parseAttrs(buf []byte) ([]attr, error) {
	var out []attr
	for len(buf) >= 4 {
		l := int(binary.LittleEndian.Uint16(buf[0:2]))
		t := binary.LittleEndian.Uint16(buf[2:4])
		if l < 4 {
			// len==0 会导致死循环；len<4 是损坏消息
			return out, fmt.Errorf("解析属性失败: 长度为 %d（应 >= 4）", l)
		}
		if l > len(buf) {
			return out, fmt.Errorf("解析属性失败: 声明长度 %d 超过剩余 %d", l, len(buf))
		}
		out = append(out, attr{
			typ:   t &^ NLAFNested, // 剥掉 nested 标志
			value: buf[4:l],
		})
		// 按 4 字节对齐推进
		aligned := (l + 3) &^ 3
		if aligned > len(buf) {
			break
		}
		buf = buf[aligned:]
	}
	return out, nil
}

// findAttr 返回指定类型的属性（第一个匹配）。
func findAttr(attrs []attr, typ uint16) (attr, bool) {
	for _, a := range attrs {
		if a.typ == typ {
			return a, true
		}
	}
	return attr{}, false
}

// parseTuple 解析一个 CTA_TUPLE_* 嵌套属性。
//
// 结构（两层嵌套）：
//
//	CTA_TUPLE_ORIG (nested)
//	  CTA_TUPLE_IP (nested)
//	    CTA_TUPLE_IPV4_SRC: 4 字节
//	    CTA_TUPLE_IPV4_DST: 4 字节
//	  CTA_TUPLE_PROTO (nested)
//	    CTA_TUPLE_PROTO_NUM: 1 字节
//	    CTA_TUPLE_PROTO_SRC_PORT: 2 字节（网络序）
//	    CTA_TUPLE_PROTO_DST_PORT: 2 字节（网络序）
func parseTuple(raw []byte) (Tuple, error) {
	var t Tuple
	attrs, err := parseAttrs(raw)
	if err != nil {
		return t, err
	}
	// IP 地址
	if ip, ok := findAttr(attrs, CTATupleIP); ok {
		ipAttrs, err := parseAttrs(ip.value)
		if err != nil {
			return t, fmt.Errorf("解析 tuple 的 IP 失败: %w", err)
		}
		if v, ok := findAttr(ipAttrs, CTATupleIPV4Src); ok {
			if len(v.value) != 4 {
				return t, fmt.Errorf("IPv4 源地址长度应为 4，实际 %d", len(v.value))
			}
			t.SrcAddr = addrFrom4(v.value)
		} else if v, ok := findAttr(ipAttrs, CTATupleIPV6Src); ok {
			if len(v.value) != 16 {
				return t, fmt.Errorf("IPv6 源地址长度应为 16，实际 %d", len(v.value))
			}
			var a [16]byte
			copy(a[:], v.value)
			t.SrcAddr = netip.AddrFrom16(a)
		}
		if v, ok := findAttr(ipAttrs, CTATupleIPV4Dst); ok {
			if len(v.value) != 4 {
				return t, fmt.Errorf("IPv4 目的地址长度应为 4，实际 %d", len(v.value))
			}
			t.DstAddr = addrFrom4(v.value)
		} else if v, ok := findAttr(ipAttrs, CTATupleIPV6Dst); ok {
			if len(v.value) != 16 {
				return t, fmt.Errorf("IPv6 目的地址长度应为 16，实际 %d", len(v.value))
			}
			var a [16]byte
			copy(a[:], v.value)
			t.DstAddr = netip.AddrFrom16(a)
		}
	}
	// 协议与端口
	if pr, ok := findAttr(attrs, CTATupleProto); ok {
		pAttrs, err := parseAttrs(pr.value)
		if err != nil {
			return t, fmt.Errorf("解析 tuple 的 proto 失败: %w", err)
		}
		if v, ok := findAttr(pAttrs, CTATupleProtoNum); ok && len(v.value) >= 1 {
			t.Proto = v.value[0]
		}
		if v, ok := findAttr(pAttrs, CTATupleProtoSrcPort); ok && len(v.value) == 2 {
			t.SrcPort = binary.BigEndian.Uint16(v.value)
		}
		if v, ok := findAttr(pAttrs, CTATupleProtoDstPort); ok && len(v.value) == 2 {
			t.DstPort = binary.BigEndian.Uint16(v.value)
		}
	}
	return t, nil
}

// addrFrom4 把 4 字节网络序转换成 netip.Addr。
func addrFrom4(b []byte) netip.Addr {
	var a [4]byte
	copy(a[:], b)
	return netip.AddrFrom4(a)
}

// ParseFlow 解析一条 conntrack 消息的属性区（nfgenmsg 之后的部分）。
//
// 消息布局：
//
//	[netlink header (可选，调用方已剥)][nfgenmsg 4B][attributes...]
//	attributes 含：CTA_TUPLE_ORIG / CTA_TUPLE_REPLY / CTA_STATUS /
//	               CTA_TIMEOUT / CTA_COUNTERS
func ParseFlow(raw []byte) (Flow, error) {
	var f Flow
	if len(raw) < NFGenMsgSize {
		return f, fmt.Errorf("解析 conntrack 消息失败: 长度 %d 不足 nfgenmsg 头（%d）",
			len(raw), NFGenMsgSize)
	}
	attrs, err := parseAttrs(raw[NFGenMsgSize:])
	if err != nil {
		return f, fmt.Errorf("解析 conntrack 消息失败: %w", err)
	}
	if v, ok := findAttr(attrs, CTAATupleOrig); ok {
		t, err := parseTuple(v.value)
		if err != nil {
			return f, fmt.Errorf("解析原始方向五元组失败: %w", err)
		}
		f.Orig = t
	}
	if v, ok := findAttr(attrs, CTAATupleReply); ok {
		t, err := parseTuple(v.value)
		if err != nil {
			return f, fmt.Errorf("解析应答方向五元组失败: %w", err)
		}
		f.Reply = t
	}
	if v, ok := findAttr(attrs, CTAAStatus); ok && len(v.value) >= 4 {
		f.Status = binary.BigEndian.Uint32(v.value)
	}
	// CTA_TIMEOUT 是大端 32 位。
	//
	// 注意：这个字段在真机上**确实存在**（实测值 19 / 18 秒），但早期版本
	// 漏读了它——自造消息测试没覆盖，只有 golden 真机字节才暴露。
	if v, ok := findAttr(attrs, CTAATimeout); ok && len(v.value) >= 4 {
		f.Timeout = binary.BigEndian.Uint32(v.value)
	}
	if v, ok := findAttr(attrs, CTAACounters); ok {
		cAttrs, err := parseAttrs(v.value)
		if err == nil {
			if p, ok := findAttr(cAttrs, CTAACountersPackets); ok && len(p.value) >= 8 {
				f.Packets = binary.BigEndian.Uint64(p.value)
			}
			if b, ok := findAttr(cAttrs, CTAACountersBytes); ok && len(b.value) >= 8 {
				f.Bytes = binary.BigEndian.Uint64(b.value)
			}
		}
	}
	return f, nil
}

// Validate 校验解析出的 Flow 是否可用。
//
// 为什么需要：内核可能发来 IPS_EXPECTED（期望连接）或缺少 orig tuple 的
// 特殊消息。把这些放进会话表会污染统计。**校验失败应跳过而不是报错**——
// 一条坏消息不该让整个订阅循环退出。
func (f Flow) Validate() error {
	if !f.Orig.SrcAddr.IsValid() {
		return fmt.Errorf("会话缺少原始方向源地址")
	}
	if !f.Orig.DstAddr.IsValid() {
		return fmt.Errorf("会话缺少原始方向目的地址")
	}
	if f.Orig.SrcAddr.Is4() != f.Orig.DstAddr.Is4() {
		return fmt.Errorf("会话源/目的地址族不一致: %s 与 %s", f.Orig.SrcAddr, f.Orig.DstAddr)
	}
	if f.Orig.Proto == 0 {
		return fmt.Errorf("会话缺少协议")
	}
	if f.Status&IPSTemplate != 0 {
		return fmt.Errorf("会话是模板（IPS_TEMPLATE），不纳入统计")
	}
	if f.Status&IPSExpected != 0 {
		return fmt.Errorf("会话是期望连接（IPS_EXPECTED），不纳入统计")
	}
	return nil
}

// BuildDeleteRequest 构造「删除一条 conntrack 表项」的 netlink 请求体。
//
// **必须带完整属性集**，只给 orig tuple 会被内核以 EINVAL 拒绝。
// 这是真机 strace `conntrack -D` 得出的权威格式（消息长度 196 字节）：
//
//	0x0001 CTA_TUPLE_ORIG   (nested) ← 原始方向五元组
//	0x0002 CTA_TUPLE_REPLY  (nested) ← 应答方向五元组
//	0x0003 CTA_STATUS       4B
//	0x0004 CTA_PROTOINFO    (nested) ← 协议层信息（TCP 状态 / ICMP id）
//	0x0007 CTA_TIMEOUT      4B
//	0x0008 CTA_MARK         4B
//
// 如果只有 orig tuple，内核回 "netlink receive: invalid argument"。
func BuildDeleteRequest(orig, reply Tuple, status, timeout, mark uint32) ([]byte, error) {
	if !orig.SrcAddr.IsValid() || !orig.DstAddr.IsValid() {
		return nil, fmt.Errorf("构造删除请求失败: 原始方向地址无效")
	}
	if orig.SrcAddr.Is4() != orig.DstAddr.Is4() {
		return nil, fmt.Errorf("构造删除请求失败: 原始方向地址族不一致")
	}
	if orig.Proto == 0 {
		return nil, fmt.Errorf("构造删除请求失败: 协议为 0")
	}

	family := uint8(unix.AF_INET)
	if orig.SrcAddr.Is6() {
		family = unix.AF_INET6
	}
	// nfgenmsg: family(1) version(1) res_id(2)
	out := []byte{family, NFNetlinkV0, 0, 0}

	out = appendNLA(out, CTAATupleOrig, buildTuplePayload(orig))
	// 应答方向：调用方可能没有（新建连接的 reply 是全零）。
	// 缺省时用 orig 的镜像补齐——内核按五元组匹配，多给无害。
	if !reply.SrcAddr.IsValid() {
		reply = Tuple{
			SrcAddr: orig.DstAddr,
			DstAddr: orig.SrcAddr,
			SrcPort: orig.DstPort,
			DstPort: orig.SrcPort,
			Proto:   orig.Proto,
		}
	}
	out = appendNLA(out, CTAATupleReply, buildTuplePayload(reply))

	st := make([]byte, 4)
	binary.BigEndian.PutUint32(st, status)
	out = appendNLA(out, CTAAStatus, st)

	// CTA_PROTOINFO：TCP 用 state，ICMP 用 id/type/code。
	// 精确删除时内核不强校验，但缺失会被判 EINVAL，故给一个最小合法结构。
	out = appendNLA(out, CTAAProtoinfo, buildProtoinfoPayload(orig.Proto))

	to := make([]byte, 4)
	binary.BigEndian.PutUint32(to, timeout)
	out = appendNLA(out, CTAATimeout, to)

	mk := make([]byte, 4)
	binary.BigEndian.PutUint32(mk, mark)
	out = appendNLA(out, CTAAMark, mk)

	return out, nil
}

// buildTuplePayload 构造一个 CTA_TUPLE_* 的 payload（两层嵌套）。
func buildTuplePayload(t Tuple) []byte {
	ipBuf := make([]byte, 0, 24)
	if t.SrcAddr.Is4() {
		a := t.SrcAddr.As4()
		ipBuf = appendNLA(ipBuf, CTATupleIPV4Src, a[:])
		b := t.DstAddr.As4()
		ipBuf = appendNLA(ipBuf, CTATupleIPV4Dst, b[:])
	} else {
		a := t.SrcAddr.As16()
		ipBuf = appendNLA(ipBuf, CTATupleIPV6Src, a[:])
		b := t.DstAddr.As16()
		ipBuf = appendNLA(ipBuf, CTATupleIPV6Dst, b[:])
	}

	protoBuf := make([]byte, 0, 16)
	protoBuf = appendNLA(protoBuf, CTATupleProtoNum, []byte{t.Proto})
	sp := make([]byte, 2)
	binary.BigEndian.PutUint16(sp, t.SrcPort)
	protoBuf = appendNLA(protoBuf, CTATupleProtoSrcPort, sp)
	dp := make([]byte, 2)
	binary.BigEndian.PutUint16(dp, t.DstPort)
	protoBuf = appendNLA(protoBuf, CTATupleProtoDstPort, dp)

	out := make([]byte, 0, len(ipBuf)+len(protoBuf)+16)
	out = appendNLA(out, CTATupleIP, ipBuf)
	out = appendNLA(out, CTATupleProto, protoBuf)
	return out
}

// buildProtoinfoPayload 构造 CTA_PROTOINFO 的最小合法 payload。
//
// TCP(6)：含 CTA_PROTOINFO_TCP + state 子属性。
// ICMP(1)/ICMPv6(58)：含 id/type/code。
// 其他协议：空 payload（内核接受）。
func buildProtoinfoPayload(proto uint8) []byte {
	switch proto {
	case 6: // TCP
		// CTA_PROTOINFO_TCP = 1（nested），内含 CTA_PROTOINFO_TCP_STATE = 1
		inner := make([]byte, 2)
		binary.BigEndian.PutUint16(inner, 0) // state 0 = NONE，精确删除不依赖它
		sub := appendNLA(nil, 1, inner)
		return appendNLA(nil, 1, sub)
	case 1, 58: // ICMP / ICMPv6
		buf := make([]byte, 0, 16)
		buf = appendNLA(buf, 1, make([]byte, 2)) // id
		buf = appendNLA(buf, 2, []byte{0})       // type
		buf = appendNLA(buf, 3, []byte{0})       // code
		return buf
	}
	return nil
}

// appendNLA 按 NLA 格式追加：len | type | payload，4 字节对齐。
//
// 长度字段包含 4 字节头本身。
func appendNLA(dst []byte, typ uint16, payload []byte) []byte {
	total := 4 + len(payload)
	start := len(dst)
	dst = append(dst,
		byte(total), byte(total>>8), // len (little endian)
		byte(typ), byte(typ>>8), // type
	)
	dst = append(dst, payload...)
	// 补齐到 4 字节边界
	for (len(dst)-start)%4 != 0 {
		dst = append(dst, 0)
	}
	return dst
}

// MessageType 构造完整的 nfnetlink 消息类型（subsys<<8 | msgtype）。
func MessageType(msgtype uint8) uint16 {
	return uint16(NFNLSubsysCtnetlink)<<8 | uint16(msgtype)
}
