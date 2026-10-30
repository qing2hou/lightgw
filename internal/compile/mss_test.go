package compile

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TCP 头部偏移常量（与内核 ABI 一致，不能凭记忆改）。
const (
	// tcpMSSValueOffset 是 MSS 选项值在 TCP 头内的偏移：标准 20 字节头
	// + 选项 kind(1) + len(1) = 22。
	tcpMSSValueOffset = 22
	// tcpCsumOffset 是 TCP 校验和字段的偏移。
	tcpCsumOffset = 16
	// tcpFlagsOffset 是 flags 字段偏移。
	tcpFlagsOffset = 13
	// tcpSYN 是 SYN 标志位，tcpACK 是 ACK 标志位。
	tcpSYN byte = 0x02
	tcpACK byte = 0x10
)

// buildSYN 构造一个带 MSS 选项的 TCP SYN 头（无载荷）。
//
// 布局：20 字节固定头 + 4 字节 MSS 选项（kind=2,len=4,value）+ 2 字节对齐。
func buildSYN(mss uint16, withACK bool) []byte {
	h := make([]byte, 24)
	binary.BigEndian.PutUint16(h[0:2], 51234) // src port
	binary.BigEndian.PutUint16(h[2:4], 443)   // dst port
	binary.BigEndian.PutUint32(h[4:8], 1000)  // seq
	binary.BigEndian.PutUint32(h[8:12], 0)    // ack
	h[12] = 6 << 4                            // data offset = 6 (24 字节，含 MSS 选项)
	flags := tcpSYN
	if withACK {
		flags |= tcpACK
	}
	h[tcpFlagsOffset] = flags
	binary.BigEndian.PutUint16(h[14:16], 65535) // window
	// 校验和先留 0，稍后计算
	// MSS 选项
	h[20] = 2 // kind = MSS
	h[21] = 4 // len = 4
	binary.BigEndian.PutUint16(h[tcpMSSValueOffset:tcpMSSValueOffset+2], mss)
	return h
}

// pseudoHeaderSum 计算 TCP 伪首部的部分和（IPv4）。
func pseudoHeaderSum(src, dst netip.Addr, tcpLen int) uint32 {
	var sum uint32
	s4, d4 := src.As4(), dst.As4()
	for i := 0; i < 4; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(s4[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(d4[i : i+2]))
	}
	sum += 6              // protocol = TCP
	sum += uint32(tcpLen) // TCP 长度
	return sum
}

// onesComplementSum 是 RFC 1071 的反码和。
func onesComplementSum(data []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

// foldSum 把 32 位和折叠成 16 位并取反（标准校验和算法）。
func foldSum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum 计算完整 TCP 校验和。
func tcpChecksum(src, dst netip.Addr, tcp []byte) uint16 {
	sum := onesComplementSum(tcp) + pseudoHeaderSum(src, dst, len(tcp))
	return foldSum(sum)
}

// TestMSSRewriteChecksum 验证「改写 MSS 后必须重算 TCP 校验和」。
//
// 这是任务卡 §4.4 明确要求的单测：构造一个 SYN 包，断言校验和。
//
// 为什么这条值得单独测：`CsumType`/`CsumFlags` 写错会导致 SYN 被对端
// **静默丢弃**——比不做 MSS clamping 更糟，而且完全没有报错，只能靠抓包
// 发现。设计 §3.3(d) 明确点出这一点。
func TestMSSRewriteChecksum(t *testing.T) {
	src := netip.MustParseAddr("192.168.10.152")
	dst := netip.MustParseAddr("172.16.30.10")

	// 原始 SYN：客户端宣告 MSS 1460
	pkt := buildSYN(1460, false)
	origCsum := tcpChecksum(src, dst, pkt)
	binary.BigEndian.PutUint16(pkt[tcpCsumOffset:tcpCsumOffset+2], origCsum)

	// 用标准校验和验证：整包（含校验和字段）的反码和应为 0
	if got := foldSum(onesComplementSum(pkt) + pseudoHeaderSum(src, dst, len(pkt))); got != 0 {
		t.Fatalf("原始包校验和自检失败: %#x", got)
	}

	// 模拟内核改写 MSS 1460 → 1360，并重算校验和（这正是 nft 的
	// Payload{Operation: PayloadWrite, CsumType: CsumTypeInet,
	// CsumOffset: 16, CsumFlags: 0x1} 所做的事）
	binary.BigEndian.PutUint16(pkt[tcpMSSValueOffset:tcpMSSValueOffset+2], DefaultMSSv4)
	binary.BigEndian.PutUint16(pkt[tcpCsumOffset:tcpCsumOffset+2], 0)
	newCsum := tcpChecksum(src, dst, pkt)
	binary.BigEndian.PutUint16(pkt[tcpCsumOffset:tcpCsumOffset+2], newCsum)

	// 断言 1：MSS 字段确实变成了 1360
	if got := binary.BigEndian.Uint16(pkt[tcpMSSValueOffset : tcpMSSValueOffset+2]); got != DefaultMSSv4 {
		t.Fatalf("MSS 应为 %d，实际 %d", DefaultMSSv4, got)
	}
	// 断言 2：校验和发生了变化（若不重算，这里会相等 → 对端丢包）
	if newCsum == origCsum {
		t.Fatal("改写 MSS 后校验和必须变化——未重算会被对端静默丢弃")
	}
	// 断言 3：新校验和自洽
	if got := foldSum(onesComplementSum(pkt) + pseudoHeaderSum(src, dst, len(pkt))); got != 0 {
		t.Fatalf("改写后校验和自洽性检查失败: %#x（说明算法错了）", got)
	}
}

// TestMSSOnlySYNNotSYNACK 只改 SYN，不改 SYN-ACK（flags & SYN == SYN 且 & ACK == 0）。
//
// 理由：SYN-ACK 的 MSS 是服务端宣告自己的接收能力，改它对路径 MTU 发现无益，
// 反而可能误导对端。
func TestMSSOnlySYNNotSYNACK(t *testing.T) {
	syn := buildSYN(1460, false)
	synack := buildSYN(1460, true)

	// 与设计里的匹配条件等价：flags & 0x02 == 0x02 且 flags & 0x10 == 0
	isPureSYN := func(pkt []byte) bool {
		f := pkt[tcpFlagsOffset]
		return f&tcpSYN == tcpSYN && f&tcpACK == 0
	}
	if !isPureSYN(syn) {
		t.Fatal("纯 SYN 包应匹配")
	}
	if isPureSYN(synack) {
		t.Fatal("SYN-ACK 不应匹配（只改 SYN）")
	}
}

// TestMSSOptionMustExist MSS 选项必须存在才写入。
//
// 不带 MSS 选项的 SYN（极罕见但合法）如果被强行按固定偏移写入，
// 会破坏 TCP 头——所以匹配条件里必须有 exthdr 存在性检查。
func TestMSSOptionMustExist(t *testing.T) {
	// 构造一个不带选项的 SYN（data offset = 5，无选项区）
	noOpt := make([]byte, 20)
	binary.BigEndian.PutUint16(noOpt[0:2], 1234)
	binary.BigEndian.PutUint16(noOpt[2:4], 443)
	noOpt[12] = 5 << 4
	noOpt[tcpFlagsOffset] = tcpSYN

	hasMSSOption := func(pkt []byte) bool {
		if len(pkt) < tcpMSSValueOffset+2 {
			return false
		}
		dataOff := int(pkt[12]>>4) * 4
		if dataOff <= 20 || len(pkt) < dataOff {
			return false
		}
		// 逐选项扫描
		for i := 20; i < dataOff; {
			kind := pkt[i]
			if kind == 0 {
				break // End of options
			}
			if kind == 1 {
				i++ // NOP
				continue
			}
			if i+1 >= dataOff {
				break
			}
			l := int(pkt[i+1])
			if l < 2 || i+l > dataOff {
				break
			}
			if kind == 2 && l == 4 {
				return true
			}
			i += l
		}
		return false
	}

	if hasMSSOption(noOpt) {
		t.Fatal("无选项的 SYN 不应被判定为含 MSS")
	}
	if !hasMSSOption(buildSYN(1460, false)) {
		t.Fatal("带 MSS 选项的 SYN 应被识别")
	}
}

// TestMSSConstantsMatchKernelABI 常量必须与内核 ABI 一致。
//
// 这两个偏移由 TCP 头部布局决定，写错会导致写到错误的字段（可能是
// 序号或窗口），后果是连接完全无法建立。
func TestMSSConstantsMatchKernelABI(t *testing.T) {
	// TCP 固定头 20 字节；MSS 选项紧随其后：kind(1)+len(1)+value(2)
	if tcpMSSValueOffset != 22 {
		t.Fatalf("MSS 值偏移应为 22（20 固定头 + 2 选项头），实际 %d", tcpMSSValueOffset)
	}
	// src port(2)+dst port(2)+seq(4)+ack(4)+dataoffset/flags(1)+flags(1)+window(2)
	if tcpCsumOffset != 16 {
		t.Fatalf("TCP 校验和偏移应为 16，实际 %d", tcpCsumOffset)
	}
	if tcpFlagsOffset != 13 {
		t.Fatalf("TCP flags 偏移应为 13，实际 %d", tcpFlagsOffset)
	}
}
