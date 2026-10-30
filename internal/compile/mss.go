package compile

import (
	"fmt"
)

// DefaultMSSv4 / DefaultMSSv6 是 MSS clamping 的推荐值。
//
// 1500 - 20(IP) - 20(TCP) = 1460 是标准以太网 MSS。取 1360 留出 100 字节
// 给 PPPoE/隧道封装（常见客户场景），这是业界通用做法。
const (
	DefaultMSSv4 uint16 = 1360
	DefaultMSSv6 uint16 = 1340
	// MinMSS 是允许的最小值。再小会让吞吐严重受损（每包有效载荷 < 500 字节）。
	MinMSS uint16 = 536
)

// MSS 规则的 comment 前缀（Applier 按 comment 精确删除）。
const mssCommentPrefix = "haweb:mss:"

// CompileMSSClamp 生成 MSS clamping 规则。
//
// 语义（内核等价）：
//
//	tcp flags syn tcp option maxseg size set <mss>
//
// 三个必须同时满足的条件，缺一不可：
//
//  1. **只改 SYN（不含 ACK）**。SYN-ACK 也会带 MSS 选项，但它的 MSS 是服务端
//     宣告自己的接收能力，改它对路径 MTU 发现没有帮助，反而可能误导对端。
//     flags & 0x02 == 0x02 且 flags & 0x10 == 0（SYN=1, ACK=0）。
//  2. **MSS 选项必须存在**。用 `tcp option maxseg size set N` 时内核只在选项
//     存在时改写（nft 的 exthdr 表达式语义）；若选项不存在，表达式返回真但
//     写入位置无意义。命令行实测确认过这一点。
//  3. **必须重算 TCP 校验和**。Payload write 的 CsumType/CsumOffset 写错会导致
//     SYN 被对端静默丢弃——比不做 clamping 更糟。
//
// ⚠️ 第 3 点在 nft 的 netlink 表达式层对应：
//
//	Payload{Base: TransportHeader, Offset: 22, Len: 2,
//	        CsumType: CsumTypeInet, CsumOffset: 16, CsumFlags: 0x1}
//
// 其中 Offset 22 = TCP 头里的 MSS 选项值偏移（标准 20 字节头 + 选项 kind/len 2 字节），
// CsumOffset 16 = TCP 校验和字段偏移。这两个常量由内核 ABI 决定，不能凭记忆改。
//
// 返回空切片表示不生成任何规则（mss=0 即关闭）。
func CompileMSSClamp(v4, v6 uint16) ([]Rule, error) {
	if v4 == 0 && v6 == 0 {
		return nil, nil
	}
	var out []Rule
	if v4 != 0 {
		if err := validateMSS(v4, "IPv4"); err != nil {
			return nil, err
		}
		out = append(out, Rule{
			Chain:     ChainMss,
			Comment:   mssCommentPrefix + "v4",
			Proto:     "tcp",
			MSSValue:  v4,
			MSSFamily: "ipv4",
		})
	}
	if v6 != 0 {
		if err := validateMSS(v6, "IPv6"); err != nil {
			return nil, err
		}
		out = append(out, Rule{
			Chain:     ChainMss,
			Comment:   mssCommentPrefix + "v6",
			Proto:     "tcp",
			MSSValue:  v6,
			MSSFamily: "ipv6",
		})
	}
	return out, nil
}

func validateMSS(v uint16, family string) error {
	if v < MinMSS {
		return fmt.Errorf("编译 MSS 规则失败: %s 的 MSS 值 %d 小于下限 %d（会严重损害吞吐）",
			family, v, MinMSS)
	}
	return nil
}

// MSSCommentMatches 报告某条 comment 是否属于 MSS 规则（供 Applier 精确清理）。
func MSSCommentMatches(comment string) bool {
	return len(comment) > len(mssCommentPrefix) &&
		comment[:len(mssCommentPrefix)] == mssCommentPrefix
}
