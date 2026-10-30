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
// 两个必须同时满足的条件：
//
//  1. **只改 SYN（不含 ACK）**。SYN-ACK 也会带 MSS 选项，但它的 MSS 是服务端
//     宣告自己的接收能力，改它对路径 MTU 发现没有帮助，反而可能误导对端。
//  2. **MSS 选项必须存在**。内核的 `tcp option maxseg size set` 只在选项存在时
//     改写；选项不存在时该表达不做任何事（不会写到错误偏移）。
//
// **校验和由内核自动重算**——这一点在真机上核对过 `nft -j` 输出：
//
//	{"mangle": {"key": {"tcp option": {"name": "maxseg", "field": "size"}}, "value": 1360}}
//
// 内核只需要一条 `mangle` 表达，不需要手工构造
// `Payload{CsumType: CsumTypeInet, CsumOffset: 16, CsumFlags: 0x1}`。
// （早期文档写「必须手工重算校验和」是误解了 nft 的命令行语法与 netlink
// 表达式的对应关系：命令行里的 `set` 会由 nft 工具翻译成内核的 mangle，
// 而 mangle 天然带校验和更新语义。）
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
