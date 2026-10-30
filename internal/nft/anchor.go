// 锚点与打标规则的表达式序列（table.go 的核心动作，独立小文件便于离线单测引用）。
package nft

import (
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// fwmark 位段（design-fwgateway.md ADR-11）：
const (
	// MarkFwdOK bit0：规则放行位（snat/dnat 规则白名单命中；默认拒绝尾行只查它）
	MarkFwdOK uint32 = 0x1
	// MarkPolicyOK bit1：策略放行位（accept 策略命中——仅计数/标记用途，
	// 不参与默认拒绝判定：策略 accept 不豁免规则白名单，AND 语义——评审 #2）
	MarkPolicyOK uint32 = 0x2
	// MarkDNAT bit2：DNAT 发布命中位（DEFECT-4：源=某 snat 白名单的客户端访问
	// 发布地址时，DNAT 改写后的内网后端流量被该源的策略路由（from 源 lookup 出口表）
	// 拉去外网出口绕行并误 SNAT——发布流量应直连后端：srcnat 豁免 + 策略路由回 main 表）
	MarkDNAT uint32 = 0x4
)

// 关于"每源保底带宽"的实现限制（重要，改动前必读）
//
// 目标：带宽包内多个客户端并发时，每个客户端至少拿到 MinKBps。
// 实现它需要把包按"原始客户端"分类到各自的 htb 子类。
//
// 本环境（virtio + Linux 6.8，实测 170 生产机）上所有按源分类的通路都不可用：
//   - cls_u32：完全不参与分类。挂上后各 class 的 Sent 恒为 0、流量全走
//     default；把限速类压到 1 Kbit 仍能 79.9MB/s 满速上传。
//   - cls_fw：只按 mark 的**完整值**匹配，且 handle 位图只接受奇数
//     （实测 1/3/5/9/31 命中，2/16/32/50/100 全部失配），mark 带任何
//     额外位（如 MarkFwdOK）也会失配 —— 最多 16 个源且必须独占 mark。
//   - cls_flower：本 tc 版本不支持 skb mark / fwmark 匹配（只有 ct_mark）。
//
// 另外上传方向的包在 egress 上源地址已被 SNAT 改成网关 IP，按 saddr 分类
// 本就不可能区分原始客户端。
//
// 当前采用的可实现折中：qdisc default 直连限速类 + 该 class 挂 fq_codel。
//   - 总额严格受 htb rate 约束（实测 8MB/s 配置跑 6.67MB/s，扣 TCP 开销）
//   - fq_codel 保证**流级公平**：并发连接之间按流轮转，单个源吸血式
//     多连接会被摊平，不会饿死其他源
//   - 但**不是按源 IP 的硬保底**：同一源若只开 1 条流、另一源开 20 条，
//     前者拿不到"至少 MinKBps"的保证
//
// MinKBps 仍保留为配置值（前端可配、库里有值），待换 BPF/自定义分类器后
// 再接上。不要因为"看到配置项"就以为它生效了。

// anchorExprs 锚点规则表达式：meta mark & 0x1 == 0x1 → accept。
// 形态与 PoC #7 位测试一致（load → Bitwise AND → Cmp neq 0 → Accept）。
func anchorExprs() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(MarkFwdOK),
			Xor:  binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1,
			Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// SetMarkExprs 打标规则表达式：meta mark set bits | 原值（幂等 OR——不翻转已置位）。
// 实现：load → (in & ~bits) ^ bits（等价 in|bits——Bitwise 无 OR 原语；
// 曾经的 mask 全 1 + xor=bits 是 XOR 语义：重传包二次命中会把 1 翻回 0，
// 容器实测白名单源被拒/双行 counter 同增即此——修复为幂等 OR）→ write。
func SetMarkExprs(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		// Bitwise: reg1 = (reg1 & mask) ^ xor —— mask=~bits、xor=bits ⇒ in|bits
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(^bits),
			Xor:  binaryutil.NativeEndian.PutUint32(bits)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
	}
}
