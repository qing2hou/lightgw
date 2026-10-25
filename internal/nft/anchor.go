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
)

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
