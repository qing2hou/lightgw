// 锚点与打标规则的表达式序列（table.go 的核心动作，独立小文件便于离线单测引用）。
package nft

import (
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// MarkFwdOK 放行标记位（fwmark bit0；位段规划见 design-fwgateway.md ADR-11）。
const MarkFwdOK uint32 = 0x1

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

// SetMarkExprs 打标规则表达式：meta mark set | bits（保留其他位，OR 语义）。
// 实现：load mark → OR bits（Bitwise Xor 充当 OR：mask 全 1 + xor=bits）→ write。
func SetMarkExprs(bits uint32) []expr.Any {
	ones := uint32(0xFFFFFFFF)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		// Bitwise: reg1 = (reg1 & mask) ^ xor —— mask 全 1、xor=bits 即纯 OR
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(ones),
			Xor:  binaryutil.NativeEndian.PutUint32(bits)},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
	}
}
