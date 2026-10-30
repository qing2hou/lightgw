package compile

import (
	"fmt"
	"net/netip"
)

// ExpandAddrMatches 把含多网段的规则展开成「每条只有单个网段」的规则集合。
//
// 为什么必须展开：nft 的地址匹配可以用匿名 set（`ip saddr { a, b }`）表达，
// 但本项目的表达式层（adapter/nftables/translate.go）只构造单网段的
// Payload+Bitwise+Cmp。要在表达式层支持多网段，需要预建命名 set 并用
// Lookup —— 那会引入「set 的生命周期管理」「set 与规则的原子性」两个新问题。
//
// 展开的成本是规则数按笛卡尔积增长（源网段数 × 目的网段数），换来的是：
//   - 表达式构造简单，没有外部状态
//   - 每条规则的语义独立可验证（`nft list` 一眼能读懂）
//   - 删除精确（按 comment 逐条删，不依赖 set）
//
// 对典型配置（源白名单 1~10 个网段，目的地址通常 1 个）规则数完全可控。
//
// comment 处理：展开后每条规则的 comment 追加 `#<序号>`，保证全局唯一
// （Plan.Validate 强制 comment 唯一，Applier 靠它精确删除）。
// 不需要展开的规则保持原 comment 不变——避免无谓的规则名漂移。
func ExpandAddrMatches(rules []Rule) ([]Rule, error) {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		// 空白（不做该维度匹配）用 nil 表示，非空用排序后的网段列表。
		srcs := expandDim(r.Src)
		dsts := expandDim(r.Dst)

		if r.Src.Negated && len(srcs) > 1 {
			return nil, fmt.Errorf("展开规则 %s 失败: 不支持「多网段 + 取反」的源匹配"+
				"（取反需要 OR 语义，无法用多条规则表达）", r.Comment)
		}
		if r.Dst.Negated && len(dsts) > 1 {
			return nil, fmt.Errorf("展开规则 %s 失败: 不支持「多网段 + 取反」的目的匹配", r.Comment)
		}

		nSrc := card(srcs)
		nDst := card(dsts)
		if nSrc*nDst <= 1 {
			out = append(out, r)
			continue
		}
		idx := 0
		for _, s := range each(srcs) {
			for _, d := range each(dsts) {
				nr := r
				nr.Comment = fmt.Sprintf("%s#%d", r.Comment, idx)
				if nSrc > 1 {
					nr.Src = AddrMatch{Prefixes: []netip.Prefix{s}, Negated: r.Src.Negated}
				}
				if nDst > 1 {
					nr.Dst = AddrMatch{Prefixes: []netip.Prefix{d}, Negated: r.Dst.Negated}
				}
				out = append(out, nr)
				idx++
			}
		}
	}
	return out, nil
}

// each 让「空白维度」（nil）也迭代一次，保证笛卡尔积正确。
//
// 直接 range nil 会零次迭代 —— 那会让「只配了源网段、没配目的地址」的规则
// 一条都不生成（静默丢规则）。这是本函数最容易被改错的一处。
func each(dim []netip.Prefix) []netip.Prefix {
	if dim == nil {
		return []netip.Prefix{{}}
	}
	return dim
}

// expandDim 返回某个维度的展开单元。
//
// 约定：返回 nil 表示「该维度不参与匹配」（基数 1，展开时保留原值）；
// 返回非 nil 表示需要为每个元素各生成一条规则。
func expandDim(m AddrMatch) []netip.Prefix {
	if m.Empty() {
		return nil
	}
	return SortedPrefixes(m.Prefixes)
}

// card 返回展开单元的数量：nil 视为 1（不展开）。
func card(dim []netip.Prefix) int {
	if dim == nil {
		return 1
	}
	return len(dim)
}
