// Package bandwidth 提供带宽包的额度分配与超额订阅校验。
//
// 这是**纯数学**层，不碰 tc、不碰内核。
//
// 关键背景（真机实测，docs/poc-result.md §4.2.1，15 组二维扫描）：
//
//	htb 树「总额父类 rate + 每源保底子类」的实际总量约为
//	    max(parent.rate, Σ(子类 rate))
//	误差 −2.5% ~ −4.2%。
//
// 也就是说 **parent.rate 是「保底总池」而不是硬上限**：当 Σ保底 > 总额时，
// 合计会突破总额（实测 N=12 / 总额 4MB/s 跑出 11.50 MB/s，超 187.6%）。
//
// 因此产品语义（ADR-15）采用「约束式」：保存带宽包时校验
// Σ(成员 MinKBps) ≤ 总额，超额直接拒绝。本包提供该校验与额度计算。
//
// 纯函数层：零 IO。不 import os/net/os-exec/netlink/database-sql（C-12）。
package bandwidth

import (
	"fmt"
	"sort"
)

// 每源保底的兜底默认值（KB/s）。
//
// 与旧实现保持一致：配置为 0 时按 1024 KB/s 处理。注意这个默认值在
// 「源数 × 1024 > 总额」时必然造成超额订阅，必须由 CheckOversubscription 拦住。
const DefaultMinKBps int64 = 1024

// Oversubscription 描述一次超额订阅判定。
type Oversubscription struct {
	// TotalKBps 是带宽包总额。
	TotalKBps int64
	// MinKBps 是每源保底（已应用默认值）。
	MinKBps int64
	// Sources 是成员源数量。
	Sources int
	// RequiredKBps 是 Σ保底 = MinKBps × Sources。
	RequiredKBps int64
	// Oversubscribed 为 true 表示 Σ保底 > 总额。
	Oversubscribed bool
}

// CheckOversubscription 判定给定总额与源数是否构成超额订阅。
//
// ADR-15 决策：超额订阅必须**拒绝保存**，因为 htb 无法把总额压成硬上限。
// 一旦允许超额，用户会以为「配了总额就一定能守住」，而实测会突破。
func CheckOversubscription(totalKBps, minKBps int64, sources int) Oversubscription {
	if minKBps <= 0 {
		minKBps = DefaultMinKBps
	}
	if sources < 0 {
		sources = 0
	}
	required := minKBps * int64(sources)
	return Oversubscription{
		TotalKBps:      totalKBps,
		MinKBps:        minKBps,
		Sources:        sources,
		RequiredKBps:   required,
		Oversubscribed: required > totalKBps,
	}
}

// ValidateOversubscription 是 CheckOversubscription 的断言版，返回中文错误。
//
// 错误消息要给出「三个数」——总额、每源保底、成员数——让人一眼看出怎么改。
func ValidateOversubscription(totalKBps, minKBps int64, sources int) error {
	if totalKBps <= 0 {
		return fmt.Errorf("校验带宽包失败: 总额必须为正（当前 %d KB/s）", totalKBps)
	}
	o := CheckOversubscription(totalKBps, minKBps, sources)
	if !o.Oversubscribed {
		return nil
	}
	return fmt.Errorf(
		"校验带宽包失败: 超额订阅 %d 个源 × 保底 %d KB/s = %d KB/s，超过总额 %d KB/s。"+
			"限速树无法把总额压成硬上限（实测超额时会突破），请降低保底至 %d KB/s 以下或减少成员",
		o.Sources, o.MinKBps, o.RequiredKBps, o.TotalKBps, totalKBps/int64(o.Sources))
}

// AllocatableMinKBps 返回「在总额内每个成员最多能分到多少保底」。
//
// 供 UI 提示：用户填了 N 个成员时，保底的上限是多少。
// sources 为 0 时返回总额本身（无成员则无分摊）。
func AllocatableMinKBps(totalKBps int64, sources int) int64 {
	if sources <= 0 {
		return totalKBps
	}
	if totalKBps <= 0 {
		return 0
	}
	return totalKBps / int64(sources)
}

// SourceQuota 是单个源的实际可用额度。
type SourceQuota struct {
	Source string
	// GuaranteedKBps 是保底（拥塞时的下限）。
	GuaranteedKBps int64
	// CeilKBps 是上限（空闲时可借满）。
	CeilKBps int64
}

// Plan 是一次带宽分配的结果。
//
// 不变量：构造后不可变。Entries 按 Source 字典序排序，保证结果确定
// （顺序不稳定会让每次 Apply 产生无意义的 diff）。
type Plan struct {
	TotalKBps int64
	MinKBps   int64
	Entries   []SourceQuota
	// Oversubscribed 为 true 时，实际分配会按 rate 比例压缩，
	// 不保证每个源拿到 MinKBps，**且合计会突破 TotalKBps**。
	Oversubscribed bool
}

// Allocate 计算一组源在给定带宽包下的额度。
//
// 语义（与 htb 实测行为一致）：
//   - 每个源的 rate（保底）= MinKBps
//   - 每个源的 ceil（上限）= 总额（空闲时可借满）
//   - 当 Σ保底 > 总额时，HTB 按 rate 比例分配，**不保证**每源拿到保底，
//     且合计会突破总额——这时 Oversubscribed 为 true。
//
// MinKBps 为 0 时应用 DefaultMinKBps；超过总额时被截到总额
// （单源吃满整个包是合法的，不该报错）。
func Allocate(totalKBps, minKBps int64, sources []string) Plan {
	if minKBps <= 0 {
		minKBps = DefaultMinKBps
	}
	if minKBps > totalKBps && totalKBps > 0 {
		// 单源保底超过总额：截到总额。这不是超额订阅（只有一个源）。
		minKBps = totalKBps
	}
	uniq := dedupeSorted(sources)
	p := Plan{TotalKBps: totalKBps, MinKBps: minKBps}
	o := CheckOversubscription(totalKBps, minKBps, len(uniq))
	p.Oversubscribed = o.Oversubscribed
	for _, s := range uniq {
		p.Entries = append(p.Entries, SourceQuota{
			Source:         s,
			GuaranteedKBps: minKBps,
			CeilKBps:       totalKBps,
		})
	}
	return p
}

// dedupeSorted 去重并按字典序排序（结果必须确定）。
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SharedTotalKBps 计算「多个带宽包共享同一网卡」时的注意事项返回值。
//
// 说明：不同带宽包必须用**不同的 ifb 设备**（§3.5.2），否则父类 rate 会被
// 后应用的包覆盖，先前包的额度失效。本函数返回各组总额的最大值，仅用于
// 生成提示信息——真正的隔离靠设备命名（ifb-hw<groupID>）。
func SharedTotalKBps(groups []int64) int64 {
	var max int64
	for _, g := range groups {
		if g > max {
			max = g
		}
	}
	return max
}
