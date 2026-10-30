package sqlite

import (
	"fmt"
	"regexp"
	"time"
)

// TrafficTablePrefix 是流量日志分表的前缀。
const TrafficTablePrefix = "traffic_log_"

// trafficTableRe 是分表表名的**白名单**正则。
//
// 为什么必须有它（playbook §7.2）：表名**不能参数化**（SQL 的标识符位置
// 不接受绑定参数），所以只能拼字符串。这是本项目唯一真正的 SQL 注入面——
// 如果有人把用户输入当表名传进来，`traffic_log_2026; DROP TABLE user`
// 会执行第二条语句。
//
// 白名单而不是黑名单：只允许「前缀 + 恰好 8 位数字」，任何其它字符一律拒绝。
var trafficTableRe = regexp.MustCompile(`^traffic_log_\d{8}$`)

// TrafficTableName 返回某天的分表名（如 traffic_log_20261030）。
//
// 用 UTC 还是本地时区由调用方决定：本函数接受 time.Time 并按其自身的
// 年月日取值，不做时区转换（转换是调用方的事，避免两端理解不一致）。
func TrafficTableName(t time.Time) string {
	return fmt.Sprintf("%s%s", TrafficTablePrefix, t.Format("20060102"))
}

// ParseTrafficTableName 解析分表名，返回它代表的日期。
//
// **先做白名单校验，再解析**——顺序不能反：直接对任意字符串做
// time.Parse 会把 `traffic_log_20261332` 这类非法日期解析成奇怪的值。
func ParseTrafficTableName(name string) (time.Time, error) {
	if !IsValidTrafficTableName(name) {
		return time.Time{}, fmt.Errorf("解析分表名失败: %q 不符合 %s\\d{8} 格式", name, TrafficTablePrefix)
	}
	t, err := time.ParseInLocation("20060102", name[len(TrafficTablePrefix):], time.UTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析分表名 %q 的日期失败: %w", name, err)
	}
	return t, nil
}

// IsValidTrafficTableName 报告表名是否通过白名单校验。
//
// **所有接收表名的函数都必须先调它**，包括内部的 DROP / CREATE / INSERT。
// 这条纪律没有例外：一旦有一处漏检，注入面就成立。
func IsValidTrafficTableName(name string) bool {
	return trafficTableRe.MatchString(name)
}

// RetentionPolicy 是日志保留策略的三档（沿用旧代码语义，不重新发明）。
//
// 三档**同时生效，任一触发即清理**：
//   - Days > 0         ：删除早于 N 天的分表
//   - MaxDiskMB > 0    ：总大小超限时从最老的开始删
//   - DiskWatermarkPct > 0 ：磁盘使用率超限时从最老的开始删
type RetentionPolicy struct {
	Days             int
	MaxDiskMB        int64
	DiskWatermarkPct int
}

// Validate 校验策略取值。
//
// 负值一律拒绝而不是当作「关闭」：负数的 Days 会让「早于 N 天」变成
// 「早于过去某天」，行为反直觉。
func (p RetentionPolicy) Validate() error {
	if p.Days < 0 {
		return fmt.Errorf("校验保留策略失败: 保留天数不能为负（%d）", p.Days)
	}
	if p.MaxDiskMB < 0 {
		return fmt.Errorf("校验保留策略失败: 最大磁盘 MB 不能为负（%d）", p.MaxDiskMB)
	}
	if p.DiskWatermarkPct < 0 || p.DiskWatermarkPct > 100 {
		return fmt.Errorf("校验保留策略失败: 磁盘水位百分比应在 0..100（%d）", p.DiskWatermarkPct)
	}
	return nil
}

// IsZero 报告策略是否全部关闭（不做任何清理）。
func (p RetentionPolicy) IsZero() bool {
	return p.Days == 0 && p.MaxDiskMB == 0 && p.DiskWatermarkPct == 0
}

// SelectExpired 从分表清单里挑出应删除的表。
//
// tables 是 (表名 -> 大小字节)。返回按「最老优先」排序的待删列表。
//
// 判定顺序与理由：
//  1. 天数：绝对到期，无条件删
//  2. 磁盘大小 / 水位：从最老的开始删，**直到满足限制**
//
// 注意：磁盘大小与水位两档都要「删到够为止」，不能只看「是否超标」——
// 超标时需要删足够多的表才能回到线下。
func (p RetentionPolicy) SelectExpired(now time.Time, tables map[string]int64, diskFreePct float64) ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.IsZero() || len(tables) == 0 {
		return nil, nil
	}

	type entry struct {
		name string
		date time.Time
		size int64
	}
	entries := make([]entry, 0, len(tables))
	for name, size := range tables {
		t, err := ParseTrafficTableName(name)
		if err != nil {
			// 非分表名的条目跳过（可能是未来的 audit_log 之类）
			continue
		}
		entries = append(entries, entry{name: name, date: t, size: size})
	}
	// 最老优先
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].date.Before(entries[j-1].date); j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}

	drop := make(map[string]bool, len(entries))
	var totalSize int64
	for _, e := range entries {
		totalSize += e.size
	}

	// ① 天数：绝对到期
	if p.Days > 0 {
		cutoff := now.AddDate(0, 0, -p.Days)
		for _, e := range entries {
			if e.date.Before(cutoff) {
				drop[e.name] = true
				totalSize -= e.size
			}
		}
	}

	// ② 大小上限
	if p.MaxDiskMB > 0 {
		limit := p.MaxDiskMB << 20
		for _, e := range entries {
			if totalSize <= limit {
				break
			}
			if drop[e.name] {
				continue
			}
			drop[e.name] = true
			totalSize -= e.size
		}
	}

	// ③ 磁盘水位：剩余百分比低于阈值时继续删
	if p.DiskWatermarkPct > 0 && diskFreePct < float64(100-p.DiskWatermarkPct) {
		for _, e := range entries {
			if drop[e.name] {
				continue
			}
			drop[e.name] = true
			// 单表删完后无法准确预测新水位（没有总量），
			// 所以按「删到只剩最老的一张」的保守策略：由调用方在下一轮复查。
			// 这里只保证至少删一张，避免死循环。
			break
		}
	}

	out := make([]string, 0, len(drop))
	for _, e := range entries {
		if drop[e.name] {
			out = append(out, e.name)
		}
	}
	return out, nil
}
