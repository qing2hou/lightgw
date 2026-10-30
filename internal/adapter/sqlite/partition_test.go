package sqlite

import (
	"testing"
	"time"
)

// TestTrafficTableName 表名格式必须固定。
func TestTrafficTableName(t *testing.T) {
	d := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	if got := TrafficTableName(d); got != "traffic_log_20261030" {
		t.Fatalf("表名错误: %q", got)
	}
}

// TestIsValidTrafficTableName 白名单校验（SQL 注入面，playbook §7.2）。
func TestIsValidTrafficTableName(t *testing.T) {
	valid := []string{
		"traffic_log_20261030",
		"traffic_log_00000000",
		"traffic_log_99999999",
	}
	for _, n := range valid {
		if !IsValidTrafficTableName(n) {
			t.Fatalf("%q 应通过校验", n)
		}
	}
	// ★ 注入与格式错误必须全部拒绝
	invalid := []string{
		"traffic_log_2026; DROP TABLE user", // DoD 明确要求的注入用例
		"traffic_log_2026103",               // 7 位
		"traffic_log_202610301",             // 9 位
		"traffic_log_2026103a",              // 含字母
		"traffic_log_",                      // 无日期
		"Traffic_Log_20261030",              // 大小写不符
		"traffic_log_20261030'",             // 引号
		"traffic_log_20261030--",            // 注释
		"users",                             // 完全无关的表
		"",                                  // 空
		"traffic_log_20261030 UNION SELECT 1",
	}
	for _, n := range invalid {
		if IsValidTrafficTableName(n) {
			t.Fatalf("★ %q 必须被拒绝（SQL 注入面）", n)
		}
	}
}

// TestParseTrafficTableName 解析与格式校验的顺序必须正确。
func TestParseTrafficTableName(t *testing.T) {
	d, err := ParseTrafficTableName("traffic_log_20261030")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if d.Year() != 2026 || d.Month() != 10 || d.Day() != 30 {
		t.Fatalf("日期错误: %v", d)
	}
	// 非法表名
	if _, err := ParseTrafficTableName("traffic_log_2026; DROP TABLE user"); err == nil {
		t.Fatal("注入表名必须报错")
	}
	// 格式对但日期非法（20261332 -> 13 月 32 日）
	if _, err := ParseTrafficTableName("traffic_log_20261332"); err == nil {
		t.Fatal("非法日期必须报错")
	}
}

// TestRetentionPolicyValidate 策略校验。
func TestRetentionPolicyValidate(t *testing.T) {
	if err := (RetentionPolicy{Days: 30}).Validate(); err != nil {
		t.Fatalf("合法策略应通过: %v", err)
	}
	if err := (RetentionPolicy{Days: -1}).Validate(); err == nil {
		t.Fatal("负天数应报错")
	}
	if err := (RetentionPolicy{MaxDiskMB: -1}).Validate(); err == nil {
		t.Fatal("负磁盘上限应报错")
	}
	if err := (RetentionPolicy{DiskWatermarkPct: 101}).Validate(); err == nil {
		t.Fatal("水位 >100 应报错")
	}
	if !(RetentionPolicy{}).IsZero() {
		t.Fatal("全零策略应判定为 zero")
	}
}

// TestSelectExpiredByDays 天数档：早于 N 天的分表被删。
func TestSelectExpiredByDays(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	tables := map[string]int64{
		"traffic_log_20261030": 100, // 今天
		"traffic_log_20261029": 100, // 1 天前
		"traffic_log_20261020": 100, // 10 天前
		"traffic_log_20260901": 100, // 59 天前
	}
	got, err := RetentionPolicy{Days: 30}.SelectExpired(now, tables, 100)
	if err != nil {
		t.Fatalf("计算失败: %v", err)
	}
	if len(got) != 1 || got[0] != "traffic_log_20260901" {
		t.Fatalf("应只删 20260901（59 天前），实际 %v", got)
	}
}

// TestSelectExpiredBySize 大小档：超限时从最老开始删到够。
func TestSelectExpiredBySize(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	tables := map[string]int64{
		"traffic_log_20261030": 2 << 20, // 2MB
		"traffic_log_20261029": 2 << 20,
		"traffic_log_20261028": 2 << 20,
		"traffic_log_20261027": 2 << 20,
	}
	// 上限 5MB，当前 8MB → 需删 2 张（最老的两张）
	got, err := RetentionPolicy{MaxDiskMB: 5}.SelectExpired(now, tables, 100)
	if err != nil {
		t.Fatalf("计算失败: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应删 2 张表，实际 %d: %v", len(got), got)
	}
	// 必须是最老的两张
	if got[0] != "traffic_log_20261027" || got[1] != "traffic_log_20261028" {
		t.Fatalf("应按最老优先删除，实际 %v", got)
	}
}

// TestSelectExpiredZeroPolicy 全零策略不删任何表。
func TestSelectExpiredZeroPolicy(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	tables := map[string]int64{"traffic_log_20200101": 999 << 20}
	got, err := RetentionPolicy{}.SelectExpired(now, tables, 1)
	if err != nil {
		t.Fatalf("计算失败: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("零策略不应删除，实际 %v", got)
	}
}

// TestSelectExpiredSkipsNonMatching 非分表名的条目必须跳过（不能误删）。
func TestSelectExpiredSkipsNonMatching(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	tables := map[string]int64{
		"audit_log":            10 << 20,
		"health_log":           10 << 20,
		"traffic_log_20200101": 1,
	}
	got, err := RetentionPolicy{Days: 30}.SelectExpired(now, tables, 100)
	if err != nil {
		t.Fatalf("计算失败: %v", err)
	}
	// 只应删分表，audit_log/health_log 不能动
	if len(got) != 1 || got[0] != "traffic_log_20200101" {
		t.Fatalf("应只删分表，实际 %v", got)
	}
}

// TestSelectExpiredByWatermark 水位档：磁盘紧张时至少删一张。
func TestSelectExpiredByWatermark(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	tables := map[string]int64{
		"traffic_log_20261030": 1 << 20,
		"traffic_log_20261029": 1 << 20,
	}
	// 水位阈值 90%，当前剩余 5% → 紧张，应删
	got, err := RetentionPolicy{DiskWatermarkPct: 90}.SelectExpired(now, tables, 5)
	if err != nil {
		t.Fatalf("计算失败: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("水位紧张时应至少删一张")
	}
	// 剩余 50% → 不紧张，不删
	got, err = RetentionPolicy{DiskWatermarkPct: 90}.SelectExpired(now, tables, 50)
	if err != nil {
		t.Fatalf("计算失败: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("水位充足时不应删，实际 %v", got)
	}
}
