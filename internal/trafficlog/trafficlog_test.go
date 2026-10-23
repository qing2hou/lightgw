package trafficlog

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/model"
)

// 保留期清理：过期流量日志被删除，未过期保留，清理失败不静默。
func TestCleanupRetention(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "t.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.TrafficLog{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	now := time.Now()
	if err := db.Create(&model.TrafficLog{RuleName: "old", StartedAt: now.AddDate(0, 0, -40)}).Error; err != nil {
		t.Fatalf("插入失败: %v", err)
	}
	if err := db.Create(&model.TrafficLog{RuleName: "fresh", StartedAt: now}).Error; err != nil {
		t.Fatalf("插入失败: %v", err)
	}

	w := New(db, Options{RetentionDays: 30})
	defer w.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var n int64
		db.Model(&model.TrafficLog{}).Count(&n)
		if n == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var n int64
	db.Model(&model.TrafficLog{}).Count(&n)
	if n != 1 {
		t.Fatalf("应只保留 1 条未过期日志，实际 %d", n)
	}
	if w.CleanupFailures() != 0 {
		t.Errorf("清理不应失败")
	}
}

// 容量轮转（行数配额语义）：cap 外的最老行被淘汰、删到 cap×90% 一次到位；
// 未超配额不动；轮转计数准确；淘汰的确实是最老行。
func TestRotateToRowsCap(t *testing.T) {
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "haproxyweb.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.TrafficLog{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	base := time.Now().Add(-48 * time.Hour)
	rows := make([]model.TrafficLog, 0, 5000)
	for i := 0; i < 5000; i++ {
		rows = append(rows, model.TrafficLog{RuleName: "r", StartedAt: base.Add(time.Duration(i) * time.Second)})
	}
	if err := db.CreateInBatches(rows, 500).Error; err != nil {
		t.Fatalf("批量插入失败: %v", err)
	}
	w := New(db, Options{RetentionDays: 365, DataDir: dir})
	defer w.Close()

	// 未超配额（cap=10000 > 5000）：不删
	w.rotateToRowsCap(db, 10000, "容量")
	var n int64
	db.Model(&model.TrafficLog{}).Count(&n)
	if n != 5000 {
		t.Fatalf("未超配额不应删除: %d", n)
	}

	// 超配额（cap=2000）：删 5000-1800=3200 条，剩 1800（=cap×90%）
	w.rotateToRowsCap(db, 2000, "容量")
	db.Model(&model.TrafficLog{}).Count(&n)
	if n != 1800 {
		t.Fatalf("应删到 cap×90%%=1800，实际 %d", n)
	}
	if w.Rotated() != 3200 {
		t.Fatalf("轮转计数应 3200: %d", w.Rotated())
	}
	// 剩余应是最新的行：最小 started_at ≈ base+(3200-1)s（允许边界 ±2s）
	var first model.TrafficLog
	if err := db.Order("started_at ASC").First(&first).Error; err != nil {
		t.Fatalf("查询最老行失败: %v", err)
	}
	minT := first.StartedAt
	want := base.Add(3199 * time.Second)
	if minT.Before(want.Add(-2*time.Second)) || minT.After(want.Add(2*time.Second)) {
		t.Fatalf("淘汰的不是最老行: min=%v want≈%v", minT, want)
	}
	// 再次触发（cap 更小）：继续从当前最老删
	w.rotateToRowsCap(db, 1000, "容量")
	db.Model(&model.TrafficLog{}).Count(&n)
	if n != 900 {
		t.Fatalf("二次轮转应删到 900: %d", n)
	}
	if w.Rotated() != 3200+900 {
		t.Fatalf("累计轮转应 4100: %d", w.Rotated())
	}
}

// diskUsagePct：目录可测（返回 0-100）；不存在目录返回 -1。
func TestDiskUsagePct(t *testing.T) {
	if p := diskUsagePct(t.TempDir()); p < 0 || p > 100 {
		t.Fatalf("临时目录使用率应 0-100: %d", p)
	}
	if p := diskUsagePct("/no/such/dir"); p != -1 {
		t.Fatalf("不存在目录应 -1: %d", p)
	}
}
