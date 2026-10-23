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

	w := New(db, 30)
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
