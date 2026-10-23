package audit

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/model"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "t.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	return db
}

func countRows(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AuditLog{}).Count(&n).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	return n
}

// 保留期清理：过期行被删除，未过期保留，之后写入器仍正常工作。
func TestCleanupRetention(t *testing.T) {
	db := newTestDB(t)
	old := time.Now().AddDate(0, 0, -40)
	fresh := time.Now()
	if err := db.Create(&model.AuditLog{Username: "u", Action: "old", CreatedAt: old}).Error; err != nil {
		t.Fatalf("插入失败: %v", err)
	}
	if err := db.Create(&model.AuditLog{Username: "u", Action: "fresh", CreatedAt: fresh}).Error; err != nil {
		t.Fatalf("插入失败: %v", err)
	}

	w := New(db, 30)
	// 注意：本测试在末尾显式 Close，不能 defer（Close 只能调用一次）

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if countRows(t, db) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := countRows(t, db); got != 1 {
		t.Fatalf("应只保留 1 条未过期审计，实际 %d", got)
	}
	if w.CleanupFailures() != 0 {
		t.Errorf("清理不应失败")
	}

	// 清理不影响写入器本身
	w.Record("u", "login", "", "127.0.0.1")
	w.Close() // 显式关闭触发残余落库
	if got := countRows(t, db); got != 2 {
		t.Fatalf("Close 落库后应有 2 条，实际 %d", got)
	}
}

// retention=0 表示永久保留，不清理。
func TestRetentionDisabled(t *testing.T) {
	db := newTestDB(t)
	old := time.Now().AddDate(0, 0, -400)
	if err := db.Create(&model.AuditLog{Username: "u", Action: "old", CreatedAt: old}).Error; err != nil {
		t.Fatalf("插入失败: %v", err)
	}
	w := New(db, 0)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)
	if got := countRows(t, db); got != 1 {
		t.Fatalf("retention=0 不应清理，实际剩 %d", got)
	}
}
