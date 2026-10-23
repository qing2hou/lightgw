package store

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/model"
)

// TestCleanupRemovedProtocols 旧库升级场景：http 规则被清理、domains 列被删除、
// tcp 规则与 traffic_logs 历史不受影响。
func TestCleanupRemovedProtocols(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "test.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}

	// 模拟旧 schema：forward_rules 带 domains 列
	legacy := `CREATE TABLE forward_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(128), protocol VARCHAR(16), listen_addr VARCHAR(64),
		target_addr VARCHAR(256), domains VARCHAR(512),
		acl_mode VARCHAR(16), allow_list TEXT, deny_list TEXT,
		upload_limit_kbps INTEGER DEFAULT 0, download_limit_kbps INTEGER DEFAULT 0,
		max_conns INTEGER DEFAULT 0, idle_timeout_sec INTEGER DEFAULT 0, health_check BOOLEAN,
		enabled BOOLEAN DEFAULT 0, last_error VARCHAR(512),
		created_at DATETIME, updated_at DATETIME)`
	if err := db.Exec(legacy).Error; err != nil {
		t.Fatalf("建旧表失败: %v", err)
	}
	inserts := []string{
		`INSERT INTO forward_rules (name, protocol, listen_addr, target_addr, domains, enabled, created_at, updated_at)
		 VALUES ('旧HTTP', 'http', ':8081', '10.0.0.1:80', 'a.com,b.com', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		`INSERT INTO forward_rules (name, protocol, listen_addr, target_addr, domains, enabled, created_at, updated_at)
		 VALUES ('MySQL', 'tcp', ':3306', '10.0.0.2:3306', '', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		`INSERT INTO forward_rules (name, protocol, listen_addr, target_addr, domains, enabled, created_at, updated_at)
		 VALUES ('DNS', 'udp', ':53', '10.0.0.3:53', '', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
	}
	for _, q := range inserts {
		if err := db.Exec(q).Error; err != nil {
			t.Fatalf("插入测试数据失败: %v", err)
		}
	}

	// 模拟真实启动顺序的迁移步骤（Open 里 AutoMigrate 先于 cleanup 执行）：
	// 旧表补齐新列后清理
	if err := db.AutoMigrate(&model.ForwardRule{}, &model.AclGroup{}); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	cleanupRemovedProtocols(db)

	var httpCount, tcpCount, udpCount int64
	db.Model(&model.ForwardRule{}).Where("protocol = ?", "http").Count(&httpCount)
	db.Model(&model.ForwardRule{}).Where("protocol = ?", "tcp").Count(&tcpCount)
	db.Model(&model.ForwardRule{}).Where("protocol = ?", "udp").Count(&udpCount)
	if httpCount != 0 {
		t.Errorf("http 规则应被清理，实际剩 %d 条", httpCount)
	}
	if tcpCount != 1 || udpCount != 1 {
		t.Errorf("tcp/udp 规则不应受影响，实际 tcp=%d udp=%d", tcpCount, udpCount)
	}

	var hasDomains int64
	db.Raw("SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name = 'domains'").Scan(&hasDomains)
	if hasDomains != 0 {
		t.Error("domains 列应被删除")
	}

	// 清理后表仍可正常写入（schema 未损坏）
	if err := db.Create(&model.ForwardRule{Name: "新规则", Protocol: "tcp", ListenAddr: ":1234", TargetAddr: "10.0.0.9:1234"}).Error; err != nil {
		t.Errorf("清理后写入失败: %v", err)
	}
}
