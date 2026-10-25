package store

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/model"
)

// Open 初始化 SQLite（WAL 模式）并自动建表、写入默认管理员。
func Open(dataDir string) (*gorm.DB, error) {
	dsn := filepath.Join(dataDir, "haproxyweb.db")
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	if err := db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		return nil, err
	}
	if err := db.Exec("PRAGMA busy_timeout=5000").Error; err != nil {
		return nil, err
	}
	// 数据库（含 WAL/SHM）仅属主可读写，防止同机其他用户读取流量与审计数据
	for _, name := range []string{"haproxyweb.db", "haproxyweb.db-wal", "haproxyweb.db-shm"} {
		_ = os.Chmod(filepath.Join(dataDir, name), 0600)
	}
	if err := db.AutoMigrate(&model.User{}, &model.ForwardRule{}, &model.TrafficLog{}, &model.AuditLog{}, &model.HealthLog{}, &model.LoginFail{}, &model.AclGroup{}, &model.BWGroup{}, &model.FwPolicy{}); err != nil {
		return nil, err
	}
	cleanupRemovedProtocols(db)
	if err := seedAdmin(db); err != nil {
		return nil, err
	}
	return db, nil
}

// cleanupRemovedProtocols HTTP 转发功能已移除：删除历史遗留的 http 规则行，
// 并尽力删除不再使用的 domains 列。traffic_logs 中的 http 历史记录保留。
// 失败只告警不阻断启动。
func cleanupRemovedProtocols(db *gorm.DB) {
	res := db.Where("protocol = ?", "http").Delete(&model.ForwardRule{})
	if res.Error != nil {
		fmt.Printf("[store] 清理遗留 http 规则失败: %v\n", res.Error)
	} else if res.RowsAffected > 0 {
		fmt.Printf("[store] 已清理 %d 条遗留 http 规则（HTTP 转发功能已移除）\n", res.RowsAffected)
	}
	var hasDomains int64
	db.Raw("SELECT COUNT(*) FROM pragma_table_info('forward_rules') WHERE name = 'domains'").Scan(&hasDomains)
	if hasDomains > 0 {
		if err := db.Exec("ALTER TABLE forward_rules DROP COLUMN domains").Error; err != nil {
			fmt.Printf("[store] 移除 forward_rules.domains 列失败（不影响使用）: %v\n", err)
		}
	}
}

// seedAdmin 首次启动生成默认管理员 admin/admin123，登录后提示修改。
func seedAdmin(db *gorm.DB) error {
	var count int64
	if err := db.Model(&model.User{}).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return db.Create(&model.User{
		Username:           "admin",
		PasswordHash:       string(hash),
		MustChangePassword: true,
	}).Error
}

func GetUser(db *gorm.DB, username string) (*model.User, error) {
	var u model.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

// BackupTo 用 VACUUM INTO 生成数据库一致性快照（在线备份，不阻塞业务读写）。
// 目标文件必须在数据目录内（systemd 沙箱仅允许写该目录），已存在时会失败，由调用方负责清理。
func BackupTo(db *gorm.DB, dest string) error {
	return db.Exec("VACUUM INTO ?", dest).Error
}
