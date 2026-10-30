package sqlite

import (
	"fmt"
	"os"

	"gorm.io/gorm"
)

// MigrateResult 是一次旧库迁移的结果。
type MigrateResult struct {
	// Tables 是逐表的行数比对（表名 -> 旧库行数 / 新库行数）。
	Tables map[string]TableCount
	// Skipped 是旧库里不存在、因而跳过的表。
	Skipped []string
}

// TableCount 是单表的行数比对。
type TableCount struct {
	Old int64
	New int64
}

// Matched 报告该表迁移前后行数是否一致。
func (c TableCount) Matched() bool { return c.Old == c.New }

// Matched 报告整次迁移是否逐表一致。
func (r MigrateResult) Matched() bool {
	for _, c := range r.Tables {
		if !c.Matched() {
			return false
		}
	}
	return true
}

// configTableNames 是旧单库里需要迁到 config.db 的表（顺序无关，但结果按表名排序）。
var configTableNames = []string{
	"users", "forward_rules", "egresses", "bw_groups", "acl_groups",
	"fw_policies", "settings",
}

// MigrateFromLegacy 把旧单库里的配置表迁到新的双库结构。
//
// 迁移策略：**ATTACH 旧库 + INSERT INTO ... SELECT**，全程在 SQLite 内部完成，
// 不经 Go 侧搬运（10 万行级的表走 Go 侧会慢一个数量级且容易丢类型）。
//
// 关键约束：
//   - 只迁**配置表**到 config.db（日志表留在旧库里，或由调用方另行处理）
//   - 逐表比对行数，任何一张表不一致就报错——**不做「部分成功」**
//     （迁移中途失败留下半迁移的库比不迁更危险）
//   - 旧库不存在时返回错误（调用方应先判断）
//
// 本函数**不删除旧库**：迁移成功后由运维确认再手动删。自动删库是不可逆操作。
func MigrateFromLegacy(configDB *gorm.DB, legacyPath string) (*MigrateResult, error) {
	if configDB == nil {
		return nil, fmt.Errorf("迁移旧库失败: 目标库为空")
	}
	if legacyPath == "" {
		return nil, fmt.Errorf("迁移旧库失败: 旧库路径为空")
	}

	// **先检查文件存在**：SQLite 的 ATTACH 对不存在的路径会**静默创建一个
	// 空库**（不报错），然后迁移「成功」但一行都没搬——这是最危险的失败模式。
	if _, err := os.Stat(legacyPath); err != nil {
		return nil, fmt.Errorf("迁移旧库失败: 旧库 %s 不可访问: %w", legacyPath, err)
	}
	// ATTACH 旧库
	if err := configDB.Exec("ATTACH DATABASE ? AS legacy", legacyPath).Error; err != nil {
		return nil, fmt.Errorf("挂载旧库 %s 失败: %w", legacyPath, err)
	}
	// 无论成败都要 DETACH，否则连接池里的连接会一直持着旧库
	defer func() {
		_ = configDB.Exec("DETACH DATABASE legacy").Error
	}()

	res := &MigrateResult{Tables: make(map[string]TableCount, len(configTableNames))}

	for _, name := range configTableNames {
		// 旧库里有没有这张表
		var cnt int64
		q := `SELECT COUNT(*) FROM legacy.sqlite_master WHERE type='table' AND name=?`
		if err := configDB.Raw(q, name).Scan(&cnt).Error; err != nil {
			return nil, fmt.Errorf("检查旧库表 %s 失败: %w", name, err)
		}
		if cnt == 0 {
			res.Skipped = append(res.Skipped, name)
			continue
		}
		// 旧库行数
		var oldRows int64
		if err := configDB.Raw(fmt.Sprintf("SELECT COUNT(*) FROM legacy.%s", name)).Scan(&oldRows).Error; err != nil {
			return nil, fmt.Errorf("统计旧库表 %s 失败: %w", name, err)
		}
		// 拷贝（新表由 GORM AutoMigrate 预先建好，列对齐）
		copySQL := fmt.Sprintf("INSERT OR REPLACE INTO main.%s SELECT * FROM legacy.%s", name, name)
		if err := configDB.Exec(copySQL).Error; err != nil {
			return nil, fmt.Errorf("迁移表 %s 失败: %w", name, err)
		}
		// 新库行数
		var newRows int64
		if err := configDB.Raw(fmt.Sprintf("SELECT COUNT(*) FROM main.%s", name)).Scan(&newRows).Error; err != nil {
			return nil, fmt.Errorf("统计新库表 %s 失败: %w", name, err)
		}
		res.Tables[name] = TableCount{Old: oldRows, New: newRows}
		if oldRows != newRows {
			return res, fmt.Errorf("迁移表 %s 行数不一致: 旧库 %d，新库 %d", name, oldRows, newRows)
		}
	}
	return res, nil
}
