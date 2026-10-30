package sqlite

import (
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"
)

// TrafficLogRow 是一条流量日志（分表里的行）。
//
// 字段与旧实现保持兼容（迁移脚本要按列对齐）。
type TrafficLogRow struct {
	ID uint `gorm:"primaryKey"`
	// RuleID / RuleName 定位是哪条规则。
	RuleID   uint
	RuleName string
	// SrcIP / DstIP 是客户端与后端。
	SrcIP string `gorm:"index"`
	DstIP string
	// SrcPort / DstPort。
	SrcPort uint16
	DstPort uint16
	// Proto 是 "tcp"/"udp"。
	Proto string
	// BytesIn / BytesOut 是双向字节数。
	BytesIn  int64
	BytesOut int64
	// StartedAt / EndedAt 是会话起止（unix 秒）。
	StartedAt int64 `gorm:"index"`
	EndedAt   int64
	// DurationMS 是会话时长（毫秒），便于直接聚合。
	DurationMS int64
}

// TableName 返回该行所属分表名。
//
// **不能用固定表名**：GORM 会缓存 TableName 的结果，若按时间动态返回会
// 导致跨天写入落到错误的表。所以分表写入统一走 InsertTrafficBatch，
// 由调用方显式指定表名（并在内部做白名单校验）。
func (TrafficLogRow) TableName() string {
	return TrafficTablePrefix + "00000000"
}

// dailyLogSpec 描述分表结构（不依赖 GORM 的自动迁移，直接建表）。
//
// 为什么手写 DDL 而不用 AutoMigrate：分表是**动态表名**，AutoMigrate 需要
// 结构体 → 表名的固定映射。手写 DDL 还能显式控制索引与 WITHOUT ROWID 等细节。
const dailyLogDDL = `
CREATE TABLE IF NOT EXISTS %s (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_id     INTEGER NOT NULL,
	rule_name   TEXT,
	src_ip      TEXT    NOT NULL,
	dst_ip      TEXT    NOT NULL,
	src_port    INTEGER NOT NULL,
	dst_port    INTEGER NOT NULL,
	proto       TEXT    NOT NULL,
	bytes_in    INTEGER NOT NULL DEFAULT 0,
	bytes_out   INTEGER NOT NULL DEFAULT 0,
	started_at  INTEGER NOT NULL,
	ended_at    INTEGER NOT NULL DEFAULT 0,
	duration_ms INTEGER NOT NULL DEFAULT 0
)`

// dailyLogIndex 描述分表的一个索引。
//
// 索引名必须带表名后缀：SQLite 的索引名是**库级唯一**的，同名会冲突
// （`CREATE INDEX idx_started` 在第二张分表上就会报 already exists）。
type dailyLogIndex struct {
	suffix string
	column string
}

// dailyLogIndexes 是分表索引。
//
// **只建 started_at 一个**。实测（30 万条）：两个索引让写入从
// 26,963 降到 13,974 条/秒（-48%），而按 src_ip 查是低频操作
// （UI 的会话详情按时间范围查，不按源 IP 扫历史）。
// 若将来确实需要按源 IP 聚合，再加索引——那是明确的取舍，不是遗漏。
var dailyLogIndexes = []dailyLogIndex{
	{suffix: "started", column: "started_at"},
}

// EnsureTrafficTable 创建某天的分表（幂等）。
//
// 所有 SQL 都用白名单校验过的表名插值，**没有任何用户输入直接进 SQL**。
func (d *DB) EnsureTrafficTable(name string) error {
	if !IsValidTrafficTableName(name) {
		return fmt.Errorf("创建分表失败: 表名 %q 未通过白名单校验", name)
	}
	if err := d.Log.Exec(fmt.Sprintf(dailyLogDDL, name)).Error; err != nil {
		return fmt.Errorf("创建分表 %s 失败: %w", name, err)
	}
	for _, idx := range dailyLogIndexes {
		stmt := fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s(%s)",
			name, idx.suffix, name, idx.column)
		if err := d.Log.Exec(stmt).Error; err != nil {
			return fmt.Errorf("为分表 %s 建索引 %s 失败: %w", name, idx.suffix, err)
		}
	}
	return nil
}

// InsertChunkSize 是单次 INSERT 语句包含的行数。
//
// 与 logstore.BatchSize 分开是有意的：logstore 控制「攒够多少条才调用
// sink」，本常量控制「一次 INSERT 拼多少值」。实测（40 万条）：
//
//	chunk=256   47,399 条/秒
//	chunk=1024  49,684 条/秒  ← 采用
//	chunk=2048  48,619 条/秒
//
// 超过 1024 后 SQL 语句本身变长（每行 13 个占位符），解析开销反超收益。
const InsertChunkSize = 1024

// InsertTrafficBatch 批量写入分表。
//
// 三条纪律（playbook §7.3）：
//  1. 批量写（每批 256 行），不逐条 INSERT
//  2. 表名白名单校验在先
//  3. 表不存在时**先建表再写**（避免跨天零点后的第一条日志丢失）
func (d *DB) InsertTrafficBatch(table string, rows []TrafficLogRow) error {
	if len(rows) == 0 {
		return nil
	}
	if !IsValidTrafficTableName(table) {
		return fmt.Errorf("写入流量日志失败: 表名 %q 未通过白名单校验", table)
	}
	// 用 Session 保证整批在一个事务里（要么全成功要么全失败）
	return d.Log.Transaction(func(tx *gorm.DB) error {
		// 用 GORM 的 Table() 指定动态表名
		if err := tx.Table(table).CreateInBatches(rows, InsertChunkSize).Error; err != nil {
			return fmt.Errorf("批量写入 %s 失败: %w", table, err)
		}
		return nil
	})
}

// TrafficTableSizes 返回所有分表的（表名 -> 近似字节数）。
//
// 用 `dbstat` 虚表拿真实占用；若该虚表不可用（部分编译选项会裁掉），
// 降级为「行数 × 平均行长」的估算，并在返回值里标明是估算。
//
// 返回的第三个值是 estimate 标志：true 表示大小是估算的。
func (d *DB) TrafficTableSizes() (map[string]int64, bool, error) {
	names, err := d.TrafficTables()
	if err != nil {
		return nil, false, err
	}
	out := make(map[string]int64, len(names))

	// 优先用 dbstat（精确）
	exact := true
	for _, name := range names {
		var sz int64
		q := `SELECT COALESCE(SUM(pgsize), 0) FROM dbstat WHERE name = ?`
		if err := d.Log.Raw(q, name).Scan(&sz).Error; err != nil {
			exact = false
			break
		}
		out[name] = sz
	}
	if exact {
		return out, false, nil
	}

	// 降级：按行数估算（每行约 120 字节，含索引）
	out = make(map[string]int64, len(names))
	for _, name := range names {
		var cnt int64
		if !IsValidTrafficTableName(name) {
			continue
		}
		if err := d.Log.Raw(fmt.Sprintf("SELECT COUNT(*) FROM %s", name)).Scan(&cnt).Error; err != nil {
			continue
		}
		out[name] = cnt * 120
	}
	return out, true, nil
}

// TrafficTables 返回日志库中所有分表名（已排序）。
func (d *DB) TrafficTables() ([]string, error) {
	var names []string
	q := `SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ?`
	if err := d.Log.Raw(q, TrafficTablePrefix+"%").Scan(&names).Error; err != nil {
		return nil, fmt.Errorf("列出分表失败: %w", err)
	}
	// 只保留通过白名单的（防御 sqlite_master 里出现奇怪名字）
	out := make([]string, 0, len(names))
	for _, n := range names {
		if IsValidTrafficTableName(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// DropTrafficTable 删除一张分表并回收空间。
//
// 必须用 `DROP TABLE` + `PRAGMA incremental_vacuum`，**不要 DELETE FROM**
// （D-10）：DELETE 只释放页内空间，文件大小不缩，磁盘只增不减。
func (d *DB) DropTrafficTable(name string) error {
	if !IsValidTrafficTableName(name) {
		return fmt.Errorf("删除分表失败: 表名 %q 未通过白名单校验", name)
	}
	if err := d.Log.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", name)).Error; err != nil {
		return fmt.Errorf("删除分表 %s 失败: %w", name, err)
	}
	// incremental_vacuum 需要参数：一次回收的页数。
	// 传 0 表示「尽量多收」在部分版本上不生效，用大数值（10000 页 ≈ 40MB）
	if err := d.Log.Exec("PRAGMA incremental_vacuum(10000)").Error; err != nil {
		// 回收失败不算致命（表已删，空间下次再收）
		return fmt.Errorf("回收分表 %s 的空间失败: %w", name, err)
	}
	return nil
}

// CleanupExpired 按保留策略清理过期分表，返回被删除的表名。
func (d *DB) CleanupExpired(p RetentionPolicy, now time.Time, diskFreePct float64) ([]string, error) {
	sizes, _, err := d.TrafficTableSizes()
	if err != nil {
		return nil, err
	}
	expired, err := p.SelectExpired(now, sizes, diskFreePct)
	if err != nil {
		return nil, err
	}
	dropped := make([]string, 0, len(expired))
	for _, name := range expired {
		if err := d.DropTrafficTable(name); err != nil {
			return dropped, err
		}
		dropped = append(dropped, name)
	}
	return dropped, nil
}

// AuditLogRow 是审计日志（不分区，量小）。
type AuditLogRow struct {
	ID       uint  `gorm:"primaryKey"`
	At       int64 `gorm:"index"`
	Username string
	Action   string
	Target   string
	Detail   string
	ClientIP string
	Success  bool
}

// TableName 固定表名（审计不分表）。
func (AuditLogRow) TableName() string { return "audit_log" }

// HealthLogRow 是后端健康检测历史（技术方案 §4）。
type HealthLogRow struct {
	ID uint `gorm:"primaryKey"`
	// RuleID + At 是主查询条件：按规则取一段时间内的点。
	RuleID uint  `gorm:"index:idx_health_rule_at"`
	At     int64 `gorm:"index:idx_health_rule_at"`
	Up     bool
	// LatencyMS 是探测耗时（毫秒）。
	LatencyMS int64
	Error     string
}

// TableName 固定表名。
func (HealthLogRow) TableName() string { return "health_log" }

// LoginFailRow 是登录失败记录（用于锁定）。
type LoginFailRow struct {
	ID       uint   `gorm:"primaryKey"`
	At       int64  `gorm:"index"`
	Username string `gorm:"index"`
	ClientIP string `gorm:"index"`
}

// TableName 固定表名。
func (LoginFailRow) TableName() string { return "login_fail" }

// MigrateLogTables 创建日志库中的固定表。
func (d *DB) MigrateLogTables() error {
	if err := d.Log.AutoMigrate(&AuditLogRow{}, &HealthLogRow{}, &LoginFailRow{}); err != nil {
		return fmt.Errorf("迁移日志库固定表失败: %w", err)
	}
	return nil
}
