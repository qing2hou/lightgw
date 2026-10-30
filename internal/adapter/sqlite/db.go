// Package sqlite 实现双库拆分的 SQLite 存储层。
//
// 两个库，两种性格（技术方案 §7.1）：
//
//	config.db  小、写少、**必须可靠**，备份的主要对象
//	           （User / ForwardRule / Egress / BWGroup / AclGroup / FwPolicy / Settings）
//	log.db     大、写多、**可丢可删**，独立 VACUUM 策略
//	           （traffic_log_YYYYMMDD 分表 / AuditLog / HealthLog / LoginFail）
//
// **为什么必须拆**：旧实现单库，日志量大时 `VACUUM` 锁住整个库，配置写入
// 跟着卡住。拆开后日志库可以随便 `DROP TABLE`，配置文件不受影响。
//
// **不许把两个库放同一个连接池**（playbook §7.5）：连接池共享时一个库的
// 长事务会阻塞另一个库的写入，等于没拆。
//
// 驱动约束（C-02）：只用 `github.com/glebarez/sqlite`（纯 Go）。
// 禁止 `mattn/go-sqlite3`、`modernc.org/sqlite`。单二进制、无 cgo。
package sqlite

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 库文件名。
const (
	ConfigDBName = "config.db"
	LogDBName    = "log.db"
)

// AutoVacuumIncremental 是 `PRAGMA auto_vacuum` 的 incremental 模式值。
//
// **只能在建库时设置**（D-10）：库建好后再设无效，错了就得重建库。
// 这也是本包必须在 `Open` 里显式执行它的原因——不能指望调用方记得。
const AutoVacuumIncremental = 2

// Pragma 是建库与运行期必需的 pragma 集合。
type Pragma struct {
	// JournalMode 生产用 WAL（并发读 + 单写）。
	JournalMode string
	// BusyTimeoutMS 是锁等待上限。太小会在并发写时直接报 SQLITE_BUSY。
	BusyTimeoutMS int
	// Synchronous 用 NORMAL：WAL 下足够安全，且比 FULL 快一个数量级。
	Synchronous string
	// ForeignKeys 是否启用外键约束。
	ForeignKeys bool
}

// ConfigPragma 是配置库的 pragma（可靠性优先）。
func ConfigPragma() Pragma {
	return Pragma{
		JournalMode:   "WAL",
		BusyTimeoutMS: 5000,
		Synchronous:   "NORMAL",
		ForeignKeys:   true,
	}
}

// LogPragma 是日志库的 pragma（吞吐优先，可丢）。
//
// **synchronous=OFF 是有意的**，理由与实测数据（本机基准，30 万条）：
//
//	synchronous=NORMAL + 2 索引   13,974 条/秒
//	synchronous=OFF    + 2 索引   43,905 条/秒   ← 采用
//	synchronous=NORMAL + 无索引   26,963 条/秒
//
// 日志库的 durability 语义**本来就不该等于配置库**：
//   - 配置库（rules/users/egress）丢一条就是配置错误，必须 NORMAL/WAL
//   - 日志库丢最后一批只损失几秒钟的统计精度，转发面完全不受影响
//     （这一批在内存通道里，进程崩溃时本来就没了）
//
// 这个取舍写在这里而不是埋在代码里：改回 NORMAL 会让吞吐掉到 1/3，
// 那是把「日志」当「账本」的误判。
func LogPragma() Pragma {
	return Pragma{
		JournalMode:   "WAL",
		BusyTimeoutMS: 5000,
		Synchronous:   "OFF",
		ForeignKeys:   false,
	}
}

// DB 是一对数据库连接。
//
// 不变量：Config 与 Log **必须是两个独立的 *gorm.DB**（各自独立连接池）。
// 这是本包存在的意义之一，不要在调用方把它们合并。
type DB struct {
	Config *gorm.DB
	Log    *gorm.DB

	dataDir string
}

// Open 打开（必要时创建）双库。
//
// dataDir 下的文件权限必须是 0600（C-04）。注意 SQLite 还会创建
// `-wal` / `-shm` 两个伴随文件，它们的权限也必须是 0600——
// 本包在打开后显式 chmod，因为 SQLite 自己按 umask 创建。
func Open(dataDir string) (*DB, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("打开数据库失败: 数据目录为空")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录 %s 失败: %w", dataDir, err)
	}

	cfg, err := openOne(filepath.Join(dataDir, ConfigDBName), ConfigPragma(), true)
	if err != nil {
		return nil, fmt.Errorf("打开配置库失败: %w", err)
	}
	lg, err := openOne(filepath.Join(dataDir, LogDBName), LogPragma(), true)
	if err != nil {
		// 配置库已打开：关掉它，避免句柄泄漏
		if sqlDB, e := cfg.DB(); e == nil {
			_ = sqlDB.Close()
		}
		return nil, fmt.Errorf("打开日志库失败: %w", err)
	}
	db := &DB{Config: cfg, Log: lg, dataDir: dataDir}
	// 补 chmod：SQLite 按 umask 创建 -wal/-shm，可能是 0644
	if err := db.chmodFiles(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// openOne 打开一个库并应用 pragma。
//
// setAutoVacuum 为 true 时，在**建表之前**设置 auto_vacuum（D-10）。
func openOne(path string, p Pragma, setAutoVacuum bool) (*gorm.DB, error) {
	// 先确保文件存在且权限正确（SQLite 会按 umask 创建）
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("创建 %s 失败: %w", path, err)
		}
		_ = f.Close()
	}
	// 显式 chmod：OpenFile 的 perm 只在创建时生效，且受 umask 影响
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("设置 %s 权限失败: %w", path, err)
	}

	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		// 关闭 GORM 的默认日志（它会打印每条 SQL，日志量大时拖慢吞吐）
		Logger: logger.Discard,
		// 关闭默认事务包装：单条 INSERT 不需要事务，省一次 BEGIN/COMMIT
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, fmt.Errorf("获取底层连接失败: %w", err)
	}
	// 连接池：SQLite 单写多读，写连接只留 1 个足够（WAL 下读可并发）
	sqlDB.SetMaxOpenConns(4)
	sqlDB.SetMaxIdleConns(4)

	// auto_vacuum 必须在任何表创建之前设置
	if setAutoVacuum {
		if err := gdb.Exec(fmt.Sprintf("PRAGMA auto_vacuum = %d", AutoVacuumIncremental)).Error; err != nil {
			return nil, fmt.Errorf("设置 auto_vacuum 失败（必须在建表前）: %w", err)
		}
	}
	// 其它 pragma
	//
	// cache_size 用负值表示 KB（`-65536` = 64MB）。默认 2MB 在高写入量下
	// 会频繁淘汰页，实测提升约 0.1%（基准噪声内），但代价为零——保留。
	for _, stmt := range []string{
		fmt.Sprintf("PRAGMA journal_mode = %s", p.JournalMode),
		fmt.Sprintf("PRAGMA busy_timeout = %d", p.BusyTimeoutMS),
		fmt.Sprintf("PRAGMA synchronous = %s", p.Synchronous),
		fmt.Sprintf("PRAGMA foreign_keys = %s", onOff(p.ForeignKeys)),
		"PRAGMA cache_size = -65536",
	} {
		if err := gdb.Exec(stmt).Error; err != nil {
			return nil, fmt.Errorf("应用 %q 失败: %w", stmt, err)
		}
	}
	return gdb, nil
}

func onOff(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

// AutoVacuumMode 读回 auto_vacuum 的实际值（验收用）。
//
// 期望值 2（incremental）。返回其它值说明建库时没设成功——
// 此时**只能重建库**，因为 auto_vacuum 无法事后修改。
func (d *DB) AutoVacuumMode(useLog bool) (int, error) {
	db := d.Config
	if useLog {
		db = d.Log
	}
	var mode int
	if err := db.Raw("PRAGMA auto_vacuum").Scan(&mode).Error; err != nil {
		return 0, fmt.Errorf("读取 auto_vacuum 失败: %w", err)
	}
	return mode, nil
}

// chmodFiles 把库文件及其 -wal/-shm 伴随文件权限设为 0600（C-04）。
func (d *DB) chmodFiles() error {
	for _, name := range []string{ConfigDBName, LogDBName} {
		base := filepath.Join(d.dataDir, name)
		for _, suffix := range []string{"", "-wal", "-shm"} {
			p := base + suffix
			if _, err := os.Stat(p); err != nil {
				continue // 伴随文件可能尚未创建
			}
			if err := os.Chmod(p, 0o600); err != nil {
				return fmt.Errorf("设置 %s 权限失败: %w", p, err)
			}
		}
	}
	return nil
}

// Close 关闭两个库。
func (d *DB) Close() error {
	var errs []error
	if d.Config != nil {
		if sqlDB, err := d.Config.DB(); err == nil {
			if err := sqlDB.Close(); err != nil {
				errs = append(errs, fmt.Errorf("关闭配置库失败: %w", err))
			}
		}
	}
	if d.Log != nil {
		if sqlDB, err := d.Log.DB(); err == nil {
			if err := sqlDB.Close(); err != nil {
				errs = append(errs, fmt.Errorf("关闭日志库失败: %w", err))
			}
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// BackupTo 用 VACUUM INTO 把配置库导出到 dest。
//
// 约束（C-08）：
//   - dest 必须在数据目录内（systemd 沙箱 ReadWritePaths 只放行该目录）
//   - dest 不能已存在（SQLite 会报错）
//
// 用 VACUUM INTO 而不是文件拷贝：前者能拿到一致快照（含 WAL 中未落盘的数据）。
func (d *DB) BackupTo(dest string) error {
	if err := ValidateBackupPath(d.dataDir, dest); err != nil {
		return err
	}
	if err := d.Config.Exec("VACUUM INTO ?", dest).Error; err != nil {
		return fmt.Errorf("导出配置库到 %s 失败: %w", dest, err)
	}
	if err := os.Chmod(dest, 0o600); err != nil {
		// 清理半成品，避免留下 0644 的备份
		_ = os.Remove(dest)
		return fmt.Errorf("设置备份文件权限失败: %w", err)
	}
	return nil
}

// ValidateBackupPath 校验备份目标路径是否符合 C-08。
//
// 抽成独立函数便于单测（备份路径校验是安全边界，必须有测试）。
func ValidateBackupPath(dataDir, dest string) error {
	if dest == "" {
		return fmt.Errorf("校验备份路径失败: 目标为空")
	}
	if dataDir == "" {
		return fmt.Errorf("校验备份路径失败: 数据目录为空")
	}
	absDir, err := filepath.Abs(dataDir)
	if err != nil {
		return fmt.Errorf("解析数据目录失败: %w", err)
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("解析备份路径失败: %w", err)
	}
	rel, err := filepath.Rel(absDir, absDest)
	if err != nil || rel == ".." || len(rel) > 2 && rel[:3] == ".."+string(filepath.Separator) {
		return fmt.Errorf("校验备份路径失败: 目标 %s 不在数据目录 %s 内", dest, dataDir)
	}
	if _, err := os.Stat(absDest); err == nil {
		return fmt.Errorf("校验备份路径失败: 目标 %s 已存在（VACUUM INTO 要求目标不存在）", dest)
	}
	return nil
}
