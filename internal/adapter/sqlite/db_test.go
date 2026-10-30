package sqlite

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpenCreatesDualDB 双库必须建成两个独立文件。
func TestOpenCreatesDualDB(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("打开双库失败: %v", err)
	}
	defer db.Close()

	for _, name := range []string{ConfigDBName, LogDBName} {
		p := filepath.Join(dir, name)
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s 未创建: %v", name, err)
		}
		// C-04：0600
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s 权限应为 0600，实际 %04o", name, perm)
		}
	}
	// 两个库必须是不同文件（不是同一个句柄）
	if db.Config == db.Log {
		t.Fatal("配置库与日志库必须是独立的连接")
	}
}

// TestAutoVacuumIsIncremental DoD 第 1 条：PRAGMA auto_vacuum 必须是 2。
//
// 这条必须在**建表之前**设置，否则无效——本包在 Open 里执行，
// 本测试验证它真的生效了。
func TestAutoVacuumIsIncremental(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("打开双库失败: %v", err)
	}
	defer db.Close()

	for _, isLog := range []bool{false, true} {
		mode, err := db.AutoVacuumMode(isLog)
		if err != nil {
			t.Fatalf("读取 auto_vacuum 失败: %v", err)
		}
		name := "config"
		if isLog {
			name = "log"
		}
		if mode != AutoVacuumIncremental {
			t.Fatalf("★ %s.db 的 auto_vacuum 应为 %d（incremental），实际 %d"+
				"——建库时没设成功，只能重建库", name, AutoVacuumIncremental, mode)
		}
	}
}

// TestOpenEmptyDirRejected 空目录必须报错。
func TestOpenEmptyDirRejected(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("空数据目录应报错")
	}
}

// TestCloseTwice Close 可重复调用。
func TestCloseTwice(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("首次关闭失败: %v", err)
	}
	// 二次关闭不应 panic（可能返回错误，因为连接已关）
	_ = db.Close()
}

// TestValidateBackupPath C-08：备份目标必须在数据目录内且不存在。
func TestValidateBackupPath(t *testing.T) {
	dir := t.TempDir()
	// 合法：数据目录内的新文件
	if err := ValidateBackupPath(dir, filepath.Join(dir, "backup.db")); err != nil {
		t.Fatalf("目录内的新文件应合法: %v", err)
	}
	// 非法：目录外
	outside := filepath.Join(filepath.Dir(dir), "outside.db")
	if err := ValidateBackupPath(dir, outside); err == nil {
		t.Fatal("目录外的路径应被拒")
	}
	// 非法：已存在
	existing := filepath.Join(dir, "exists.db")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackupPath(dir, existing); err == nil {
		t.Fatal("已存在的文件应被拒（VACUUM INTO 要求目标不存在）")
	}
	// 非法：路径穿越
	if err := ValidateBackupPath(dir, filepath.Join(dir, "..", "escape.db")); err == nil {
		t.Fatal("路径穿越应被拒")
	}
	// 非法：空
	if err := ValidateBackupPath(dir, ""); err == nil {
		t.Fatal("空路径应被拒")
	}
}

// TestBackupTo 备份产出可用文件且权限 0600。
func TestBackupTo(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer db.Close()
	// 建张表灌点数据
	if err := db.Config.Exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Config.Exec("INSERT INTO t (v) VALUES ('hello')").Error; err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "backup.db")
	if err := db.BackupTo(dest); err != nil {
		t.Fatalf("备份失败: %v", err)
	}
	st, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("备份文件不存在: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("备份文件权限应为 0600，实际 %04o", perm)
	}
	if st.Size() == 0 {
		t.Fatal("备份文件为空")
	}
}

// TestBackupToOutsideRejected 目录外备份必须被拒（systemd 沙箱只放行数据目录）。
func TestBackupToOutsideRejected(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer db.Close()
	outside := filepath.Join(filepath.Dir(dir), "bad.db")
	if err := db.BackupTo(outside); err == nil {
		t.Fatal("目录外备份应被拒")
	}
}
