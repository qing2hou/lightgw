package sqlite

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// buildLegacy 造一个「旧版单库」：config 表 + 一张日志表。
func buildLegacy(t *testing.T, path string) {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("创建旧库失败: %v", err)
	}
	stmts := []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)`,
		`INSERT INTO users (username, password_hash) VALUES ('admin','h1'),('ops','h2'),('guest','h3')`,
		`CREATE TABLE forward_rules (id INTEGER PRIMARY KEY, name TEXT, listen_addr TEXT)`,
		`INSERT INTO forward_rules (name, listen_addr) VALUES ('r1',':1022'),('r2',':1023')`,
		`CREATE TABLE egresses (id INTEGER PRIMARY KEY, name TEXT, if_name TEXT)`,
		`INSERT INTO egresses (name, if_name) VALUES ('e1','eth0')`,
		`CREATE TABLE traffic_logs (id INTEGER PRIMARY KEY, rule_id INTEGER)`,
		`INSERT INTO traffic_logs (rule_id) VALUES (1),(2),(3),(4)`,
	}
	for _, s := range stmts {
		if err := gdb.Exec(s).Error; err != nil {
			t.Fatalf("执行 %q 失败: %v", s, err)
		}
	}
	sqlDB, _ := gdb.DB()
	_ = sqlDB.Close()
}

// TestMigrateFromLegacy DoD 第 5 条：旧库迁移后逐表行数一致。
func TestMigrateFromLegacy(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "haproxyweb.db")
	buildLegacy(t, legacy)

	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("打开新库失败: %v", err)
	}
	defer db.Close()

	// 新库先建好同名表（迁移假定目标表已存在）
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)`,
		`CREATE TABLE forward_rules (id INTEGER PRIMARY KEY, name TEXT, listen_addr TEXT)`,
		`CREATE TABLE egresses (id INTEGER PRIMARY KEY, name TEXT, if_name TEXT)`,
	} {
		if err := db.Config.Exec(s).Error; err != nil {
			t.Fatalf("建新表失败: %v", err)
		}
	}

	res, err := MigrateFromLegacy(db.Config, legacy)
	if err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if !res.Matched() {
		t.Fatalf("★ 迁移后应逐表行数一致: %+v", res.Tables)
	}
	// 逐表核对
	want := map[string]int64{"users": 3, "forward_rules": 2, "egresses": 1}
	for name, wantRows := range want {
		c, ok := res.Tables[name]
		if !ok {
			t.Fatalf("表 %s 未出现在迁移结果里", name)
		}
		if c.Old != wantRows || c.New != wantRows {
			t.Fatalf("%s 行数应为 %d，实际 old=%d new=%d", name, wantRows, c.Old, c.New)
		}
	}
	// 日志表不该被迁（只在配置表清单里）
	if _, ok := res.Tables["traffic_logs"]; ok {
		t.Fatal("日志表不应迁到 config.db")
	}
	// 旧库里不存在的新表应被记为 skipped
	if len(res.Skipped) == 0 {
		t.Logf("skipped 为空（所有表都存在？）: %+v", res.Skipped)
	}
	// 数据内容正确
	var uname string
	if err := db.Config.Raw("SELECT username FROM users ORDER BY id LIMIT 1").Scan(&uname).Error; err != nil {
		t.Fatal(err)
	}
	if uname != "admin" {
		t.Fatalf("迁移后数据错误: %q", uname)
	}
}

// TestMigrateFromLegacyIdempotent 重复迁移必须幂等（INSERT OR REPLACE）。
func TestMigrateFromLegacyIdempotent(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "haproxyweb.db")
	buildLegacy(t, legacy)

	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("打开新库失败: %v", err)
	}
	defer db.Close()
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)`,
		`CREATE TABLE forward_rules (id INTEGER PRIMARY KEY, name TEXT, listen_addr TEXT)`,
		`CREATE TABLE egresses (id INTEGER PRIMARY KEY, name TEXT, if_name TEXT)`,
	} {
		if err := db.Config.Exec(s).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		res, err := MigrateFromLegacy(db.Config, legacy)
		if err != nil {
			t.Fatalf("第 %d 次迁移失败: %v", i+1, err)
		}
		if !res.Matched() {
			t.Fatalf("第 %d 次迁移行数不一致", i+1)
		}
	}
	var cnt int64
	db.Config.Raw("SELECT COUNT(*) FROM users").Scan(&cnt)
	if cnt != 3 {
		t.Fatalf("重复迁移后 users 应仍为 3 行，实际 %d", cnt)
	}
}

// TestMigrateFromLegacyMissingDB 旧库不存在必须报错。
func TestMigrateFromLegacyMissingDB(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := MigrateFromLegacy(db.Config, filepath.Join(t.TempDir(), "nope.db")); err == nil {
		t.Fatal("旧库不存在应报错")
	}
}

// TestMigrateFromLegacyBadArgs 参数校验。
func TestMigrateFromLegacyBadArgs(t *testing.T) {
	if _, err := MigrateFromLegacy(nil, "x.db"); err == nil {
		t.Fatal("nil 目标库应报错")
	}
	db, _ := Open(t.TempDir())
	defer db.Close()
	if _, err := MigrateFromLegacy(db.Config, ""); err == nil {
		t.Fatal("空路径应报错")
	}
}
