package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalSinkPutAndVerify 写入后读回校验，权限 0600。
func TestLocalSinkPutAndVerify(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	local, err := NewLocalSink(dst)
	if err != nil {
		t.Fatalf("创建 sink 失败: %v", err)
	}
	p := filepath.Join(src, "snap.db")
	if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, _ := FileSHA256(p)
	m := Manifest{Name: "config-20261030-120000.db", SHA256: sum, Size: 4}

	if err := local.Put(context.Background(), p, m); err != nil {
		t.Fatalf("上传失败: %v", err)
	}
	got := filepath.Join(dst, m.Name)
	st, err := os.Stat(got)
	if err != nil {
		t.Fatalf("目标文件不存在: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("备份文件权限应为 0600，实际 %04o", perm)
	}
}

// TestLocalSinkRejectsTamperedManifest 摘要不符时必须删除半成品。
func TestLocalSinkRejectsTamperedManifest(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	local, _ := NewLocalSink(dst)
	p := filepath.Join(src, "snap.db")
	os.WriteFile(p, []byte("data"), 0o600)
	// 故意给错摘要
	m := Manifest{Name: "config-20261030-120000.db", SHA256: strings.Repeat("0", 64)}
	if err := local.Put(context.Background(), p, m); err == nil {
		t.Fatal("摘要不符应报错")
	}
	// 半成品必须被删
	if _, err := os.Stat(filepath.Join(dst, m.Name)); err == nil {
		t.Fatal("★ 校验失败时必须删除半成品（否则恢复时会拿到坏文件）")
	}
}

// TestLocalSinkRejectsOverwrite 同名文件已存在时必须拒绝（不覆盖）。
func TestLocalSinkRejectsOverwrite(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	local, _ := NewLocalSink(dst)
	p := filepath.Join(src, "snap.db")
	os.WriteFile(p, []byte("data"), 0o600)
	sum, _ := FileSHA256(p)
	m := Manifest{Name: "config-20261030-120000.db", SHA256: sum}
	if err := local.Put(context.Background(), p, m); err != nil {
		t.Fatal(err)
	}
	if err := local.Put(context.Background(), p, m); err == nil {
		t.Fatal("同名文件已存在时应拒绝覆盖")
	}
}

// TestLocalSinkList 只认备份命名约定，忽略其它文件。
func TestLocalSinkList(t *testing.T) {
	dst := t.TempDir()
	local, _ := NewLocalSink(dst)
	// 造 3 个合法备份 + 2 个无关文件
	for _, n := range []string{
		"config-20260101-000000.db",
		"config-20260102-000000.db",
		"config-20260103-000000.db",
	} {
		if err := os.WriteFile(filepath.Join(dst, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"notes.txt", "important.conf", "config.db"} {
		if err := os.WriteFile(filepath.Join(dst, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	list, err := local.List(context.Background())
	if err != nil {
		t.Fatalf("列出失败: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("★ 应只识别 3 个备份，实际 %d: %v", len(list), names(list))
	}
	// 必须按时间升序
	for i := 1; i < len(list); i++ {
		if list[i].CreatedAt.Before(list[i-1].CreatedAt) {
			t.Fatal("应按时间升序")
		}
	}
}

// TestLocalSinkRemoveRejectsForeignName 删除必须校验命名（防误删用户文件）。
func TestLocalSinkRemoveRejectsForeignName(t *testing.T) {
	dst := t.TempDir()
	local, _ := NewLocalSink(dst)
	// 造一个用户的文件
	userFile := filepath.Join(dst, "important.conf")
	os.WriteFile(userFile, []byte("keep me"), 0o600)

	if err := local.Remove(context.Background(), "important.conf"); err == nil {
		t.Fatal("★ 不属于备份命名的文件必须拒绝删除")
	}
	if _, err := os.Stat(userFile); err != nil {
		t.Fatal("★ 用户文件被误删了")
	}
}

// TestLocalSinkGetRoundTrip 取回内容与源文件一致。
func TestLocalSinkGetRoundTrip(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	local, _ := NewLocalSink(dst)
	p := filepath.Join(src, "snap.db")
	content := "round-trip-content"
	os.WriteFile(p, []byte(content), 0o600)
	sum, _ := FileSHA256(p)
	m := Manifest{Name: "config-20261030-120000.db", SHA256: sum}
	if err := local.Put(context.Background(), p, m); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(src, "restored.db")
	if err := local.Get(context.Background(), m.Name, out); err != nil {
		t.Fatalf("取回失败: %v", err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != content {
		t.Fatalf("内容不一致: %q", string(got))
	}
}

// TestParseBackupName 命名解析必须严格。
func TestParseBackupName(t *testing.T) {
	valid := []struct {
		name    string
		y, m, d int
	}{
		{"config-20261030-120000.db", 2026, 10, 30},
		{"log-20260101-000000.db", 2026, 1, 1},
	}
	for _, c := range valid {
		ts, ok := parseBackupName(c.name)
		if !ok {
			t.Fatalf("%q 应被识别", c.name)
		}
		if ts.Year() != c.y || int(ts.Month()) != c.m || ts.Day() != c.d {
			t.Fatalf("%q 日期错误: %v", c.name, ts)
		}
	}
	// ★ 非备份命名必须全拒绝（防误删）
	invalid := []string{
		"important.conf",
		"config.db",
		"config-20261030.db",       // 缺时间
		"config-20261030-12000.db", // 时间少一位
		"../etc/passwd",
		"config-20261030-120000.db.bak",
		"-20261030-120000.db", // 缺 source
		"config/../evil-20261030-120000.db",
	}
	for _, n := range invalid {
		if _, ok := parseBackupName(n); ok {
			t.Fatalf("★ %q 必须被拒绝（命名约定是防误删的边界）", n)
		}
	}
}

// TestNewLocalSinkEmptyDir 空目录必须报错。
func TestNewLocalSinkEmptyDir(t *testing.T) {
	if _, err := NewLocalSink(""); err == nil {
		t.Fatal("空目录应报错")
	}
}

func names(ms []Manifest) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Name
	}
	return out
}
