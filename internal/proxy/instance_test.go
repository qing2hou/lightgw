package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadOrCreateInstanceIDCreates ID 不存在时创建，权限 0600。
func TestLoadOrCreateInstanceIDCreates(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreateInstanceID(dir)
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if len(id) != instanceIDLen {
		t.Fatalf("ID 长度应为 %d，实际 %d", instanceIDLen, len(id))
	}
	if !isValidInstanceID(id) {
		t.Fatalf("生成的 ID 格式非法: %q", id)
	}
	// 文件必须 0600（C-04）
	st, err := os.Stat(filepath.Join(dir, instanceIDFile))
	if err != nil {
		t.Fatalf("ID 文件未创建: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ID 文件权限应为 0600，实际 %04o", perm)
	}
}

// TestLoadOrCreateInstanceIDStable 同一目录多次读取必须返回同一 ID。
//
// 这是「归属可证明」的前提：重启后必须还能认出自己的规则。
func TestLoadOrCreateInstanceIDStable(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateInstanceID(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got, err := LoadOrCreateInstanceID(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != first {
			t.Fatalf("第 %d 次读取得到不同的 ID: %q vs %q（重启后会认不出自己的规则）",
				i+1, got, first)
		}
	}
}

// TestLoadOrCreateInstanceIDDifferentDirs 不同数据目录必须得到不同 ID。
//
// 事故场景的直接回归：两个实例共用一张 nft 表时，ID 不同才不会互拆。
func TestLoadOrCreateInstanceIDDifferentDirs(t *testing.T) {
	a, err := LoadOrCreateInstanceID(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateInstanceID(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("★ 不同数据目录得到了相同 ID %q——两个实例会互拆规则", a)
	}
}

// TestLoadOrCreateInstanceIDRejectsCorrupt 损坏的 ID 文件必须报错，不能静默重建。
//
// 重建会让「本实例的旧规则」变成「别人的规则」，永久泄漏（没人会再清理）。
func TestLoadOrCreateInstanceIDRejectsCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, instanceIDFile)
	for _, bad := range []string{
		"",
		"short",
		"GGGGGGGGGGGGGGGG",    // 非十六进制
		"0123456789ABCDEF",    // 大写
		"0123456789abcdef0",   // 17 位
		"0123456789abcde",     // 15 位
		"../../../etc/passwd", // 路径穿越
	} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreateInstanceID(dir); err == nil {
			t.Fatalf("★ 损坏的 ID %q 必须报错（静默重建会让旧规则永久失去归属）", bad)
		}
	}
}

// TestLoadOrCreateInstanceIDEmptyDir 空目录报错。
func TestLoadOrCreateInstanceIDEmptyDir(t *testing.T) {
	if _, err := LoadOrCreateInstanceID(""); err == nil {
		t.Fatal("空目录应报错")
	}
}

// TestIsValidInstanceID 格式校验必须严格（这个值会进 nft comment）。
func TestIsValidInstanceID(t *testing.T) {
	valid := []string{
		"0123456789abcdef",
		"ffffffffffffffff",
		"0000000000000000",
	}
	for _, id := range valid {
		if !isValidInstanceID(id) {
			t.Fatalf("%q 应合法", id)
		}
	}
	invalid := []string{
		"", "0123456789abcde", "0123456789abcdef0",
		"0123456789ABCDEF", "0123456789abcdeG",
		"01234567-89abcdef", "0123456789abcdef\n",
	}
	for _, id := range invalid {
		if isValidInstanceID(id) {
			t.Fatalf("%q 应非法", id)
		}
	}
}

// TestSetInstanceIDValidation SetInstanceID 必须校验格式。
func TestSetInstanceIDValidation(t *testing.T) {
	m := &Manager{}
	// 空串合法（表示未启用实例隔离）
	if err := m.SetInstanceID(""); err != nil {
		t.Fatalf("空串应允许: %v", err)
	}
	if m.InstanceID() != "" {
		t.Fatal("应为空")
	}
	// 合法 ID
	good := "0123456789abcdef"
	if err := m.SetInstanceID(good); err != nil {
		t.Fatalf("合法 ID 应通过: %v", err)
	}
	if m.InstanceID() != good {
		t.Fatalf("实例 ID 未设置: %q", m.InstanceID())
	}
	// 非法 ID
	for _, bad := range []string{"short", "0123456789ABCDEF", strings.Repeat("g", 16)} {
		if err := m.SetInstanceID(bad); err == nil {
			t.Fatalf("非法 ID %q 应报错", bad)
		}
	}
	// 设置失败不应破坏原值
	if m.InstanceID() != good {
		t.Fatal("失败的设置不应改变原值")
	}
}
