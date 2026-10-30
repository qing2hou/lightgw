package backup

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestExpandArgsKeepsSingleArg 占位符替换后仍是**一个**参数（与 sh -c 的本质区别）。
//
// 这是 D-15 的核心：`sh -c "cp {local} {remote}"` 会把 `{remote}` 里的空格
// 变成参数分隔符，而 expandArgs 不会。
func TestExpandArgsKeepsSingleArg(t *testing.T) {
	tmpl := []string{"scp", "{local}", "{remote}"}
	// 故意在值里放空格与 shell 元字符
	got := expandArgs(tmpl, map[string]string{
		"{local}":  "/tmp/a b.db",
		"{remote}": "host:/backup/x;rm -rf /.db",
	})
	if len(got) != 3 {
		t.Fatalf("★ 参数数量必须仍为 3，实际 %d: %q"+
			"（变成更多个说明被当作 shell 拆分，这就是向 sh -c 退化）", len(got), got)
	}
	if got[1] != "/tmp/a b.db" {
		t.Fatalf("含空格的参数不应被拆分: %q", got[1])
	}
	if got[2] != "host:/backup/x;rm -rf /.db" {
		t.Fatalf("命令注入载荷应作为单个参数原样传递（由 exec 拒绝执行，而非 shell 解释）: %q", got[2])
	}
}

// TestNewCommandSinkValidation 构造参数校验。
func TestNewCommandSinkValidation(t *testing.T) {
	valid := CommandSpec{
		Name:          "sftp",
		RemoteDir:     "/backup",
		PutCommand:    []string{"scp", "{local}", "{remote}"},
		ListCommand:   []string{"ssh", "h", "ls", "{remoteDir}"},
		GetCommand:    []string{"scp", "{remote}", "{local}"},
		RemoveCommand: []string{"ssh", "h", "rm", "{remote}"},
	}
	if _, err := NewCommandSink(valid); err != nil {
		t.Fatalf("合法 spec 应通过: %v", err)
	}
	// 名字非法
	bad := valid
	bad.Name = "sf tp"
	if _, err := NewCommandSink(bad); err == nil {
		t.Fatal("非法名字应报错")
	}
	// 上传命令为空
	bad = valid
	bad.PutCommand = nil
	if _, err := NewCommandSink(bad); err == nil {
		t.Fatal("空上传命令应报错")
	}
	// 远端目录为空
	bad = valid
	bad.RemoteDir = " "
	if _, err := NewCommandSink(bad); err == nil {
		t.Fatal("空远端目录应报错")
	}
	// ★ 远端目录含 shell 元字符必须拒绝（纵深防御：远端可能经过 shell）
	for _, dir := range []string{"/backup;rm -rf /", "/backup$(id)", "/backup`id`", "/backup&&x"} {
		bad = valid
		bad.RemoteDir = dir
		if _, err := NewCommandSink(bad); err == nil {
			t.Fatalf("★ 远端目录 %q 含 shell 元字符必须被拒", dir)
		}
	}
}

// TestCommandSinkRemotePath 远端路径拼接。
func TestCommandSinkRemotePath(t *testing.T) {
	s, err := NewCommandSink(CommandSpec{
		Name: "sftp", RemoteDir: "/backup/haweb",
		PutCommand: []string{"true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.remotePath("config-20261030-120000.db"); got != "/backup/haweb/config-20261030-120000.db" {
		t.Fatalf("远端路径错误: %q", got)
	}
}

// TestCommandSinkRemoveRejectsForeignName 删除必须校验命名。
func TestCommandSinkRemoveRejectsForeignName(t *testing.T) {
	s, _ := NewCommandSink(CommandSpec{
		Name: "sftp", RemoteDir: "/backup",
		PutCommand:    []string{"true"},
		RemoveCommand: []string{"true"},
	})
	if err := s.Remove(context.Background(), "important.conf"); err == nil {
		t.Fatal("★ 非备份命名必须拒绝删除")
	}
	if err := s.Remove(context.Background(), "../etc/passwd"); err == nil {
		t.Fatal("★ 路径穿越必须拒绝")
	}
}

// TestCommandSinkGetRejectsForeignName 读取也必须校验命名。
func TestCommandSinkGetRejectsForeignName(t *testing.T) {
	s, _ := NewCommandSink(CommandSpec{
		Name: "sftp", RemoteDir: "/backup",
		PutCommand: []string{"true"},
		GetCommand: []string{"true"},
	})
	if err := s.Get(context.Background(), "notes.txt", "/tmp/x"); err == nil {
		t.Fatal("非备份命名必须拒绝读取")
	}
}

// TestCommandSinkNoCommands 未配置命令时的行为。
func TestCommandSinkNoCommands(t *testing.T) {
	s, _ := NewCommandSink(CommandSpec{
		Name: "s3", RemoteDir: "s3://bucket",
		PutCommand: []string{"true"},
	})
	// List 无命令 → 返回空，不报错（清理逻辑不该因为没配 list 而失败）
	list, err := s.List(context.Background())
	if err != nil || len(list) != 0 {
		t.Fatalf("无 list 命令应返回空: %v %v", list, err)
	}
	// Remove 无命令 → 报错（静默不删会让旧备份堆积）
	if err := s.Remove(context.Background(), "config-20261030-120000.db"); err == nil {
		t.Fatal("无删除命令时 Remove 应报错")
	}
	// Get 无命令 → 报错
	if err := s.Get(context.Background(), "config-20261030-120000.db", "/tmp/x"); err == nil {
		t.Fatal("无下载命令时 Get 应报错")
	}
}

// TestCommandSinkPutWithoutGetSkipsVerify 无下载命令时跳过读回校验（但上传失败仍报错）。
func TestCommandSinkPutWithoutGet(t *testing.T) {
	s, _ := NewCommandSink(CommandSpec{
		Name: "s3", RemoteDir: "/b",
		PutCommand: []string{"true"},
	})
	// 命令为 true 时上传成功，无 get 则跳过校验
	if err := s.Put(context.Background(), "/dev/null", Manifest{Name: "config-20261030-120000.db"}); err != nil {
		t.Fatalf("应成功（跳过校验）: %v", err)
	}
}

// TestCommandSinkPutFailureReportsStderr 上传失败必须带 stderr（便于排障）。
func TestCommandSinkPutFailureReportsStderr(t *testing.T) {
	s, _ := NewCommandSink(CommandSpec{
		Name: "sftp", RemoteDir: "/b",
		PutCommand: []string{"sh", "-c", "echo 'permission denied' >&2; exit 1"},
	})
	err := s.Put(context.Background(), "/dev/null", Manifest{Name: "config-20261030-120000.db"})
	if err == nil {
		t.Fatal("应报错")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("错误应包含 stderr 内容以便排障，实际: %v", err)
	}
}

// TestRunCommandEmpty 空命令必须报错而不是 panic。
func TestRunCommandEmpty(t *testing.T) {
	if err := runCommand(context.Background(), nil); err == nil {
		t.Fatal("空命令应报错")
	}
	if _, err := captureCommand(context.Background(), nil); err == nil {
		t.Fatal("空命令应报错")
	}
}

// TestRunCommandCancelled ctx 取消必须中断。
func TestRunCommandCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runCommand(ctx, []string{"sleep", "5"})
	if err == nil {
		t.Fatal("已取消的 ctx 应中断命令")
	}
	if !errors.Is(err, context.Canceled) {
		// exec.CommandContext 返回 "signal: killed"，不是 context.Canceled——
		// 只要求非 nil 即可
		t.Logf("取消后的错误类型: %v（预期 signal: killed）", err)
	}
}
