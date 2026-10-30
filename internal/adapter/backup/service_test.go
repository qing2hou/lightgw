package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSnapshot 模拟 vacuum：往 dest 写一段确定内容。
func writeSnapshot(content string) func(context.Context, string) error {
	return func(ctx context.Context, dest string) error {
		return os.WriteFile(dest, []byte(content), 0o600)
	}
}

// countingSink 记录每次操作，用于验证「先写后删」的顺序。
type countingSink struct {
	name    string
	puts    []Manifest
	removes []string
	putsErr error
	list    []Manifest
	// order 记录操作顺序（"put" / "remove"）
	order []string
}

func newCountingSink(name string) *countingSink {
	return &countingSink{name: name}
}

func (s *countingSink) Name() string { return s.name }
func (s *countingSink) Put(ctx context.Context, localPath string, m Manifest) error {
	if s.putsErr != nil {
		return s.putsErr
	}
	s.puts = append(s.puts, m)
	s.order = append(s.order, "put:"+m.Name)
	return nil
}
func (s *countingSink) List(ctx context.Context) ([]Manifest, error) { return s.list, nil }
func (s *countingSink) Remove(ctx context.Context, name string) error {
	s.removes = append(s.removes, name)
	s.order = append(s.order, "remove:"+name)
	return nil
}
func (s *countingSink) Get(ctx context.Context, name, localPath string) error { return nil }

// TestRunBackupBasic 一次成功备份：快照 + 摘要 + 上传。
func TestRunBackupBasic(t *testing.T) {
	dir := t.TempDir()
	sink := newCountingSink("local")
	svc := New(filepath.Join(dir, "config.db"), dir, writeSnapshot("hello-backup"), sink)
	svc.now = func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC) }

	res, err := svc.Run(context.Background(), Options{Source: "config", Keep: 3})
	if err != nil {
		t.Fatalf("备份失败: %v", err)
	}
	if len(res.Sinks) != 1 || res.Sinks[0] != "local" {
		t.Fatalf("应成功写入 local，实际 %v", res.Sinks)
	}
	// 文件名必须符合约定
	if res.Name != "config-20261030-120000.db" {
		t.Fatalf("文件名错误: %q", res.Name)
	}
	// 摘要必须与内容一致
	want := sha256Of([]byte("hello-backup"))
	if res.SHA256 != want {
		t.Fatalf("摘要错误: %s（期望 %s）", res.SHA256, want)
	}
	if res.Size != int64(len("hello-backup")) {
		t.Fatalf("大小错误: %d", res.Size)
	}
	// 快照临时文件必须被清理
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".config-") {
			t.Fatalf("快照临时文件未清理: %s", e.Name())
		}
	}
}

// TestRunBackupPartialFailure 一个目标失败不影响其它目标。
func TestRunBackupPartialFailure(t *testing.T) {
	dir := t.TempDir()
	okSink := newCountingSink("local")
	badSink := newCountingSink("sftp")
	badSink.putsErr = errors.New("连接超时")
	svc := New(filepath.Join(dir, "config.db"), dir, writeSnapshot("x"), okSink, badSink)

	res, err := svc.Run(context.Background(), Options{Source: "config"})
	if err != nil {
		t.Fatalf("部分失败不应整体报错: %v", err)
	}
	if len(res.Sinks) != 1 || res.Sinks[0] != "local" {
		t.Fatalf("local 应成功，实际 %v", res.Sinks)
	}
	if len(res.Failures) != 1 || res.Failures["sftp"] == "" {
		t.Fatalf("sftp 应记录失败原因，实际 %v", res.Failures)
	}
}

// TestRunBackupAllFail 全部失败必须报错。
func TestRunBackupAllFail(t *testing.T) {
	dir := t.TempDir()
	a := newCountingSink("a")
	a.putsErr = errors.New("fail a")
	b := newCountingSink("b")
	b.putsErr = errors.New("fail b")
	svc := New(filepath.Join(dir, "config.db"), dir, writeSnapshot("x"), a, b)
	if _, err := svc.Run(context.Background(), Options{Source: "config"}); err == nil {
		t.Fatal("全部失败应报错")
	}
}

// TestPruneOnlyAfterAllSucceed 「先写后删」：有目标失败时不清理旧备份。
//
// 顺序反了（先删后写）会在网络抖动时两头空。
func TestPruneOnlyAfterAllSucceed(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mkOld := func(n int) []Manifest {
		out := make([]Manifest, n)
		for i := range out {
			out[i] = Manifest{
				Name:      "config-2026010" + string(rune('1'+i)) + "-000000.db",
				CreatedAt: old.AddDate(0, 0, i),
				Source:    "config",
			}
		}
		return out
	}

	dir := t.TempDir()
	okSink := newCountingSink("local")
	okSink.list = mkOld(5) // 已有 5 份旧备份
	badSink := newCountingSink("sftp")
	badSink.putsErr = errors.New("网络失败")

	svc := New(filepath.Join(dir, "config.db"), dir, writeSnapshot("x"), okSink, badSink)
	svc.now = func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC) }
	if _, err := svc.Run(context.Background(), Options{Source: "config", Keep: 2}); err != nil {
		t.Fatalf("备份失败: %v", err)
	}
	if len(okSink.removes) != 0 {
		t.Fatalf("★ 有目标失败时不应清理旧备份（先写后删），实际删了 %v", okSink.removes)
	}
}

// TestPruneWhenAllSucceed 全部成功时按保留份数删最旧的。
func TestPruneWhenAllSucceed(t *testing.T) {
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sink := newCountingSink("local")
	for i := 0; i < 5; i++ {
		sink.list = append(sink.list, Manifest{
			Name:      "config-2026010" + string(rune('1'+i)) + "-000000.db",
			CreatedAt: old.AddDate(0, 0, i),
		})
	}
	dir := t.TempDir()
	svc := New(filepath.Join(dir, "config.db"), dir, writeSnapshot("x"), sink)
	svc.now = func() time.Time { return time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC) }

	if _, err := svc.Run(context.Background(), Options{Source: "config", Keep: 2}); err != nil {
		t.Fatalf("备份失败: %v", err)
	}
	// 5 份旧备保留最后 2 份，删最老的 3 份
	if len(sink.removes) != 3 {
		t.Fatalf("应删 3 份，实际 %d: %v", len(sink.removes), sink.removes)
	}
	if sink.removes[0] != "config-20260101-000000.db" {
		t.Fatalf("应从最老的开始删，实际先删 %s", sink.removes[0])
	}
}

// TestSnapshotPathOutsideDataDir 快照必须落在数据目录内（C-08）。
func TestSnapshotPathOutsideDataDir(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(filepath.Dir(dir), "outside.db")
	svc := New(filepath.Join(dir, "config.db"), dir, func(ctx context.Context, dest string) error {
		t.Fatalf("不应调用 vacuum（路径校验应先失败）")
		return nil
	}, newCountingSink("local"))
	// 用合法的 sink 但把 dataDir 设成 dir，dest 会落在 dir 内 —— 正常。
	// 这里直接测 ValidateSnapshotPath 的越界分支
	if err := ValidateSnapshotPath(dir, outside); err == nil {
		t.Fatal("目录外路径应被拒")
	}
	if err := ValidateSnapshotPath(dir, filepath.Join(dir, "..", "x.db")); err == nil {
		t.Fatal("路径穿越应被拒")
	}
	_ = svc
}

// TestSnapshotPathExists 已存在的目标必须被拒（VACUUM INTO 要求不存在）。
func TestSnapshotPathExists(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "exists.db")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSnapshotPath(dir, p); err == nil {
		t.Fatal("已存在的目标应被拒")
	}
}

// TestRunNoSinks 没有目标必须报错。
func TestRunNoSinks(t *testing.T) {
	dir := t.TempDir()
	svc := New(filepath.Join(dir, "config.db"), dir, writeSnapshot("x"))
	if _, err := svc.Run(context.Background(), Options{Source: "config"}); err == nil {
		t.Fatal("没有目标应报错")
	}
}

// TestRunNoVacuum 未配置快照函数必须报错。
func TestRunNoVacuum(t *testing.T) {
	svc := New("x", t.TempDir(), nil, newCountingSink("local"))
	if _, err := svc.Run(context.Background(), Options{Source: "config"}); err == nil {
		t.Fatal("未配置 vacuum 应报错")
	}
}

// TestRunVacuumError 快照失败必须中止且不调用任何 sink。
func TestRunVacuumError(t *testing.T) {
	dir := t.TempDir()
	sink := newCountingSink("local")
	svc := New(filepath.Join(dir, "config.db"), dir, func(ctx context.Context, dest string) error {
		return errors.New("磁盘满")
	}, sink)
	if _, err := svc.Run(context.Background(), Options{Source: "config"}); err == nil {
		t.Fatal("快照失败应报错")
	}
	if len(sink.puts) != 0 {
		t.Fatal("快照失败时不应上传")
	}
}

// TestVerify 校验：大小与摘要都要对。
func TestVerify(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b.db")
	content := "backup-content"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, _ := FileSHA256(p)
	good := Manifest{Name: "b.db", Size: int64(len(content)), SHA256: sum}
	if err := Verify(p, good); err != nil {
		t.Fatalf("合法备份应通过: %v", err)
	}
	// 大小不符
	bad := good
	bad.Size = 999
	if err := Verify(p, bad); err == nil {
		t.Fatal("大小不符应报错")
	}
	// 摘要不符
	bad = good
	bad.SHA256 = strings.Repeat("0", 64)
	if err := Verify(p, bad); err == nil {
		t.Fatal("摘要不符应报错")
	}
	// 文件不存在
	if err := Verify(filepath.Join(dir, "nope.db"), good); err == nil {
		t.Fatal("文件不存在应报错")
	}
}

// sha256Of 计算字节切片摘要（测试辅助，不进生产代码）。
func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
