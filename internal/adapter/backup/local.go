package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LocalSink 是本地目录目标。
//
// 用途：同机异盘、或挂载了 NFS 的目录。**不是「放同一个数据目录」**——
// 那等于没有备份（盘坏了全丢）。
type LocalSink struct {
	dir string
}

// NewLocalSink 创建本地目标。目录不存在时自动创建工作。
func NewLocalSink(dir string) (*LocalSink, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("创建本地备份目标失败: 目录为空")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建本地备份目录 %s 失败: %w", dir, err)
	}
	return &LocalSink{dir: dir}, nil
}

// Name 实现 Sink。
func (s *LocalSink) Name() string { return "local" }

// Put 复制文件到目标目录，并**读回校验 sha256**。
//
// 为什么复制后要重算而不是信任源文件摘要：跨文件系统（尤其 NFS）
// 写入可能静默截断。只有读回来算一遍才能确认落盘内容正确。
func (s *LocalSink) Put(ctx context.Context, localPath string, m Manifest) error {
	dst := filepath.Join(s.dir, m.Name)
	// 目标已存在视为失败：避免覆盖同名备份（时间戳到秒，理论上不会撞，
	// 但两次手动触发可能同秒）
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("目标文件已存在: %s", m.Name)
	}
	if err := copyFile(localPath, dst); err != nil {
		return err
	}
	// 读回校验
	sum, err := FileSHA256(dst)
	if err != nil {
		os.Remove(dst)
		return fmt.Errorf("校验写入结果失败: %w", err)
	}
	if sum != m.SHA256 {
		os.Remove(dst)
		return fmt.Errorf("写入后摘要不符（期望 %s，实际 %s），已删除半成品", m.SHA256, sum)
	}
	// 备份文件含数据库内容，权限必须 0600（C-04）
	if err := os.Chmod(dst, 0o600); err != nil {
		os.Remove(dst)
		return fmt.Errorf("设置备份文件权限失败: %w", err)
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("备份被取消: %w", ctx.Err())
	default:
	}
	return nil
}

// List 列出目标目录下的备份（只认本 sink 的命名约定）。
func (s *LocalSink) List(ctx context.Context) ([]Manifest, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("读取备份目录失败: %w", err)
	}
	var out []Manifest
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// 只认 "<source>-YYYYMMDD-HHMMSS.db" 形式，避免误删用户的其它文件
		ts, ok := parseBackupName(name)
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Manifest{
			Name:      name,
			CreatedAt: ts,
			Size:      info.Size(),
			Source:    sourceOf(name),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// Remove 删除一份备份。
func (s *LocalSink) Remove(ctx context.Context, name string) error {
	if !isValidBackupName(name) {
		return fmt.Errorf("拒绝删除 %q: 不符合备份文件命名约定", name)
	}
	if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除备份 %s 失败: %w", name, err)
	}
	return nil
}

// Get 把备份复制到本地路径。
func (s *LocalSink) Get(ctx context.Context, name, localPath string) error {
	if !isValidBackupName(name) {
		return fmt.Errorf("拒绝读取 %q: 不符合备份文件命名约定", name)
	}
	return copyFile(filepath.Join(s.dir, name), localPath)
}

// copyFile 复制文件并保证 0600 权限。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("打开源文件失败: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("创建目标文件失败: %w", err)
	}
	if _, err := out.ReadFrom(in); err != nil {
		out.Close()
		os.Remove(dst)
		return fmt.Errorf("复制数据失败: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return fmt.Errorf("关闭目标文件失败: %w", err)
	}
	return nil
}

// 备份文件命名：<source>-YYYYMMDD-HHMMSS.db
//
// 命名约定是**安全边界**的一部分：List/Remove 靠它区分「本 sink 的备份」
// 与「用户的其它文件」。放宽它会带来误删风险。
const backupNameLayout = "20060102-150405"

func isValidBackupName(name string) bool {
	_, ok := parseBackupName(name)
	return ok
}

// parseBackupName 解析备份文件名，返回时间戳。
//
// 严格校验：必须是 "<source>-YYYYMMDD-HHMMSS.db" 且 source 只含
// 字母数字下划线。任何其它形式一律拒绝（返回 ok=false）。
func parseBackupName(name string) (time.Time, bool) {
	if !strings.HasSuffix(name, ".db") {
		return time.Time{}, false
	}
	base := strings.TrimSuffix(name, ".db")
	// 时间戳固定 15 字符（YYYYMMDD-HHMMSS），前面是 source 与连字符
	const tsLen = len("20060102-150405")
	if len(base) < tsLen+2 {
		return time.Time{}, false
	}
	tsPart := base[len(base)-tsLen:]
	srcPart := strings.TrimSuffix(base[:len(base)-tsLen], "-")
	if srcPart == "" || !isSimpleIdent(srcPart) {
		return time.Time{}, false
	}
	ts, err := time.ParseInLocation(backupNameLayout, tsPart, time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// sourceOf 从文件名里取 source 部分。
func sourceOf(name string) string {
	base := strings.TrimSuffix(name, ".db")
	const tsLen = len("20060102-150405")
	if len(base) < tsLen+2 {
		return ""
	}
	return strings.TrimSuffix(base[:len(base)-tsLen], "-")
}

// isSimpleIdent 报告 s 是否只含字母数字下划线（防路径穿越与怪异文件名）。
func isSimpleIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}
