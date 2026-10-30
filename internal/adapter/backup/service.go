// Package backup 提供配置库的备份与恢复能力。
//
// 三种目标（技术方案 §9.1）：local / sftp / s3。
// 每种都要 sha256 校验 + 回滚可用性验证。
//
// 三条硬约束：
//
//  1. **用 `VACUUM INTO` 而不是文件拷贝**：前者能拿到一致快照
//     （含 WAL 中尚未落盘的数据），后者在并发写时可能拿到半写状态。
//  2. **目标必须在数据目录内且不存在**（C-08）：systemd 沙箱
//     ReadWritePaths 只放行数据目录，写到别处会权限失败；
//     `VACUUM INTO` 要求目标不存在。
//  3. **不许 `sh -c` 拼命令**（D-15）：旧 deploy/backup.sh 里
//     `sh -c "$HAWEB_BACKUP_PUSH_CMD '$dest'"` 是注入面。
//     远端推送要么走 Go 原生客户端，要么走 exec.Command 逐参数传。
package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Manifest 是一次备份的元数据。
//
// 不变量：写入后不可变。恢复时用它校验完整性。
type Manifest struct {
	// Name 是备份文件名（按时间戳，天然可排序）。
	Name string `json:"name"`
	// CreatedAt 是生成时刻。
	CreatedAt time.Time `json:"created_at"`
	// Size 是字节数。
	Size int64 `json:"size"`
	// SHA256 是内容摘要（hex）。
	SHA256 string `json:"sha256"`
	// Source 是源库的标识（"config" / "log"），便于区分备份对象。
	Source string `json:"source"`
}

// Sink 是一个备份目标。
//
// 契约：
//   - Put 必须**先写后校验**：写完立刻读回算 sha256 与期望值比对
//   - Put 失败时不能留下半个文件（自己清理）
//   - List / Prune 只作用于**本 sink 管理的命名空间**，
//     不能删用户的其它文件
type Sink interface {
	// Name 返回目标名（local / sftp / s3）。
	Name() string
	// Put 上传一个本地文件并校验。
	Put(ctx context.Context, localPath string, m Manifest) error
	// List 返回该目标上现有的备份（按 CreatedAt 升序）。
	List(ctx context.Context) ([]Manifest, error)
	// Remove 删除一份备份。
	Remove(ctx context.Context, name string) error
	// Get 把备份下载到本地路径（恢复用）。
	Get(ctx context.Context, name, localPath string) error
}

// Options 是备份任务参数。
type Options struct {
	// Keep 是保留份数（按时间戳排序，删最旧的）。
	// 0 表示不自动删。
	Keep int
	// Source 是源库标识。
	Source string
}

// Result 是一次备份的结果。
type Result struct {
	Manifest
	// Sinks 是成功写入的目标名。
	Sinks []string
	// Failures 是失败的目标（名 -> 原因）。
	//
	// **一个目标失败不影响其它目标**：本地成功但 sftp 失败时，
	// 本地那份仍然可用，不应整体回滚。
	Failures map[string]string
	// Pruned 是被删掉的旧备份名。
	Pruned []string
}

// Service 是备份用例。
type Service struct {
	// configDBPath 是配置库文件路径（VACUUM INTO 的源）。
	configDBPath string
	// dataDir 是数据目录（临时快照必须放这里，C-08）。
	dataDir string
	// vacuum 执行 `VACUUM INTO`。
	//
	// 抽成函数注入而不是直接依赖 gorm：backup 层不应被 ORM 绑死，
	// 且测试可以用「写一个固定内容的文件」替代真实 VACUUM。
	vacuum func(ctx context.Context, dest string) error

	sinks []Sink
	now   func() time.Time
}

// New 创建备份服务。
func New(configDBPath, dataDir string, vacuum func(ctx context.Context, dest string) error, sinks ...Sink) *Service {
	return &Service{
		configDBPath: configDBPath,
		dataDir:      dataDir,
		vacuum:       vacuum,
		sinks:        sinks,
		now:          time.Now,
	}
}

// Run 执行一次备份。
//
// 流程：
//  1. 在数据目录内生成一致快照（VACUUM INTO）
//  2. 算 sha256 + 大小
//  3. 推送到每个目标（各自独立，互不影响）
//  4. **全部目标都成功后**才删本地快照与旧的远端备份
//
// 「先写后删」的顺序不能反：远端成功之前删本地，网络抖动时就两头空。
func (s *Service) Run(ctx context.Context, opt Options) (*Result, error) {
	if s.vacuum == nil {
		return nil, fmt.Errorf("备份失败: 未配置快照函数")
	}
	if len(s.sinks) == 0 {
		return nil, fmt.Errorf("备份失败: 没有配置任何备份目标")
	}
	ts := s.now().UTC()
	name := fmt.Sprintf("%s-%s.db", opt.Source, ts.Format("20060102-150405"))

	// ① 快照：必须落在数据目录内（C-08）且不存在
	snapPath := filepath.Join(s.dataDir, "."+name+".snapshot")
	if err := ValidateSnapshotPath(s.dataDir, snapPath); err != nil {
		return nil, err
	}
	if err := s.vacuum(ctx, snapPath); err != nil {
		return nil, fmt.Errorf("生成数据库快照失败: %w", err)
	}
	// 快照是临时文件，无论成败都要删
	defer os.Remove(snapPath)

	// ② 摘要
	st, err := os.Stat(snapPath)
	if err != nil {
		return nil, fmt.Errorf("读取快照信息失败: %w", err)
	}
	sum, err := FileSHA256(snapPath)
	if err != nil {
		return nil, fmt.Errorf("计算快照摘要失败: %w", err)
	}
	m := Manifest{
		Name:      name,
		CreatedAt: ts,
		Size:      st.Size(),
		SHA256:    sum,
		Source:    opt.Source,
	}
	res := &Result{Manifest: m, Failures: map[string]string{}}

	// ③ 推送到各目标
	for _, sink := range s.sinks {
		if err := ctx.Err(); err != nil {
			return res, fmt.Errorf("备份被取消: %w", err)
		}
		if err := sink.Put(ctx, snapPath, m); err != nil {
			res.Failures[sink.Name()] = publicReason(err)
			continue
		}
		res.Sinks = append(res.Sinks, sink.Name())
	}

	// ④ 只有全部目标成功才清理旧备份
	if len(res.Sinks) == len(s.sinks) && opt.Keep > 0 {
		for _, sink := range s.sinks {
			pruned, err := pruneSink(ctx, sink, opt.Keep)
			if err != nil {
				// 清理失败不影响备份本身
				res.Failures[sink.Name()+":prune"] = publicReason(err)
				continue
			}
			res.Pruned = append(res.Pruned, pruned...)
		}
	}

	if len(res.Sinks) == 0 {
		return res, fmt.Errorf("备份失败: 所有目标都写失败（%v）", res.Failures)
	}
	return res, nil
}

// pruneSink 删除超出保留份数的旧备份（最老优先）。
func pruneSink(ctx context.Context, sink Sink, keep int) ([]string, error) {
	list, err := sink.List(ctx)
	if err != nil {
		return nil, err
	}
	// 按 CreatedAt 升序（最老在前）
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.Before(list[j].CreatedAt)
	})
	if len(list) <= keep {
		return nil, nil
	}
	var pruned []string
	for _, m := range list[:len(list)-keep] {
		if err := sink.Remove(ctx, m.Name); err != nil {
			return pruned, err
		}
		pruned = append(pruned, m.Name)
	}
	return pruned, nil
}

// Verify 校验一份备份的完整性（恢复前的第一步）。
//
// 检查两项：① 大小与 manifest 一致 ② sha256 与 manifest 一致。
// 只验其一会漏掉「同样大小但内容损坏」的情形。
func Verify(path string, m Manifest) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("校验备份失败: 无法读取 %s: %w", filepath.Base(path), err)
	}
	if st.Size() != m.Size {
		return fmt.Errorf("校验备份失败: 大小不符（期望 %d，实际 %d）", m.Size, st.Size())
	}
	sum, err := FileSHA256(path)
	if err != nil {
		return fmt.Errorf("校验备份失败: 计算摘要失败: %w", err)
	}
	if sum != m.SHA256 {
		return fmt.Errorf("校验备份失败: SHA256 不符（期望 %s，实际 %s）", m.SHA256, sum)
	}
	return nil
}

// FileSHA256 计算文件摘要。
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ValidateSnapshotPath 校验快照路径符合 C-08。
//
// 与 sqlite.ValidateBackupPath 的规则一致，但独立实现：
// backup 层不应 import sqlite（它只对「一个文件路径」负责）。
func ValidateSnapshotPath(dataDir, dest string) error {
	if dataDir == "" || dest == "" {
		return fmt.Errorf("校验快照路径失败: 路径为空")
	}
	absDir, err := filepath.Abs(dataDir)
	if err != nil {
		return fmt.Errorf("解析数据目录失败: %w", err)
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("解析快照路径失败: %w", err)
	}
	rel, err := filepath.Rel(absDir, absDest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("校验快照路径失败: 目标 %s 不在数据目录 %s 内"+
			"（systemd 沙箱只放行数据目录）", dest, dataDir)
	}
	if _, err := os.Stat(absDest); err == nil {
		return fmt.Errorf("校验快照路径失败: 目标 %s 已存在（VACUUM INTO 要求不存在）", dest)
	}
	return nil
}

// publicReason 把内部错误压成简短原因（不泄露路径与内部细节）。
func publicReason(err error) string {
	if err == nil {
		return ""
	}
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const max = 200
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
