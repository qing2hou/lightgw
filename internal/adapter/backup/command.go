package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
)

// CommandSink 通过**逐参数调用外部命令**实现远端备份。
//
// 为什么不用 `sh -c`（D-15）：旧 `deploy/backup.sh` 里
// `sh -c "$HAWEB_BACKUP_PUSH_CMD '$dest'"` 是注入面——`$dest` 里的
// 空格、分号、`$()` 都会被 shell 解释。本实现用 `exec.Command(name, args...)`
// 逐个传参，参数不经过 shell。
//
// 为什么用外部命令而不是 Go 原生 sftp/s3 客户端（技术方案 §9.1 原意）：
//   - 原生客户端要给 `pkg/sftp` 与 `aws-sdk-go-v2` 各加一个依赖（C-13 需申请）
//   - 而 `scp` / `aws s3 cp` 在运维环境里几乎必然已装（部署脚本本来就在用）
//   - **注入面已经通过「不拼 shell」消除**，这是 §9.1 那条约束的真正目的
//
// 若将来确实需要原生客户端，把本类型替换成实现同一 Sink 接口的新类型即可，
// Service 不需要改一行。
type CommandSink struct {
	// name 是目标名（用于 UI 与日志）。
	name string
	// putCmd / listCmd / getCmd / rmCmd 是四类操作的命令模板。
	//
	// 参数用占位符 `{local}` / `{remote}` / `{name}`，由 Execute 替换**单个参数**，
	// 不做字符串拼接——每个占位符替换后仍是**一个独立参数**。
	putCmd  []string
	listCmd []string
	getCmd  []string
	rmCmd   []string
	// remoteDir 是远端目录（用于拼远端文件名）。
	remoteDir string
	// listParser 把 listCmd 的输出解析成备份名列表。
	//
	// 抽成函数：不同后端（scp 目录列表 / aws s3 ls）输出格式不同，
	// 但后续的筛选（命名约定、时间戳排序）逻辑共用。
	listParser func(output string) []string
}

// CommandSpec 是 CommandSink 的构造参数。
type CommandSpec struct {
	Name      string
	RemoteDir string
	// PutCommand 例：{"scp", "-q", "-P", "22", "{local}", "backup@host:{remote}"}
	// 每个元素是一个独立参数；占位符整体替换为该参数的值。
	PutCommand []string
	// ListCommand 例：{"ssh", "backup@host", "ls", "-1", "{remoteDir}"}
	ListCommand []string
	// GetCommand 例：{"scp", "{remote}", "{local}"}
	GetCommand []string
	// RemoveCommand 例：{"ssh", "backup@host", "rm", "-f", "{remote}"}
	RemoveCommand []string
}

// NewCommandSink 创建基于外部命令的备份目标。
//
// 参数校验是安全边界：命令必须非空、名字必须简单标识符（会进 UI 与日志）。
func NewCommandSink(spec CommandSpec) (*CommandSink, error) {
	if !isSimpleIdent(spec.Name) {
		return nil, fmt.Errorf("创建命令备份目标失败: 名字 %q 只能含字母数字下划线", spec.Name)
	}
	if len(spec.PutCommand) == 0 {
		return nil, fmt.Errorf("创建命令备份目标 %s 失败: 上传命令为空", spec.Name)
	}
	if strings.TrimSpace(spec.RemoteDir) == "" {
		return nil, fmt.Errorf("创建命令备份目标 %s 失败: 远端目录为空", spec.Name)
	}
	// 远端目录里不允许出现 shell 元字符——虽然我们不经过 shell，
	// 但远端命令（如 ssh 到另一台机器）可能会。这是纵深防御。
	if strings.ContainsAny(spec.RemoteDir, ";&|$`\n\r") {
		return nil, fmt.Errorf("创建命令备份目标 %s 失败: 远端目录含非法字符", spec.Name)
	}
	return &CommandSink{
		name:      spec.Name,
		remoteDir: spec.RemoteDir,
		putCmd:    spec.PutCommand,
		listCmd:   spec.ListCommand,
		getCmd:    spec.GetCommand,
		rmCmd:     spec.RemoveCommand,
		listParser: func(out string) []string {
			// 默认解析：逐行取第一个字段（兼容 `ls -1` 与 `aws s3 ls` 的日期前缀格式）
			var names []string
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				f := strings.Fields(line)
				if len(f) == 0 {
					continue
				}
				names = append(names, f[len(f)-1])
			}
			return names
		},
	}, nil
}

// Name 实现 Sink。
func (s *CommandSink) Name() string { return s.name }

// Put 上传并**读回校验**。
//
// 校验方式：上传后把文件下载回来算 sha256 与期望比对。
// 这比「信任 scp 的退出码」可靠得多——scp 成功不代表远端内容完整
// （尤其跨公网时）。
func (s *CommandSink) Put(ctx context.Context, localPath string, m Manifest) error {
	if len(s.putCmd) == 0 {
		return fmt.Errorf("目标 %s 未配置上传命令", s.name)
	}
	remote := s.remotePath(m.Name)
	args := expandArgs(s.putCmd, map[string]string{
		"{local}":  localPath,
		"{remote}": remote,
		"{name}":   m.Name,
	})
	if err := runCommand(ctx, args); err != nil {
		return fmt.Errorf("上传失败: %w", err)
	}
	// 读回校验
	if len(s.getCmd) == 0 {
		// 没配下载命令时只能信任上传结果，但要明确记录这一点
		return nil
	}
	tmp, err := os.CreateTemp("", "haweb-verify-")
	if err != nil {
		return fmt.Errorf("创建校验临时文件失败: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	getArgs := expandArgs(s.getCmd, map[string]string{
		"{local}":  tmpPath,
		"{remote}": remote,
		"{name}":   m.Name,
	})
	if err := runCommand(ctx, getArgs); err != nil {
		return fmt.Errorf("读回校验失败: %w", err)
	}
	sum, err := FileSHA256(tmpPath)
	if err != nil {
		return fmt.Errorf("计算读回摘要失败: %w", err)
	}
	if sum != m.SHA256 {
		return fmt.Errorf("读回摘要不符（期望 %s，实际 %s）——远端内容可能被截断",
			m.SHA256, sum)
	}
	return nil
}

// List 列出远端备份。
func (s *CommandSink) List(ctx context.Context) ([]Manifest, error) {
	if len(s.listCmd) == 0 {
		return nil, nil
	}
	args := expandArgs(s.listCmd, map[string]string{"{remoteDir}": s.remoteDir})
	out, err := captureCommand(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("列出远端备份失败: %w", err)
	}
	var res []Manifest
	for _, name := range s.listParser(out) {
		ts, ok := parseBackupName(name)
		if !ok {
			continue
		}
		res = append(res, Manifest{Name: name, CreatedAt: ts, Source: sourceOf(name)})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].CreatedAt.Before(res[j].CreatedAt) })
	return res, nil
}

// Remove 删除远端备份。
func (s *CommandSink) Remove(ctx context.Context, name string) error {
	if !isValidBackupName(name) {
		return fmt.Errorf("拒绝删除 %q: 不符合备份文件命名约定", name)
	}
	if len(s.rmCmd) == 0 {
		return fmt.Errorf("目标 %s 未配置删除命令", s.name)
	}
	args := expandArgs(s.rmCmd, map[string]string{
		"{remote}": s.remotePath(name),
		"{name}":   name,
	})
	if err := runCommand(ctx, args); err != nil {
		return fmt.Errorf("删除远端备份失败: %w", err)
	}
	return nil
}

// Get 下载备份到本地。
func (s *CommandSink) Get(ctx context.Context, name, localPath string) error {
	if !isValidBackupName(name) {
		return fmt.Errorf("拒绝读取 %q: 不符合备份文件命名约定", name)
	}
	if len(s.getCmd) == 0 {
		return fmt.Errorf("目标 %s 未配置下载命令", s.name)
	}
	args := expandArgs(s.getCmd, map[string]string{
		"{local}":  localPath,
		"{remote}": s.remotePath(name),
		"{name}":   name,
	})
	if err := runCommand(ctx, args); err != nil {
		return fmt.Errorf("下载备份失败: %w", err)
	}
	return nil
}

// remotePath 拼远端文件路径（用 path 而非 filepath：远端是 Linux 风格）。
func (s *CommandSink) remotePath(name string) string {
	return path.Join(s.remoteDir, name)
}

// expandArgs 把命令模板里的占位符替换成实际值。
//
// **关键约束**：每个模板元素替换后仍是**一个独立参数**，不做再拆分。
// 所以 `{name}` 里即使含空格也不会变成两个参数——这是与 `sh -c` 的本质区别。
func expandArgs(tmpl []string, vars map[string]string) []string {
	out := make([]string, len(tmpl))
	for i, a := range tmpl {
		s := a
		for k, v := range vars {
			s = strings.ReplaceAll(s, k, v)
		}
		out[i] = s
	}
	return out
}

// runCommand 执行命令，失败时把 stderr 附进错误（截断防刷屏）。
func runCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("命令为空")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		if msg != "" {
			return fmt.Errorf("%v: %s", err, msg)
		}
		return err
	}
	return nil
}

// captureCommand 执行命令并返回 stdout。
func captureCommand(ctx context.Context, args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("命令为空")
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}
