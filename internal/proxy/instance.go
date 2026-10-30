// 实例隔离：给每个数据目录一个稳定的实例 ID，让「我装的规则」可以被证明。
//
// 事故背景（docs/incident-2026-10-30-orphan-reconcile.md）：
// 旧的对账判据是「内核里有 haweb-nft 标记、但我的库里没有对应启用规则 = 孤儿」。
// 这个判据只在「内核里只有我自己装的规则」时成立。一旦有第二个进程
// （灰度、测试、双进程升级期间的新进程）用不同数据目录碰同一张表，
// 它就会把别人的规则全判成孤儿拆掉。
//
// 修复（方案 A）：实例 ID 参与规则标记，对账时只认自己 ID 的规则。
//
//	旧标记：haweb-nft:snat:<ruleID>
//	新标记：haweb-nft:<instanceID>:snat:<ruleID>
//
// 兼容性：
//   - **旧标记的规则一律视为「非本实例」**，不会被拆（这是安全的默认，
//     代价是升级后第一次启动不会自动清理升级前遗留的孤儿）
//   - 需要清理旧孤儿时用显式的运维命令（见 ReconcileLegacyOrphans），
//     而不是在启动路径里自动做
package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// instanceIDFile 是实例 ID 的文件名（放在数据目录下）。
const instanceIDFile = "instance_id"

// instanceIDLen 是实例 ID 的字符数（8 字节十六进制 = 16 字符）。
//
// 16 字符足够避免碰撞（2^64），且能塞进 nft 规则的 comment 而不显著增长。
const instanceIDLen = 16

// LoadOrCreateInstanceID 读取（不存在则创建）数据目录的实例 ID。
//
// 语义：
//   - 文件存在且格式合法 → 读取
//   - 文件不存在 → 生成新的并落盘（0600）
//   - 文件存在但格式非法 → **报错而不是重建**
//     （重建会让「本实例的旧规则」变成「别人的规则」，永久泄漏）
//
// 为什么 ID 落在数据目录而不是配置文件：
// 它标识的是「这份数据（库 + 我装的规则）」，不是「这台机器」。
// 同一台机上跑两个实例（不同数据目录）必须得到不同的 ID。
func LoadOrCreateInstanceID(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", fmt.Errorf("读取实例 ID 失败: 数据目录为空")
	}
	path := filepath.Join(dataDir, instanceIDFile)
	b, err := os.ReadFile(path)
	if err == nil {
		id := strings.TrimSpace(string(b))
		if !isValidInstanceID(id) {
			return "", fmt.Errorf("读取实例 ID 失败: %s 内容 %q 格式非法"+
				"（应为 %d 位十六进制）；请人工确认后修复或删除该文件（删除会让本实例的旧规则失去归属）",
				path, id, instanceIDLen)
		}
		return id, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("读取实例 ID 失败: %w", err)
	}

	// 生成新的
	raw := make([]byte, instanceIDLen/2)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("生成实例 ID 失败: %w", err)
	}
	id := hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("写入实例 ID 到 %s 失败: %w", path, err)
	}
	// 显式 chmod：WriteFile 的 perm 受 umask 影响（C-04）
	if err := os.Chmod(path, 0o600); err != nil {
		return "", fmt.Errorf("设置实例 ID 文件权限失败: %w", err)
	}
	return id, nil
}

// isValidInstanceID 校验实例 ID 格式（纯小写十六进制，长度精确匹配）。
//
// 严格校验的理由：这个值会进 nft 的 comment 字符串，任何非十六进制字符
// 都可能破坏 comment 的解析（对账靠正则提取）。
func isValidInstanceID(id string) bool {
	if len(id) != instanceIDLen {
		return false
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// InstanceID 返回 Manager 的实例 ID（未设置时返回空串）。
func (m *Manager) InstanceID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.instanceID
}

// SetInstanceID 设置实例 ID（由装配层在启动时调用）。
//
// 空串表示「未启用实例隔离」——此时对账**不做任何拆除**（见 purgeOrphanNFTRules
// 的安全分支），这是方案 C 的默认行为。
func (m *Manager) SetInstanceID(id string) error {
	if id != "" && !isValidInstanceID(id) {
		return fmt.Errorf("设置实例 ID 失败: %q 格式非法（应为 %d 位小写十六进制）", id, instanceIDLen)
	}
	m.mu.Lock()
	m.instanceID = id
	m.mu.Unlock()
	return nil
}
