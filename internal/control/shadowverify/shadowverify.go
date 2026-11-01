// Package shadowverify 在生产机上安全地比对「新编译产物」与「现网实际规则」。
//
// 为什么需要它（路径 B 的第一步）：
//
// 完整替换 proxy.Manager 需要重写用户态转发、监听管理、健康检查、
// 双进程升级、优雅排空 —— 那是多轮的工作，而且必须在真机反复验证。
// 今天的对账事故（docs/incident-2026-10-30-orphan-reconcile.md）证明
// 「一次改太多 + 直接上生产」的代价。
//
// 所以先做**只读影子比对**：
//   - 从 DB 读出规则，用新的 compile 编译成 Plan（纯函数，零副作用）
//   - 读取内核上**现有的** nft 规则（只读）
//   - 比对两者，报告差异
//   - **不写任何内核对象**
//
// 这样能在生产机上安全回答一个问题：新编译器和旧实现产出的规则集是否等价？
// 等价才敢替换，不等价先查清为什么。
package shadowverify

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// RuleDigest 是一条规则的可比对摘要。
//
// 只保留「语义相关」的字段：链、匹配条件、动作。刻意不含 comment
// 的实例 ID 段（那个每次部署可能不同，不构成语义差异）。
type RuleDigest struct {
	Chain string
	// Match 是规范化的匹配条件描述（如 "saddr=192.168.10.0/24 dport=1022"）。
	Match string
	// Action 是规范化的动作（如 "snat to 192.168.10.170" / "drop"）。
	Action string
}

// Key 是该规则的唯一标识（用于集合比对）。
func (r RuleDigest) Key() string {
	return r.Chain + "|" + r.Match + "|" + r.Action
}

// String 便于日志输出。
func (r RuleDigest) String() string {
	return fmt.Sprintf("%s: %s → %s", r.Chain, r.Match, r.Action)
}

// Diff 是一次比对的结果。
type Diff struct {
	// OnlyInDesired 是新编译产物里有、内核上没有的规则（**缺失**）。
	//
	// 这是最需要关注的：说明新代码想装但现网没有，替换后行为会变。
	OnlyInDesired []RuleDigest
	// OnlyInActual 是内核上有、新编译产物里没有的规则（**多余**）。
	//
	// 通常是旧实现遗留或手工添加的；替换后会消失。
	OnlyInActual []RuleDigest
	// DesiredCount / ActualCount 是两侧的规则总数（供快速判断规模是否对得上）。
	DesiredCount int
	ActualCount  int
}

// Equivalent 报告两侧规则集是否完全一致。
func (d Diff) Equivalent() bool {
	return len(d.OnlyInDesired) == 0 && len(d.OnlyInActual) == 0
}

// Summary 返回一行摘要（供日志）。
func (d Diff) Summary() string {
	if d.Equivalent() {
		return fmt.Sprintf("规则集等价（各 %d 条）", d.DesiredCount)
	}
	return fmt.Sprintf("规则集不等价：期望 %d 条，实际 %d 条，缺失 %d 条，多余 %d 条",
		d.DesiredCount, d.ActualCount, len(d.OnlyInDesired), len(d.OnlyInActual))
}

// Compare 比对两组规则摘要。
//
// 归一化处理（避免假差异）：
//   - 空白折叠（内核输出与代码生成的空格数常不同）
//   - 忽略 counter 的计数值（那是运行时数据，不是配置）
//   - 忽略 comment 里的实例 ID（见 RuleDigest 注释）
func Compare(desired, actual []RuleDigest) Diff {
	d := Diff{DesiredCount: len(desired), ActualCount: len(actual)}
	desiredSet := make(map[string]RuleDigest, len(desired))
	for _, r := range desired {
		desiredSet[r.Key()] = r
	}
	actualSet := make(map[string]RuleDigest, len(actual))
	for _, r := range actual {
		actualSet[r.Key()] = r
	}
	for k, r := range desiredSet {
		if _, ok := actualSet[k]; !ok {
			d.OnlyInDesired = append(d.OnlyInDesired, r)
		}
	}
	for k, r := range actualSet {
		if _, ok := desiredSet[k]; !ok {
			d.OnlyInActual = append(d.OnlyInActual, r)
		}
	}
	// 排序保证输出稳定（map 迭代顺序随机）
	sortDigests(d.OnlyInDesired)
	sortDigests(d.OnlyInActual)
	return d
}

func sortDigests(rs []RuleDigest) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Key() < rs[j].Key() })
}

// Normalize 把一段规则描述归一化，供比对用。
//
// 具体做三件事：
//  1. 折叠连续空白为单个空格
//  2. 去掉 counter 及其数值（`counter packets 123 bytes 456` → `counter`）
//  3. 去掉 comment 里的实例 ID 段（`haweb-nft:<16hex>:` → `haweb-nft:`）
func Normalize(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = stripCounterCounts(s)
	s = stripInstanceID(s)
	return s
}

// stripCounterCounts 去掉 counter 的 packets/bytes 数值。
//
// 用状态机而不是正则：正则要处理「packets 123 bytes 456」与
// 「packets 0 bytes 0」两段，且不能误伤 `bytes` 作为其它字段名的情形。
func stripCounterCounts(s string) string {
	fields := strings.Fields(s)
	out := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch f {
		case "packets", "bytes":
			// 后面跟数字则一起跳过
			if i+1 < len(fields) && isAllDigits(fields[i+1]) {
				i++
				// packets/bytes 只保留第一次出现的 "counter" 语义
				continue
			}
			out = append(out, f)
		default:
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// stripInstanceID 去掉 comment 里的 16 位实例 ID 段。
//
// 例：`haweb-nft:0123456789abcdef:snat:30` → `haweb-nft:snat:30`
func stripInstanceID(s string) string {
	const prefix = "haweb-nft:"
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return s
	}
	rest := s[idx+len(prefix):]
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 || !isInstanceSegment(parts[0]) {
		return s
	}
	return s[:idx+len(prefix)] + parts[1]
}

// isInstanceSegment 判断某段是否为 16 位小写十六进制。
//
// 与 nft 包的实现保持一致（那边是权威定义，这里为避免 import 依赖重复一份）。
func isInstanceSegment(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// Reader 读取内核现状（只读端口）。
//
// 抽成接口：真实实现走 nft list（只读），测试用假数据。
type Reader interface {
	// ReadActual 返回现网实际规则摘要。
	ReadActual(ctx context.Context) ([]RuleDigest, error)
}

// Verifier 是影子比对器。
type Verifier struct {
	reader Reader
	// logf 是日志回调（避免本包依赖具体的 logger）。
	logf func(format string, args ...any)
}

// NewVerifier 创建比对器。
func NewVerifier(reader Reader, logf func(string, ...any)) *Verifier {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Verifier{reader: reader, logf: logf}
}

// Verify 执行一次只读比对。
//
// **本方法不做任何写操作**：只读内核、只计算、只记录。
func (v *Verifier) Verify(ctx context.Context, desired []RuleDigest) (Diff, error) {
	if v.reader == nil {
		return Diff{}, fmt.Errorf("影子比对失败: 未配置内核读取器")
	}
	actual, err := v.reader.ReadActual(ctx)
	if err != nil {
		return Diff{}, fmt.Errorf("读取现网规则失败: %w", err)
	}
	d := Compare(desired, actual)
	v.logf("[shadowverify] %s", d.Summary())
	// 差异逐条打印（截断防刷屏：只看前 20 条）
	const maxPrint = 20
	for i, r := range d.OnlyInDesired {
		if i >= maxPrint {
			v.logf("[shadowverify]   缺失（共 %d 条，只显示前 %d）", len(d.OnlyInDesired), maxPrint)
			break
		}
		v.logf("[shadowverify]   缺失: %s", r)
	}
	for i, r := range d.OnlyInActual {
		if i >= maxPrint {
			v.logf("[shadowverify]   多余（共 %d 条，只显示前 %d）", len(d.OnlyInActual), maxPrint)
			break
		}
		v.logf("[shadowverify]   多余: %s", r)
	}
	return d, nil
}
