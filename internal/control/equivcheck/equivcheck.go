// Package equivcheck 是 B-1 的实战工具：从生产库读规则、用新编译器编译、
// 与现网 nft 规则比对，**全程只读**。
//
// 目的：在生产机上安全回答「新编译器与旧实现产出的规则集是否等价」。
// 等价才敢进 B-2（让新链路接管 nft/tc）；不等价先查清原因。
//
// 安全边界（这是本包存在的全部理由）：
//   - 只读 DB（gorm 的 Read 操作）
//   - 只读内核（`nft list table`）
//   - **不调用任何写接口**：不 apply、不 commit、不 drop
//   - 不 import adapter 的写路径（只 import shadowverify 的只读端口）
package equivcheck

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"haproxyweb/internal/control/shadowverify"
	"haproxyweb/internal/model"
)

// LegacyReader 从现网 nft 表读规则（只读）。
//
// 用 `nft -a list table` 而不是 netlink：CLI 输出是文本，便于归一化后比对；
// 且本包只需要读，不涉及原子性。
type LegacyReader struct {
	// Table 是现网表名（生产上是 haweb）。
	Table string
	// run 可注入以便测试（默认 exec nft）。
	run func(args ...string) (string, error)
}

// NewLegacyReader 创建读器。
func NewLegacyReader(table string) *LegacyReader {
	return &LegacyReader{
		Table: table,
		run: func(args ...string) (string, error) {
			out, err := exec.Command(args[0], args[1:]...).Output()
			return string(out), err
		},
	}
}

// NewLegacyReaderWithRunner 供测试注入命令执行器。
func NewLegacyReaderWithRunner(table string, run func(...string) (string, error)) *LegacyReader {
	return &LegacyReader{Table: table, run: run}
}

// ruleLineRe 匹配 nft 输出里的规则行（以两个 tab 缩进、非 chain/type 开头）。
//
// nft list 的形态：
//
//	table inet haweb {
//		chain fwd {
//			type filter hook forward priority filter - 10; policy accept;
//			iifname "eth0" oifname "eth0" ... counter packets 0 bytes 0 drop
//		}
//	}
//
// 规则行 = 以「iifname / oifname / ip / tcp / udp / ct / meta / counter」等
// 匹配表达式开头的行。
var ruleStartRe = regexp.MustCompile(`^\s+(iifname|oifname|ip |tcp |udp |ct |meta |counter|icmp|udplite)`)

// chainRe 匹配 chain 声明行。
var chainRe = regexp.MustCompile(`^\s*chain\s+(\S+)\s*\{`)

// ReadActual 实现 shadowverify.Reader。
func (r *LegacyReader) ReadActual(ctx context.Context) ([]shadowverify.RuleDigest, error) {
	if r.Table == "" {
		return nil, fmt.Errorf("读取现网规则失败: 表名为空")
	}
	if r.run == nil {
		return nil, fmt.Errorf("读取现网规则失败: 未配置命令执行器")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("读取现网规则被取消: %w", err)
	}
	out, err := r.run("nft", "-a", "list", "table", "inet", r.Table)
	if err != nil {
		return nil, fmt.Errorf("执行 nft list 失败: %w", err)
	}
	return ParseNftListing(out), nil
}

// ParseNftListing 解析 `nft list table` 的文本输出。
//
// 只提取「链名 + 规则体」，归一化交给 shadowverify.Normalize。
// 跳过：chain 声明行、type ... hook ... 行、花括号行、空行。
func ParseNftListing(out string) []shadowverify.RuleDigest {
	var res []shadowverify.RuleDigest
	var curChain string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		// chain 声明：`chain fwd { # handle 9` —— 行尾是 handle 注解而非 `{`，
		// 所以必须用正则匹配而不是 HasSuffix("{").
		if m := chainRe.FindStringSubmatch(line); m != nil {
			curChain = m[1]
			continue
		}
		if trimmed == "" || trimmed == "}" {
			continue
		}
		// 跳过链类型声明（type filter hook ...）
		if strings.HasPrefix(trimmed, "type ") {
			continue
		}
		// 跳过表声明与链名（已由 chainRe 处理）
		if strings.HasPrefix(trimmed, "table ") || strings.HasPrefix(trimmed, "chain ") {
			continue
		}
		if curChain == "" {
			continue
		}
		// 去掉行尾的 `# handle N`
		body := trimmed
		if i := strings.LastIndex(body, " # handle "); i >= 0 {
			body = body[:i]
		}
		// 必须是匹配表达式开头的行
		if !ruleStartRe.MatchString(" " + body) {
			continue
		}
		norm := shadowverify.Normalize(body)
		// 动作与匹配的切分：这里不细分，整行作为 Match，Action 留空。
		//
		// 为什么这样切：nft 的规则体是「匹配 动作」混排（drop 前面可能还有
		// counter），可靠切分需要完整解析表达式语法。B-1 的目的是
		// 「规则集是否等价」，整行比对已经能回答这个问题，且不会因为
		// 切分错误产生假差异。
		res = append(res, shadowverify.RuleDigest{
			Chain:  curChain,
			Match:  norm,
			Action: "",
		})
	}
	return res
}

// RuleConverter 把 DB 的 ForwardRule 转成 compile.State。
//
// 只做「格式转换」，不做业务判断——业务判断在 compile 层。
type RuleConverter struct{}

// BuildState 从 DB 读出规则并构造 compile.State。
//
// **只读**：全部是 gorm 的 Find/Raw 读操作。
func BuildState(db *gorm.DB) (Rules, error) {
	var out Rules
	if db == nil {
		return out, fmt.Errorf("从库构造状态失败: 数据库为空")
	}
	var rules []model.ForwardRule
	if err := db.Find(&rules).Error; err != nil {
		return out, fmt.Errorf("读取转发规则失败: %w", err)
	}
	out.ForwardRules = rules

	var groups []model.AclGroup
	if err := db.Find(&groups).Error; err != nil {
		// 名单组表可能不存在（旧库）——不阻塞，记为空
		out.Warnings = append(out.Warnings, fmt.Sprintf("读取名单组失败（按空处理）: %v", err))
	}
	out.AclGroups = groups

	var bws []model.BWGroup
	if err := db.Find(&bws).Error; err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("读取带宽包失败（按空处理）: %v", err))
	}
	out.BWGroups = bws

	var eg []model.Egress
	if err := db.Find(&eg).Error; err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("读取出口失败（按空处理）: %v", err))
	}
	out.Egresses = eg

	var pols []model.FwPolicy
	if err := db.Find(&pols).Error; err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("读取策略失败（按空处理）: %v", err))
	}
	out.Policies = pols

	return out, nil
}

// Rules 是从 DB 读出的原始实体集合（尚未转成 compile 类型）。
//
// 保留原始实体而不是直接转 State：转换需要字段级取舍（比如 protocol
// 字符串到枚举），那部分后续单独实现并单测。
type Rules struct {
	ForwardRules []model.ForwardRule
	AclGroups    []model.AclGroup
	BWGroups     []model.BWGroup
	Egresses     []model.Egress
	Policies     []model.FwPolicy
	// Warnings 是读取过程中的非致命问题（某张表读不到 → 按空处理）。
	Warnings []string
}

// Summary 返回一行摘要（供日志）。
func (r Rules) Summary() string {
	return fmt.Sprintf("规则 %d 条 / 名单组 %d 个 / 带宽包 %d 个 / 出口 %d 个 / 策略 %d 条",
		len(r.ForwardRules), len(r.AclGroups), len(r.BWGroups), len(r.Egresses), len(r.Policies))
}

// ExpectationDigest 把 DB 规则转成「期望的规则摘要」用于比对。
//
// 这一步刻意做得**保守**：只产出能确定映射的项（源白名单 → saddr 匹配、
// SNAT → snat 动作），不确定的跳过并记录原因。宁可少报差异，
// 也不要因为映射不完整产生一堆假差异。
func ExpectationDigest(r Rules) ([]shadowverify.RuleDigest, []string) {
	var out []shadowverify.RuleDigest
	var notes []string
	for _, fr := range r.ForwardRules {
		if !fr.Enabled {
			continue
		}
		switch strings.ToLower(fr.Protocol) {
		case "snat":
			// SNAT 规则：每个白名单源一条 snat 行（daddr=源 的计数行另算）
			//
			// ★ 源的来源有两条路径（AGENTS.md 记录过的坑）：
			//   1. 规则直配的 allow_list
			//   2. 引用名单组 acl_group_id → 组内的 entries
			// 只读路径 1 会漏掉「通过名单组授权」的源——本次实战就踩了这个：
			// 规则#30 的 allow_list 为空、acl_group_id=1，组里有 2 个源，
			// 于是期望算成 0 条而现网有 2 条 SNAT，误报「不等价」。
			srcs := splitList(fr.AllowList)
			if fr.AclGroupID != 0 {
				groupSources, ok := groupEntries(r.AclGroups, fr.AclGroupID)
				if !ok {
					notes = append(notes, fmt.Sprintf(
						"snat 规则#%d 引用名单组#%d 但组不存在或已禁用，跳过比对", fr.ID, fr.AclGroupID))
					continue
				}
				srcs = append(srcs, groupSources...)
				notes = append(notes, fmt.Sprintf(
					"snat 规则#%d 展开名单组#%d 得 %d 个源", fr.ID, fr.AclGroupID, len(groupSources)))
			}
			if len(srcs) == 0 {
				notes = append(notes, fmt.Sprintf("snat 规则#%d 无白名单源，跳过比对", fr.ID))
				continue
			}
			target := fr.SnatIP
			for _, src := range srcs {
				out = append(out, shadowverify.RuleDigest{
					Chain:  "srcnat",
					Match:  shadowverify.Normalize("@nh,96,32 " + cidrToHex(src)),
					Action: "snat ip to " + target,
				})
			}
		case "tcp", "udp":
			notes = append(notes, fmt.Sprintf("转发规则#%d（%s）走用户态转发，不在 nft 比对面", fr.ID, fr.Protocol))
		default:
			notes = append(notes, fmt.Sprintf("规则#%d 协议 %q 未纳入比对", fr.ID, fr.Protocol))
		}
	}
	return out, notes
}

// splitList 解析 JSON 数组字符串（AutoMigrate 里存的是 JSON）。
//
// AGENTS.md 记录过：这些字段在库里是 JSON 字符串，必须先解析再 .map()。
func splitList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "[]" || s == "null" {
		return nil
	}
	// 去掉方括号与引号，按逗号切——足够处理 ["a","b"] 形态
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	var out []string
	for _, part := range strings.Split(s, ",") {
		p := strings.Trim(strings.TrimSpace(part), `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cidrToHex 把 "192.168.10.152" 或 "192.168.10.0/24" 转成 nft 的 @nh,96,32 十六进制。
//
// 只处理 IPv4（现网全是 IPv4）。
func cidrToHex(s string) string {
	host := s
	if i := strings.Index(s, "/"); i >= 0 {
		host = s[:i]
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return s // 无法解析时原样返回（会产生差异，人工核对）
	}
	var b [4]uint64
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return s
		}
		b[i] = v
	}
	return fmt.Sprintf("0x%02x%02x%02x%02x", b[0], b[1], b[2], b[3])
}

// groupEntries 从名单组里取出网段列表。
//
// 返回 (entries, ok)：ok=false 表示组不存在或已禁用——调用方应跳过比对
// 而不是当作「没有源」（后者会让期望为空、误报一堆「多余」）。
func groupEntries(groups []model.AclGroup, id uint) ([]string, bool) {
	for _, g := range groups {
		if g.ID != id {
			continue
		}
		// 名单组没有启停概念（model.AclGroup 无 Enabled 字段），
		// 存在即视为可用。字段是 entries（JSON 字符串数组），不是 cidrs。
		return splitList(g.Entries), true
	}
	return nil, false
}
