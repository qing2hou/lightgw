// nft 规则标记（comment 即 Rule.UserData）与按标记的精确装卸/对账。
// 纪律沿承 iptables 时代（ADR-4）：全部自有规则带 haweb-nft:<kind>:<id>
// 标记，删除按标记精确匹配，绝不 flush 整链/整表。
package nft

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// 规则标记 kind 枚举（标记格式 haweb-nft:<kind>:<id>）。
const (
	KindSNAT   = "snat"   // SNAT 主行/池扇出行
	KindDNAT   = "dnat"   // DNAT 发布行
	KindPolicy = "pol"    // 防火墙策略行
	KindAnchor = "anchor" // 宿主 filter 表内的放行锚点行（kind 例外：无 id）
	KindMark   = "mark"   // pre_mark 链内打标行
	KindEgress = "eg"     // 出口 SNAT 行（多出口跟随）
)

// Comment 构造标记（无实例 ID 的旧格式）。
//
// ** deprecated **：新代码用 CommentFor(instance, kind, id)。
// 保留它是为了测试与「旧版本装的规则」的解析兼容。
func Comment(kind string, id uint) string {
	if kind == KindAnchor {
		return "haweb-nft:anchor"
	}
	return "haweb-nft:" + kind + ":" + strconv.FormatUint(uint64(id), 10)
}

// CommentFor 构造带实例 ID 的标记：haweb-nft:<instance>:<kind>:<id>
//
// 为什么必须带实例 ID（事故 2026-10-30）：
// 旧标记 `haweb-nft:<kind>:<id>` 无法区分「谁装的」。启动对账用
// 「内核有但我的库里没有 = 孤儿」判定，在「第二个进程用不同数据目录碰
// 同一张表」时会把别人的规则全拆掉。带上实例 ID 之后，对账可以先按
// 实例过滤，从根本上消除这类误拆。
//
// instance 为空时退化为旧格式（保持兼容；但此时对账不做拆除，见
// proxy.purgeOrphanNFTRules 的安全分支）。
func CommentFor(instance, kind string, id uint) string {
	if kind == KindAnchor {
		if instance == "" {
			return "haweb-nft:anchor"
		}
		return "haweb-nft:" + instance + ":anchor"
	}
	base := "haweb-nft:"
	if instance != "" {
		base += instance + ":"
	}
	return base + kind + ":" + strconv.FormatUint(uint64(id), 10)
}

// ParsedComment 是解析后的标记。
type ParsedComment struct {
	// Instance 是实例 ID；旧格式（无实例段）时为空串。
	Instance string
	Kind     string
	ID       uint
	// Legacy 为 true 表示这是旧格式标记（无实例 ID）。
	//
	// **对账必须把 Legacy 视为「非本实例」**——升级后第一次启动不会自动
	// 清理升级前的孤儿，这是有意的安全取舍：清不掉只占空间，清错了会断网。
	Legacy bool
}

// ParseComment 解析标记（kind, id, ok）——旧接口，保留兼容。
func ParseComment(ud string) (string, uint, bool) {
	pc, ok := ParseCommentFull(ud)
	if !ok {
		return "", 0, false
	}
	return pc.Kind, pc.ID, true
}

// ParseCommentFull 解析标记，同时给出实例归属。
//
// 接受两种格式：
//
//	haweb-nft:<instance>:<kind>:<id>   新格式（instance 为 16 位十六进制）
//	haweb-nft:<kind>:<id>             旧格式（Legacy=true）
//	haweb-nft:anchor / haweb-nft:<instance>:anchor   锚点行
func ParseCommentFull(ud string) (ParsedComment, bool) {
	parts := strings.Split(ud, ":")
	if len(parts) < 2 || parts[0] != "haweb-nft" {
		return ParsedComment{}, false
	}
	switch len(parts) {
	case 2:
		// haweb-nft:anchor
		if parts[1] != KindAnchor {
			return ParsedComment{}, false
		}
		return ParsedComment{Kind: KindAnchor, Legacy: true}, true
	case 3:
		// 可能：haweb-nft:<kind>:<id>（旧） 或 haweb-nft:<instance>:anchor（新锚点）
		if parts[2] == KindAnchor && isInstanceSegment(parts[1]) {
			return ParsedComment{Instance: parts[1], Kind: KindAnchor}, true
		}
		id, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return ParsedComment{}, false
		}
		return ParsedComment{Kind: parts[1], ID: uint(id), Legacy: true}, true
	case 4:
		// haweb-nft:<instance>:<kind>:<id>
		if !isInstanceSegment(parts[1]) {
			return ParsedComment{}, false
		}
		id, err := strconv.ParseUint(parts[3], 10, 32)
		if err != nil {
			return ParsedComment{}, false
		}
		return ParsedComment{Instance: parts[1], Kind: parts[2], ID: uint(id)}, true
	}
	return ParsedComment{}, false
}

// isInstanceSegment 判断某段是否为实例 ID（16 位小写十六进制）。
//
// 严格校验的意义：区分 `haweb-nft:<kind>:<id>`（旧）与
// `haweb-nft:<instance>:anchor`（新）两种 3 段格式。
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

// rulesOf 单链全部规则（链上无规则返回空切片）。
func (n *Conn) rulesOf(chain string) ([]*nftables.Rule, error) {
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: Table}
	chains, err := n.c.ListChains()
	if err != nil {
		return nil, fmt.Errorf("枚举 %s 表链失败: %w", Table, err)
	}
	for _, c := range chains {
		if c.Table == nil || c.Table.Name != Table || c.Name != chain {
			continue
		}
		return n.c.GetRules(tbl, c)
	}
	return nil, nil
}

// PurgeByComment 按标记盲拆：遍历自有表全部链，UserData 命中标记的
// 规则按 Handle 精确删除（半装/漏拆兜底；幂等）。
func (n *Conn) PurgeByComment(kind string, id uint) error {
	removed, err := n.purgeByCommentTarget(Comment(kind, id))
	if err != nil {
		return err
	}
	if removed == 0 {
		return nil // 幂等：无残留即成功
	}
	return n.Flush()
}

// PurgeByCommentNoFlush 暂存式拆除（返回暂存删除数，不提交——调用方在同
// batch 追加新增后一次 FlushCommit，消掉拆装间隙窗口，复审 N6）。
func (n *Conn) PurgeByCommentNoFlush(kind string, id uint) (int, error) {
	return n.purgeByCommentTarget(Comment(kind, id))
}

// purgeByCommentTarget 按标记遍历四链暂存删除，返回暂存删除数
// （错误路径：先提交已暂存部分再返回错误）。
func (n *Conn) purgeByCommentTarget(target string) (int, error) {
	removed := 0
	for _, chain := range []string{ChainPreMark, ChainDstNAT, ChainFwd, ChainSrcNAT, ChainInput} {
		rules, err := n.rulesOf(chain)
		if err == nil {
			for _, r := range rules {
				if string(r.UserData) == target {
					if err := n.c.DelRule(r); err == nil {
						removed++
					}
				}
			}
			continue
		}
		// 中途失败：已暂存的删除先提交（删除幂等且 comment 域内，发出去无害），
		// 绝不留在共享缓冲里被下次无关 Flush 顺带发出（评审 M7）
		if flushErr := n.Flush(); flushErr != nil {
			return removed, fmt.Errorf("对账读取链 %s 失败（且暂存删除提交失败）: %w / %v", chain, err, flushErr)
		}
		return removed, fmt.Errorf("对账读取链 %s 失败: %w", chain, err)
	}
	return removed, nil
}

// InstalledIDs 列出自有表内已安装的 (kind, id) 集合（启动对账数据源）。
func (n *Conn) InstalledIDs() (map[string]map[uint]bool, error) {
	out := map[string]map[uint]bool{}
	for _, chain := range []string{ChainPreMark, ChainDstNAT, ChainFwd, ChainSrcNAT, ChainInput} {
		rules, err := n.rulesOf(chain)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			kind, id, ok := ParseComment(string(r.UserData))
			if !ok {
				continue
			}
			if out[kind] == nil {
				out[kind] = map[uint]bool{}
			}
			out[kind][id] = true
		}
	}
	return out, nil
}

// InstalledIDsByInstance 列出**指定实例**已安装的 (kind, id) 集合。
//
// 与 InstalledIDs 的区别（事故修复的核心）：
//   - InstalledIDs 返回所有带 haweb-nft 标记的规则（含别人的实例、含旧格式）
//   - 本函数**只返回 instance 匹配的**，旧格式一律排除（Legacy=true 跳过）
//
// 旧格式被排除是有意的安全取舍：升级后第一次启动不会自动清理升级前的
// 孤儿。清不掉只占几 KB 规则空间，清错了会断网。
func (n *Conn) InstalledIDsByInstance(instance string) (map[string]map[uint]bool, error) {
	out := map[string]map[uint]bool{}
	if instance == "" {
		return out, nil
	}
	for _, chain := range []string{ChainPreMark, ChainDstNAT, ChainFwd, ChainSrcNAT, ChainInput} {
		rules, err := n.rulesOf(chain)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			pc, ok := ParseCommentFull(string(r.UserData))
			if !ok || pc.Legacy || pc.Instance != instance {
				continue
			}
			if pc.Kind == KindAnchor {
				continue
			}
			if out[pc.Kind] == nil {
				out[pc.Kind] = map[uint]bool{}
			}
			out[pc.Kind][pc.ID] = true
		}
	}
	return out, nil
}

// PurgeByCommentFor 按（实例, kind, id）精确拆除。
//
// 与 PurgeByComment 的区别：本函数**只删 instance 匹配的**，
// 绝不碰到别的实例或旧格式的规则。
func (n *Conn) PurgeByCommentFor(instance, kind string, id uint) error {
	if instance == "" {
		return fmt.Errorf("按实例拆除失败: 实例 ID 为空")
	}
	_, err := n.purgeByCommentTarget(CommentFor(instance, kind, id))
	return err
}

// CounterPair 双桶计数（复审 N1：同标记多行——放行桶与拒绝桶分开求和，
// 不再 last-writer-wins）。
type CounterPair struct {
	Accept CounterSnapshot // 放行语义行（fwd 放行、srcnat 改写）
	Drop   CounterSnapshot // 拒绝语义行（含 VerdictDrop 的行）
}

// hasDropVerdict 规则表达式序列尾部是否 VerdictDrop。
func hasDropVerdictRule(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
			return true
		}
	}
	return false
}

// CountersByComment 按标记读规则内嵌 counter，双桶求和（复审 N1/N2/三轮）：
// 同标记的放行行（fwd ③④，每源/每目标行）求和进 Accept、拒绝行（② 黑名单
// DROP）求和进 Drop。单一计数点语义（fwd hook）——评审三轮定案：**不采纳**
// fwd/srcnat 分桶 max 口径，因为 nftables NAT 链只对每连接首包求值（srcnat
// 行加 counter 也只计连接数），fwd 桶天然 ≥ srcnat 桶且语义正确（与旧 tc
// 单点口径一致）。srcnat 行因此不加 counter（compile.go ⑤）。
type CountersByCommentResult struct {
	ByRule   map[string]CounterPair // haweb-nft:<kind>:<id> → 双桶
	DenyDeny CounterSnapshot        // 全局默认拒绝尾行（deny:0）合计（多网卡同标记求和）
}

func (n *Conn) CountersByComment() (*CountersByCommentResult, error) {
	out := &CountersByCommentResult{
		ByRule: map[string]CounterPair{},
	}
	for _, chain := range []string{ChainPreMark, ChainDstNAT, ChainFwd, ChainSrcNAT, ChainInput} {
		rules, err := n.rulesOf(chain)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			var ctr *expr.Counter
			for _, e := range r.Exprs {
				if c, ok := e.(*expr.Counter); ok {
					ctr = c
					break
				}
			}
			if ctr == nil {
				continue
			}
			ud := string(r.UserData)
			snap := CounterSnapshot{Bytes: ctr.Bytes, Packets: ctr.Packets}
			pair := out.ByRule[ud]
			if hasDropVerdictRule(r) {
				pair.Drop.add(snap)
			} else {
				pair.Accept.add(snap)
			}
			out.ByRule[ud] = pair
		}
	}
	// 全局默认拒绝（deny:0 标记——多网卡多行同标记求和）
	out.DenyDeny = out.ByRule[Comment(KindDefaultDeny, 0)].Drop
	return out, nil
}

func (c *CounterSnapshot) add(o CounterSnapshot) {
	c.Bytes += o.Bytes
	c.Packets += o.Packets
}

// CounterSnapshot counter 读数快照（脱离 expr 包类型的稳定视图）。
type CounterSnapshot struct {
	Bytes   uint64
	Packets uint64
}

// ---------- T006：旧 iptables 形态（haweb-sn: 标记）启动迁移 ----------

// legacyComment 旧 iptables 时代的 comment 标记前缀（snat v1 形态）。
const legacyComment = "haweb-sn:"

// PurgeLegacyIPTables 把旧 iptables 形态标记的规则（经 iptables-nft 后端
// 写入 nf_tables 的 nat 表 POSTROUTING / filter 表 FORWARD）读出并删除。
// 零 exec（升级目标机可能已无 iptables 二进制；iptables-nft 宿主上旧规则
// 就在 nf_tables 里，netlink 可直达）。幂等：无标记规则返回 0。
//
// 匹配口径（QA P1-01 修正）：iptables-nft 的 -m comment 把评论文本存在
// **xt 表达式 blob**（NFTA_MATCH_INFO，256 字节定长 xt.Comment）而非
// NFTA_RULE_USERDATA——两者都要匹配：
//   - 原生 nft 规则的 comment → UserData（"\x00<len>text\x00" TLV）
//   - iptables-nft 的 -m comment → 表达式级 Match{Name:"comment"}
//
// 返回删除条数与错误。
func (n *Conn) PurgeLegacyIPTables() (int, error) {
	removed := 0
	type target struct {
		fam   nftables.TableFamily
		table string
		chain string
	}
	for _, tg := range []target{
		{nftables.TableFamilyIPv4, "nat", "POSTROUTING"},
		{nftables.TableFamilyIPv4, "filter", "FORWARD"},
	} {
		tbl := &nftables.Table{Family: tg.fam, Name: tg.table}
		chains, err := n.c.ListChainsOfTableFamily(tg.fam)
		if err != nil {
			continue // 家族/表不存在（全新部署）——无旧形态
		}
		var fwd *nftables.Chain
		for _, ch := range chains {
			if ch.Table != nil && ch.Table.Name == tg.table && ch.Name == tg.chain {
				fwd = ch
				break
			}
		}
		if fwd == nil {
			continue
		}
		rules, err := n.c.GetRules(tbl, fwd)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if !ruleHasLegacyMark(string(r.UserData), r.Exprs) {
				continue
			}
			if err := n.c.DelRule(r); err != nil {
				// S4：删除失败留痕（虚报"迁移完成"比残留更坏）
				fmt.Printf("[nft] 旧 iptables 形态规则删除失败（handle=%d）: %v\n", r.Handle, err)
				continue
			}
			removed++
		}
	}
	if removed > 0 {
		if err := n.Flush(); err != nil {
			return removed, fmt.Errorf("旧 iptables 形态删除提交失败: %w", err)
		}
	}
	return removed, nil
}

// ruleHasLegacyMark 旧标记判定：UserData 含 haweb-sn:（原生 nft comment TLV）
// 或表达式级 comment match 明文含 haweb-sn:（iptables-nft -m comment）。
func ruleHasLegacyMark(userData string, exprs []expr.Any) bool {
	if strings.Contains(userData, legacyComment) {
		return true
	}
	for _, e := range exprs {
		m, ok := e.(*expr.Match)
		if !ok || m.Name != "comment" {
			continue
		}
		if cm, ok := m.Info.(*xt.Comment); ok && strings.Contains(string(*cm), legacyComment) {
			return true
		}
	}
	return false
}

// KindDefaultDeny 全局默认拒绝尾行（fw.CompileDefaultDeny；多规则共享，
// 拆装由 Manager 统一管理——ruleID 维度取启用规则的最小 ID，随集变化重装）。
const KindDefaultDeny = "deny"

// RulesOfForDebug/DelRuleForDebug 排查用钩子（cmd/vd；生产面禁用）。
func (n *Conn) RulesOfForDebug(chain string) ([]*nftables.Rule, error) { return n.rulesOf(chain) }
func (n *Conn) DelRuleForDebug(r *nftables.Rule) error                 { return n.c.DelRule(r) }

// KindDnatDrop dnat timeout 模式的静默丢弃行（input 链；健康卸载时随装随拆）。
const KindDnatDrop = "dnatdrop"
