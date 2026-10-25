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

// Comment 构造标记。
func Comment(kind string, id uint) string {
	if kind == KindAnchor {
		return "haweb-nft:anchor"
	}
	return "haweb-nft:" + kind + ":" + strconv.FormatUint(uint64(id), 10)
}

// ParseComment 解析标记（kind, id, ok）。
func ParseComment(ud string) (string, uint, bool) {
	parts := strings.Split(ud, ":")
	if len(parts) != 3 || parts[0] != "haweb-nft" {
		return "", 0, false
	}
	id, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return "", 0, false
	}
	return parts[1], uint(id), true
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
	target := Comment(kind, id)
	removed := 0
	for _, chain := range []string{ChainPreMark, ChainDstNAT, ChainFwd, ChainSrcNAT} {
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
			return fmt.Errorf("对账读取链 %s 失败（且暂存删除提交失败）: %w / %v", chain, err, flushErr)
		}
		return fmt.Errorf("对账读取链 %s 失败: %w", chain, err)
	}
	if removed == 0 {
		return nil // 幂等：无残留即成功
	}
	return n.Flush()
}

// InstalledIDs 列出自有表内已安装的 (kind, id) 集合（启动对账数据源）。
func (n *Conn) InstalledIDs() (map[string]map[uint]bool, error) {
	out := map[string]map[uint]bool{}
	for _, chain := range []string{ChainPreMark, ChainDstNAT, ChainFwd, ChainSrcNAT} {
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

// CountersByComment 按标记读规则内嵌 counter（计数轮询数据源）。
// 返回 map[标记]counter；不含 counter 的规则跳过。
func (n *Conn) CountersByComment() (map[string]CounterSnapshot, error) {
	out := map[string]CounterSnapshot{}
	for _, chain := range []string{ChainPreMark, ChainDstNAT, ChainFwd, ChainSrcNAT} {
		rules, err := n.rulesOf(chain)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			for _, e := range r.Exprs {
				if ctr, ok := e.(*expr.Counter); ok {
					out[string(r.UserData)] = CounterSnapshot{Bytes: ctr.Bytes, Packets: ctr.Packets}
					break
				}
			}
		}
	}
	return out, nil
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
// 写入 nf_tables 的 nat 表 POSTROUTING / filter 表 FORWARD）按标记读出并删除。
// 零 exec（升级目标机可能已无 iptables 二进制；iptables-nft 宿主上旧规则
// 就在 nf_tables 里，netlink 可直达）。幂等：无标记规则返回 0。
// 返回删除条数与错误。
func (n *Conn) PurgeLegacyIPTables() (int, error) {
	removed := 0
	// 旧形态所在：nat 表 POSTROUTING（ip 家族）+ filter 表 FORWARD（ip 家族）
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
			if !strings.Contains(string(r.UserData), legacyComment) {
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

// KindDefaultDeny 全局默认拒绝尾行（fw.CompileDefaultDeny；多规则共享，
// 拆装由 Manager 统一管理——ruleID 维度取启用规则的最小 ID，随集变化重装）。
const KindDefaultDeny = "deny"
