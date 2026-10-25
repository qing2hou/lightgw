// 宿主防火墙形态探测与共存（设计支柱 2 / ADR-11 / T007 矩阵的数据源）。
// 探测零 exec：nftables 状态看 netlink，iptables-legacy 看_PROC 接口。
package nft

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/nftables"
)

// HostProfile 宿主防火墙形态（共存策略的判据）。
type HostProfile struct {
	// LegacyIPv4Tables: /proc/net/ip_tables_names 非空（iptables-legacy v4 在用）。
	// legacy 与 nftables 两套 hook 并行评估、ACCEPT 不互认——policy DROP 时
	// 我们经 nftables 的放行压不住 legacy 链尾 DROP，必须 fail-fast（PRD AC-1.2 边界）。
	LegacyIPTables bool
	// ForwardPolicyDrop: 宿主 filter FORWARD 挂 policy DROP（docker 常态）。
	// 此时必须在宿主 FORWARD 链头装放行锚点（标记命中 → accept）。
	ForwardPolicyDrop bool
	// 有 filter 表（ip/ip6/inet 家族，iptables-nft 或 firewalld 建）。
	HasFilterTable bool
}

// DetectHost 探测宿主形态。
// 无法确证 policy 状态时保守假设 ForwardPolicyDrop=true（安全侧：多装锚点无害，
// 漏装是黑洞）。iptables-legacy 只是存在性检测（policy 读取需 root netlink，
// 保守按存在即拒）。
func (n *Conn) DetectHost() (HostProfile, error) {
	p := HostProfile{}
	// iptables-legacy 探测：/proc/net/ip_tables_names（legacy 内核模块的注册表）。
	if b, err := os.ReadFile("/proc/net/ip_tables_names"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(ln) == "filter" {
				p.LegacyIPTables = true
				break
			}
		}
	}

	// nftables filter 表探测（ip/ip6/inet 三个家族都查——iptables-nft 默认建 ip+ip6）。
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6, nftables.TableFamilyINet} {
		tables, err := n.c.ListTablesOfFamily(fam)
		if err != nil {
			continue // 家族不存在（如系统无 v6）不算错
		}
		for _, t := range tables {
			if t.Name == "filter" {
				p.HasFilterTable = true
			}
		}
	}

	// FORWARD policy 精确判定：枚举 ip/inet 家族 filter 表的 FORWARD 基础链。
	// 有 DROP policy 链 → ForwardPolicyDrop=true。读不到链（无表）时保守 true？
	// 不——无 filter 表说明宿主零防火墙（vanilla），policy 缺省 accept，
	// 且我们自有 fwd 链在 -10 先执行、范围内默认拒绝已覆盖，锚点无必要。
	if p.HasFilterTable {
		drop, err := n.forwardPolicyDrop()
		if err != nil {
			// 读得到表读不到链：保守装锚点（无害）
			p.ForwardPolicyDrop = true
		} else {
			p.ForwardPolicyDrop = drop
		}
	}
	return p, nil
}

// forwardPolicyDrop 检查宿主 filter 表 FORWARD 基础链是否 policy DROP。
func (n *Conn) forwardPolicyDrop() (bool, error) {
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6, nftables.TableFamilyINet} {
		chains, err := n.c.ListChainsOfTableFamily(fam)
		if err != nil {
			continue
		}
		for _, ch := range chains {
			if ch.Table == nil || ch.Table.Name != "filter" || ch.Name != "FORWARD" {
				continue
			}
			if ch.Policy != nil && *ch.Policy == nftables.ChainPolicyDrop {
				return true, nil
			}
		}
	}
	return false, nil
}

// anchorComment 宿主锚点规则标记（filter 表 FORWARD 头部；见标记规则例外）。
const anchorUD = "haweb-nft:anchor"

// EnsureAnchor 在宿主 filter FORWARD policy DROP 时于链头装放行锚点：
//
//	meta mark & 0x1 == 0x1 → accept
//
// 幂等：已有同标记锚点则跳过。每家族（ip/ip6——宿主策略链所在家族）一条。
func (n *Conn) EnsureAnchor(profile HostProfile) error {
	if !profile.ForwardPolicyDrop {
		return nil
	}
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		tbl := &nftables.Table{Family: fam, Name: "filter"}
		fwd, ok, err := n.hostForwardChain(fam)
		if err != nil || !ok {
			continue // 该家族无 filter FORWARD（如纯 v4 宿主的 ip6）
		}
		if n.anchorPresent(fam, fwd) {
			continue
		}
		n.c.InsertRule(&nftables.Rule{
			Table: tbl, Chain: fwd, UserData: []byte(anchorUD),
			Exprs: anchorExprs(),
		})
	}
	return n.Flush()
}

// RemoveAnchors 拆除全部宿主锚点（停用/退出路径；按标记精确删）。
func (n *Conn) RemoveAnchors() error {
	removed := false
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6, nftables.TableFamilyINet} {
		tbl := &nftables.Table{Family: fam, Name: "filter"}
		fwd, ok, err := n.hostForwardChain(fam)
		if err != nil || !ok {
			continue
		}
		rules, err := n.c.GetRules(tbl, fwd)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if string(r.UserData) == anchorUD {
				if err := n.c.DelRule(r); err == nil {
					removed = true
				}
			}
		}
	}
	if !removed {
		return nil
	}
	return n.Flush()
}

// hostForwardChain 找宿主某家族 filter 表的 FORWARD 链。
func (n *Conn) hostForwardChain(fam nftables.TableFamily) (*nftables.Chain, bool, error) {
	chains, err := n.c.ListChainsOfTableFamily(fam)
	if err != nil {
		return nil, false, err
	}
	for _, ch := range chains {
		if ch.Table != nil && ch.Table.Name == "filter" && ch.Name == "FORWARD" {
			return ch, true, nil
		}
	}
	return nil, false, nil
}

// anchorPresent 锚点是否已在（幂等判据）。
func (n *Conn) anchorPresent(fam nftables.TableFamily, fwd *nftables.Chain) bool {
	tbl := &nftables.Table{Family: fam, Name: "filter"}
	rules, err := n.c.GetRules(tbl, fwd)
	if err != nil {
		return false
	}
	for _, r := range rules {
		if string(r.UserData) == anchorUD {
			return true
		}
	}
	return false
}

// LegacyConflictError iptables-legacy 宿主冲突（fail-fast，PRD 边界）。
type LegacyConflictError struct{ Profile HostProfile }

func (e *LegacyConflictError) Error() string {
	return fmt.Sprintf("检测到 iptables-legacy filter 表与 FORWARD 策略链并存：" +
		"legacy 与 nftables 防火墙在内核并行评估、放行不互认，" +
		"继续运行将产生黑洞。请先迁移宿主到 nftables 后端" +
		"（iptables-nft）或清除 legacy FORWARD policy DROP 后重启本服务")
}
