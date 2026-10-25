// Package nft 提供 nftables 内核面的 netlink 引擎层：表/链/规则/set 的
// 生命周期、宿主探测、标记对账。全部经 google/nftables 直连内核，
// 零 exec、零 iptables 依赖（设计见 docs/design-fwgateway.md，PoC 见 docs/poc-nftables.md）。
//
// 分层纪律：本包只做 I/O 与内核形态操作；规则语义编译（什么规则序列
// 表达一条转发规则/防火墙策略）在 internal/proxy/fw（纯函数、离线可测）。
package nft

import (
	"fmt"

	"github.com/google/nftables"
)

// Conn netlink 连接包装：持久 netlink 连接（AsLasting——连接级复用，
// 避免 5s 计数轮询每轮拨号）+ 统一错误中文语义。单次 Flush 原子由
// 库内锁保证；purge-then-add 跨 Flush 序列的互斥由上层 nftApplyMu 承担。
type Conn struct {
	c *nftables.Conn
}

// Dial 打开 netlink 连接（进程内复用单连接）。
func Dial() (*Conn, error) {
	inner, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("打开 nftables netlink 连接失败（需要 CAP_NET_ADMIN）: %w", err)
	}
	return &Conn{c: inner}, nil
}

// CloseLasting 关闭持久连接（进程退出路径）。
func (n *Conn) CloseLasting() error { return n.c.CloseLasting() }

// Flush 冲刷暂存区（见 PoC 坑 10：失败实测无残留，但上层仍按
// "失败即拆段重装"防御，不依赖该行为）。
func (n *Conn) Flush() error {
	if err := n.c.Flush(); err != nil {
		return fmt.Errorf("nftables 规则下发失败: %w", err)
	}
	return nil
}

// inner 暴露原始连接（同包内编排水层的表/链/规则操作用）。
func (n *Conn) inner() *nftables.Conn { return n.c }

// 表与链名（内核内名字空间，自有表隔离一切变更——设计支柱 1）。
const (
	// Table 自有表名：全部 haweb 规则的唯一容器。
	Table = "haweb"
	// ChainPreMark 预标记链（prerouting -150）：established 短路/发布命中打标。
	ChainPreMark = "pre_mark"
	// ChainDstNAT 目的改写链（prerouting -100）：端口发布 DNAT。
	ChainDstNAT = "dstnat"
	// ChainFwd 转发裁决链（forward -10）：ACL 有序策略 + 范围内默认拒绝。
	ChainFwd = "fwd"
	// ChainSrcNAT 源改写链（postrouting +100）：SNAT（固定/池）。
	ChainSrcNAT = "srcnat"
	// ChainInput 本机入向链（input +0；dnat timeout 模式的静默丢弃行）。
	ChainInput = "input"
)

// EnsureTable 确保自有表与四条基础链在位（幂等：缺失补建，在位不动）。
// 返回错误时内核面可能零变更（补建表失败）或部分变更（链补建部分成功——
// 调用方按"失败即 EnsureTable 重试"处理，幂等保证收敛）。
func (n *Conn) EnsureTable() error {
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: Table}
	n.c.AddTable(tbl)

	// hook/priority 常量是指针（PoC 坑 6），取值后取址。
	baseChains := []struct {
		name string
		typ  nftables.ChainType
		hook nftables.ChainHook
		prio nftables.ChainPriority
	}{
		{ChainPreMark, nftables.ChainTypeFilter, *nftables.ChainHookPrerouting, *nftables.ChainPriorityMangle},
		{ChainDstNAT, nftables.ChainTypeNAT, *nftables.ChainHookPrerouting, *nftables.ChainPriorityNATDest},
		{ChainFwd, nftables.ChainTypeFilter, *nftables.ChainHookForward, *nftables.ChainPriorityRef(-10)},
		{ChainSrcNAT, nftables.ChainTypeNAT, *nftables.ChainHookPostrouting, *nftables.ChainPriorityNATSource},
		{ChainInput, nftables.ChainTypeFilter, *nftables.ChainHookInput, *nftables.ChainPriorityFilter},
	}
	for _, bc := range baseChains {
		hook, prio := bc.hook, bc.prio
		n.c.AddChain(&nftables.Chain{
			Name: bc.name, Table: tbl, Type: bc.typ,
			Hooknum: &hook, Priority: &prio,
		})
	}
	return n.Flush()
}

// AddCompiled 暂存一条已编译规则（链名→链对象解析；装载语义：链尾追加，
// 即数组序 = 最终链上序，先装先评估——与旧 iptables 头插语义相反，
// 语义差异已在 upgrade 文档记录）。
func (n *Conn) AddCompiled(chain string, r *nftables.Rule) {
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: Table}
	r.Table = tbl
	r.Chain = &nftables.Chain{Name: chain, Table: tbl}
	n.c.AddRule(r)
}

// FlushCommit 提交暂存（Flush 别名——语义化：装规则后的显式提交点）。
func (n *Conn) FlushCommit() error { return n.Flush() }

// DropTable 删除自有表（legacy 冲突弃用路径；幂等）。
func (n *Conn) DropTable() error {
	n.c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: Table})
	return n.Flush()
}
