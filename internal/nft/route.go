// 策略路由（T005：ip rule / ip route 的 netlink 化，替换 exec "ip"）。
// 设计（ADR-12）：每 snat 规则专属路由表 2xx，default nexthop 按出口层/权重
// 排列；ip rule from <源> lookup <表> pref 1。
package nft

import (
	"fmt"
	"net"

	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RouteTableBase haweb 专属路由表号起点（沿承 iptables 时代段位）。
const RouteTableBase = 201

// RouteTableEnd haweb 专属路由表号终点（含）。
//
// 绝不能取到 253 及以上：253=default、254=main、255=local 都是内核保留表。
// 曾有一版启动对账按 201..300 扫描孤儿表，把系统自带的 `32766: lookup main`
// 判成孤儿并连带删掉 main 的默认路由——整机瞬间失去全部非本机路由
// （192.168.10.170 生产事故）。分配与任何清理逻辑都必须以本常量为界。
const RouteTableEnd = 252

// IsReservedRouteTable 内核保留表号（分配/清理的硬性护栏）。
// 0=unspec、253=default、254=main、255=local，以及 32766/32767 段。
func IsReservedRouteTable(t int) bool {
	switch t {
	case 0, 253, 254, 255:
		return true
	}
	return t >= 32766
}

// RulePref haweb ip rule 的优先级（先于 main 32766；与旧形态一致取 1）。
const RulePref = 1

// Nexthop 路由下一跳（出口网卡 + 网关 + weight）。
type Nexthop struct {
	Iface  string
	Gw     net.IP
	Weight int // 1..（内核存储 Hops=weight-1；PoC 坑 3）
}

// EnsureEgressRoute 安装 per-规则策略路由（幂等：先拆后装）：
//
//	ip route replace default scope global table <tbl> nexthop via A dev x weight 1 ...
//	ip rule add from <each src> lookup <tbl> pref 1
//
// srcs 为空时不装（无源名单的穿越按默认路由走，规则本就无效——上层保证）。
// rtTable 为路由表号（上层 per-规则分配）；主备列（同层多weight）在下层传
// 平铺 Nexthop 列表（层/权重的语义编译在 internal/proxy/fw）。
func (n *Conn) EnsureEgressRoute(rtTable int, srcs []string, nexthops []Nexthop) error {
	if rtTable == 0 {
		return nil
	}
	// 幂等：先清旧
	if err := n.TearEgressRoute(rtTable, srcs); err != nil {
		return err
	}
	if len(nexthops) == 0 {
		return nil
	}
	linkIdx := map[string]int{}
	mp := make([]*vnetlink.NexthopInfo, 0, len(nexthops))
	for _, nh := range nexthops {
		idx, ok := linkIdx[nh.Iface]
		if !ok {
			l, err := vnetlink.LinkByName(nh.Iface)
			if err != nil {
				return fmt.Errorf("出口网卡 %s 不存在: %w", nh.Iface, err)
			}
			idx = l.Attrs().Index
			linkIdx[nh.Iface] = idx
		}
		w := nh.Weight
		if w <= 0 {
			w = 1
		}
		mp = append(mp, &vnetlink.NexthopInfo{
			LinkIndex: idx, Gw: nh.Gw, Hops: w - 1,
		})
	}
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	if err := vnetlink.RouteReplace(&vnetlink.Route{
		Table: rtTable, Dst: defaultNet, MultiPath: mp,
	}); err != nil {
		return fmt.Errorf("路由表 %d 建立（multipath %d 跳）失败: %w", rtTable, len(mp), err)
	}
	for _, src := range srcs {
		var srcNet *net.IPNet
		if ip, ipn, err := net.ParseCIDR(src); err == nil {
			srcNet = &net.IPNet{IP: ip, Mask: ipn.Mask}
		} else if ip := net.ParseIP(src); ip != nil {
			srcNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			return fmt.Errorf("策略路由源 %s 不是合法 IP/CIDR", src)
		}
		// DEFECT-4：DNAT 发布流量豁免——带 DNAT 位的包先回 main 表直连内网后端
		//（否则源在白名单的客户端访问发布地址时，改写后的流量被 from 源 lookup 出口表
		//  拉去外网网卡绕行）。pref 0（先于本规则的 pref 1）；幂等：先删同 pref 再装。
		exempt := vnetlink.NewRule()
		exempt.Family = unix.AF_INET
		exempt.Priority = 0
		exempt.Mark = MarkDNAT
		exempt.Mask = uint32Ptr(MarkDNAT)
		exempt.Table = unix.RT_TABLE_MAIN
		exempt.Src = srcNet
		_ = vnetlink.RuleDel(exempt) // 幂等
		if err := vnetlink.RuleAdd(exempt); err != nil {
			return fmt.Errorf("DNAT 直连豁免路由（from %s mark %#x lookup main）安装失败: %w", src, MarkDNAT, err)
		}
		r := vnetlink.NewRule() // PoC 坑 2：必须 NewRule()，裸字面量零值即 EINVAL
		r.Family = unix.AF_INET
		r.Table, r.Priority = rtTable, RulePref
		r.Src = srcNet
		if err := vnetlink.RuleAdd(r); err != nil {
			return fmt.Errorf("策略路由（from %s lookup %d）安装失败: %w", src, rtTable, err)
		}
	}
	return nil
}

func uint32Ptr(v uint32) *uint32 { return &v }

// TearEgressRoute 拆除 per-规则策略路由。
// 只删"lookup 本表"的规则（表号 per-规则分配，同表只可能属于本规则——
// 沿承 iptables 时代的精确清理纪律，绝不盲删 pref 槽）。
//
// 硬性护栏：表号越界或命中内核保留表时直接拒做。拆除动作会连带删除该表的
// default 路由与 lookup 该表的 ip rule，一旦传入 254(main) 就是整机失联。
func (n *Conn) TearEgressRoute(rtTable int, _ []string) error {
	if rtTable < RouteTableBase || rtTable > RouteTableEnd || IsReservedRouteTable(rtTable) {
		if rtTable != 0 {
			return fmt.Errorf("拒绝拆除路由表 %d：不在 haweb 专属段 %d-%d 内（保护内核保留表 main/local/default）",
				rtTable, RouteTableBase, RouteTableEnd)
		}
		return nil
	}
	rules, err := vnetlink.RuleList(unix.AF_INET)
	if err != nil {
		return fmt.Errorf("读取策略路由列表失败: %w", err)
	}
	for _, r := range rules {
		if r.Table != rtTable {
			continue
		}
		dr := vnetlink.NewRule()
		dr.Family = unix.AF_INET
		dr.Priority, dr.Table, dr.Src = r.Priority, r.Table, r.Src
		_ = vnetlink.RuleDel(dr)
		// DEFECT-4：同步清理该源的 DNAT 直连豁免行（pref 0 mark lookup main）
		if r.Src != nil {
			ex := vnetlink.NewRule()
			ex.Family = unix.AF_INET
			ex.Priority = 0
			ex.Mark = MarkDNAT
			ex.Mask = uint32Ptr(MarkDNAT)
			ex.Table = unix.RT_TABLE_MAIN
			ex.Src = r.Src
			_ = vnetlink.RuleDel(ex)
		}
	}
	// QA P2-01：RouteDel 单靠 Table 匹配不到 default 路由（内核要求
	// Dst/Src/Gw 至少其一）——显式 0.0.0.0/0
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	_ = vnetlink.RouteDel(&vnetlink.Route{Table: rtTable, Dst: defaultNet})
	return nil
}
