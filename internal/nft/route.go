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

// RouteTableBase haweb 专属路由表号起点（沿承 iptables 时代段位 201-300）。
const RouteTableBase = 201

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
		r := vnetlink.NewRule() // PoC 坑 2：必须 NewRule()，裸字面量零值即 EINVAL
		r.Family = unix.AF_INET
		r.Table, r.Priority = rtTable, RulePref
		if ip, ipn, err := net.ParseCIDR(src); err == nil {
			r.Src = &net.IPNet{IP: ip, Mask: ipn.Mask}
		} else if ip := net.ParseIP(src); ip != nil {
			r.Src = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
		} else {
			return fmt.Errorf("策略路由源 %s 不是合法 IP/CIDR", src)
		}
		if err := vnetlink.RuleAdd(r); err != nil {
			return fmt.Errorf("策略路由（from %s lookup %d）安装失败: %w", src, rtTable, err)
		}
	}
	return nil
}

// TearEgressRoute 拆除 per-规则策略路由。
// 只删"lookup 本表"的规则（表号 per-规则分配，同表只可能属于本规则——
// 沿承 iptables 时代的精确清理纪律，绝不盲删 pref 槽）。
func (n *Conn) TearEgressRoute(rtTable int, _ []string) error {
	if rtTable == 0 {
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
	}
	_ = vnetlink.RouteDel(&vnetlink.Route{Table: rtTable})
	return nil
}
