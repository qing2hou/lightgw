// nft set 生命周期：源名单/发布地址等集合的构建与增删。
package nft

import (
	"fmt"
	"net"

	"github.com/google/nftables"
)

// EnsureIPSet 确保指定名的 IP set 存在（幂等：重建语义——先删后建带全量元素，
// 名单变更即整体替换，规避 incremental diff 的复杂度；调用方在标记对账后调用）。
// 元素支持单 IP 与 CIDR 网段（interval set）。
func (n *Conn) EnsureIPSet(name string, entries []string) error {
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: Table}
	elems := make([]nftables.SetElement, 0, len(entries)*2)
	for _, e := range entries {
		ip, ipn, err := net.ParseCIDR(e)
		if err == nil {
			// 网段：[start, end] 成对的 interval 元素
			start := ipn.IP.To4()
			if start == nil {
				return fmt.Errorf("set 元素 %s 非 IPv4（IPv6 支持在 M3/T210）", e)
			}
			end := lastIP(ipn)
			elems = append(elems,
				nftables.SetElement{Key: start},
				nftables.SetElement{Key: end, IntervalEnd: true},
			)
			continue
		}
		ip = net.ParseIP(e)
		if v4 := ip.To4(); v4 != nil {
			elems = append(elems, nftables.SetElement{Key: v4})
			continue
		}
		return fmt.Errorf("set 元素 %s 不是合法 IP/CIDR", e)
	}

	// 同名 set 先删（幂等重建）
	if old, err := n.c.GetSetByName(tbl, name); err == nil {
		n.c.DelSet(old)
		_ = n.Flush()
	}
	set := &nftables.Set{
		Table: tbl, Name: name,
		KeyType:  nftables.TypeIPAddr,
		Interval: true,
	}
	if err := n.c.AddSet(set, elems); err != nil {
		return fmt.Errorf("构建 set %s 失败: %w", name, err)
	}
	return n.Flush()
}

// lastIP 网段最后一个地址（interval 元素用）。
func lastIP(ipn *net.IPNet) net.IP {
	ip := ipn.IP.To4()
	mask := ipn.Mask
	if len(mask) != 4 || ip == nil {
		return nil
	}
	out := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}
