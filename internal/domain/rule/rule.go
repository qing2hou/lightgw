// Package rule 提供转发规则的校验与聚合。
//
// 纯函数层：零 IO。不 import os/net/os-exec/netlink/database-sql（C-12）。
package rule

import (
	"fmt"
	"net/netip"
	"sort"

	"haproxyweb/internal/domain/model"
)

// Validate 校验一组规则，并检测监听端点冲突。
//
// 冲突判据：同一 (proto, listen_addr, listen_port) 只能有一条启用的规则。
// 这是内核层面的硬限制——同一 socket 不能绑两次。禁用规则不参与冲突检测。
func Validate(rules []model.Rule) error {
	seen := make(map[model.ListenerKey]uint, len(rules))
	for i := range rules {
		r := rules[i]
		if err := r.Validate(); err != nil {
			return fmt.Errorf("校验规则[%s#%d] 失败: %w", r.Name, r.ID, err)
		}
		if !r.Enabled {
			continue
		}
		k := r.ListenerKey()
		if prevID, dup := seen[k]; dup {
			return fmt.Errorf("校验规则失败: 规则#%d 与规则#%d 都监听 %s/%d（协议 %s），会冲突",
				prevID, r.ID, k.Addr, k.Port, string(k.Proto))
		}
		seen[k] = r.ID
	}
	return nil
}

// Enabled 返回规则集中所有启用的规则。
func Enabled(rules []model.Rule) []model.Rule {
	out := make([]model.Rule, 0, len(rules))
	for _, r := range rules {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

// SortByID 返回按 ID 升序排序的副本。
//
// 排序的必要性：内核规则的下发顺序必须稳定，否则每次 Apply 都会产生
// 无意义的 diff（同样的配置被判定为「变了」）。ID 是稳定键。
func SortByID(rules []model.Rule) []model.Rule {
	out := make([]model.Rule, len(rules))
	copy(out, rules)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// BackendTargets 汇总所有启用规则的后端地址，用于构造默认拒绝的
// `dnat_target` 作用域集合（§3.6）。
//
// 返回去重且按字典序排序的列表——集合内容必须稳定，理由同 SortByID。
func BackendTargets(rules []model.Rule) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(rules))
	for _, r := range rules {
		if !r.Enabled || !r.Backend.IsValid() {
			continue
		}
		seen[r.Backend.Addr()] = struct{}{}
	}
	out := make([]netip.Addr, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Conflict 描述一次监听端点冲突。
type Conflict struct {
	Key     model.ListenerKey
	RuleIDs []uint
}

// Conflicts 返回全部冲突（不止第一个），供 UI 一次性展示。
func Conflicts(rules []model.Rule) []Conflict {
	byKey := make(map[model.ListenerKey][]uint, len(rules))
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		k := r.ListenerKey()
		byKey[k] = append(byKey[k], r.ID)
	}
	var out []Conflict
	for k, ids := range byKey {
		if len(ids) > 1 {
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			out = append(out, Conflict{Key: k, RuleIDs: ids})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key.Addr != out[j].Key.Addr {
			return out[i].Key.Addr.Less(out[j].Key.Addr)
		}
		return out[i].Key.Port < out[j].Key.Port
	})
	return out
}

// ExpandedSources 返回规则命中所需匹配的源网段。
//
// ACLOff 返回 nil（表示「匹配所有源」，编译层据此**不生成**源匹配条件，
// 而不是生成一个空的匹配条件——空条件在 nft 里等价于恒真，但会白白
// 消耗一条规则，且让 `nft list` 的输出难以人工核对）。
func ExpandedSources(r model.Rule) []netip.Prefix {
	if r.ACLMode == model.ACLOff || len(r.ACL) == 0 {
		return nil
	}
	return r.ACL
}
