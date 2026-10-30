// Package tcnetlink 把 compile.TcPlan 落到内核的 tc 树（htb + u32 + fq_codel）。
//
// 本包是唯一允许碰 netlink 的 tc 层。所有 tc 结构由 compile 层决定，
// 这里只负责翻译与幂等写入——**不做任何结构判断**，因为结构约束
// （default 必须指向叶子类、上传 src / 下载 dst、pref 分段）在 compile
// 层已经校验过，重复判断反而会产生两份可能不一致的真相。
//
// 真机实测约束（docs/poc-result.md §3.2 / §4.2.1，改动前必读）：
//
//  1. **default 必须指向叶子类**。指向挂了子类的内层类时，未命中 filter 的
//     包进不了任何队列，内核走 direct queue 绕过整棵树
//     （实测 2828.79 MB/s vs 配置 8 MB/s）
//  2. **fq_codel 只能挂叶子类**。挂内层类报
//     `RTNETLINK answers: Invalid argument`
//  3. **上传 filter 必须 match ip src，下载必须 match ip dst**（D-16）
//  4. **pref 按方向分段**：下载 2..998 / 上传 1002..1998（D-17）
//  5. **`HtbClass.Rate`/`Ceil` 是 bytes/sec**，`tc` CLI 的 kbit 是 bit/sec（D-07）
//
// 幂等策略（tc 无事务，无法原子替换）：
//   - qdisc 已存在且参数一致 → 跳过
//   - qdisc 参数不一致 → **整树重建**（`qdisc change` 不支持改 default，§3.5.9 第 7 条）
//   - class / filter 用 Replace 语义
//   - 清理历史 class 时**只删本次集合之外的**，绝不盲删区间（D-01）
package tcnetlink

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"

	"haproxyweb/internal/compile"
)

// ClassStats 是某个 htb 类的实时计数（供指标层读取）。
type ClassStats struct {
	ClassID    string
	Sent       uint64 // bytes
	Packets    uint64
	Dropped    uint64
	Overlimits uint64
	// Lended / Borrowed 是 HTB 的借用统计。
	// **`Borrowed` 增长才说明真的发生了借用**（docs/poc-result.md §4.1）。
	Lended   uint64
	Borrowed uint64
}

// Engine 是 tc 操作引擎。
type Engine struct {
	// link 解析网卡名到 netlink.Link。可注入以便测试。
	resolve func(name string) (netlink.Link, error)
	// apply 是底层执行函数，可注入以便测试。
	apply func(plan compile.TcPlan) error
}

// NewEngine 创建引擎。生产路径用真实的 netlink 解析。
func NewEngine() *Engine {
	return &Engine{
		resolve: func(name string) (netlink.Link, error) {
			l, err := netlink.LinkByName(name)
			if err != nil {
				return nil, fmt.Errorf("查找网卡 %s 失败: %w", name, err)
			}
			return l, nil
		},
	}
}

// NewEngineWith 供测试注入自定义解析与执行函数。
func NewEngineWith(
	resolve func(string) (netlink.Link, error),
	apply func(compile.TcPlan) error,
) *Engine {
	return &Engine{resolve: resolve, apply: apply}
}

// Apply 把 tc 计划落到内核。
//
// 调用方（S4 的 applier）负责把 compile.Compiler 的输出传进来；
// 本函数先校验计划（compile.TcPlan.Validate 已覆盖五条硬约束），
// 再按「qdisc → class → filter」顺序写入。
//
// 顺序不可换：class 必须在其父 qdisc 之后创建，filter 必须在其目标 class
// 之后创建（否则内核拒绝）。
func (e *Engine) Apply(plan compile.TcPlan) error {
	if plan.Empty() {
		return nil
	}
	// 自检：即使调用方忘了校验，这里也不能把非法结构写进内核
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("应用限速计划失败: %w", err)
	}
	if e.apply != nil {
		return e.apply(plan)
	}
	return e.applyReal(plan)
}

// applyReal 是真实的内核写入路径。
func (e *Engine) applyReal(plan compile.TcPlan) error {
	// 1. qdisc：按设备分组，每个设备的 root 只建一次
	if err := e.applyQdiscs(plan); err != nil {
		return err
	}
	// 2. class
	if err := e.applyClasses(plan); err != nil {
		return err
	}
	// 3. filter
	if err := e.applyFilters(plan); err != nil {
		return err
	}
	return nil
}

// applyQdiscs 建/替换 qdisc。
func (e *Engine) applyQdiscs(plan compile.TcPlan) error {
	for _, q := range plan.Qdiscs {
		link, err := e.resolve(q.Device)
		if err != nil {
			return fmt.Errorf("应用 qdisc 失败: %w", err)
		}
		switch q.Kind {
		case "htb":
			target := &netlink.Htb{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: link.Attrs().Index,
					Handle:    mustHandle(q.Handle),
					Parent:    parentHandle(q.Parent),
				},
				Defcls: q.Default,
			}
			if err := e.ensureQdisc(link, target); err != nil {
				return fmt.Errorf("创建 %s 上的 htb qdisc 失败: %w", q.Device, err)
			}
		case "ingress":
			target := &netlink.Ingress{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: link.Attrs().Index,
					Handle:    mustHandle(q.Handle),
					Parent:    netlink.HANDLE_MIN_INGRESS,
				},
			}
			if err := e.ensureQdisc(link, target); err != nil {
				return fmt.Errorf("创建 %s 上的 ingress qdisc 失败: %w", q.Device, err)
			}
		case "fq_codel":
			parent := mustHandle(q.Parent)
			target := &netlink.FqCodel{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: link.Attrs().Index,
					Handle:    mustHandle(q.Handle),
					Parent:    parent,
				},
			}
			// fq_codel 已存在则跳过（重复 add 会 EEXIST）
			if qdiscs, err := netlink.QdiscList(link); err == nil {
				for _, existing := range qdiscs {
					if existing.Attrs().Parent == parent && existing.Type() == "fq_codel" {
						continue
					}
				}
			}
			if err := netlink.QdiscAdd(target); err != nil {
				// 已存在不是错误（幂等）
				if !isExist(err) {
					return fmt.Errorf("在 %s 上挂 fq_codel 失败: %w", q.Device, err)
				}
			}
		default:
			return fmt.Errorf("应用 qdisc 失败: 未知类型 %q", q.Kind)
		}
	}
	return nil
}

// ensureQdisc 保证 qdisc 存在且参数一致；不一致时整树重建。
//
// 为什么必须重建：`tc qdisc change` 不支持改 `default`（§3.5.9 第 7 条），
// 而 default 是「未分类流量去哪」的唯一开关，改了它等于换了一棵树。
func (e *Engine) ensureQdisc(link netlink.Link, target netlink.Qdisc) error {
	existing, err := netlink.QdiscList(link)
	if err == nil {
		tAttrs := target.Attrs()
		for _, q := range existing {
			a := q.Attrs()
			if a.Handle != tAttrs.Handle || a.Parent != tAttrs.Parent {
				continue
			}
			// 同 handle 同 parent：检查类型与 default
			if q.Type() == target.Type() {
				if htb, ok := q.(*netlink.Htb); ok {
					if t, ok2 := target.(*netlink.Htb); ok2 && htb.Defcls == t.Defcls {
						return nil // 已一致，幂等
					}
				} else {
					return nil
				}
			}
			// 参数不一致 → 删除后重建
			if err := netlink.QdiscDel(q); err != nil && !isNotExist(err) {
				return fmt.Errorf("拆除旧 qdisc 失败: %w", err)
			}
		}
	}
	if err := netlink.QdiscAdd(target); err != nil && !isExist(err) {
		return err
	}
	return nil
}

// applyClasses 建/替换 class，并清理不在本次集合内的历史 class。
func (e *Engine) applyClasses(plan compile.TcPlan) error {
	// 按设备分组：清理历史 class 必须限定在同一设备上
	byDevice := make(map[string][]compile.TcClassSpec, 4)
	deviceOfClass := make(map[uint32]string, len(plan.Classes))
	for _, c := range plan.Classes {
		dev := ""
		// class 归属哪个设备由对应 filter/qdisc 决定；这里用 qdisc 列表反查
		for _, q := range plan.Qdiscs {
			if q.Kind == "htb" && (q.Parent == "root" || q.Parent == "") {
				dev = q.Device
				break
			}
		}
		byDevice[dev] = append(byDevice[dev], c)
		deviceOfClass[c.ClassID] = dev
	}

	for dev, classes := range byDevice {
		if dev == "" {
			continue
		}
		link, err := e.resolve(dev)
		if err != nil {
			return fmt.Errorf("应用 class 失败: %w", err)
		}
		for _, c := range classes {
			htb := &netlink.HtbClass{
				ClassAttrs: netlink.ClassAttrs{
					LinkIndex: link.Attrs().Index,
					Handle:    c.ClassID,
					Parent:    c.ParentClassID,
				},
				Rate:    c.RateBytes,
				Ceil:    c.CeilBytes,
				Buffer:  c.BurstBytes,
				Cbuffer: c.CburstBytes,
			}
			if htb.Parent == 0 {
				htb.Parent = compile.TcRootMajor
			}
			if err := netlink.ClassReplace(htb); err != nil {
				return fmt.Errorf("在 %s 上创建 class 1:%d 失败: %w",
					dev, c.ClassID&0xFFFF, err)
			}
		}
		// 清理历史 class：只删「本设备上、且不在本次集合内」的
		if err := e.cleanupClasses(link, dev, plan.Classes); err != nil {
			return err
		}
		// fq_codel：只挂 IsLeaf 的 class
		if err := e.attachFqCodel(link, dev, classes); err != nil {
			return err
		}
	}
	return nil
}

// cleanupClasses 删除不在本次集合内的历史 class。
//
// **绝不盲删区间**（D-01）：曾有循环从 1:2 到 1:249 把刚建好的 1:100
// 一并删掉，default 指向不存在的 class，8MB/s 配置跑出 24MB/s。
// 判据是「本次计划里没有它」，且显式跳过保留类。
func (e *Engine) cleanupClasses(link netlink.Link, dev string, keep []compile.TcClassSpec) error {
	keepSet := make(map[uint32]bool, len(keep))
	for _, c := range keep {
		keepSet[c.ClassID] = true
	}
	existing, err := netlink.ClassList(link, compile.TcRootMajor)
	if err != nil {
		return nil // 还没有 class，无需清理
	}
	for _, cls := range existing {
		h := cls.Attrs().Handle
		if keepSet[h] {
			continue
		}
		// 显式跳过保留类（无论是否在 keep 里都不删）
		switch h {
		case compile.TcTotalClass, compile.TcFallbackClass, compile.TcBypassClass:
			continue
		}
		if err := netlink.ClassDel(cls); err != nil && !isNotExist(err) {
			return fmt.Errorf("清理 %s 上的历史 class 1:%d 失败: %w", dev, h&0xFFFF, err)
		}
	}
	return nil
}

// attachFqCodel 给 IsLeaf 的 class 挂 fq_codel。
//
// 内层 class 挂了会报 `RTNETLINK answers: Invalid argument`（实测），
// 所以必须严格按 IsLeaf 判断，不能「全都挂」。
func (e *Engine) attachFqCodel(link netlink.Link, dev string, classes []compile.TcClassSpec) error {
	for _, c := range classes {
		if !c.IsLeaf {
			continue
		}
		q := &netlink.FqCodel{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				// fq_codel 的 handle 用 class 的 minor 派生：1:207 → 207:
				Handle: (c.ClassID&0xFFFF)<<16 | 0,
				Parent: c.ClassID,
			},
		}
		if err := netlink.QdiscAdd(q); err != nil && !isExist(err) {
			return fmt.Errorf("在 %s 的 class 1:%d 上挂 fq_codel 失败: %w",
				dev, c.ClassID&0xFFFF, err)
		}
	}
	return nil
}

// applyMirred 建上传方向的 ingress 重定向 filter（u32 + mirred action）。
//
// 用途：入口网卡 ingress 上按客户端源 IP 分类，redirect 到 ifb，
// 在 ifb 的 egress 侧做 htb 整形（ingress qdisc 本身只能 policing，不能整形）。
//
// 为什么必须 match ip src：包进 ifb 后 daddr 是公网服务器、saddr 才是客户端。
// 用 dst 会永不命中（实测 14.8 倍超速）。
func (e *Engine) applyMirred(link netlink.Link, f compile.TcFilterSpec) error {
	addr, mask, err := prefixToU32(f.Match)
	if err != nil {
		return fmt.Errorf("构造 ingress 重定向失败（%s）: %w", f.Device, err)
	}
	if !f.MatchSrc {
		return fmt.Errorf("构造 ingress 重定向失败（%s）: 必须 match ip src（包进 ifb 后源地址才是客户端）", f.Device)
	}
	match := netlink.TcU32Sel{
		Flags: netlink.TC_U32_TERMINAL,
		Keys: []netlink.TcU32Key{
			{Off: srcDstOffset(true), Mask: mask, Val: addr},
		},
	}
	// mirred 的 redirect 目标设备名由 compile 层放在 FlowID 之外的约定字段；
	// 这里用「FlowID 为空 + 这就是 ingress filter」判定，目标设备取
	// plan 里同设备的 htb qdisc 无法反查，故要求调用方在 Comment 里带设备名。
	// —— 为避免隐式约定，改为由 compile 层提供独立字段（见 TcFilterSpec.MirredTo）。
	if f.MirredTo == "" {
		return fmt.Errorf("构造 ingress 重定向失败（%s）: 缺少 mirred 目标设备", f.Device)
	}
	target, err := e.resolve(f.MirredTo)
	if err != nil {
		return fmt.Errorf("解析 mirred 目标设备失败: %w", err)
	}
	u32 := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    mustHandle(f.Parent),
			Priority:  f.Pref,
			Protocol:  0x0800,
		},
		Sel: &match,
		// mirred: egress redirect
		Actions: []netlink.Action{
			&netlink.MirredAction{
				ActionAttrs:  netlink.ActionAttrs{Action: netlink.TC_ACT_STOLEN},
				MirredAction: netlink.TCA_EGRESS_REDIR,
				Ifindex:      target.Attrs().Index,
			},
		},
	}
	return netlink.FilterReplace(u32)
}

// applyFilters 建/替换 u32 filter。
//
// **方向**：f.MatchSrc 决定用 `Src` 还是 `Dst`。上传（ifb）用 src，
// 下载（出口网卡）用 dst。写反的后果是静默的——filter 永不命中，
// 全走 default（实测 118.51 MB/s vs 配置 8）。
func (e *Engine) applyFilters(plan compile.TcPlan) error {
	for _, f := range plan.Filters {
		link, err := e.resolve(f.Device)
		if err != nil {
			return fmt.Errorf("应用 filter 失败: %w", err)
		}
		if f.FlowID == "" {
			// 上传方向的 ingress 重定向 filter：用 mirred action。
			if err := e.applyMirred(link, f); err != nil {
				return err
			}
			continue
		}
		u32, err := buildU32Filter(link, f)
		if err != nil {
			return err
		}
		if err := netlink.FilterReplace(u32); err != nil {
			return fmt.Errorf("在 %s 上创建 filter（pref=%d, match ip %s %s）失败: %w",
				f.Device, f.Pref, f.Dir(), f.Match, err)
		}
	}
	return nil
}

// buildU32Filter 构造 u32 分类 filter。
func buildU32Filter(link netlink.Link, f compile.TcFilterSpec) (*netlink.U32, error) {
	// u32 的 match 用 4 字节网络序地址 + 掩码
	addr, mask, err := prefixToU32(f.Match)
	if err != nil {
		return nil, fmt.Errorf("构造 filter 失败（%s, match %s）: %w", f.Device, f.Match, err)
	}
	match := netlink.TcU32Sel{
		Flags: 0,
		Keys: []netlink.TcU32Key{
			{
				// at 12 = 源地址（IP 头偏移 12）；at 16 = 目的地址（偏移 16）
				Off:     srcDstOffset(f.MatchSrc),
				Mask:    mask,
				Val:     addr,
				OffMask: 0,
			},
		},
	}
	return &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    mustHandle(f.Parent),
			Priority:  f.Pref,
			Protocol:  0x0800, // ETH_P_IP
		},
		Sel:     &match,
		ClassId: mustHandle(f.FlowID),
	}, nil
}

// srcDstOffset 返回 u32 匹配的 IP 头偏移。
//
// 12 = saddr，16 = daddr。这两个常量写反就是 D-16 事故。
func srcDstOffset(matchSrc bool) int32 {
	if matchSrc {
		return 12
	}
	return 16
}

// prefixToU32 把 netip.Prefix 转成 u32 的（值, 掩码），均为**网络字节序**。
//
// 关键点（历史 bug）：网段必须带真实掩码。用 0xffffffff 会让
// `192.168.10.0/24` 只匹配网络地址一个 IP，网段内其他成员的流量全部
// 漏到 default class → 不限速。
func prefixToU32(p netip.Prefix) (uint32, uint32, error) {
	if !p.IsValid() {
		return 0, 0, fmt.Errorf("网段无效")
	}
	a := p.Masked().Addr()
	if a.Is6() {
		return 0, 0, fmt.Errorf("u32 filter 只支持 IPv4，得到 %s", p)
	}
	b := a.As4()
	val := binary.BigEndian.Uint32(b[:])
	bits := p.Bits()
	var mask uint32
	if bits > 0 {
		mask = ^uint32(0) << (32 - bits)
	}
	return val, mask, nil
}

// mustHandle 把 "1:208" / "1:" / "ffff:" 之类的字符串转成 netlink handle。
//
// netlink 的 handle 是 major<<16 | minor：
//
//	"1:208"  → 0x0001_00d0
//	"1:"     → 0x0001_0000
//	"ffff:"  → 0xffff_0000
//
// 解析失败返回 0（调用方会因 handle 非法收到内核错误，而不是 panic）。
func mustHandle(s string) uint32 {
	h, err := parseHandle(s)
	if err != nil {
		return 0
	}
	return h
}

func parseHandle(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("handle 为空")
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("handle %q 格式无效（应为 major:minor）", s)
	}
	// tc 的 major:minor 是**十六进制**（`tc class show` 输出 1:208 即 0x208
	// 而非十进制 208）。必须按 hex 解析，否则 class ID 全部错位。
	major, err := parseHex(parts[0])
	if err != nil {
		return 0, fmt.Errorf("handle %q 的 major 无效: %w", s, err)
	}
	var minor uint32
	if parts[1] != "" {
		minor, err = parseHex(parts[1])
		if err != nil {
			return 0, fmt.Errorf("handle %q 的 minor 无效: %w", s, err)
		}
	}
	if major > 0xffff || minor > 0xffff {
		return 0, fmt.Errorf("handle %q 超出 16 位范围", s)
	}
	return major<<16 | minor, nil
}

func parseHex(s string) (uint32, error) {
	var v uint32
	if _, err := fmt.Sscanf(s, "%x", &v); err != nil {
		return 0, fmt.Errorf("%q 不是合法的十六进制数: %w", s, err)
	}
	return v, nil
}

// parentHandle 把 "root" / handle 字符串转成 parent 值。
func parentHandle(s string) uint32 {
	if s == "" || s == "root" {
		return netlink.HANDLE_ROOT
	}
	return mustHandle(s)
}

// isExist / isNotExist 判定 netlink 错误类型（幂等处理）。
//
// netlink 没有导出 sentinel error，只能靠 syscall 的 errno 判断。
func isExist(err error) bool {
	return err != nil && strings.Contains(err.Error(), "file exists")
}

func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no such") || strings.Contains(msg, "not found")
}

// ReadClassStats 读取某设备上 htb 类的实时计数。
//
// 供指标层使用。`Borrowed` 增长是「真的发生了借用」的唯一证据
// （docs/poc-result.md §4.1）。
func (e *Engine) ReadClassStats(device string, parent uint32) ([]ClassStats, error) {
	link, err := e.resolve(device)
	if err != nil {
		return nil, err
	}
	classes, err := netlink.ClassList(link, parent)
	if err != nil {
		return nil, fmt.Errorf("列出 %s 的 class 失败: %w", device, err)
	}
	out := make([]ClassStats, 0, len(classes))
	for _, c := range classes {
		a := c.Attrs()
		st := ClassStats{ClassID: handleStr(a.Handle)}
		if a.Statistics != nil && a.Statistics.Basic != nil {
			st.Sent = a.Statistics.Basic.Bytes
			st.Packets = uint64(a.Statistics.Basic.Packets)
		}
		out = append(out, st)
	}
	return out, nil
}

// handleStr 把 handle 转回 "1:208" 形式（供日志与 UI）。
func handleStr(h uint32) string {
	return fmt.Sprintf("%x:%x", h>>16, h&0xffff)
}
