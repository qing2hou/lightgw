package compile

import (
	"fmt"
	"net/netip"
	"time"

	"haproxyweb/internal/domain/bandwidth"
)

// HTB class ID 约定（与旧实现保持兼容，便于现场对账）。
//
// 类 ID 用 0x10000|minor 表示 "1:minor"，与 `tc` 的 major:minor 记法对应。
const (
	// TcRootMajor 是 qdisc handle 1: 的 major。
	TcRootMajor uint32 = 0x10000
	// TcTotalClass 是带宽包总额父类：1:100。
	TcTotalClass uint32 = TcRootMajor | 100
	// TcFallbackClass 是承接 default 的叶子兜底类：1:199。
	//
	// **这是本轮 PoC 的核心修正**（docs/poc-result.md §3.2）：
	// 原设计让 default 指向 1:100，但 1:100 挂了子类后是内层类，其上无 qdisc，
	// 未命中 filter 的包进不了任何队列 → 内核走 direct queue 绕过整棵树。
	// 实测 2828.79 MB/s（配置 8MB/s）。所以必须有独立的叶子类承接 default。
	TcFallbackClass uint32 = TcRootMajor | 199
	// TcBypassClass 是占位类：1:30，rate=10gbit，不承载流量。
	TcBypassClass uint32 = TcRootMajor | 30

	// TcFallbackMinor 与 TcTotalMinor 是上面对应的 minor 值（写进 default）。
	TcFallbackMinor uint32 = 199
	TcTotalMinor    uint32 = 100
	TcBypassMinor   uint32 = 30

	// TcSourceClassBase 是每源子类的起始 minor：1:201 起。
	//
	// 必须**跳过** 1:30（占位）、1:100（总额父类）、1:199（兜底叶子）：
	// D-01 记录过「清理循环从 1:2 到 1:249 把刚建好的限速类删掉」的事故，
	// 那次导致 default 指向不存在的 class，8MB/s 配置跑出 24MB/s。
	TcSourceClassBase uint32 = 201
	// TcSourceClassMax 是每源子类的最大 minor（留出余量给未来扩展）。
	TcSourceClassMax uint32 = 998
)

// Filter pref 区段（D-17：不许写死 10）。
const (
	// DownloadPrefBase 是下载方向 pref 起点，区段 2..998。
	DownloadPrefBase uint16 = 2
	// UploadPrefBase 是上传方向 pref 起点，区段 1002..1998。
	//
	// 两段必须不相交：单臂网关下（入口==出口同卡）两个方向的 filter 落在
	// 同一个 qdisc 上，pref 重叠会被 `tc filter replace` 互相覆盖，导致某一
	// 方向限速**静默失效**（§3.5.6②）。
	UploadPrefBase uint16 = 1002
	// PrefSpan 是每个区段的跨度。
	PrefSpan uint16 = 997
)

// DownloadPref 按源索引派生下载方向（egress）的 filter pref，区段 2..998。
//
// 下载方向匹配「回程包的目的地址」= 客户端 IP（match ip dst）。
func DownloadPref(idx int) uint16 {
	return DownloadPrefBase + uint16(idx)%PrefSpan
}

// UploadPref 按源索引派生上传方向的 filter pref，区段 1002..1998。
//
// 上传方向匹配「包进入 ifb 后的源地址」= 客户端 IP（match ip src）。
// 与下载区段严格不相交——单臂网关的前提。
func UploadPref(idx int) uint16 {
	return UploadPrefBase + uint16(idx)%PrefSpan
}

// BurstBytes 按速率与令牌深度计算 burst，单位 byte。
//
// 为什么必须随速率缩放（技术方案 §3.5.9 第 6 条）：固定 burst 在千兆下只有
// 10ms 额度的 1/40，表现为「限 1Gbps 实测只跑 200Mbps」。
//
// 公式：bps/8 * quantum/1000，下限 32KB、上限 8MB。
// bps 是 bit/sec，返回值是 byte。
func BurstBytes(bpsPerSec int64, quantum time.Duration) uint32 {
	const (
		lower = 32 << 10
		upper = 8 << 20
	)
	if bpsPerSec <= 0 {
		return lower
	}
	v := uint64(bpsPerSec) / 8 * uint64(quantum/time.Millisecond) / 1000
	if v < lower {
		v = lower
	}
	if v > upper {
		v = upper
	}
	return uint32(v)
}

// KBpsToBytesPerSec 把 KB/s 转成 netlink 需要的 **bytes/sec**。
//
// D-07：`netlink.HtbClass` 的 Rate/Ceil 是 bytes/sec，而 `tc` CLI 的
// kbit/mbit 是 bit/sec。这里是唯一允许做换算的地方——换算错 8 倍是
// 这块的经典 bug，所以集中一处便于审计。
func KBpsToBytesPerSec(kbps int64) uint64 {
	if kbps <= 0 {
		return 0
	}
	return uint64(kbps) * 1024
}

// KBpsToBitsPerSec 把 KB/s 转成 bit/sec（给需要 bit 单位的调用方，如 BurstBytes）。
func KBpsToBitsPerSec(kbps int64) int64 {
	if kbps <= 0 {
		return 0
	}
	return kbps * 1024 * 8
}

// TcSpec 是编译 tc 树的输入。
type TcSpec struct {
	// Group 是带宽包（总额 + 每源保底）。
	Group bandwidth.Plan
	// EgressDevice 是下载方向（出口）网卡名。
	EgressDevice string
	// IngressDevice 是上传方向的入口网卡名（通常是同一张卡，单臂网关）。
	IngressDevice string
	// IfbDevice 是该带宽包专属的 ifb 设备名（ifb-hw<groupID>）。
	//
	// **必须按包隔离**（§3.5.2）：不同包共用同一 ifb 时，父类 rate 会被
	// 后应用的包覆盖，先前包的额度失效。
	IfbDevice string
}

// CompileTc 生成带宽包的 tc 树规格。
//
// 结构（双向，实测通过 docs/poc-result.md §3.3 / §4.1）：
//
//	【下载：出口网卡 egress】
//	qdisc htb 1: default 199                     ← default 指向叶子兜底类
//	class 1:100  parent 1:     rate=ceil=<总额>
//	class 1:199  parent 1:100  rate=<保底> ceil=<总额>   ← 叶子兜底（IsLeaf）
//	class 1:201+ parent 1:100  rate=<保底> ceil=<总额>   ← 每源（IsLeaf）
//	filter parent 1: pref <DownloadPref> u32 match ip dst <源> flowid 1:1NN
//
//	【上传：入口网卡 ingress → ifb】
//	qdisc ingress ffff: (入口网卡)
//	filter parent ffff: pref <UploadPref> u32 match ip src <源> action mirred → ifb
//	qdisc htb 1: default 199 (ifb)               ← 同样指向叶子兜底类
//	... 与下载侧同构 ...
//	filter parent 1: pref <UploadPref> u32 match ip src <源> flowid 1:1NN
//
// 返回空计划表示不限速（总额为 0 或无源）。
func CompileTc(spec TcSpec) (TcPlan, error) {
	var p TcPlan
	if spec.Group.TotalKBps <= 0 || len(spec.Group.Entries) == 0 {
		return p, nil
	}
	if spec.EgressDevice == "" {
		return p, fmt.Errorf("编译限速树失败: 出口网卡名为空")
	}

	totalBytes := KBpsToBytesPerSec(spec.Group.TotalKBps)
	totalBits := KBpsToBitsPerSec(spec.Group.TotalKBps)
	totalBurst := BurstBytes(totalBits, 10*time.Millisecond)

	// 每个方向都要建一棵完整的树
	buildSide := func(device string, upload bool) {
		// 根 qdisc：default 指向叶子兜底类
		p.Qdiscs = append(p.Qdiscs, TcQdiscSpec{
			Device:  device,
			Parent:  "root",
			Handle:  "1:",
			Kind:    "htb",
			Default: TcFallbackMinor,
		})
		// 总额父类（内层类，不挂 fq_codel）
		p.Classes = append(p.Classes, TcClassSpec{
			ClassID:     TcTotalClass,
			RateBytes:   totalBytes,
			CeilBytes:   totalBytes,
			BurstBytes:  totalBurst,
			CburstBytes: totalBurst,
			IsLeaf:      false, // 内层：有子类，不能挂 fq_codel（否则 EINVAL）
		})
		// 叶子兜底类：承接 default，必须挂 fq_codel
		fallbackBytes := KBpsToBytesPerSec(spec.Group.MinKBps)
		if fallbackBytes == 0 {
			fallbackBytes = totalBytes
		}
		p.Classes = append(p.Classes, TcClassSpec{
			ClassID:       TcFallbackClass,
			ParentClassID: TcTotalClass,
			RateBytes:     fallbackBytes,
			CeilBytes:     totalBytes,
			BurstBytes:    BurstBytes(int64(fallbackBytes)*8, 10*time.Millisecond),
			CburstBytes:   totalBurst,
			IsLeaf:        true, // 叶子：挂 fq_codel
		})
		// 每源子类（叶子）
		for i, e := range spec.Group.Entries {
			minor := TcSourceClassBase + uint32(i)
			if minor > TcSourceClassMax {
				// 超出区段：不再建类，并记录降级（不能静默丢弃）
				continue
			}
			classID := TcRootMajor | minor
			rateBytes := KBpsToBytesPerSec(e.GuaranteedKBps)
			if rateBytes == 0 {
				rateBytes = totalBytes
			}
			p.Classes = append(p.Classes, TcClassSpec{
				ClassID:       classID,
				ParentClassID: TcTotalClass,
				RateBytes:     rateBytes,
				CeilBytes:     totalBytes,
				BurstBytes:    BurstBytes(int64(rateBytes)*8, 10*time.Millisecond),
				CburstBytes:   totalBurst,
				IsLeaf:        true,
			})
			pref := DownloadPref(i)
			if upload {
				pref = UploadPref(i)
			}
			p.Filters = append(p.Filters, TcFilterSpec{
				Device:   device,
				Parent:   "1:",
				Pref:     pref,
				MatchSrc: upload, // ★ C-17：上传 src / 下载 dst，严禁照抄
				Match:    prefixOf(e.Source),
				FlowID:   fmt.Sprintf("1:%d", minor),
			})
		}
	}

	// 下载方向：出口网卡 egress
	buildSide(spec.EgressDevice, false)

	// 上传方向：入口网卡 ingress 重定向 + ifb 上整形
	if spec.IfbDevice != "" {
		ingress := spec.IngressDevice
		if ingress == "" {
			ingress = spec.EgressDevice
		}
		p.Qdiscs = append(p.Qdiscs, TcQdiscSpec{
			Device: ingress,
			Parent: "root",
			Handle: "ffff:",
			Kind:   "ingress",
		})
		// ingress 上的重定向 filter（每个源一条）
		for i, e := range spec.Group.Entries {
			p.Filters = append(p.Filters, TcFilterSpec{
				Device:   ingress,
				Parent:   "ffff:",
				Pref:     UploadPref(i),
				MatchSrc: true,
				Match:    prefixOf(e.Source),
				FlowID:   "", // 重定向用 action mirred，无 flowid
				MirredTo: spec.IfbDevice,
			})
		}
		buildSide(spec.IfbDevice, true)
	}

	return p, nil
}

// prefixOf 把源字符串（可能是单 IP 或 CIDR）转成 netip.Prefix。
//
// 单 IP 转 /32（或 /128）——这一步必须做，否则 adapter 无法区分
// 「单个地址」与「网段」，而两者的 u32 掩码不同（0xffffffff vs 0xffffff00）。
// 历史 bug：网段用精确掩码只匹配网络地址一个 IP，网段内成员流量全部漏到
// default class 不限速。
//
// 解析失败时返回零值 Prefix（IsValid()==false），由 Validate 拦住。
func prefixOf(s string) netip.Prefix {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen())
	}
	return netip.Prefix{}
}
