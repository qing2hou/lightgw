// Package fw 防火墙语义编译层：把 snat/dnat/策略实体编译为 nftables 规则
// 结构（internal/nft 的输入）。纯函数、零 I/O——全部单测离线可跑
// （分层纪律见 internal/nft/conn.go 文件头）。
package fw

import (
	"net"
)

// Spec 一条 snat 规则的内核面全部参数（由 ForwardRule 展开——展开逻辑
// 沿承旧 buildSnatSpec；本层只编译不再展开）。
type Spec struct {
	ID        uint
	IfIn      string   // 入口网卡
	IfOut     string   // 出口网卡
	OutIP     string   // SNAT 源（v4）
	AllowSrcs []string // 源白名单（IP/CIDR；空=名单缺失——上游黑洞化处理）
	DstMode   string   // 目标名单模式 off/whitelist/blacklist
	DstAllow  []string
	DstDeny   []string
	EgGw      string   // 出口网关（M3 多出口预留；v1 由 Manager 侧装策略路由，本层不编译）
	Pool      []string // SNAT 源池（T207：rotate/sticky 按源确定性映射；空=fixed）
}

// PayloadOffsets IPv4 头内偏移（payload 表达式的物理事实，独立常量防魔法数）。
const (
	offSaddr = 12 // IPv4 saddr
	offDaddr = 16 // IPv4 daddr
	offDport = 2  // TCP/UDP dport（传输层头内）
	offSport = 0  // TCP/UDP sport
)

func v4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// SnatPool 一条 snat 规则的源池（T207：rotate/sticky 模式下每源映射成员）。
// 空 = fixed 单 IP 形态（OutIP）。
type SnatPool struct {
	Mode string   // fixed / rotate / sticky（v1 两者同为源确定性映射——语义修订记任务表）
	IPs  []string // 池成员（≤32）
}
