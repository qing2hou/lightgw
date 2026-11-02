// 会话可视化 API（US3 AC-3.5 / 契约 API-C1/C2）：conntrack dump 聚合 +
// 单会话掐断。
package api

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
)

// ctSessionView 会话列表行（契约 API-C1）。
type ctSessionView struct {
	ID       string `json:"id"` // orig 四元组稳定编码（掐断引用）
	Proto    string `json:"proto"`
	Src      string `json:"src"`       // 客户端 源ip:port（穿越/发布前）
	Dst      string `json:"dst"`       // 目标 ip:port（DNAT 前）
	SrcAfter string `json:"src_after"` // NAT 改写后的源（snat 出口 IP；dnat 为空）
	// Backend 是**实际后端地址** ip:port（端口映射转发到的目标）。
	//
	// 为什么需要它：conntrack 只记录 NAT 前后的四元组，端口映射（tcp/udp）
	// 是**用户态重新 dial** 后端，conntrack 里根本没有后端信息——
	// 会话看起来只是「客户端 → 网关监听口」。后端地址只在进程内
	// 会话表（ActiveSessions 的 TargetAddr）里有。
	// 关联键 = (src ip, src port, listen ip, listen port)，见 buildBackendIndex。
	//
	// 空串表示无法关联（内核转发的 snat/dnat 会话，或会话已结束）。
	Backend string `json:"backend"`
	Router  string `json:"router"` // 归属：snat:<规则源网卡> / dnat:<发布IP> / policy / other
	State   string `json:"state"`
}

// backendIndex 是「conntrack 记录 → 用户态会话」的关联索引。
//
// 端口映射是用户态转发，一条逻辑连接在 conntrack 里是**两条**：
//
//	入向段（clientLeg）：客户端 ip:sport → 网关监听 ip:dport
//	出向段（dialLeg）：  网关 dial 源 ip:lport → 后端 ip:dport
//
// 会话表要展示成一行，所以需要两种关联：
//
//	byClient  四元组(客户端 + 监听口) → 会话，用于给入向段补后端地址
//	byDialPort dial 本地端口           → 会话，用于识别并**吞掉**出向段那一行
//
// 出向段只按端口匹配：它的源 ip 恒为网关本机地址，端口才是唯一区分键。
// （同一网关同时有多个端口映射时，不同连接的 dial 端口必然不同。）
type backendIndex struct {
	byClient   map[string]*model.SessionInfo // key = backendKey(...)
	byDialPort map[int]*model.SessionInfo    // key = dial 本地端口
}

// backendKey 拼关联键。用 \x00 分隔避免 IP/端口的字符串歧义。
func backendKey(srcIP string, srcPort int, listenIP string, listenPort int) string {
	return srcIP + "\x00" + strconv.Itoa(srcPort) + "\x00" +
		listenIP + "\x00" + strconv.Itoa(listenPort)
}

// buildBackendIndex 从用户态会话表建关联索引。
//
// 只收 target_addr 非空的会话（tcp/udp 端口映射才有后端；snat/dnat 走内核，
// 不会有对应 session 条目）。DialLocalPort 为 0 的会话不进 byDialPort
// （dial 尚未完成或失败），此时出向段无法合并，会单独显示。
func buildBackendIndex(sessions []model.SessionInfo) *backendIndex {
	idx := &backendIndex{
		byClient:   make(map[string]*model.SessionInfo, len(sessions)),
		byDialPort: make(map[int]*model.SessionInfo, len(sessions)),
	}
	for i := range sessions {
		s := &sessions[i]
		if s.TargetAddr == "" {
			continue
		}
		idx.byClient[backendKey(s.SourceIP, s.SourcePort, s.ListenIP, s.ListenPort)] = s
		if s.DialLocalPort > 0 {
			idx.byDialPort[s.DialLocalPort] = s
		}
	}
	return idx
}

// lookupSession 按入向段的 src/dst 反查会话。
//
// src/dst 是 "ip:port" 形式（net.JoinHostPort 产出）。解析失败返回 nil——
// 宁可少显示一列，也不能因为格式异常让整个会话表 500。
func (b *backendIndex) lookupSession(src, dst string) *model.SessionInfo {
	if b == nil || len(b.byClient) == 0 {
		return nil
	}
	sip, sport, err := net.SplitHostPort(src)
	if err != nil {
		return nil
	}
	dip, dport, err := net.SplitHostPort(dst)
	if err != nil {
		return nil
	}
	sp, err1 := strconv.Atoi(sport)
	dp, err2 := strconv.Atoi(dport)
	if err1 != nil || err2 != nil {
		return nil
	}
	return b.byClient[backendKey(sip, sp, dip, dp)]
}

// dialLegOwner 判断某条 conntrack 行是否是「端口映射的出向段」，
// 是则返回它归属的会话（该行应被合并、不单独展示）。
//
// 判据（两个都必须满足）：
//  1. 该行的**源端口**命中某会话的 DialLocalPort
//  2. 该行的**目的地址**等于该会话的 TargetAddr
//
// 第 2 条是必要的双保险：dial 端口会被内核复用，仅凭端口命中有可能
// 把一条无关连接（恰好复用了同端口）误判成出向段而隐藏掉。
func (b *backendIndex) dialLegOwner(src, dst string) *model.SessionInfo {
	if b == nil || len(b.byDialPort) == 0 {
		return nil
	}
	_, sport, err := net.SplitHostPort(src)
	if err != nil {
		return nil
	}
	sp, err := strconv.Atoi(sport)
	if err != nil {
		return nil
	}
	s := b.byDialPort[sp]
	if s == nil {
		return nil
	}
	// 目的地址必须与会话的后端一致（大小写归一：IPv6 十六进制可能不同写法）
	if !strings.EqualFold(dst, s.TargetAddr) {
		return nil
	}
	return s
}

// listSessions 会话列表（?proto=&q=&limit=）。
//
// **只返回 ESTABLISHED 状态的会话**（产品决定 2026-11-01）。
// 过滤放在后端而不是前端：`total` 要是真实的 ESTABLISHED 条数，
// 且掐断接口按 id 操作——前端隐藏行、后端仍返回会让两处语义打架。
//
// 数据源是**两个**，必须合并：
//
//	conntrack         —— 内核转发的会话（SNAT 穿越、DNAT 发布）
//	进程内 sessions   —— 用户态转发的会话（端口映射 tcp/udp）
//
// 端口映射由网关进程 accept 后重新 dial 后端，**完全不经过 netfilter 的
// conntrack 钩子**（实测：重装后 conntrack_count=0，而端口映射正在跑 1.7GB
// 流量）。只查 conntrack 会让会话表对端口映射永远显示"共 0 条"。
func (h *handlers) listSessions(c *gin.Context) {
	sessions := h.Mgr.SnapshotSessions()
	proto := strings.ToLower(strings.TrimSpace(c.Query("proto")))
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	limit := 500
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 && v <= 5000 {
		limit = v
	}
	// 用户态会话：既用于给 conntrack 行补后端地址，也用于**独立成行**
	// （端口映射根本不进 conntrack，见 listSessions 的说明）。
	userSessions := h.Mgr.ActiveSessions()
	idx := buildBackendIndex(userSessions)
	items := filterSessions(sessions, idx, proto, q, limit)
	// 合并进程内会话：端口映射的会话不在 conntrack 里，必须单独补进来。
	items = appendUserSessions(items, userSessions, proto, q, limit)
	c.JSON(200, gin.H{"items": items, "total": len(items)})
}

// filterSessions 把 conntrack 快照筛成会话表行。
//
// 抽成纯函数而不是写在 handler 里：过滤规则（尤其"只留 ESTABLISHED"、
// "合并两段"）是产品语义，必须有单元测试盯着——写在 handler 里就只能
// 靠起 HTTP 服务测。
//
// 过滤顺序：状态 → 协议 → **合并出向段** → 关键词 → 截断。
// 状态过滤放在最前，保证 limit 截的是真实活跃会话，而不是被 TIME_WAIT 占满。
//
// backend 可为 nil（无用户态会话时）——此时 Backend 列留空、两段不合并，
// 每条 conntrack 记录各占一行（退化行为，不影响其它列）。
func filterSessions(sessions []proxy.CTSnapshot, backend *backendIndex, proto, q string, limit int) []ctSessionView {
	items := make([]ctSessionView, 0, len(sessions))
	for _, s := range sessions {
		// 只保留 ESTABLISHED（产品决定 2026-11-01）：其余状态
		// （TIME_WAIT / SYN_SENT / CLOSE_WAIT / FIN_WAIT ...）已无数据流，
		// 混在会话表里既淹没真实连接，又让"共 N 条"失去意义。
		// 生产实测：9 条 conntrack 表项里 7 条是 TIME_WAIT。
		if s.State != ctStateEstablished {
			continue
		}
		if proto != "" && s.Proto != proto {
			continue
		}
		// 端口映射的出向段（网关 → 后端）不单独成行：它是同一逻辑连接的
		// 后半段，后端信息已经并到入向段那一行。留着会让一条连接显示两行。
		if backend.dialLegOwner(s.Src, s.Dst) != nil {
			continue
		}
		v := ctSessionView{
			ID: s.ID, Proto: s.Proto,
			Src: s.Src, Dst: s.Dst, SrcAfter: s.SrcAfter,
			Router: s.Router, State: s.State,
		}
		if owner := backend.lookupSession(s.Src, s.Dst); owner != nil {
			v.Backend = owner.TargetAddr
		}
		if q != "" {
			blob := strings.ToLower(v.Proto + " " + v.Src + " " + v.Dst + " " +
				v.SrcAfter + " " + v.Backend + " " + v.Router)
			if !strings.Contains(blob, q) {
				continue
			}
		}
		items = append(items, v)
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

// ctStateEstablished 是内核 conntrack 的「已建立」状态字面量。
//
// 取自 /proc/net/nf_conntrack 与 `conntrack -L` 输出里状态列原文（两者格式
// 一致，见 proxy 包的解析）。内核输出全大写，比较必须大小写敏感。
const ctStateEstablished = "ESTABLISHED"

// killSession 掐断单会话（契约 API-C2：按 id 掐断）。
func (h *handlers) killSession(c *gin.Context) {
	var in struct {
		ID string `json:"id"`
	}
	if err := c.ShouldBindJSON(&in); err != nil || strings.TrimSpace(in.ID) == "" {
		c.JSON(400, gin.H{"error": "请求体需含会话 id（见会话列表）"})
		return
	}
	killed, err := h.Mgr.KillSessionByID(in.ID)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if killed == 0 {
		c.JSON(400, gin.H{"error": "会话不存在（可能已结束）"})
		return
	}
	h.Audit.Record(h.username(c), "session_kill", fmt.Sprintf("掐断会话 %s", in.ID), h.clientIP(c))
	c.JSON(200, gin.H{"killed": killed})
}

// appendUserSessions 把进程内会话（端口映射）补进会话表。
//
// 为什么必须单独补：端口映射由网关进程 accept 后重新 dial 后端，
// **不经过 netfilter 的 conntrack 钩子**。实测（2026-11-02 重装后）：
// 端口映射正在传 1.7GB，但 `conntrack -L` 返回 "0 flow entries"，
// 会话表因此永远显示"共 0 条"——用户以为没生效。
//
// 这些行的 ID 用进程内会话 id 的稳定编码（带 "u:" 前缀区分于 conntrack 的
// base64 四元组），掐断接口据此识别走哪条路径。
func appendUserSessions(items []ctSessionView, userSessions []model.SessionInfo, proto, q string, limit int) []ctSessionView {
	for _, s := range userSessions {
		if proto != "" && s.Protocol != proto {
			continue
		}
		// ID 前缀 "u:" 标明这是进程内会话，KillSessionByID 据此走用户态关闭路径。
		// 用 rule_id + 源端口做稳定标识（同一连接在生命周期内不变）。
		id := fmt.Sprintf("u:%d:%s:%d", s.RuleID, s.SourceIP, s.SourcePort)
		v := ctSessionView{
			ID:      id,
			Proto:   s.Protocol,
			Src:     net.JoinHostPort(s.SourceIP, strconv.Itoa(s.SourcePort)),
			Dst:     net.JoinHostPort(s.ListenIP, strconv.Itoa(s.ListenPort)),
			Backend: s.TargetAddr,
			// 用户态转发的会话归属就是端口映射本身，不带 snat/dnat 前缀
			Router: "portmap",
			State:  ctStateEstablished, // 进程内会话只要在表里就是活跃的
		}
		if q != "" {
			blob := strings.ToLower(v.Proto + " " + v.Src + " " + v.Dst + " " + v.Backend + " " + v.Router)
			if !strings.Contains(blob, q) {
				continue
			}
		}
		items = append(items, v)
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}
