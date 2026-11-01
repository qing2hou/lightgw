// 会话可视化 API（US3 AC-3.5 / 契约 API-C1/C2）：conntrack dump 聚合 +
// 单会话掐断。
package api

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/proxy"
)

// ctSessionView 会话列表行（契约 API-C1）。
type ctSessionView struct {
	ID       string `json:"id"` // orig 四元组稳定编码（掐断引用）
	Proto    string `json:"proto"`
	Src      string `json:"src"`       // 客户端 源ip:port（穿越/发布前）
	Dst      string `json:"dst"`       // 目标 ip:port（DNAT 前）
	SrcAfter string `json:"src_after"` // NAT 改写后的源（snat 出口 IP；dnat 为空）
	Router   string `json:"router"`    // 归属：snat:<规则源网卡> / dnat:<发布IP> / policy / other
	State    string `json:"state"`
}

// listSessions 会话列表（?proto=&q=&limit=）。
// listSessions 会话列表（?proto=&q=&limit=）。
//
// **只返回 ESTABLISHED 状态的会话**（产品决定 2026-11-01）。
// 过滤放在后端而不是前端：`total` 要是真实的 ESTABLISHED 条数，
// 且掐断接口按 id 操作——前端隐藏行、后端仍返回会让两处语义打架。
func (h *handlers) listSessions(c *gin.Context) {
	sessions := h.Mgr.SnapshotSessions()
	proto := strings.ToLower(strings.TrimSpace(c.Query("proto")))
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	limit := 500
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 && v <= 5000 {
		limit = v
	}
	items := filterSessions(sessions, proto, q, limit)
	c.JSON(200, gin.H{"items": items, "total": len(items)})
}

// filterSessions 把 conntrack 快照筛成会话表行。
//
// 抽成纯函数而不是写在 handler 里：过滤规则（尤其"只留 ESTABLISHED"）
// 是产品语义，必须有单元测试盯着——写在 handler 里就只能靠起 HTTP 服务测。
//
// 过滤顺序：状态 → 协议 → 关键词 → 截断。
// 状态过滤放在最前，保证 limit 截的是真实活跃会话，而不是被 TIME_WAIT 占满。
func filterSessions(sessions []proxy.CTSnapshot, proto, q string, limit int) []ctSessionView {
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
		v := ctSessionView{
			ID: s.ID, Proto: s.Proto,
			Src: s.Src, Dst: s.Dst, SrcAfter: s.SrcAfter,
			Router: s.Router, State: s.State,
		}
		if q != "" {
			blob := strings.ToLower(v.Proto + " " + v.Src + " " + v.Dst + " " + v.SrcAfter + " " + v.Router)
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
