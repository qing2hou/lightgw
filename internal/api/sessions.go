// 会话可视化 API（US3 AC-3.5 / 契约 API-C1/C2）：conntrack dump 聚合 +
// 单会话掐断。
package api

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
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
func (h *handlers) listSessions(c *gin.Context) {
	sessions := h.Mgr.SnapshotSessions()
	proto := strings.ToLower(strings.TrimSpace(c.Query("proto")))
	q := strings.ToLower(strings.TrimSpace(c.Query("q")))
	limit := 500
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 && v <= 5000 {
		limit = v
	}
	items := make([]ctSessionView, 0, len(sessions))
	for _, s := range sessions {
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
	if len(items) > limit {
		items = items[:limit]
	}
	c.JSON(200, gin.H{"items": items, "total": len(items)})
}

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
