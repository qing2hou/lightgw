package api

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/model"
)

// escapeLike 转义 LIKE 通配符，防止用户输入的 %/_ 改变筛选语义。
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// ---------- 流量日志 ----------

func (h *handlers) trafficLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}

	q := h.DB.Model(&model.TrafficLog{})
	if v := c.Query("rule_id"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			q = q.Where("rule_id = ?", id)
		}
	}
	if v := c.Query("protocol"); v != "" {
		q = q.Where("protocol = ?", v)
	}
	if v := c.Query("source_ip"); v != "" {
		q = q.Where("source_ip LIKE ? ESCAPE '\\'", "%"+escapeLike(v)+"%")
	}
	if v := c.Query("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	if v := c.Query("start"); v != "" {
		if t, ok := parseTime(v); ok {
			q = q.Where("started_at >= ?", t)
		}
	}
	if v := c.Query("end"); v != "" {
		if t, ok := parseTime(v); ok {
			q = q.Where("started_at < ?", t)
		}
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		h.serverError(c, "查询流量日志", err)
		return
	}
	var items []model.TrafficLog
	if err := q.Order("id DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&items).Error; err != nil {
		h.serverError(c, "查询流量日志", err)
		return
	}
	c.JSON(200, gin.H{"items": items, "total": total})
}

// ---------- 操作审计 ----------

func (h *handlers) auditLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}

	q := h.DB.Model(&model.AuditLog{})
	if v := c.Query("username"); v != "" {
		q = q.Where("username LIKE ? ESCAPE '\\'", "%"+escapeLike(v)+"%")
	}
	if v := c.Query("action"); v != "" {
		q = q.Where("action = ?", v)
	}
	if v := c.Query("start"); v != "" {
		if t, ok := parseTime(v); ok {
			q = q.Where("created_at >= ?", t)
		}
	}
	if v := c.Query("end"); v != "" {
		if t, ok := parseTime(v); ok {
			q = q.Where("created_at < ?", t)
		}
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		h.serverError(c, "查询操作审计", err)
		return
	}
	var items []model.AuditLog
	if err := q.Order("id DESC").Limit(pageSize).Offset((page - 1) * pageSize).Find(&items).Error; err != nil {
		h.serverError(c, "查询操作审计", err)
		return
	}
	c.JSON(200, gin.H{"items": items, "total": total})
}

// parseTime 支持 "2006-01-02 15:04:05" 与 RFC3339 两种格式。
func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339, "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
