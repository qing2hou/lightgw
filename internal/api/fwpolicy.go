// 防火墙策略 API（US3/契约 API-P1..P6）。
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/model"
)

// fwPolicyInput 策略创建/更新请求体。
type fwPolicyInput struct {
	Name      string `json:"name"`
	Action    string `json:"action"`
	SrcList   string `json:"src_list"`
	DstList   string `json:"dst_list"`
	Proto     string `json:"proto"`
	PortRange string `json:"port_range"`
	Enabled   *bool  `json:"enabled"`
	Comment   string `json:"comment"`
	// 创建/更新 drop 策略时的可选立即掐断（API-P6）
	KillEstablished bool `json:"kill_established"`
}

func (h *handlers) listFwPolicies(c *gin.Context) {
	var pols []model.FwPolicy
	if err := h.DB.Order("`order` asc").Find(&pols).Error; err != nil {
		h.serverError(c, "查询策略", err)
		return
	}
	// T108 命中计数注入（Manager 快照：nft counter 按 pol 标记聚合——drop 桶为
	// 拒绝量、accept 桶为放行量；计数滞后 5s 轮询内可接受）
	stats := h.Mgr.PolicyCounters()
	var out []gin.H
	for _, p := range pols {
		row := gin.H{
			"id": p.ID, "name": p.Name, "order": p.Order, "action": p.Action,
			"src_list": parseListOrNull(p.SrcList), "dst_list": parseListOrNull(p.DstList),
			"proto": p.Proto, "port_range": p.PortRange, "enabled": p.Enabled, "comment": p.Comment,
		}
		if st, ok := stats[p.ID]; ok {
			row["stats"] = gin.H{"pkts": st.Packets, "bytes": st.Bytes}
		}
		out = append(out, row)
	}
	if out == nil {
		out = []gin.H{}
	}
	c.JSON(200, gin.H{"items": out, "total": len(out)})
}

func (h *handlers) createFwPolicy(c *gin.Context) {
	var in fwPolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := validateFwPolicy(&in); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// order = 当前最大 +1（末尾插入）
	var maxOrder int
	h.DB.Model(&model.FwPolicy{}).Select("COALESCE(MAX(`order`), 0)").Scan(&maxOrder)
	pol := model.FwPolicy{
		Name: strings.TrimSpace(in.Name), Order: maxOrder + 1,
		Action: in.Action, SrcList: in.SrcList, DstList: in.DstList,
		Proto: in.Proto, PortRange: strings.TrimSpace(in.PortRange),
		Enabled: in.Enabled == nil || *in.Enabled,
		Comment: strings.TrimSpace(in.Comment),
	}
	if err := h.DB.Create(&pol).Error; err != nil {
		h.serverError(c, "创建策略", err)
		return
	}
	h.applyFwPolicies(c, &pol, in.KillEstablished, fmt.Sprintf("创建策略[%s]（%s）", pol.Name, pol.Action))
}

func (h *handlers) updateFwPolicy(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var pol model.FwPolicy
	if err := h.DB.First(&pol, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "策略不存在"})
		return
	}
	var in fwPolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := validateFwPolicy(&in); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	pol.Name = strings.TrimSpace(in.Name)
	pol.Action = in.Action
	pol.SrcList = in.SrcList
	pol.DstList = in.DstList
	pol.Proto = in.Proto
	pol.PortRange = strings.TrimSpace(in.PortRange)
	if in.Enabled != nil {
		pol.Enabled = *in.Enabled
	}
	pol.Comment = strings.TrimSpace(in.Comment)
	if err := h.DB.Save(&pol).Error; err != nil {
		h.serverError(c, "保存策略", err)
		return
	}
	h.applyFwPolicies(c, &pol, in.KillEstablished, fmt.Sprintf("更新策略[%s]（%s）", pol.Name, pol.Action))
}

func (h *handlers) deleteFwPolicy(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var pol model.FwPolicy
	if err := h.DB.First(&pol, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "策略不存在"})
		return
	}
	if err := h.DB.Delete(&pol).Error; err != nil {
		h.serverError(c, "删除策略", err)
		return
	}
	if err := h.Mgr.ReinstallPolicies(); err != nil {
		h.serverError(c, "删除后重装策略", err)
		return
	}
	h.Audit.Record(h.username(c), "fw_policy_delete", fmt.Sprintf("删除策略[%s]", pol.Name), h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}

// reorderFwPolicies 全量重排（契约 API-P5：ordered_ids 必须是全部 ID 的排列）。
func (h *handlers) reorderFwPolicies(c *gin.Context) {
	var in struct {
		OrderedIDs []uint `json:"ordered_ids"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	var pols []model.FwPolicy
	if err := h.DB.Find(&pols).Error; err != nil {
		h.serverError(c, "查询策略", err)
		return
	}
	if len(in.OrderedIDs) != len(pols) {
		c.JSON(400, gin.H{"error": fmt.Sprintf("ordered_ids 必须包含全部 %d 条策略 ID", len(pols))})
		return
	}
	byID := map[uint]bool{}
	for _, id := range in.OrderedIDs {
		if byID[id] {
			c.JSON(400, gin.H{"error": "ordered_ids 含重复 ID"})
			return
		}
		byID[id] = true
	}
	for _, p := range pols {
		if !byID[p.ID] {
			c.JSON(400, gin.H{"error": "ordered_ids 必须是全部策略 ID 的一个排列"})
			return
		}
	}
	if err := h.DB.Transaction(func(tx *gorm.DB) error {
		for i, id := range in.OrderedIDs {
			if err := tx.Model(&model.FwPolicy{}).Where("id = ?", id).Update("order", i+1).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		h.serverError(c, "删除后重装策略", err)
		return
	}
	if err := h.Mgr.ReinstallPolicies(); err != nil {
		h.serverError(c, "重装策略", err)
		return
	}
	h.Audit.Record(h.username(c), "fw_policy_reorder", fmt.Sprintf("策略新序: %v", in.OrderedIDs), h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}

// applyFwPolicies 保存后统一动作：重装 + 审计 + （可选）drop 策略立即掐断存量。
func (h *handlers) applyFwPolicies(c *gin.Context, pol *model.FwPolicy, kill bool, actionDetail string) {
	if err := h.Mgr.ReinstallPolicies(); err != nil {
		h.serverError(c, "保存策略", err)
		return
	}
	killed := 0
	if kill && pol.Action == "drop" {
		killed = h.Mgr.KillPolicySessions(*pol)
	}
	h.Audit.Record(h.username(c), "fw_policy_apply", actionDetail, h.clientIP(c))
	c.JSON(200, gin.H{"id": pol.ID, "killed_sessions": killed})
}

// validateFwPolicy 策略字段校验（契约 40010-40013）。
func validateFwPolicy(in *fwPolicyInput) error {
	in.Action = strings.ToLower(strings.TrimSpace(in.Action))
	if in.Action != "accept" && in.Action != "drop" {
		return fmt.Errorf("action 只能是 accept 或 drop")
	}
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("策略名称不能为空")
	}
	in.Proto = strings.ToLower(strings.TrimSpace(in.Proto))
	switch in.Proto {
	case "tcp", "udp", "icmp", "any", "":
		if in.Proto == "" {
			in.Proto = "tcp"
		}
	default:
		return fmt.Errorf("协议只能是 tcp / udp / icmp / any")
	}
	if (in.Proto == "icmp" || in.Proto == "any") && strings.TrimSpace(in.PortRange) != "" {
		return fmt.Errorf("proto 为 icmp/any 时 port_range 必须为空")
	}
	if err := validateIPListJSON(in.SrcList, "src_list"); err != nil {
		return err
	}
	if err := validateIPListJSON(in.DstList, "dst_list"); err != nil {
		return err
	}
	// 端口串逐组校验（语法；单端口/范围）
	if s := strings.TrimSpace(in.PortRange); s != "" {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				return fmt.Errorf("port_range 含空组（格式 80,443,1000-2000）")
			}
			if lo, hi, ok := strings.Cut(part, "-"); ok {
				l, e1 := strconv.Atoi(strings.TrimSpace(lo))
				hh, e2 := strconv.Atoi(strings.TrimSpace(hi))
				if e1 != nil || e2 != nil || l < 1 || hh > 65535 || l > hh {
					return fmt.Errorf("端口范围 %q 无效", part)
				}
				continue
			}
			p, e := strconv.Atoi(part)
			if e != nil || p < 1 || p > 65535 {
				return fmt.Errorf("端口 %q 无效", part)
			}
		}
	}
	return nil
}

// validateIPListJSON JSON 字符串数组 + 每条 IPv4/CIDR 校验（空串合法=任意；
// v6 支持在 M3/T210——评审 #8：v6 进编译层会产出畸形规则）。
func validateIPListJSON(s, field string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var entries []string
	if err := json.Unmarshal([]byte(s), &entries); err != nil {
		return fmt.Errorf("%s 必须是 JSON 字符串数组: %w", field, err)
	}
	for _, e := range entries {
		if ip := net.ParseIP(e); ip != nil && ip.To4() != nil {
			continue
		}
		if _, ipn, err := net.ParseCIDR(e); err == nil && ipn.IP.To4() != nil {
			continue
		}
		return fmt.Errorf("%s 条目 %q 不是合法的 IPv4 或 v4 网段（v6 支持将在后续版本提供）", field, e)
	}
	return nil
}

// parseListOrNull JSON 数组 → []string（空/非法返回 nil——展示容错）。
func parseListOrNull(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(strings.TrimSpace(s)), &out)
	return out
}
