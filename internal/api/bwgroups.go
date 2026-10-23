package api

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"haproxyweb/internal/model"
)

// hasMembersErr 删除保护错误（事务内回传给 handler 转 400）。
type hasMembersErr struct{ count int64 }

func (e *hasMembersErr) Error() string { return fmt.Sprintf("仍有 %d 条成员规则", e.count) }

// ---------- 带宽包 CRUD ----------

type bwGroupInput struct {
	Name         string `json:"name"`
	TotalKBps    int64  `json:"total_kbps"`
	MinKBps      int64  `json:"min_kbps"`
	MemberRuleID []uint `json:"member_rule_ids"`
}

func (in *bwGroupInput) validate(h *handlers, groupID uint) error {
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("带宽包名称不能为空")
	}
	if in.TotalKBps <= 0 {
		return fmt.Errorf("合计额度必须大于 0（KB/s）")
	}
	// 保底：0=默认 1024KB/s；自定义须为正且不超过包总额
	if in.MinKBps < 0 {
		return fmt.Errorf("保底带宽不能为负数（0 = 默认 1024 KB/s）")
	}
	if in.MinKBps > in.TotalKBps {
		return fmt.Errorf("保底带宽（%d KB/s）不能超过包总额度（%d KB/s）", in.MinKBps, in.TotalKBps)
	}
	for _, id := range in.MemberRuleID {
		var rule model.ForwardRule
		if err := h.DB.First(&rule, id).Error; err != nil {
			return fmt.Errorf("成员规则 #%d 不存在", id)
		}
		if !rule.Enabled {
			return fmt.Errorf("成员规则[%s#%d]未启用（仅启用规则可入包）", rule.Name, rule.ID)
		}

		// 跨包偷成员（前端只灰显已属他人成员，API 强校验防线；本包已有成员放行——编辑场景）
		if rule.BWGroupID != 0 && rule.BWGroupID != groupID {
			return fmt.Errorf("规则[%s#%d] 已属于其他带宽包（#%d），请先在原包中移除", rule.Name, rule.ID, rule.BWGroupID)
		}
	}
	return nil
}

// listBWGroups 包列表（含成员摘要）。
func (h *handlers) listBWGroups(c *gin.Context) {
	var groups []model.BWGroup
	if err := h.DB.Order("id").Find(&groups).Error; err != nil {
		h.serverError(c, "查询带宽包", err)
		return
	}
	type member struct {
		ID       uint   `json:"id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
	}
	type item struct {
		model.BWGroup
		Members     []member `json:"members"`
		MemberCount int      `json:"member_count"`
	}
	var rules []model.ForwardRule
	h.DB.Where("bw_group_id > 0").Find(&rules)
	byGroup := map[uint][]member{}
	for _, r := range rules {
		byGroup[r.BWGroupID] = append(byGroup[r.BWGroupID], member{ID: r.ID, Name: r.Name, Protocol: r.Protocol})
	}
	items := make([]item, 0, len(groups))
	for _, g := range groups {
		it := item{BWGroup: g, Members: byGroup[g.ID]}
		if it.Members == nil {
			it.Members = []member{}
		}
		it.MemberCount = len(it.Members)
		items = append(items, it)
	}
	c.JSON(200, gin.H{"items": items})
}

// applyBWMembers 成员关系批量落库 + tc 重建（创建/更新共用）。
// 成员全量替换语义：diff 出新增/移除，逐规则更新 bw_group_id 并触发引擎重建。
func (h *handlers) applyBWMembers(groupID uint, want []uint) error {
	// 包令牌桶失效（额度/成员变更——重建期各规则 Apply 懒建新桶）
	h.Mgr.ResetBWLimiters()
	var rules []model.ForwardRule
	h.DB.Where("bw_group_id = ?", groupID).Find(&rules)
	current := map[uint]bool{}
	for _, r := range rules {
		current[r.ID] = true
	}
	wantSet := map[uint]bool{}
	for _, id := range want {
		wantSet[id] = true
	}
	// 移除
	for _, r := range rules {
		if !wantSet[r.ID] {
			r.BWGroupID = 0
			if err := h.DB.Model(&model.ForwardRule{}).Where("id = ?", r.ID).Update("bw_group_id", 0).Error; err != nil {
				return err
			}
			if err := h.Mgr.Apply(r); err != nil {
				return fmt.Errorf("规则[%s#%d] 移出带宽包重建失败: %w", r.Name, r.ID, err)
			}
		}
	}
	// 新增
	for _, id := range want {
		if current[id] {
			continue
		}
		var r model.ForwardRule
		if err := h.DB.First(&r, id).Error; err != nil {
			return fmt.Errorf("成员规则 #%d 不存在", id)
		}
		r.BWGroupID = groupID
		if err := h.DB.Model(&model.ForwardRule{}).Where("id = ?", r.ID).Update("bw_group_id", groupID).Error; err != nil {
			return err
		}
		if err := h.Mgr.Apply(r); err != nil {
			return fmt.Errorf("规则[%s#%d] 入包重建失败: %w", r.Name, r.ID, err)
		}
	}
	return nil
}

func (h *handlers) createBWGroup(c *gin.Context) {
	var in bwGroupInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := in.validate(h, 0); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var dup int64
	h.DB.Model(&model.BWGroup{}).Where("name = ?", strings.TrimSpace(in.Name)).Count(&dup)
	if dup > 0 {
		c.JSON(409, gin.H{"error": fmt.Sprintf("带宽包名称 %q 已存在", strings.TrimSpace(in.Name))})
		return
	}
	g := model.BWGroup{Name: strings.TrimSpace(in.Name), TotalKBps: in.TotalKBps, MinKBps: in.MinKBps}
	if err := h.DB.Create(&g).Error; err != nil {
		h.serverError(c, "保存带宽包", err)
		return
	}
	if err := h.applyBWMembers(g.ID, in.MemberRuleID); err != nil {
		h.serverError(c, "绑定成员规则", err)
		return
	}
	h.Audit.Record(h.username(c), "bw_group_create",
		fmt.Sprintf("带宽包[%s]（合计 %d KB/s，成员 %d 条）", g.Name, g.TotalKBps, len(in.MemberRuleID)), h.clientIP(c))
	c.JSON(201, gin.H{"id": g.ID})
}

func (h *handlers) updateBWGroup(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "无效的带宽包 ID"})
		return
	}
	var old model.BWGroup
	if err := h.DB.First(&old, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "带宽包不存在"})
		return
	}
	var in bwGroupInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := in.validate(h, uint(id)); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var dup int64
	h.DB.Model(&model.BWGroup{}).Where("name = ? AND id <> ?", strings.TrimSpace(in.Name), id).Count(&dup)
	if dup > 0 {
		c.JSON(409, gin.H{"error": fmt.Sprintf("带宽包名称 %q 已存在", strings.TrimSpace(in.Name))})
		return
	}
	if err := h.DB.Model(&old).Select("Name", "TotalKBps", "MinKBps").
		Updates(model.BWGroup{Name: strings.TrimSpace(in.Name), TotalKBps: in.TotalKBps, MinKBps: in.MinKBps}).Error; err != nil {
		h.serverError(c, "保存带宽包", err)
		return
	}
	if err := h.applyBWMembers(uint(id), in.MemberRuleID); err != nil {
		h.serverError(c, "更新成员规则", err)
		return
	}
	// 额度变化或成员变化：全部成员规则重应用（tc 重建）
	var members []model.ForwardRule
	h.DB.Where("bw_group_id = ?", id).Find(&members)
	for _, r := range members {
		if err := h.Mgr.Apply(r); err != nil {
			h.Audit.Record(h.username(c), "bw_group_update", fmt.Sprintf("带宽包[%s] 成员[%s]重建失败: %v", in.Name, r.Name, err), h.clientIP(c))
		}
	}
	h.Audit.Record(h.username(c), "bw_group_update",
		fmt.Sprintf("带宽包[%s]（合计 %d KB/s，成员 %d 条）", in.Name, in.TotalKBps, len(in.MemberRuleID)), h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}

func (h *handlers) deleteBWGroup(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "无效的带宽包 ID"})
		return
	}
	var g model.BWGroup
	if gerr := h.DB.First(&g, id).Error; gerr != nil {
		c.JSON(404, gin.H{"error": "带宽包不存在"})
		return
	}
	// 删除保护 + 幽灵兜底同一事务：并发拉人（TOCTOU）与历史脏数据
	// （bw_group_id 指向已删包——无 UI 路径可解）都在这里归零
	txErr := h.DB.Transaction(func(tx *gorm.DB) error {
		var cnt int64
		if err := tx.Model(&model.ForwardRule{}).Where("bw_group_id = ?", id).Count(&cnt).Error; err != nil {
			return err
		}
		if cnt > 0 {
			return &hasMembersErr{count: cnt}
		}
		if err := tx.Model(&model.ForwardRule{}).Where("bw_group_id = ?", id).
			Update("bw_group_id", 0).Error; err != nil {
			return err
		}
		return tx.Delete(&model.BWGroup{}, id).Error
	})
	if txErr != nil {
		var he *hasMembersErr
		if errors.As(txErr, &he) {
			c.JSON(400, gin.H{"error": fmt.Sprintf("带宽包[%s]仍有 %d 条成员规则，请先在包内解除全部成员", g.Name, he.count)})
			return
		}
		h.serverError(c, "删除带宽包", txErr)
		return
	}
	h.Audit.Record(h.username(c), "bw_group_delete", fmt.Sprintf("带宽包[%s]（%d KB/s）", g.Name, g.TotalKBps), h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}
