package api

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/model"
)

// ---------- 名单组 CRUD ----------

type aclGroupInput struct {
	Name    string   `json:"name"`
	Mode    string   `json:"mode"`
	Entries []string `json:"entries"`
}

func (in *aclGroupInput) validate() error {
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("名单组名称不能为空")
	}
	if len(in.Name) > 128 {
		return fmt.Errorf("名单组名称过长（最多 128 字符）")
	}
	if in.Mode != model.AclModeWhitelist && in.Mode != model.AclModeBlacklist {
		return fmt.Errorf("名单组模式必须是 whitelist 或 blacklist")
	}
	entries := in.entries()
	// 白名单组必须非空：空白名单挂在规则上等于静默拒绝所有访问
	// （与直配名单 ValidateLists 的非空门槛同一防线，联动更新同样覆盖）
	if in.Mode == model.AclModeWhitelist && len(entries) == 0 {
		return fmt.Errorf("白名单组需要至少一条条目（空组会导致引用中的规则拒绝所有访问）")
	}
	for _, e := range entries {
		if err := validateIPEntry(e); err != nil {
			return err
		}
	}
	return nil
}

// validateIPEntry 单条 IP/CIDR 校验（与 proxy 包解析语义一致：单 IP 与 CIDR）。
func validateIPEntry(e string) error {
	e = strings.TrimSpace(e)
	if e == "" {
		return fmt.Errorf("名单条目不能为空")
	}
	if !isValidIPOrCIDRStr(e) {
		return fmt.Errorf("无效的 IP 或网段: %q（应为 1.2.3.4 或 192.168.1.0/24）", e)
	}
	return nil
}

// isValidIPOrCIDRStr IP 或 CIDR 网段合法性。
func isValidIPOrCIDRStr(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func (in *aclGroupInput) toGroup() model.AclGroup {
	entries := in.entries()
	b, _ := json.Marshal(entries)
	return model.AclGroup{
		Name:    strings.TrimSpace(in.Name),
		Mode:    in.Mode,
		Entries: string(b),
	}
}

// entries 规范化后的条目列表（去空白项）；导出供校验共用。
func (in *aclGroupInput) entries() []string {
	out := make([]string, 0, len(in.Entries))
	for _, e := range in.Entries {
		if t := strings.TrimSpace(e); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// listAclGroups 名单组列表（含每组被引用的规则数，供删除前提示）。
func (h *handlers) listAclGroups(c *gin.Context) {
	var groups []model.AclGroup
	if err := h.DB.Order("id").Find(&groups).Error; err != nil {
		h.serverError(c, "查询名单组", err)
		return
	}
	type groupWithRefs struct {
		model.AclGroup
		EntryCount int  `json:"entry_count"`
		RefCount   int  `json:"ref_count"` // 引用该组的规则数
		Broken     bool `json:"broken"`    // true = 存在引用但规则模式与组不匹配（数据异常）
	}
	items := make([]groupWithRefs, 0, len(groups))
	for _, g := range groups {
		w := groupWithRefs{AclGroup: g}
		var entries []string
		_ = json.Unmarshal([]byte(g.Entries), &entries)
		w.EntryCount = len(entries)
		var refs int64
		h.DB.Model(&model.ForwardRule{}).Where("acl_group_id = ?", g.ID).Count(&refs)
		w.RefCount = int(refs)
		var bad int64
		h.DB.Model(&model.ForwardRule{}).
			Where("acl_group_id = ? AND (acl_mode IS NULL OR acl_mode <> ?)", g.ID, g.Mode).
			Count(&bad)
		w.Broken = bad > 0
		items = append(items, w)
	}
	c.JSON(200, gin.H{"items": items})
}

func (h *handlers) createAclGroup(c *gin.Context) {
	var in aclGroupInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := in.validate(); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	group := in.toGroup()
	var dup int64
	h.DB.Model(&model.AclGroup{}).Where("name = ?", group.Name).Count(&dup)
	if dup > 0 {
		c.JSON(400, gin.H{"error": fmt.Sprintf("名单组名称 %q 已存在", group.Name)})
		return
	}
	if err := h.DB.Create(&group).Error; err != nil {
		h.serverError(c, "保存名单组", err)
		return
	}
	h.Audit.Record(h.username(c), "acl_group_create", fmt.Sprintf("名单组[%s]（%s，%d 条）", group.Name, group.Mode, len(in.Entries)), h.clientIP(c))
	c.JSON(200, group)
}

func (h *handlers) updateAclGroup(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "无效的名单组 ID"})
		return
	}
	var old model.AclGroup
	if err := h.DB.First(&old, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "名单组不存在"})
		return
	}
	var in aclGroupInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := in.validate(); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	group := in.toGroup()
	group.ID = old.ID
	// 模式变更：已有引用的规则模式与新模式不匹配时拒绝（会导致引用失效）
	if group.Mode != old.Mode {
		var bad int64
		h.DB.Model(&model.ForwardRule{}).Where("acl_group_id = ?", group.ID).Count(&bad)
		if bad > 0 {
			c.JSON(400, gin.H{"error": fmt.Sprintf("该组已被 %d 条规则引用，不能变更模式；请先在规则中解除引用", bad)})
			return
		}
	}
	var dup int64
	h.DB.Model(&model.AclGroup{}).Where("name = ? AND id <> ?", group.Name, group.ID).Count(&dup)
	if dup > 0 {
		c.JSON(400, gin.H{"error": fmt.Sprintf("名单组名称 %q 已存在", group.Name)})
		return
	}
	if err := h.DB.Model(&old).Select("Name", "Mode", "Entries").Updates(group).Error; err != nil {
		h.serverError(c, "保存名单组", err)
		return
	}
	// 名单内容变更：联动重应用所有引用中的规则（展开语义，热生效）
	h.Mgr.ApplyAclGroup(group.ID)
	h.Audit.Record(h.username(c), "acl_group_update",
		fmt.Sprintf("名单组[%s]（%s，%d 条），已联动重应用引用规则", group.Name, group.Mode, len(in.Entries)), h.clientIP(c))
	c.JSON(200, group)
}

func (h *handlers) deleteAclGroup(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "无效的名单组 ID"})
		return
	}
	var group model.AclGroup
	if err := h.DB.First(&group, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "名单组不存在"})
		return
	}
	refs := h.Mgr.ReferencedByAclGroup(uint(id))
	if len(refs) > 0 {
		c.JSON(400, gin.H{"error": fmt.Sprintf("名单组[%s]仍被 %d 条规则引用（规则 ID: %v），请先解除引用再删除", group.Name, len(refs), refs)})
		return
	}
	if err := h.DB.Delete(&model.AclGroup{}, id).Error; err != nil {
		h.serverError(c, "删除名单组", err)
		return
	}
	h.Audit.Record(h.username(c), "acl_group_delete", fmt.Sprintf("名单组[%s]（%s）", group.Name, group.Mode), h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}
