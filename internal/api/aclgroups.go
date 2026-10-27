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
	if in.Mode != model.AclModeWhitelist && in.Mode != model.AclModeBlacklist && in.Mode != model.AclGroupModeIP {
		return fmt.Errorf("名单组类型必须是 whitelist / blacklist / ip")
	}
	entries := in.entries()
	// 白名单组与 IP 组必须非空：空组被白名单语义引用时等于静默拒绝所有
	// 访问（与直配名单的非空门槛同一防线，联动更新同样覆盖）
	if (in.Mode == model.AclModeWhitelist || in.Mode == model.AclGroupModeIP) && len(entries) == 0 {
		return fmt.Errorf("%s需要至少一条条目（空组被白名单引用时会拒绝所有访问）", groupModeName(in.Mode))
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
		// 引用计数：源名单（acl_group_id）+ snat 目标限制（dst_acl_group_id）
		var refs int64
		h.DB.Model(&model.ForwardRule{}).
			Where("acl_group_id = ? OR dst_acl_group_id = ?", g.ID, g.ID).Count(&refs)
		w.RefCount = int(refs)
		// broken 判据：存在引用但组类型与该引用方的模式不兼容（数据异常）。
		// IP 组对任何模式都兼容，天然不会 broken。
		if g.Mode != model.AclGroupModeIP {
			var bad int64
			h.DB.Model(&model.ForwardRule{}).
				Where("(acl_group_id = ? AND (acl_mode IS NULL OR acl_mode <> ?)) OR "+
					"(dst_acl_group_id = ? AND (dst_acl_mode IS NULL OR dst_acl_mode <> ?))",
					g.ID, g.Mode, g.ID, g.Mode).
				Count(&bad)
			w.Broken = bad > 0
		}
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
	// 类型变更：已有引用方与新类型不兼容时拒绝（会导致引用失效）。
	// IP 组可被任意模式引用，从白/黑组改成 IP 组总是安全；反向则要看引用方。
	if group.Mode != old.Mode {
		var refs []model.ForwardRule
		h.DB.Where("acl_group_id = ? OR dst_acl_group_id = ?", group.ID, group.ID).Find(&refs)
		bad := 0
		for _, r := range refs {
			if r.AclGroupID == group.ID && !model.AclGroupMatchesMode(group.Mode, r.AclMode) {
				bad++
				continue
			}
			if r.DstAclGroupID == group.ID && !model.AclGroupMatchesMode(group.Mode, r.DstAclMode) {
				bad++
			}
		}
		if bad > 0 {
			c.JSON(400, gin.H{"error": fmt.Sprintf("该组已被 %d 处引用，改成%q类型会与引用方的模式冲突；请先在规则中解除引用",
				bad, groupModeName(group.Mode))})
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
