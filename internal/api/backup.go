package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/model"
	"haproxyweb/internal/store"
)

// importMaxBodyBytes 规则导入请求体上限：规则含黑白名单 JSON，放宽到 16MB。
const importMaxBodyBytes = 16 << 20

// ---------- 导出 ----------

// exportRules 导出全部转发规则为 JSON 附件。运行时字段（last_error）不导出；
// 引用名单组的规则将组条目内联展开进对应名单字段（导出文件自包含，
// 跨实例导入无需目标库存在同名组），acl_group_id 置 0 不导出。
func (h *handlers) exportRules(c *gin.Context) {
	var rules []model.ForwardRule
	if err := h.DB.Order("id").Find(&rules).Error; err != nil {
		h.serverError(c, "查询规则", err)
		return
	}
	var allGroups []model.AclGroup
	h.DB.Find(&allGroups)
	groups := make(map[uint]model.AclGroup, len(allGroups))
	for _, g := range allGroups {
		groups[g.ID] = g
	}
	for i := range rules {
		r := &rules[i]
		r.LastError = ""
		if r.AclGroupID != 0 {
			if g, ok := groups[r.AclGroupID]; ok && model.AclGroupMatchesMode(g.Mode, r.AclMode) {
				if r.AclMode == model.AclModeWhitelist {
					r.AllowList = g.Entries
				} else if r.AclMode == model.AclModeBlacklist {
					r.DenyList = g.Entries
				}
			}
			r.AclGroupID = 0
		}
		// snat 目标限制的组引用同样内联展开（导出文件自包含）
		if r.DstAclGroupID != 0 {
			if g, ok := groups[r.DstAclGroupID]; ok && model.AclGroupMatchesMode(g.Mode, r.DstAclMode) {
				if r.DstAclMode == model.AclModeWhitelist {
					r.DstAllowList = g.Entries
				} else if r.DstAclMode == model.AclModeBlacklist {
					r.DstDenyList = g.Entries
				}
			}
			r.DstAclGroupID = 0
		}
	}
	data, err := json.MarshalIndent(gin.H{
		"version":     h.Version,
		"exported_at": time.Now().Format(time.RFC3339),
		"rules":       rules,
	}, "", "  ")
	if err != nil {
		h.serverError(c, "序列化规则", err)
		return
	}
	h.Audit.Record(h.username(c), "rule_export", fmt.Sprintf("导出 %d 条规则", len(rules)), h.clientIP(c))
	name := "haproxyweb-rules-" + time.Now().Format("20060102150405") + ".json"
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	c.Data(http.StatusOK, "application/json", data)
}

// ---------- 导入 ----------

type importPayload struct {
	Rules []ruleInput `json:"rules"`
}

// parseImportPayload 兼容两种载体：{"rules":[...]} 包装对象与裸规则数组（便于手工编辑）。
func parseImportPayload(data []byte) ([]ruleInput, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []ruleInput
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	var p importPayload
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return nil, err
	}
	return p.Rules, nil
}

// importRules 导入规则。mode=merge（默认）逐条校验+冲突跳过；mode=replace 先清空
// 全部现有规则再导入；dry_run=true 只做校验与冲突检测，不改动任何状态。
// 逐条 create→Apply，失败回滚该条并继续，结果逐条报告。
func (h *handlers) importRules(c *gin.Context) {
	mode := c.DefaultQuery("mode", "merge")
	if mode != "merge" && mode != "replace" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode 必须为 merge 或 replace"})
		return
	}
	dryRun := c.Query("dry_run") == "true"

	data, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "读取请求体失败，可能超过大小上限"})
		return
	}
	items, err := parseImportPayload(data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求体格式错误：需要 {\"rules\":[...]} 或规则数组"})
		return
	}
	if len(items) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "导入内容为空"})
		return
	}

	type itemResult struct {
		Index  int    `json:"index"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Reason string `json:"reason,omitempty"`
	}
	results := make([]itemResult, 0, len(items))
	var imported, skipped, failed int

	// replace：先停止全部现有监听再清空（dry_run 不动任何状态）
	if mode == "replace" && !dryRun {
		var existing []model.ForwardRule
		h.DB.Find(&existing)
		for _, r := range existing {
			h.Mgr.Stop(r)
		}
		if err := h.DB.Where("id > 0").Delete(&model.ForwardRule{}).Error; err != nil {
			log.Printf("[api] 导入清空现有规则失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "清空现有规则失败，导入已中止，请查看服务端日志"})
			return
		}
		for _, r := range existing {
			h.Mgr.ForgetRule(r.ID)
		}
		// 辖区重算：清空后可能已无任何 snat 规则，默认拒绝行需随之拆除
		h.Mgr.RecomputeDefaultDeny()
	}

	// 批次内同协议同端口冲突跟踪："proto|port" -> 首个占用者名称
	batchPorts := map[string]string{}

	for i := range items {
		in := &items[i]
		res := itemResult{Index: i, Name: strings.TrimSpace(in.Name)}
		if err := in.validate(h); err != nil {
			res.Status, res.Reason = "invalid", err.Error()
			results = append(results, res)
			failed++
			continue
		}
		rule := in.toRule()

		// 冲突检测：merge 对比库内启用规则（含 Web 端口）；replace 库已清空/将清空，
		// 仅需对比批次内
		if rule.Enabled {
			var conflict error
			if mode == "merge" {
				conflict = h.checkConflict(rule)
			}
			if conflict == nil {
				port := ""
				if _, portStr, err := net.SplitHostPort(rule.ListenAddr); err == nil {
					port = portStr
				}
				key := rule.Protocol + "|" + port
				if owner, ok := batchPorts[key]; ok {
					conflict = fmt.Errorf("与同批次规则[%s]的端口冲突", owner)
				} else {
					batchPorts[key] = rule.Name
				}
			}
			if conflict != nil {
				res.Status, res.Reason = "skipped", conflict.Error()
				results = append(results, res)
				skipped++
				continue
			}
		}

		if dryRun {
			res.Status = "would_import"
			results = append(results, res)
			imported++
			continue
		}

		if err := h.DB.Create(&rule).Error; err != nil {
			log.Printf("[api] 导入规则[%s]入库失败: %v", rule.Name, err)
			res.Status, res.Reason = "error", "写入数据库失败"
			results = append(results, res)
			failed++
			continue
		}
		if err := h.Mgr.Apply(rule); err != nil {
			// 应用失败回滚该条（与手工创建同语义），继续处理其余条目
			if delErr := h.DB.Delete(&model.ForwardRule{}, rule.ID).Error; delErr != nil {
				log.Printf("[api] 导入规则[%s#%d] 应用失败后回滚删除失败: %v", rule.Name, rule.ID, delErr)
			}
			res.Status, res.Reason = "error", err.Error()
			results = append(results, res)
			failed++
			continue
		}
		res.Status = "imported"
		results = append(results, res)
		imported++
	}

	if !dryRun {
		h.Audit.Record(h.username(c), "rule_import",
			fmt.Sprintf("模式=%s 总数=%d 成功=%d 跳过=%d 失败=%d", mode, len(items), imported, skipped, failed),
			h.clientIP(c))
	}
	c.JSON(http.StatusOK, gin.H{
		"mode":     mode,
		"dry_run":  dryRun,
		"total":    len(items),
		"imported": imported,
		"skipped":  skipped,
		"failed":   failed,
		"items":    results,
	})
}

// ---------- 全库快照 ----------

// backupDB 生成数据库一致性快照并作为附件下载（含用户、规则、流量与审计）。
// VACUUM INTO 目标文件必须落在数据目录内（systemd 沙箱仅允许写该目录），
// 下载完成即删除；恢复流程见 README 备份恢复 runbook（停服替换文件）。
func (h *handlers) backupDB(c *gin.Context) {
	ts := time.Now().Format("20060102150405")
	tmp := filepath.Join(h.Cfg.Web.DataDir, fmt.Sprintf(".backup-%s-%d.db", ts, os.Getpid()))
	defer os.Remove(tmp)
	if err := store.BackupTo(h.DB, tmp); err != nil {
		h.serverError(c, "生成数据库快照", err)
		return
	}
	h.Audit.Record(h.username(c), "db_backup", "下载全库快照", h.clientIP(c))
	c.FileAttachment(tmp, "haproxyweb-backup-"+ts+".db")
}
