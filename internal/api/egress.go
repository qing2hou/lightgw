// 出口管理 API（US4/US5，契约 API-E1~E5）。
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
)

type egressInput struct {
	Name        string `json:"name"`
	Iface       string `json:"iface"`
	GatewayV4   string `json:"gateway_v4"`
	GatewayV6   string `json:"gateway_v6"`
	Priority    int    `json:"priority"`
	Weight      int    `json:"weight"`
	ProbeMode   string `json:"probe_mode"`
	ProbeTarget string `json:"probe_target"`
	IntervalSec int    `json:"interval_sec"`
	FailCount   int    `json:"fail_count"`
	UpCount     int    `json:"up_count"`
	Enabled     *bool  `json:"enabled"`
}

func (in *egressInput) toEgress() model.Egress {
	return model.Egress{
		Name: strings.TrimSpace(in.Name), Iface: strings.TrimSpace(in.Iface),
		GatewayV4: strings.TrimSpace(in.GatewayV4), GatewayV6: strings.TrimSpace(in.GatewayV6),
		Priority: in.Priority, Weight: in.Weight,
		ProbeMode: strings.TrimSpace(in.ProbeMode), ProbeTarget: strings.TrimSpace(in.ProbeTarget),
		IntervalSec: in.IntervalSec, FailCount: in.FailCount, UpCount: in.UpCount,
		Enabled: in.Enabled == nil || *in.Enabled,
	}
}

// validateEgress 出口字段校验（契约 40001-40006）。
func (h *handlers) validateEgress(in *egressInput, existing *model.Egress) error {
	in.ProbeMode = strings.ToLower(strings.TrimSpace(in.ProbeMode))
	if in.ProbeMode == "" {
		in.ProbeMode = "icmp-gw"
	}
	switch in.ProbeMode {
	case "icmp-gw", "icmp-target", "tcp-target", "none":
	default:
		return fmt.Errorf("probe_mode 只能是 icmp-gw / icmp-target / tcp-target / none")
	}
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("出口名称不能为空")
	}
	// 名称唯一
	var cnt int64
	q := h.DB.Model(&model.Egress{}).Where("name = ?", strings.TrimSpace(in.Name))
	if existing != nil {
		q = q.Where("id <> ?", existing.ID)
	}
	q.Count(&cnt)
	if cnt > 0 {
		return fmt.Errorf("出口名称 %q 已存在", in.Name)
	}
	// 网卡校验：新建时网卡必须存在；编辑禁改网卡（契约 40006——出口身份=网卡）
	if existing == nil {
		if up, _ := proxy.InterfaceExists(strings.TrimSpace(in.Iface)); !up {
			return fmt.Errorf("网卡 %q 不存在或未启用（可用网卡见 GET /api/interfaces）", strings.TrimSpace(in.Iface))
		}
	} else if strings.TrimSpace(in.Iface) != existing.Iface {
		return fmt.Errorf("已启用的出口不允许变更网卡（出口身份即网卡——请新建出口）")
	}
	for _, gw := range []struct {
		v    string
		name string
	}{{in.GatewayV4, "gateway_v4"}, {in.GatewayV6, "gateway_v6"}} {
		if strings.TrimSpace(gw.v) == "" {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(gw.v))
		if ip == nil {
			return fmt.Errorf("%s %q 不是合法 IP 地址", gw.name, gw.v)
		}
	}
	if strings.TrimSpace(in.GatewayV4) == "" && strings.TrimSpace(in.GatewayV6) == "" {
		return fmt.Errorf("至少配置一个网关（gateway_v4 / gateway_v6）")
	}
	if in.Priority < 0 || in.Priority > 1000 {
		return fmt.Errorf("priority 必须为 0-1000 的整数（小者优先）")
	}
	if in.Weight < 1 || in.Weight > 100 {
		return fmt.Errorf("weight 必须为 1-100 的整数")
	}
	if (in.ProbeMode == "icmp-target" || in.ProbeMode == "tcp-target") && strings.TrimSpace(in.ProbeTarget) == "" {
		return fmt.Errorf("probe_mode 为 %s 时 probe_target 必填", in.ProbeMode)
	}
	if in.ProbeMode == "tcp-target" {
		if _, _, err := net.SplitHostPort(strings.TrimSpace(in.ProbeTarget)); err != nil {
			return fmt.Errorf("tcp-target 的 probe_target 必须是 host:端口 形式")
		}
	}
	if in.IntervalSec < 1 || in.IntervalSec > 60 {
		return fmt.Errorf("interval_sec 必须为 1-60 秒")
	}
	if in.FailCount < 1 || in.FailCount > 10 || in.UpCount < 1 || in.UpCount > 10 {
		return fmt.Errorf("fail_count / up_count 必须为 1-10")
	}
	return nil
}

func (h *handlers) listEgresses(c *gin.Context) {
	var egs []model.Egress
	if err := h.DB.Order("priority asc, id asc").Find(&egs).Error; err != nil {
		h.serverError(c, "查询出口", err)
		return
	}
	items := make([]gin.H, 0, len(egs))
	for _, e := range egs {
		info := proxy.EgressInfoOf(e.ID)
		items = append(items, gin.H{
			"id": e.ID, "name": e.Name, "iface": e.Iface,
			"gateway_v4": e.GatewayV4, "gateway_v6": e.GatewayV6,
			"priority": e.Priority, "weight": e.Weight,
			"probe_mode": e.ProbeMode, "probe_target": e.ProbeTarget,
			"interval_sec": e.IntervalSec, "fail_count": e.FailCount, "up_count": e.UpCount,
			"enabled": e.Enabled,
			"status":  map[bool]string{true: "up", false: "down"}[info.Up],
			"status_detail": gin.H{
				"probe_latency_ms": info.LatencyMs,
				"last_switch":      info.LastSwitch,
				"down_reason":      info.DownReason,
			},
		})
	}
	c.JSON(200, gin.H{"items": items, "total": len(items)})
}

func (h *handlers) createEgress(c *gin.Context) {
	var in egressInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := h.validateEgress(&in, nil); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	eg := in.toEgress()
	if eg.Weight == 0 {
		eg.Weight = 1
	}
	if eg.Priority == 0 {
		eg.Priority = 10
	}
	if eg.IntervalSec == 0 {
		eg.IntervalSec = 3
	}
	if eg.FailCount == 0 {
		eg.FailCount = 2
	}
	if eg.UpCount == 0 {
		eg.UpCount = 2
	}
	if err := h.DB.Create(&eg).Error; err != nil {
		h.serverError(c, "创建出口", err)
		return
	}
	h.Audit.Record(h.username(c), "egress_create", fmt.Sprintf("创建出口[%s]（%s，优先级 %d，权重 %d）", eg.Name, eg.Iface, eg.Priority, eg.Weight), h.clientIP(c))
	c.JSON(200, gin.H{"id": eg.ID})
}

func (h *handlers) updateEgress(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var eg model.Egress
	if err := h.DB.First(&eg, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出口不存在"})
		return
	}
	var in egressInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "请求体格式错误"})
		return
	}
	if err := h.validateEgress(&in, &eg); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	ne := in.toEgress()
	eg.Name, eg.GatewayV4, eg.GatewayV6 = ne.Name, ne.GatewayV4, ne.GatewayV6
	eg.Priority, eg.Weight = ne.Priority, ne.Weight
	eg.ProbeMode, eg.ProbeTarget = ne.ProbeMode, ne.ProbeTarget
	eg.IntervalSec, eg.FailCount, eg.UpCount = ne.IntervalSec, ne.FailCount, ne.UpCount
	if in.Enabled != nil {
		eg.Enabled = *in.Enabled
	}
	if err := h.DB.Save(&eg).Error; err != nil {
		h.serverError(c, "保存出口", err)
		return
	}
	h.reapplyEgress()
	h.Audit.Record(h.username(c), "egress_update", fmt.Sprintf("更新出口[%s]", eg.Name), h.clientIP(c))
	c.JSON(200, gin.H{"id": eg.ID})
}

func (h *handlers) deleteEgress(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var eg model.Egress
	if err := h.DB.First(&eg, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出口不存在"})
		return
	}
	// 引用检查：规则绑定该出口的需先解绑（契约 40007）
	var rules []model.ForwardRule
	h.DB.Where("protocol = ? AND enabled = ?", "snat", true).Find(&rules)
	affected := []uint{}
	for _, r := range rules {
		for _, eid := range egressIDsOfRuleAPI(r) {
			if eid == eg.ID {
				affected = append(affected, r.ID)
				break
			}
		}
	}
	if len(affected) > 0 {
		c.JSON(400, gin.H{"error": fmt.Sprintf("出口仍被 %d 条规则引用（%v），请先在规则中解绑", len(affected), affected)})
		return
	}
	if err := h.DB.Delete(&eg).Error; err != nil {
		h.serverError(c, "删除出口", err)
		return
	}
	h.reapplyEgress()
	h.Audit.Record(h.username(c), "egress_delete", fmt.Sprintf("删除出口[%s]", eg.Name), h.clientIP(c))
	c.JSON(200, gin.H{"ok": true})
}

// probeEgress 手动探测（契约 API-E5：不影响状态机）。
func (h *handlers) probeEgress(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var eg model.Egress
	if err := h.DB.First(&eg, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "出口不存在"})
		return
	}
	ok, latency, reason := proxy.ProbeEgressOnce(eg)
	c.JSON(200, gin.H{"up": ok, "latency_ms": latency, "reason": reason})
}

// reapplyEgress 出口变更后的规则重算。
func (h *handlers) reapplyEgress() {
	h.Mgr.ReapplySnatRules()
}

// egressIDsOfRuleAPI 解析规则的出口绑定（API 层防循环导入的本地实现）。
func egressIDsOfRuleAPI(r model.ForwardRule) []uint {
	s := strings.TrimSpace(r.EgressIDs)
	if s == "" {
		return nil
	}
	var ids []uint
	_ = jsonUnmarshalUints(s, &ids)
	return ids
}

func jsonUnmarshalUints(s string, out *[]uint) error {
	return json.Unmarshal([]byte(s), out)
}
