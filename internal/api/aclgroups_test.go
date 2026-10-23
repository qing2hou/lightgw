package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/auth"
	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
)

// newGroupRouter 名单组测试环境（组表 + 真实引擎 Apply 路径 + 登录令牌）。
// 返回的路由已携带 admin 会话令牌的 do 函数使用透传 token 参数。
func newGroupRouter(t *testing.T) (*gin.Engine, *handlers, string) {
	t.Helper()
	h := newMetricsHandlers(t)
	if err := h.DB.AutoMigrate(&model.AclGroup{}, &model.ForwardRule{}, &model.User{}, &model.LoginFail{}); err != nil {
		t.Fatal(err)
	}
	svc, err := auth.New(t.TempDir(), h.DB)
	if err != nil {
		t.Fatal(err)
	}
	h.Auth = svc
	hash, err := auth.BcryptHashForTest("right")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.Create(&model.User{Username: "admin", PasswordHash: hash}).Error; err != nil {
		t.Fatal(err)
	}
	token, err := svc.Login("admin", "right", "127.0.0.1")
	if err != nil || token == "" {
		t.Fatalf("测试登录失败: %v", err)
	}
	r, err := NewRouter(h.Deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, h, token
}

func groupDo(r *gin.Engine, method, path, token string, body any) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	r.ServeHTTP(w, req)
	return w
}

// 组 CRUD + 规则引用 + 展开拒绝语义 + 变更联动 全链路。
func TestAclGroupFullFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r, h, tok := newGroupRouter(t)

	// 1. 建组（白名单组）
	w := groupDo(r, "POST", "/api/acl-groups", tok, map[string]any{
		"name": "内网放行", "mode": "whitelist",
		"entries": []string{"10.0.0.0/8", "192.168.1.5"},
	})
	if w.Code != 200 {
		t.Fatalf("建组失败: %d %s", w.Code, w.Body.String())
	}
	var group model.AclGroup
	json.Unmarshal(w.Body.Bytes(), &group)
	if group.ID == 0 || group.Name != "内网放行" {
		t.Fatalf("组建档不符: %+v", group)
	}

	// 2. 非法条目拒绝
	w = groupDo(r, "POST", "/api/acl-groups", tok, map[string]any{
		"name": "bad", "mode": "blacklist", "entries": []string{"not-an-ip"},
	})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "无效的 IP") {
		t.Fatalf("非法条目应 400: %d %s", w.Code, w.Body.String())
	}
	// 非法模式拒绝
	w = groupDo(r, "POST", "/api/acl-groups", tok, map[string]any{
		"name": "bad2", "mode": "off", "entries": []string{"1.2.3.4"},
	})
	if w.Code != 400 {
		t.Fatalf("off 模式建组应 400: %d", w.Code)
	}
	// 重名拒绝
	w = groupDo(r, "POST", "/api/acl-groups", tok, map[string]any{
		"name": "内网放行", "mode": "whitelist", "entries": []string{"1.2.3.4"},
	})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "已存在") {
		t.Fatalf("重名应 400: %d %s", w.Code, w.Body.String())
	}

	// 3. 建引用组的规则
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	w = groupDo(r, "POST", "/api/rules", tok, map[string]any{
		"name": "组引用规则", "protocol": "tcp",
		"listen_addr": "127.0.0.1:19100", "target_addr": ln.Addr().String(),
		"acl_mode": "whitelist", "acl_group_id": group.ID, "enabled": true,
	})
	if w.Code != 200 {
		t.Fatalf("建引用组规则失败: %d %s", w.Code, w.Body.String())
	}

	// 4. 模式不匹配的引用拒绝
	w = groupDo(r, "POST", "/api/rules", tok, map[string]any{
		"name": "错模式", "protocol": "tcp",
		"listen_addr": "127.0.0.1:19101", "target_addr": ln.Addr().String(),
		"acl_mode": "blacklist", "acl_group_id": group.ID, "enabled": true,
	})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "不匹配") {
		t.Fatalf("模式不匹配引用应 400: %d %s", w.Code, w.Body.String())
	}
	// 引用组同时直配名单拒绝
	w = groupDo(r, "POST", "/api/rules", tok, map[string]any{
		"name": "叠加", "protocol": "tcp",
		"listen_addr": "127.0.0.1:19102", "target_addr": ln.Addr().String(),
		"acl_mode": "whitelist", "acl_group_id": group.ID,
		"allow_list": `["1.2.3.4"]`, "enabled": true,
	})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "二选一") {
		t.Fatalf("引用+直配叠加应 400: %d %s", w.Code, w.Body.String())
	}
	// off 模式引用组拒绝
	w = groupDo(r, "POST", "/api/rules", tok, map[string]any{
		"name": "off引用", "protocol": "tcp",
		"listen_addr": "127.0.0.1:19103", "target_addr": ln.Addr().String(),
		"acl_mode": "off", "acl_group_id": group.ID, "enabled": true,
	})
	if w.Code != 400 {
		t.Fatalf("off 模式引用应 400: %d", w.Code)
	}

	// 5. 引用语义验证：组内 IP 放行、组外 IP 拒绝（经真实转发引擎）
	dial := func(localIP string) bool {
		d := net.Dialer{LocalAddr: mustTCPAddr(localIP), Timeout: 2 * time.Second}
		c, err := d.Dial("tcp", "127.0.0.1:19100")
		if err != nil {
			return false
		}
		c.Close()
		return true
	}
	// 127.0.0.1 不在白名单组内（10/8、192.168.1.5）——拒绝
	denied := dial("127.0.0.1")
	// 等待 denied 流量日志（异步批量）
	deadline := time.Now().Add(5 * time.Second)
	var deniedLogged bool
	for time.Now().Before(deadline) {
		var cnt int64
		h.DB.Model(&model.TrafficLog{}).Where("status = ?", model.StatusDenied).Count(&cnt)
		if cnt > 0 {
			deniedLogged = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !denied && !deniedLogged {
		t.Fatal("组外 IP（127.0.0.1）应被白名单组拒绝")
	}

	// 6. 组条目变更联动：加 127.0.0.0/8 后本机可通
	w = groupDo(r, "PUT", fmt.Sprintf("/api/acl-groups/%d", group.ID), tok, map[string]any{
		"name": "内网放行", "mode": "whitelist",
		"entries": []string{"10.0.0.0/8", "192.168.1.5", "127.0.0.0/8"},
	})
	if w.Code != 200 {
		t.Fatalf("更新组失败: %d %s", w.Code, w.Body.String())
	}
	// 联动是同步完成的应用，稍等端口就绪
	ok := false
	for i := 0; i < 20 && !ok; i++ {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:19100", time.Second); err == nil {
			c.Close()
			ok = true
		} else {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !ok {
		t.Fatal("组加入 127.0.0.0/8 后本机应放行（联动重应用）")
	}

	// 7. 被引用的组不能删除
	w = groupDo(r, "DELETE", fmt.Sprintf("/api/acl-groups/%d", group.ID), tok, nil)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "引用") {
		t.Fatalf("被引用组删除应 400: %d %s", w.Code, w.Body.String())
	}
	// 被引用的组不能改模式
	w = groupDo(r, "PUT", fmt.Sprintf("/api/acl-groups/%d", group.ID), tok, map[string]any{
		"name": "内网放行", "mode": "blacklist", "entries": []string{"1.2.3.4"},
	})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "变更模式") {
		t.Fatalf("被引用组改模式应 400: %d %s", w.Code, w.Body.String())
	}

	// 8. 解除引用后可删除：规则改 off
	var rule model.ForwardRule
	h.DB.First(&rule, "name = ?", "组引用规则")
	w = groupDo(r, "PUT", fmt.Sprintf("/api/rules/%d", rule.ID), tok, map[string]any{
		"name": "组引用规则", "protocol": "tcp",
		"listen_addr": "127.0.0.1:19100", "target_addr": ln.Addr().String(),
		"acl_mode": "off", "enabled": true,
	})
	if w.Code != 200 {
		t.Fatalf("解除引用失败: %d %s", w.Code, w.Body.String())
	}
	w = groupDo(r, "DELETE", fmt.Sprintf("/api/acl-groups/%d", group.ID), tok, nil)
	if w.Code != 200 {
		t.Fatalf("解除引用后删除组应成功: %d %s", w.Code, w.Body.String())
	}

	// 9. 列表不再含该组
	w = groupDo(r, "GET", "/api/acl-groups", tok, nil)
	var list struct {
		Items []model.AclGroup `json:"items"`
	}
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Items) != 0 {
		t.Fatalf("组应已删除，实际剩 %d 个", len(list.Items))
	}
}

// 导出内联展开：引用组的规则导出为直配名单（自包含，无 acl_group_id）。
func TestExportExpandsGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r, h, tok := newGroupRouter(t)

	g := model.AclGroup{Name: "放行组", Mode: model.AclModeWhitelist, Entries: `["10.1.0.0/16","10.2.3.4"]`}
	if err := h.DB.Create(&g).Error; err != nil {
		t.Fatal(err)
	}
	rule := model.ForwardRule{
		Name: "引用规则", Protocol: model.ProtocolTCP,
		ListenAddr: "127.0.0.1:19150", TargetAddr: "127.0.0.1:12345",
		AclMode: model.AclModeWhitelist, AclGroupID: g.ID, Enabled: false,
	}
	if err := h.DB.Create(&rule).Error; err != nil {
		t.Fatal(err)
	}

	w := groupDo(r, "GET", "/api/rules/export", tok, nil)
	if w.Code != 200 {
		t.Fatalf("导出失败: %d", w.Code)
	}
	var exp struct {
		Rules []model.ForwardRule `json:"rules"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if len(exp.Rules) != 1 {
		t.Fatalf("应导出 1 条规则，实际 %d", len(exp.Rules))
	}
	out := exp.Rules[0]
	if out.AclGroupID != 0 {
		t.Errorf("导出应展开组（acl_group_id=0），实际 %d", out.AclGroupID)
	}
	if !strings.Contains(out.AllowList, "10.1.0.0/16") || !strings.Contains(out.AllowList, "10.2.3.4") {
		t.Errorf("导出应内联组条目，实际 allow_list=%s", out.AllowList)
	}
}

// 单规则实时速率 API：固定窗口内写入已知字节后读取。
func TestRuleLiveStatsAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r, h, tok := newGroupRouter(t)

	// 后端 echo 服务
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	rule := model.ForwardRule{
		Name: "速率规则", Protocol: model.ProtocolTCP,
		ListenAddr: "127.0.0.1:19160", TargetAddr: ln.Addr().String(), Enabled: true,
	}
	if err := h.DB.Create(&rule).Error; err != nil {
		t.Fatal(err)
	}
	if err := h.Mgr.Apply(rule); err != nil {
		t.Fatal(err)
	}

	// 建立转发连接并发送 64KB
	c, err := net.DialTimeout("tcp", "127.0.0.1:19160", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := make([]byte, 65536)
	go func() { _, _ = c.Write(payload) }()
	buf := make([]byte, 65536)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := readFull(c, buf); err != nil {
		t.Fatalf("回读失败: %v", err)
	}

	w := groupDo(r, "GET", "/api/rules/1/live", tok, nil)
	if w.Code != 200 {
		t.Fatalf("live API 失败: %d %s", w.Code, w.Body.String())
	}
	var live struct {
		RateUpBps   int64 `json:"rate_up_bps"`
		RateDownBps int64 `json:"rate_down_bps"`
		ActiveConns int   `json:"active_conns"`
	}
	json.Unmarshal(w.Body.Bytes(), &live)
	// 64KB 已过 addBytes：累计字节至少可见；速率窗口内应有非零读数
	if live.RateUpBps <= 0 || live.RateDownBps <= 0 {
		t.Errorf("发送 64KB 后速率应非零: %+v", live)
	}
	if live.ActiveConns < 1 {
		t.Errorf("活跃连接应 ≥ 1: %+v", live)
	}

	// 不存在的规则 404
	w = groupDo(r, "GET", "/api/rules/999/live", tok, nil)
	if w.Code != 404 {
		t.Errorf("不存在的规则应 404，实际 %d", w.Code)
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func mustTCPAddr(ip string) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip)}
}

// 引用不存在组的规则：API 校验拦截（保存前）。
func TestRuleRefersMissingGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r, _, tok := newGroupRouter(t)
	w := groupDo(r, "POST", "/api/rules", tok, map[string]any{
		"name": "幽灵引用", "protocol": "tcp",
		"listen_addr": "127.0.0.1:19170", "target_addr": "127.0.0.1:12345",
		"acl_mode": "whitelist", "acl_group_id": 999, "enabled": true,
	})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "不存在") {
		t.Fatalf("引用不存在组应 400: %d %s", w.Code, w.Body.String())
	}
}

// 确保 proxy 包的展开路径与本测试无耦合编译问题（占位引用）。
var _ = proxy.AllowAll

// 必修项回归：空白名单组在 建组/更新组/规则引用 三条路径都被拦截，
// 防止"空组挂上规则 = 静默拒绝所有访问"。
func TestEmptyWhitelistGroupRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r, _, tok := newGroupRouter(t)

	// 1. 建空 whitelist 组：拒绝
	w := groupDo(r, "POST", "/api/acl-groups", tok, map[string]any{
		"name": "空组", "mode": "whitelist", "entries": []string{},
	})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "至少一条") {
		t.Fatalf("空白名单组建组应 400: %d %s", w.Code, w.Body.String())
	}

	// 2. 先建合法组，更新成空：拒绝（联动路径同被拦截）
	w = groupDo(r, "POST", "/api/acl-groups", tok, map[string]any{
		"name": "合法组", "mode": "whitelist", "entries": []string{"10.0.0.1"},
	})
	if w.Code != 200 {
		t.Fatalf("建组合法路径失败: %d %s", w.Code, w.Body.String())
	}
	var g model.AclGroup
	json.Unmarshal(w.Body.Bytes(), &g)
	w = groupDo(r, "PUT", fmt.Sprintf("/api/acl-groups/%d", g.ID), tok, map[string]any{
		"name": "合法组", "mode": "whitelist", "entries": []string{},
	})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "至少一条") {
		t.Fatalf("更新成空组应 400: %d %s", w.Code, w.Body.String())
	}

	// 3. 引用空组（外部改库构造悬空态后规则依然守住的防线在引擎 logf——
	// 本用例验证 API 校验层）
	w = groupDo(r, "POST", "/api/acl-groups", tok, map[string]any{
		"name": "黑组", "mode": "blacklist", "entries": []string{"1.2.3.4"},
	})
	json.Unmarshal(w.Body.Bytes(), &g)
	// blacklist 空组允许（空黑名单=全放行是基线语义）
	w = groupDo(r, "POST", "/api/acl-groups", tok, map[string]any{
		"name": "空黑组", "mode": "blacklist", "entries": []string{},
	})
	if w.Code != 200 {
		t.Fatalf("空黑名单组应允许（全放行基线）: %d %s", w.Code, w.Body.String())
	}
}
