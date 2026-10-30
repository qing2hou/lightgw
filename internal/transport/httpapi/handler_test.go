package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/app/policyapp"
	"haproxyweb/internal/app/sessionapp"
)

func init() { gin.SetMode(gin.TestMode) }

// ---- 测试替身 ----

type fakePolicySvc struct {
	setCalls []struct {
		ID      uint
		Enabled bool
	}
	deleteCalls []uint
	res         *policyapp.EnableResult
	killed      int
	err         error
}

func (f *fakePolicySvc) SetEnabled(ctx context.Context, id uint, enabled bool, actor, ip string) (*policyapp.EnableResult, error) {
	f.setCalls = append(f.setCalls, struct {
		ID      uint
		Enabled bool
	}{id, enabled})
	if f.err != nil {
		return nil, f.err
	}
	if f.res != nil {
		return f.res, nil
	}
	return &policyapp.EnableResult{ID: id, Enabled: enabled, KilledSessions: 3}, nil
}

func (f *fakePolicySvc) Delete(ctx context.Context, id uint, actor, ip string) (int, error) {
	f.deleteCalls = append(f.deleteCalls, id)
	if f.err != nil {
		return 0, f.err
	}
	return f.killed, nil
}

type fakeSessionSvc struct {
	batchIDs []string
	groupID  uint
	prefixes []netip.Prefix
	res      *sessionapp.BatchResult
	killed   int
	err      error
}

func (f *fakeSessionSvc) KillBatch(ctx context.Context, ids []string, actor, ip string) (*sessionapp.BatchResult, error) {
	f.batchIDs = ids
	if f.err != nil {
		return nil, f.err
	}
	if f.res != nil {
		return f.res, nil
	}
	return &sessionapp.BatchResult{Killed: ids}, nil
}

func (f *fakeSessionSvc) KillByACLGroup(ctx context.Context, gid uint, pfx []netip.Prefix, actor, ip string) (int, error) {
	f.groupID = gid
	f.prefixes = pfx
	if f.err != nil {
		return 0, f.err
	}
	return f.killed, nil
}

// setup 建一个挂了本包路由的测试引擎，并注入调用者身份。
func setup(p PolicyService, s SessionService, prefixes func(context.Context, uint) ([]netip.Prefix, error)) *gin.Engine {
	return setupWithStatus(p, s, prefixes, nil)
}

// setupWithStatus 是带状态服务的版本。
func setupWithStatus(p PolicyService, s SessionService,
	prefixes func(context.Context, uint) ([]netip.Prefix, error),
	st StatusProvider) *gin.Engine {
	r := gin.New()
	// 模拟鉴权中间件：注入 username
	r.Use(func(c *gin.Context) {
		c.Set("username", "tester")
		c.Next()
	})
	h := &Handler{Policy: p, Session: s, ACLGroupPrefixes: prefixes, Status: st}
	h.Register(r)
	return r
}

func doReq(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var rd *strings.Reader
	if body == "" {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是 JSON: %v（原文 %s）", err, w.Body.String())
	}
	return out
}

// ---- 测试 ----

// TestDisablePolicyEndpoint 「禁用策略」接口：转发到 app 层且返回踢会话数。
//
// 这是 §8.2 点名缺失的接口之一（旧代码策略只能删不能停）。
func TestDisablePolicyEndpoint(t *testing.T) {
	svc := &fakePolicySvc{res: &policyapp.EnableResult{
		ID: 7, Enabled: false, KilledSessions: 42,
	}}
	r := setup(svc, nil, nil)

	w := doReq(r, http.MethodPost, "/api/fw-policies/7/disable", "")
	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", w.Code, w.Body.String())
	}
	// handler 必须把 enabled=false 传下去
	if len(svc.setCalls) != 1 {
		t.Fatalf("应调用 1 次 SetEnabled，实际 %d", len(svc.setCalls))
	}
	if svc.setCalls[0].ID != 7 || svc.setCalls[0].Enabled != false {
		t.Fatalf("参数错误: %+v", svc.setCalls[0])
	}
	body := decode(t, w)
	if body["code"].(float64) != CodeOK {
		t.Fatalf("code 应为 0，实际 %v", body["code"])
	}
	data := body["data"].(map[string]any)
	if data["killed_sessions"].(float64) != 42 {
		t.Fatalf("killed_sessions 应为 42，实际 %v", data["killed_sessions"])
	}
	if data["enabled"].(bool) {
		t.Fatal("enabled 应为 false")
	}
}

// TestEnablePolicyEndpoint 启用接口。
func TestEnablePolicyEndpoint(t *testing.T) {
	svc := &fakePolicySvc{res: &policyapp.EnableResult{ID: 7, Enabled: true}}
	r := setup(svc, nil, nil)
	w := doReq(r, http.MethodPost, "/api/fw-policies/7/enable", "")
	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d", w.Code)
	}
	if len(svc.setCalls) != 1 || !svc.setCalls[0].Enabled {
		t.Fatalf("应以 enabled=true 调用，实际 %+v", svc.setCalls)
	}
}

// TestPolicyBadID 非法 ID 返回 400。
func TestPolicyBadID(t *testing.T) {
	r := setup(&fakePolicySvc{}, nil, nil)
	for _, path := range []string{
		"/api/fw-policies/abc/disable",
		"/api/fw-policies/0/disable",
	} {
		w := doReq(r, http.MethodPost, path, "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s 应 400，实际 %d", path, w.Code)
		}
		body := decode(t, w)
		if body["code"].(float64) != CodeBadRequest {
			t.Fatalf("%s 的 code 应为 %d，实际 %v", path, CodeBadRequest, body["code"])
		}
	}
}

// TestPolicyNotFound 不存在返回 404。
func TestPolicyNotFound(t *testing.T) {
	svc := &fakePolicySvc{err: policyapp.ErrNotFound}
	r := setup(svc, nil, nil)
	w := doReq(r, http.MethodPost, "/api/fw-policies/99/disable", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("应 404，实际 %d: %s", w.Code, w.Body.String())
	}
}

// TestDeletePolicyEndpoint 删除接口转发并返回踢会话数。
func TestDeletePolicyEndpoint(t *testing.T) {
	svc := &fakePolicySvc{killed: 5}
	r := setup(svc, nil, nil)
	w := doReq(r, http.MethodDelete, "/api/fw-policies/3", "")
	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", w.Code, w.Body.String())
	}
	if len(svc.deleteCalls) != 1 || svc.deleteCalls[0] != 3 {
		t.Fatalf("应以 id=3 调用 Delete，实际 %v", svc.deleteCalls)
	}
	data := decode(t, w)["data"].(map[string]any)
	if data["killed_sessions"].(float64) != 5 {
		t.Fatalf("killed_sessions 应为 5，实际 %v", data["killed_sessions"])
	}
}

// TestKillBatchEndpoint 批量踢会话接口（§8.2 缺失接口之二）。
func TestKillBatchEndpoint(t *testing.T) {
	svc := &fakeSessionSvc{res: &sessionapp.BatchResult{
		Killed:   []string{"a", "b"},
		Failed:   map[string]string{"bad": "掐断失败"},
		NotFound: []string{"gone"},
	}}
	r := setup(nil, svc, nil)
	w := doReq(r, http.MethodPost, "/api/sessions/kill-batch", `{"ids":["a","b","bad","gone"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", w.Code, w.Body.String())
	}
	if len(svc.batchIDs) != 4 {
		t.Fatalf("应转发 4 个 ID，实际 %d", len(svc.batchIDs))
	}
	data := decode(t, w)["data"].(map[string]any)
	if len(data["killed"].([]any)) != 2 {
		t.Fatalf("killed 应为 2 条，实际 %v", data["killed"])
	}
	if len(data["not_found"].([]any)) != 1 {
		t.Fatalf("not_found 应为 1 条，实际 %v", data["not_found"])
	}
	if len(data["failed"].(map[string]any)) != 1 {
		t.Fatalf("failed 应为 1 条，实际 %v", data["failed"])
	}
}

// TestKillBatchBadBody 请求体非法返回 400。
func TestKillBatchBadBody(t *testing.T) {
	r := setup(nil, &fakeSessionSvc{}, nil)
	for _, body := range []string{"", "not-json", `{"ids":"不是数组"}`} {
		w := doReq(r, http.MethodPost, "/api/sessions/kill-batch", body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body=%q 应 400，实际 %d", body, w.Code)
		}
	}
}

// TestKickACLGroupEndpoint 名单组踢会话（§8.2 缺失接口之三）。
func TestKickACLGroupEndpoint(t *testing.T) {
	svc := &fakeSessionSvc{killed: 12}
	pfx := []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}
	r := setup(nil, svc, func(ctx context.Context, gid uint) ([]netip.Prefix, error) {
		if gid != 4 {
			t.Fatalf("应以 groupID=4 查询，实际 %d", gid)
		}
		return pfx, nil
	})
	w := doReq(r, http.MethodPost, "/api/acl-groups/4/kick-sessions", "")
	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", w.Code, w.Body.String())
	}
	if len(svc.prefixes) != 1 || svc.prefixes[0].String() != "192.168.10.0/24" {
		t.Fatalf("网段未正确传递: %v", svc.prefixes)
	}
	data := decode(t, w)["data"].(map[string]any)
	if data["killed_sessions"].(float64) != 12 {
		t.Fatalf("killed_sessions 应为 12，实际 %v", data["killed_sessions"])
	}
}

// TestKickACLGroupNotFound 名单组不存在返回 404。
func TestKickACLGroupNotFound(t *testing.T) {
	svc := &fakeSessionSvc{}
	r := setup(nil, svc, func(ctx context.Context, gid uint) ([]netip.Prefix, error) {
		return nil, errors.New("名单组不存在")
	})
	w := doReq(r, http.MethodPost, "/api/acl-groups/99/kick-sessions", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("应 404，实际 %d: %s", w.Code, w.Body.String())
	}
}

// TestServicesNotReady 服务未注入时返回 503 而不是 panic。
func TestServicesNotReady(t *testing.T) {
	r := setup(nil, nil, nil)
	cases := []struct{ method, path, body string }{
		{http.MethodPost, "/api/fw-policies/1/disable", ""},
		{http.MethodPost, "/api/fw-policies/1/enable", ""},
		{http.MethodDelete, "/api/fw-policies/1", ""},
		{http.MethodPost, "/api/sessions/kill-batch", `{"ids":["a"]}`},
		{http.MethodPost, "/api/acl-groups/1/kick-sessions", ""},
	}
	for _, c := range cases {
		w := doReq(r, c.method, c.path, c.body)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s 应 503，实际 %d", c.method, c.path, w.Code)
		}
		body := decode(t, w)
		if body["code"].(float64) != CodeUnavailable {
			t.Fatalf("code 应为 %d，实际 %v", CodeUnavailable, body["code"])
		}
	}
}

// TestErrorResponseShape 错误响应必须是 {code, message} 且 message 为中文。
func TestErrorResponseShape(t *testing.T) {
	r := setup(&fakePolicySvc{err: errors.New("重装策略失败: nft 拒绝")}, nil, nil)
	w := doReq(r, http.MethodPost, "/api/fw-policies/1/disable", "")
	body := decode(t, w)
	if _, ok := body["code"]; !ok {
		t.Fatal("错误响应必须含 code 字段")
	}
	if _, ok := body["message"]; !ok {
		t.Fatal("错误响应必须含 message 字段")
	}
	if _, ok := body["error"]; ok {
		t.Fatal("★ 不许保留旧的 {error: ...} 结构（§8.6 定死 {code,message,data}）")
	}
	msg := body["message"].(string)
	if msg == "" {
		t.Fatal("message 不应为空")
	}
	// 不含英文 SQL/路径关键字
	for _, leak := range []string{"SELECT", "/proc/", "goroutine", ".go:"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("★ message 泄露内部细节 %q: %q", leak, msg)
		}
	}
}
