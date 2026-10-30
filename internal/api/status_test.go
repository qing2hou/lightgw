package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/platform/caps"
)

// TestCapsSnapshotNilFallback 未注入 Caps 时必须返回全 false 快照而非 500。
//
// 理由：UI 显示「不可用」比 500 更有用——至少能看到是哪个能力缺失。
func TestCapsSnapshotNilFallback(t *testing.T) {
	h := &handlers{}
	snap := h.capsSnapshot()
	if snap.Nftables.Available || snap.Tc.Available || snap.PerSrcLimit.Available {
		t.Fatal("未注入时应全部为不可用")
	}
	if snap.Nftables.Detail == "" {
		t.Fatal("应给出说明（启动路径异常）")
	}
	if err := snap.Critical(); err == nil {
		t.Fatal("nftables 不可用时应 critical")
	}
}

// TestCapsEndpointTcUnavailable DoD：tc 缺失时接口返回 unavailable。
func TestCapsEndpointTcUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	snap := caps.Caps{
		Nftables:    caps.Status{Available: true},
		Conntrack:   caps.Status{Available: true},
		Tc:          caps.Status{Available: false, Detail: "tc 不可用（缺 iproute2）"},
		Ifb:         caps.Status{Available: true},
		CapNetAdmin: caps.Status{Available: true},
		SqliteWAL:   caps.Status{Available: true},
		PerSrcLimit: caps.Status{Available: false, Detail: "tc 不可用，所有限速均不生效"},
	}
	h := &handlers{Deps: Deps{Caps: &snap}}
	r := gin.New()
	r.GET("/api/capabilities", h.capabilities)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/capabilities", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 JSON: %v", err)
	}
	c := body["caps"].(map[string]any)
	tc := c["tc"].(map[string]any)
	if tc["available"].(bool) {
		t.Fatal("★ tc 缺失时 caps.tc.available 必须为 false")
	}
	warns := body["warnings"].([]any)
	if len(warns) < 2 {
		t.Fatalf("应有 tc 与 per_src_limit 两条警告，实际 %d: %v", len(warns), warns)
	}
	if body["critical"].(bool) {
		t.Fatal("tc 缺失不是 critical")
	}
}

// TestCapsEndpointAllGood 全可用时无警告。
func TestCapsEndpointAllGood(t *testing.T) {
	gin.SetMode(gin.TestMode)
	good := caps.Status{Available: true, Detail: "ok"}
	snap := caps.Caps{Nftables: good, Conntrack: good, Tc: good, Ifb: good,
		CapNetAdmin: good, SqliteWAL: good, PerSrcLimit: good}
	h := &handlers{Deps: Deps{Caps: &snap}}
	r := gin.New()
	r.GET("/api/capabilities", h.capabilities)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/capabilities", nil))

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 JSON: %v（原文 %s）", err, w.Body.String())
	}
	// warnings 必须是 []（不是 null）——前端对 null 做 .map 会抛错
	raw, exists := body["warnings"]
	if !exists {
		t.Fatalf("响应必须含 warnings 字段，原文 %s", w.Body.String())
	}
	warns, isArr := raw.([]any)
	if !isArr {
		t.Fatalf("★ warnings 必须是数组（不能是 null），实际 %T: %s", raw, w.Body.String())
	}
	if len(warns) != 0 {
		t.Fatalf("全可用时不应有警告，实际 %v", warns)
	}
}
