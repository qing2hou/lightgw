package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"haproxyweb/internal/platform/caps"
)

type fakeStatus struct{ snap StatusSnapshot }

func (f *fakeStatus) Status() StatusSnapshot { return f.snap }

func capsWith(tcAvailable bool) caps.Caps {
	return caps.Caps{
		Nftables:    caps.Status{Available: true, Detail: "ok"},
		Conntrack:   caps.Status{Available: true, Detail: "ok"},
		Tc:          caps.Status{Available: tcAvailable, Detail: pick(tcAvailable, "ok", "tc 不可用（缺 iproute2）")},
		Ifb:         caps.Status{Available: true, Detail: "ok"},
		CapNetAdmin: caps.Status{Available: true, Detail: "ok"},
		SqliteWAL:   caps.Status{Available: true, Detail: "ok"},
		PerSrcLimit: caps.Status{Available: tcAvailable, Detail: pick(tcAvailable, "ok", "tc 不可用，所有限速均不生效")},
	}
}

func pick(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// TestStatusShowsTcUnavailable DoD：tc 缺失时 /api/status 显示 unavailable。
func TestStatusShowsTcUnavailable(t *testing.T) {
	r := setup(nil, nil, nil)
	// setup 里没注入 Status，先验证 503
	w := doReq(r, http.MethodGet, "/api/status", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("未注入 Status 时应 503，实际 %d", w.Code)
	}

	// 注入一个「tc 不可用」的快照
	r2 := setupWithStatus(nil, nil, nil, &fakeStatus{snap: StatusSnapshot{
		Version:  "test",
		Caps:     capsWith(false),
		Rules:    3,
		Sessions: 7,
	}})
	w = doReq(r2, http.MethodGet, "/api/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d: %s", w.Code, w.Body.String())
	}
	body := decode(t, w)
	data := body["data"].(map[string]any)
	capsObj := data["caps"].(map[string]any)
	tc := capsObj["tc"].(map[string]any)
	if tc["available"].(bool) {
		t.Fatal("★ tc 缺失时 /api/status 的 caps.tc.available 必须为 false")
	}
	if !strings.Contains(tc["detail"].(string), "iproute2") {
		t.Fatalf("detail 应给出修复线索，实际 %q", tc["detail"])
	}
	// per_src_limit 也必须同步降级
	psl := capsObj["per_src_limit"].(map[string]any)
	if psl["available"].(bool) {
		t.Fatal("★ tc 缺失时 per_src_limit 必须同步为 false")
	}
}

// TestStatusAllAvailable 全可用时无降级标记。
func TestStatusAllAvailable(t *testing.T) {
	r := setupWithStatus(nil, nil, nil, &fakeStatus{snap: StatusSnapshot{
		Version: "test", Caps: capsWith(true),
	}})
	w := doReq(r, http.MethodGet, "/api/status", "")
	body := decode(t, w)
	data := body["data"].(map[string]any)
	capsObj := data["caps"].(map[string]any)
	tc := capsObj["tc"].(map[string]any)
	if !tc["available"].(bool) {
		t.Fatal("tc 应可用")
	}
}

// TestCapabilitiesEndpoint /api/capabilities 返回能力与警告。
func TestCapabilitiesEndpoint(t *testing.T) {
	r := setupWithStatus(nil, nil, nil, &fakeStatus{snap: StatusSnapshot{
		Caps: capsWith(false),
	}})
	w := doReq(r, http.MethodGet, "/api/capabilities", "")
	if w.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d", w.Code)
	}
	data := decode(t, w)["data"].(map[string]any)
	warns := data["warnings"].([]any)
	if len(warns) == 0 {
		t.Fatal("tc 不可用时 warnings 不应为空")
	}
	if data["critical"].(bool) {
		t.Fatal("tc 缺失不是 critical（只有 nftables 缺失才是）")
	}
}

// TestCapabilitiesCritical nftables 缺失时必须标记 critical。
func TestCapabilitiesCritical(t *testing.T) {
	c := capsWith(true)
	c.Nftables = caps.Status{Available: false, Detail: "无法建立 nft 表"}
	r := setupWithStatus(nil, nil, nil, &fakeStatus{snap: StatusSnapshot{Caps: c}})
	w := doReq(r, http.MethodGet, "/api/capabilities", "")
	data := decode(t, w)["data"].(map[string]any)
	if !data["critical"].(bool) {
		t.Fatal("★ nftables 缺失必须是 critical")
	}
}

// TestStatusNotLeakingToHealthz /status 与 /healthz 的职责分工（D-12）。
//
// 本包只提供 /api/status；/healthz 由旧 api 包提供且不鉴权。
// 这个测试锁住「详细状态不进 healthz」这条边界在**本包的路径命名**上：
// 状态接口必须在 /api/ 下（会被鉴权中间件覆盖）。
func TestStatusPathUnderAPI(t *testing.T) {
	r := setupWithStatus(nil, nil, nil, &fakeStatus{snap: StatusSnapshot{
		Caps: capsWith(true),
	}})
	// /status（不带 /api 前缀）不应存在
	w := doReq(r, http.MethodGet, "/status", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("★ /status 不应存在（详细信息必须在 /api 下受鉴权保护），实际 %d", w.Code)
	}
}
