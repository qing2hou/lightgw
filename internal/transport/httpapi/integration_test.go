package httpapi

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"haproxyweb/internal/app/policyapp"
	"haproxyweb/internal/app/sessionapp"
)

// liveSessionStore 模拟一份「仍在服务中」的会话集合。
//
// 用于验证「禁用策略后已建会话在 1 秒内消失」——
// 这是验收文档「禁用策略后流量立即断开」的端到端版本。
type liveSessionStore struct {
	mu       sync.Mutex
	sessions map[string]string // id -> 源 IP
	killedAt map[string]time.Time
}

func newLiveSessionStore(ips ...string) *liveSessionStore {
	s := &liveSessionStore{
		sessions: map[string]string{},
		killedAt: map[string]time.Time{},
	}
	for _, ip := range ips {
		s.sessions[ip] = ip
	}
	return s
}

func (s *liveSessionStore) List(ctx context.Context) ([]sessionapp.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sessionapp.Session, 0, len(s.sessions))
	for id, ip := range s.sessions {
		out = append(out, sessionapp.Session{
			ID:      id,
			SrcAddr: netip.MustParseAddr(ip),
		})
	}
	return out, nil
}

func (s *liveSessionStore) Kill(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return sessionapp.ErrNotFound
	}
	delete(s.sessions, id)
	s.killedAt[id] = time.Now()
	return nil
}

// Live 返回当前存活的会话数。
func (s *liveSessionStore) Live() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// policyKiller 把 policyapp.SessionKiller 适配到 liveSessionStore。
type policyKiller struct {
	store  *liveSessionStore
	prefix []netip.Prefix
	calls  atomic.Int64
}

func (k *policyKiller) KillByPolicy(ctx context.Context, p policyapp.Policy) (int, error) {
	k.calls.Add(1)
	sessions, _ := k.store.List(ctx)
	n := 0
	for _, s := range sessions {
		for _, pfx := range k.prefix {
			if pfx.Contains(s.SrcAddr) {
				if err := k.store.Kill(ctx, s.ID); err == nil {
					n++
				}
				break
			}
		}
	}
	return n, nil
}

type policyStoreAdapter struct {
	pol     policyapp.Policy
	enabled bool
}

func (s *policyStoreAdapter) GetPolicy(ctx context.Context, id uint) (*policyapp.Policy, error) {
	p := s.pol
	p.ID = id
	p.Enabled = s.enabled
	return &p, nil
}
func (s *policyStoreAdapter) ListPolicies(ctx context.Context) ([]policyapp.Policy, error) {
	return []policyapp.Policy{s.pol}, nil
}
func (s *policyStoreAdapter) SetEnabled(ctx context.Context, id uint, enabled bool) error {
	s.enabled = enabled
	return nil
}
func (s *policyStoreAdapter) DeletePolicy(ctx context.Context, id uint) error { return nil }

type noopInstaller struct{ calls atomic.Int64 }

func (n *noopInstaller) ReinstallPolicies(ctx context.Context) error {
	n.calls.Add(1)
	return nil
}

type nopAudit struct{}

func (nopAudit) Record(user, action, detail, clientIP string) {}

// TestDisablePolicyKillsSessionsWithin1s 「禁用策略 → 已建会话在 1 秒内断开」。
//
// 这是 S4 的核心验收用例（playbook §8.5 第 2 条）。走完整的
// HTTP → policyapp → SessionKiller 链路，不是只测 app 层。
//
// 旧实现的问题：newFlowGuard() 只拦 ct state new，已建会话最长存活 86400s，
// 所以「禁用后流量立即断开」直接不通过。
func TestDisablePolicyKillsSessionsWithin1s(t *testing.T) {
	store := newLiveSessionStore(
		"192.168.10.152", "192.168.10.151", "10.0.0.5",
	)
	killer := &policyKiller{
		store:  store,
		prefix: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")},
	}
	pstore := &policyStoreAdapter{
		pol: policyapp.Policy{
			Name: "block-clients", Action: "accept",
		},
		enabled: true,
	}
	install := &noopInstaller{}
	pSvc := policyapp.New(pstore, killer, install, nopAudit{})

	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("username", "tester"); c.Next() })
	h := &Handler{Policy: pSvc}
	h.Register(r)

	if store.Live() != 3 {
		t.Fatalf("初始应有 3 条会话，实际 %d", store.Live())
	}

	start := time.Now()
	w := doReq(r, http.MethodPost, "/api/fw-policies/1/disable", "")
	elapsed := time.Since(start)

	if w.Code != http.StatusOK {
		t.Fatalf("禁用失败: %d %s", w.Code, w.Body.String())
	}
	// ★ 核心断言 1：匹配的 2 条会话必须消失
	if got := store.Live(); got != 1 {
		t.Fatalf("★ 禁用后应只剩 1 条（10.0.0.5），实际 %d"+
			"（旧缺陷：已建会话会存活到 conntrack 超时）", got)
	}
	// ★ 核心断言 2：必须在 1 秒内完成
	if elapsed > time.Second {
		t.Fatalf("★ 禁用+踢会话耗时 %v，超过 1 秒门槛", elapsed)
	}
	// 断言 3：未匹配的会话必须保留（不能误杀）
	sessions, _ := store.List(context.Background())
	if len(sessions) != 1 || sessions[0].SrcAddr.String() != "10.0.0.5" {
		t.Fatalf("应只保留 10.0.0.5，实际 %+v", sessions)
	}
	// 断言 4：规则必须重装
	if install.calls.Load() != 1 {
		t.Fatalf("应重装 1 次规则，实际 %d", install.calls.Load())
	}
	// 断言 5：响应里必须报告踢掉的条数
	data := decode(t, w)["data"].(map[string]any)
	if data["killed_sessions"].(float64) != 2 {
		t.Fatalf("应报告踢 2 条，实际 %v", data["killed_sessions"])
	}
}

// TestDisableAllSessionsGone 全部匹配时所有会话必须清空。
func TestDisableAllSessionsGone(t *testing.T) {
	store := newLiveSessionStore("192.168.10.1", "192.168.10.2")
	killer := &policyKiller{
		store:  store,
		prefix: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")},
	}
	pstore := &policyStoreAdapter{pol: policyapp.Policy{Name: "p", Action: "drop"}, enabled: true}
	pSvc := policyapp.New(pstore, killer, &noopInstaller{}, nopAudit{})

	r := gin.New()
	h := &Handler{Policy: pSvc}
	h.Register(r)
	w := doReq(r, http.MethodPost, "/api/fw-policies/1/disable", "")
	if w.Code != http.StatusOK {
		t.Fatalf("失败: %d", w.Code)
	}
	if got := store.Live(); got != 0 {
		t.Fatalf("全部匹配时应清空，实际剩 %d 条", got)
	}
}

// TestACLGroupKickEndToEnd 名单组变更后踢会话的端到端验证。
func TestACLGroupKickEndToEnd(t *testing.T) {
	store := newLiveSessionStore("192.168.10.152", "10.0.0.5")
	sSvc := sessionapp.New(store, store, nopAudit{})

	r := gin.New()
	h := &Handler{
		Session: sSvc,
		ACLGroupPrefixes: func(ctx context.Context, gid uint) ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}, nil
		},
	}
	h.Register(r)

	w := doReq(r, http.MethodPost, "/api/acl-groups/1/kick-sessions", "")
	if w.Code != http.StatusOK {
		t.Fatalf("失败: %d %s", w.Code, w.Body.String())
	}
	if got := store.Live(); got != 1 {
		t.Fatalf("应只剩 10.0.0.5，实际 %d 条", got)
	}
}

// TestKillBatchEndToEnd 批量踢会话的端到端验证。
func TestKillBatchEndToEnd(t *testing.T) {
	store := newLiveSessionStore("192.168.10.152", "192.168.10.151", "10.0.0.5")
	sSvc := sessionapp.New(store, store, nopAudit{})
	r := gin.New()
	h := &Handler{Session: sSvc}
	h.Register(r)

	// 踢两个 + 一个不存在的
	w := doReq(r, http.MethodPost, "/api/sessions/kill-batch",
		`{"ids":["192.168.10.152","192.168.10.151","9.9.9.9"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("失败: %d %s", w.Code, w.Body.String())
	}
	if got := store.Live(); got != 1 {
		t.Fatalf("应剩 1 条，实际 %d", got)
	}
	data := decode(t, w)["data"].(map[string]any)
	if len(data["killed"].([]any)) != 2 {
		t.Fatalf("应成功 2 条，实际 %v", data["killed"])
	}
	if len(data["not_found"].([]any)) != 1 {
		t.Fatalf("应有 1 条不存在，实际 %v", data["not_found"])
	}
}
