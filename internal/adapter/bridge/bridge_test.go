package adapterbridge

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	nftlib "github.com/google/nftables"
	"github.com/google/nftables/expr"

	"haproxyweb/internal/adapter/nftables"
	"haproxyweb/internal/compile"
	"haproxyweb/internal/control"
	"haproxyweb/internal/domain/model"
)

// memConn 是 connAPI 的最小内存实现（bridge 测试专用）。
//
// 不能复用 nftables 包里的 memConn（那是它的测试私有类型），
// 但接口 connAPI 是导出的，所以这里自己实现一份。
type memConn struct {
	mu     sync.Mutex
	chains []*nftlib.Chain
	rules  map[string][]*nftlib.Rule
	next   uint64
	// pending 暂存区（Flush 提交）
	pAdds  []pending
	pDels  []uint64
	pFlush []string
}

type pending struct {
	chain string
	exprs []any
}

func newMemConn() *memConn {
	return &memConn{rules: map[string][]*nftlib.Rule{}, next: 1}
}

func (m *memConn) AddTable(t *nftlib.Table) *nftlib.Table { return t }

func (m *memConn) AddChain(c *nftlib.Chain) *nftlib.Chain {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.chains {
		if ex.Name == c.Name {
			return c
		}
	}
	m.chains = append(m.chains, c)
	return c
}

func (m *memConn) ListChains() ([]*nftlib.Chain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*nftlib.Chain, len(m.chains))
	copy(out, m.chains)
	return out, nil
}

func (m *memConn) AddRule(r *nftlib.Rule) *nftlib.Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := ""
	if r.Chain != nil {
		name = r.Chain.Name
	}
	exprs := make([]any, len(r.Exprs))
	for i, e := range r.Exprs {
		exprs[i] = e
	}
	m.pAdds = append(m.pAdds, pending{chain: name, exprs: exprs})
	return r
}

func (m *memConn) DelRule(r *nftlib.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pDels = append(m.pDels, r.Handle)
	return nil
}

func (m *memConn) GetRules(t *nftlib.Table, c *nftlib.Chain) ([]*nftlib.Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c == nil {
		return nil, nil
	}
	src := m.rules[c.Name]
	out := make([]*nftlib.Rule, len(src))
	copy(out, src)
	return out, nil
}

func (m *memConn) FlushChain(c *nftlib.Chain) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c != nil {
		m.pFlush = append(m.pFlush, c.Name)
	}
}

func (m *memConn) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.pFlush {
		delete(m.rules, n)
	}
	if len(m.pDels) > 0 {
		del := map[uint64]bool{}
		for _, h := range m.pDels {
			del[h] = true
		}
		for name, rs := range m.rules {
			kept := rs[:0]
			for _, r := range rs {
				if !del[r.Handle] {
					kept = append(kept, r)
				}
			}
			m.rules[name] = kept
		}
	}
	for _, a := range m.pAdds {
		h := m.next
		m.next++
		exprs := make([]expr.Any, len(a.exprs))
		for i, e := range a.exprs {
			exprs[i] = e.(expr.Any)
		}
		m.rules[a.chain] = append(m.rules[a.chain], &nftlib.Rule{Handle: h, Exprs: exprs})
	}
	m.pAdds, m.pDels, m.pFlush = nil, nil, nil
	return nil
}

func (m *memConn) CloseLasting() error { return nil }

// newEngine 用内存连接建一个真实 Engine。
func newEngine(t *testing.T) *nftables.Engine {
	t.Helper()
	e, err := nftables.NewEngine(newMemConn())
	if err != nil {
		t.Fatalf("创建引擎失败: %v", err)
	}
	return e
}

// mkPlan 造一份最小可翻译的编译计划。
func mkPlan(t *testing.T, version uint64, ruleID uint) *compile.Plan {
	t.Helper()
	r := model.Rule{
		ID:       ruleID,
		Name:     "t",
		Proto:    model.ProtoTCP,
		ListenAt: netip.MustParseAddrPort("192.168.10.170:1022"),
		Backend:  netip.MustParseAddrPort("192.168.10.152:22"),
		Enabled:  true,
	}
	p, err := (&compile.Compiler{Caps: compile.Caps{TcNetlink: true}}).Compile(compile.State{
		Version: version,
		Rules:   []model.Rule{r},
		MSSv4:   compile.DefaultMSSv4,
	})
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	return p
}

// TestNftBridgeStagedFlow 桥接真实执行四阶段（用内存连接）。
func TestNftBridgeStagedFlow(t *testing.T) {
	eng := newEngine(t)
	b := NewNftBridge(eng)
	p := mkPlan(t, 1, 1)
	b.SetPlan(p)

	ctx := context.Background()
	view := &control.NftPlanView{Version: 1, RuleCount: p.Nft.RuleCount()}

	if err := b.LoadShadow(ctx, view); err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	if err := b.VerifyShadow(ctx, view); err != nil {
		t.Fatalf("自检失败: %v", err)
	}
	if err := b.CommitShadow(ctx); err != nil {
		t.Fatalf("切换失败: %v", err)
	}
	if err := b.GC(ctx); err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	// 切换后 dispatch 应恒 1 条 jump
	counts, err := eng.AllJumpCounts()
	if err != nil {
		t.Fatal(err)
	}
	for disp, n := range counts {
		if n != 1 {
			t.Fatalf("%s 的 jump 应为 1，实际 %d", disp, n)
		}
	}
}

// TestNftBridgeWithoutPlan 未 SetPlan 时 LoadShadow 必须报错（不能静默成功）。
func TestNftBridgeWithoutPlan(t *testing.T) {
	b := NewNftBridge(newEngine(t))
	err := b.LoadShadow(context.Background(), &control.NftPlanView{Version: 1, RuleCount: 1})
	if err == nil {
		t.Fatal("★ 未设置计划必须报错（静默成功会让 control 以为装好了）")
	}
}

// TestNftBridgeNilEngine nil 引擎必须报错。
func TestNftBridgeNilEngine(t *testing.T) {
	b := NewNftBridge(nil)
	if err := b.LoadShadow(context.Background(), &control.NftPlanView{Version: 1}); err == nil {
		t.Fatal("nil 引擎应报错")
	}
}

// TestNftBridgeVerifyWithoutSession 没有会话时自检/切换必须报错。
func TestNftBridgeVerifyWithoutSession(t *testing.T) {
	b := NewNftBridge(newEngine(t))
	if err := b.VerifyShadow(context.Background(), &control.NftPlanView{Version: 1}); err == nil {
		t.Fatal("无会话时自检应报错")
	}
	if err := b.CommitShadow(context.Background()); err == nil {
		t.Fatal("无会话时切换应报错")
	}
	// DropShadow / GC 在无会话时应安全返回
	if err := b.DropShadow(context.Background()); err != nil {
		t.Fatalf("无会话 DropShadow 应安全: %v", err)
	}
	if err := b.GC(context.Background()); err != nil {
		t.Fatalf("无会话 GC 应安全: %v", err)
	}
}

// TestNftBridgeDropCleansShadow 装载后 DropShadow 必须清空影子槽。
func TestNftBridgeDropCleansShadow(t *testing.T) {
	eng := newEngine(t)
	b := NewNftBridge(eng)
	p := mkPlan(t, 1, 1)
	b.SetPlan(p)
	ctx := context.Background()
	if err := b.LoadShadow(ctx, &control.NftPlanView{Version: 1, RuleCount: 1}); err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	shadow := eng.Shadow()
	// 影子槽应有规则
	hasRules := false
	for _, work := range []string{"pre", "dnat", "fwd", "snat"} {
		n, _ := eng.ChainRuleCount(work + "_" + string(shadow))
		if n > 0 {
			hasRules = true
		}
	}
	if !hasRules {
		t.Fatal("装载后影子槽应有规则")
	}
	if err := b.DropShadow(ctx); err != nil {
		t.Fatalf("DropShadow 失败: %v", err)
	}
	// 影子槽必须清空
	for _, work := range []string{"pre", "dnat", "fwd", "snat"} {
		n, _ := eng.ChainRuleCount(work + "_" + string(shadow))
		if n != 0 {
			t.Fatalf("★ DropShadow 后影子槽 %s 残留 %d 条", work, n)
		}
	}
}

// TestTcBridgeNilEngine / WithoutPlan tc 桥接的错误路径。
func TestTcBridgeErrors(t *testing.T) {
	// nil 引擎
	b := NewTcBridge(nil)
	if err := b.ApplyTc(context.Background(), &control.TcPlanView{Version: 1}); err == nil {
		t.Fatal("nil 引擎应报错")
	}
	// 未 SetPlan
	b2 := NewTcBridge(nil)
	b2.engine = nil
	if err := b2.ApplyTc(context.Background(), &control.TcPlanView{Version: 1}); err == nil {
		t.Fatal("应考虑引擎与计划两种情况")
	}
}

// TestTcBridgeCancelledContext 已取消的 ctx 必须被尊重。
func TestTcBridgeCancelledContext(t *testing.T) {
	b := NewTcBridge(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.ApplyTc(ctx, &control.TcPlanView{Version: 1}); err == nil {
		t.Fatal("已取消的 ctx 应报错")
	}
}
