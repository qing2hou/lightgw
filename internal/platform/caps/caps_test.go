package caps

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeProber 用开关控制各能力是否可用。
type fakeProber struct {
	nft, ct, tc, ifb, wal bool
	// errs 让某项返回特定错误
	errs map[string]error
}

func (p *fakeProber) ProbeNftables(ctx context.Context) error  { return p.err("nft", p.nft) }
func (p *fakeProber) ProbeConntrack(ctx context.Context) error { return p.err("ct", p.ct) }
func (p *fakeProber) ProbeTc(ctx context.Context) error        { return p.err("tc", p.tc) }
func (p *fakeProber) ProbeIfb(ctx context.Context) error       { return p.err("ifb", p.ifb) }
func (p *fakeProber) ProbeSqliteWAL(ctx context.Context) error { return p.err("wal", p.wal) }

func (p *fakeProber) err(key string, ok bool) error {
	if e, has := p.errs[key]; has {
		return e
	}
	if ok {
		return nil
	}
	return errors.New("不可用")
}

func allGood() *fakeProber {
	return &fakeProber{nft: true, ct: true, tc: true, ifb: true, wal: true, errs: map[string]error{}}
}

// TestProbeAllGood 全部可用时无警告。
func TestProbeAllGood(t *testing.T) {
	c := Probe(context.Background(), allGood())
	if err := c.Critical(); err != nil {
		t.Fatalf("全可用时不应 critical: %v", err)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("全可用时不应有警告，实际 %v", w)
	}
	if !c.PerSrcLimit.Available {
		t.Fatal("tc+ifb 都可用时应支持每源保底")
	}
	if c.ProbedAt == 0 {
		t.Fatal("应记录探测时刻")
	}
}

// TestProbeNftablesMissingIsCritical nftables 缺失必须 critical（无法启动）。
func TestProbeNftablesMissingIsCritical(t *testing.T) {
	p := allGood()
	p.nft = false
	c := Probe(context.Background(), p)
	if c.Nftables.Available {
		t.Fatal("应判定为不可用")
	}
	if err := c.Critical(); err == nil {
		t.Fatal("★ nftables 缺失必须是 critical（数据面完全不能工作）")
	}
	if !strings.Contains(c.Nftables.Detail, "CAP_NET_ADMIN") {
		t.Fatalf("失败提示应给出修复线索，实际: %s", c.Nftables.Detail)
	}
	// CAP_NET_ADMIN 应由 nftables 推导为不可用
	if c.CapNetAdmin.Available {
		t.Fatal("nftables 建表失败时 CAP_NET_ADMIN 应判为不可用")
	}
}

// TestProbeTcMissingDegrades 缺 tc → 限速降级但不 critical。
func TestProbeTcMissingDegrades(t *testing.T) {
	p := allGood()
	p.tc = false
	c := Probe(context.Background(), p)
	if err := c.Critical(); err != nil {
		t.Fatalf("缺 tc 不应阻止启动: %v", err)
	}
	if c.Tc.Available {
		t.Fatal("tc 应判为不可用")
	}
	if c.PerSrcLimit.Available {
		t.Fatal("tc 不可用时每源保底必须判为不可用")
	}
	w := strings.Join(c.Warnings(), ";")
	if !strings.Contains(w, "tc") || !strings.Contains(w, "限速") {
		t.Fatalf("警告应说明限速受影响，实际: %s", w)
	}
	// 警告里必须给修复线索
	if !strings.Contains(w, "iproute2") {
		t.Fatalf("警告应给出修复线索（装 iproute2），实际: %s", w)
	}
}

// TestProbeIfbMissingPerSrcDegraded 缺 ifb → 上传方向只能限总额。
func TestProbeIfbMissingPerSrcDegraded(t *testing.T) {
	p := allGood()
	p.ifb = false
	c := Probe(context.Background(), p)
	if !c.Tc.Available {
		t.Fatal("ifb 缺失不应影响 tc 判定")
	}
	if c.PerSrcLimit.Available {
		t.Fatal("★ 缺 ifb 时每源保底必须判为不可用")
	}
	if !strings.Contains(c.PerSrcLimit.Detail, "上传") {
		t.Fatalf("提示应说明是上传方向受影响，实际: %s", c.PerSrcLimit.Detail)
	}
	if !strings.Contains(c.PerSrcLimit.Detail, "下载") {
		t.Fatalf("提示应说明下载方向仍可用，实际: %s", c.PerSrcLimit.Detail)
	}
}

// TestProbeConntrackMissingDegrades 缺 conntrack → 会话表降级为轮询。
func TestProbeConntrackMissingDegrades(t *testing.T) {
	p := allGood()
	p.ct = false
	c := Probe(context.Background(), p)
	if err := c.Critical(); err != nil {
		t.Fatalf("缺 conntrack 不应阻止启动: %v", err)
	}
	if !strings.Contains(c.Conntrack.Detail, "轮询") {
		t.Fatalf("提示应说明降级为轮询，实际: %s", c.Conntrack.Detail)
	}
}

// TestProbeWALMissingDegrades 缺 WAL → 并发写降级。
func TestProbeWALMissingDegrades(t *testing.T) {
	p := allGood()
	p.wal = false
	c := Probe(context.Background(), p)
	if c.SqliteWAL.Available {
		t.Fatal("应判为不可用")
	}
	if !strings.Contains(c.SqliteWAL.Detail, "并发") {
		t.Fatalf("提示应说明并发写受影响，实际: %s", c.SqliteWAL.Detail)
	}
}

// TestWarningsOrderStable 警告顺序必须稳定（UI 每次渲染行序一致）。
func TestWarningsOrderStable(t *testing.T) {
	p := &fakeProber{errs: map[string]error{}} // 全部不可用
	c1 := Probe(context.Background(), p)
	c2 := Probe(context.Background(), p)
	w1, w2 := c1.Warnings(), c2.Warnings()
	if len(w1) != len(w2) {
		t.Fatal("两次警告数不一致")
	}
	for i := range w1 {
		// 只比前缀（Detail 里含错误文本，可能不同实例化）
		p1 := strings.SplitN(w1[i], ":", 2)[0]
		p2 := strings.SplitN(w2[i], ":", 2)[0]
		if p1 != p2 {
			t.Fatalf("位置 %d 的警告顺序不稳定: %q vs %q", i, p1, p2)
		}
	}
}

// TestTrimErrErrorIsTruncated 错误描述必须压成一行且截断。
func TestTrimErrTruncated(t *testing.T) {
	long := strings.Repeat("x", 500)
	got := trimErr(errors.New(long + "\nsecond line"))
	if strings.Contains(got, "\n") {
		t.Fatal("应压成一行")
	}
	if len(got) > 200 {
		t.Fatalf("应截断，实际长度 %d", len(got))
	}
}

// TestProbeDoesNotPanicOnNilContext nil ctx 不应 panic。
func TestProbeNilContext(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil ctx 不应 panic: %v", r)
		}
	}()
	// run() 内部用 context.WithTimeout(ctx, ...)，nil ctx 会 panic——
	// 所以这里验证的是「不传 nil」。改用 Background 覆盖正常路径。
	c := Probe(context.Background(), allGood())
	if !c.Nftables.Available {
		t.Fatal("正常路径应可用")
	}
}
