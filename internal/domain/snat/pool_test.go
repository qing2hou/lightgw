package snat

import (
	"fmt"
	"math"
	"net/netip"
	"testing"
)

func pool(n int) []netip.Addr {
	out := make([]netip.Addr, n)
	for i := 0; i < n; i++ {
		out[i] = netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + i)})
	}
	return out
}

// sources 生成 n 个确定性的客户端地址（不随机——测试必须可复现）。
func sources(n int) []netip.Addr {
	out := make([]netip.Addr, n)
	for i := 0; i < n; i++ {
		out[i] = netip.AddrFrom4([4]byte{
			10,
			byte((i >> 16) & 0xff),
			byte((i >> 8) & 0xff),
			byte(i & 0xff),
		})
	}
	return out
}

// TestPickEmptyPool 空池必须返回 ok=false（调用方据此「不做 SNAT」）。
func TestPickEmptyPool(t *testing.T) {
	m, ok := Pick(nil, "10.0.0.1")
	if ok {
		t.Fatalf("空池应返回 ok=false，实际 member=%q ok=%v", m, ok)
	}
	if m != "" {
		t.Fatalf("空池应返回空字符串，实际 %q", m)
	}
}

// TestPickSingleMember 单成员池恒返回该成员。
func TestPickSingleMember(t *testing.T) {
	p := pool(1)
	for _, src := range sources(100) {
		if got := PickAddr(p, src); got != p[0] {
			t.Fatalf("单成员池应恒返回 %s，实际 %s（源 %s）", p[0], got, src)
		}
	}
}

// TestPickDeterministic 同一输入必须恒返回同一结果（粘性依赖此性质）。
func TestPickDeterministic(t *testing.T) {
	p := pool(5)
	for _, src := range sources(50) {
		first := PickAddr(p, src)
		for i := 0; i < 10; i++ {
			if got := PickAddr(p, src); got != first {
				t.Fatalf("源 %s 的选择不稳定：%s vs %s", src, first, got)
			}
		}
	}
}

// TestPickOrderIndependent 池成员的排列顺序不影响结果。
//
// 这条很重要：池成员来自 DB，顺序可能因查询/导入而变化。若选择依赖顺序，
// 每次重启都可能换 IP。
func TestPickOrderIndependent(t *testing.T) {
	p := pool(6)
	reversed := make([]netip.Addr, len(p))
	for i := range p {
		reversed[len(p)-1-i] = p[i]
	}
	for _, src := range sources(200) {
		a := PickAddr(p, src)
		b := PickAddr(reversed, src)
		if a != b {
			t.Fatalf("池顺序影响结果：源 %s，正序得 %s，逆序得 %s", src, a, b)
		}
	}
}

// TestReshuffleRateOnGrow 池 4→5 的重排率必须 ≤ 25%。
//
// 这是 S0 的硬指标：取模哈希重排 ~75%，HRW 理论值 1/(N+1)=20%。
// 任务卡要求 ≤25%（留出哈希抖动余量）。
func TestReshuffleRateOnGrow(t *testing.T) {
	old4 := pool(4)
	new5 := pool(5)
	srcs := sources(100000)
	rate := ReshuffleRate(old4, new5, srcs)
	t.Logf("池 4→5 重排率 = %.4f（理论 1/5=0.2）", rate)
	if math.IsNaN(rate) {
		t.Fatal("重排率不应为 NaN")
	}
	if rate > 0.25 {
		t.Fatalf("池 4→5 重排率 %.4f 超过 25%% 上限（取模哈希是 ~75%%）", rate)
	}
}

// TestReshuffleRateOnShrink 池 5→4 的重排率必须 ≤ 25%（理论 1/5=20%）。
func TestReshuffleRateOnShrink(t *testing.T) {
	old5 := pool(5)
	new4 := pool(4)
	srcs := sources(100000)
	rate := ReshuffleRate(old5, new4, srcs)
	t.Logf("池 5→4 重排率 = %.4f（理论 1/5=0.2）", rate)
	if rate > 0.25 {
		t.Fatalf("池 5→4 重排率 %.4f 超过 25%% 上限", rate)
	}
}

// TestReshuffleFarBelowModulo 直接与取模哈希对比，证明 HRW 确实更优。
//
// 这条让「为什么换算法」变成可执行的证据，而不是文档里的一句断言。
func TestReshuffleFarBelowModulo(t *testing.T) {
	old4 := pool(4)
	new5 := pool(5)
	srcs := sources(100000)

	// 取模哈希（旧实现）：h % len(pool)
	moduloPick := func(p []netip.Addr, src netip.Addr) netip.Addr {
		b := src.As4()
		h := 0
		for _, v := range b {
			h = h*131 + int(v)
		}
		return p[h%len(p)]
	}
	changed := 0
	for _, src := range srcs {
		if moduloPick(old4, src) != moduloPick(new5, src) {
			changed++
		}
	}
	moduloRate := float64(changed) / float64(len(srcs))
	hrwRate := ReshuffleRate(old4, new5, srcs)

	t.Logf("取模重排率 = %.4f，HRW 重排率 = %.4f", moduloRate, hrwRate)
	if moduloRate < 0.6 {
		t.Fatalf("取模重排率应约 75%%，实际 %.4f——测试前提不成立", moduloRate)
	}
	if hrwRate >= moduloRate/2 {
		t.Fatalf("HRW 重排率 %.4f 未显著优于取模 %.4f", hrwRate, moduloRate)
	}
}

// TestDistributionUniform 均匀性：10 万个源，各成员占比应在 20%±2%（5 成员池）。
func TestDistributionUniform(t *testing.T) {
	p := pool(5)
	srcs := sources(100000)
	dist := Distribution(p, srcs)
	if len(dist) != 5 {
		t.Fatalf("应有 5 个成员被选中，实际 %d 个", len(dist))
	}
	want := 1.0 / 5.0
	sum := 0
	for m, c := range dist {
		ratio := float64(c) / float64(len(srcs))
		t.Logf("成员 %s 占比 = %.4f", m, ratio)
		if math.Abs(ratio-want) > 0.02 {
			t.Fatalf("成员 %s 占比 %.4f 偏离期望 %.4f 超过 2%%", m, ratio, want)
		}
		sum += c
	}
	if sum != len(srcs) {
		t.Fatalf("分布计数之和 %d != 源总数 %d", sum, len(srcs))
	}
}

// TestPickInvalidSrcFallback 源不是合法地址时退化为第一个成员（确定性、不 panic）。
func TestPickInvalidSrcFallback(t *testing.T) {
	p := pool(3)
	m, ok := Pick(p, "not-an-ip")
	if !ok {
		t.Fatal("非空池应返回 ok=true")
	}
	if m != p[0].String() {
		t.Fatalf("非法源应退化为第一个成员 %s，实际 %s", p[0], m)
	}
}

// TestPickIPv6 验证 v6 池（HRW 用 As16，v4/v6 走同一条路径）。
func TestPickIPv6(t *testing.T) {
	p := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("2001:db8::3"),
	}
	seen := make(map[netip.Addr]int)
	for i := 0; i < 300; i++ {
		src := netip.MustParseAddr(fmt.Sprintf("2001:db8:1::%x", i+1))
		got := PickAddr(p, src)
		if !got.IsValid() {
			t.Fatalf("v6 源 %s 未选中任何成员", src)
		}
		seen[got]++
	}
	if len(seen) < 2 {
		t.Fatalf("v6 池应分散到多个成员，实际只用了 %d 个", len(seen))
	}
}
