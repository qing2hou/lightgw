package compile

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBurstBytesScalesWithRate burst 必须随速率缩放（技术方案 §3.5.9 第 6 条）。
//
// 固定 32k/16k 在千兆下只有 10ms 额度的 1/40，表现为「限 1Gbps 实测只跑 200Mbps」。
func TestBurstBytesScalesWithRate(t *testing.T) {
	q := 10 * time.Millisecond
	cases := []struct {
		name    string
		bps     int64
		wantMin uint32
		wantMax uint32
	}{
		// 8MB/s = 67108864 bit/s；8MiB/s * 10ms = 83886 bytes
		{"8MB/s", 67108864, 80 << 10, 90 << 10},
		// 1Gbps = 1000000000 bit/s；/8*10ms = 1,250,000 bytes
		{"1Gbps", 1000000000, 1200 << 10, 1300 << 10},
		// 极低速：走 32KB 下限
		{"1MB/s", 8388608, 32 << 10, 32 << 10},
		// 极高：走 8MB 上限
		{"100Gbps", 100000000000, 8 << 20, 8 << 20},
		{"0", 0, 32 << 10, 32 << 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := BurstBytes(c.bps, q)
			if got < c.wantMin || got > c.wantMax {
				t.Fatalf("BurstBytes(%d) = %d，期望在 [%d, %d] 内",
					c.bps, got, c.wantMin, c.wantMax)
			}
		})
	}
	// 关键性质：1Gbps 的 burst 必须显著大于 8MB/s 的（否则不叫「随速率缩放」）
	low := BurstBytes(67108864, q)
	high := BurstBytes(1000000000, q)
	if high <= low*10 {
		t.Fatalf("1Gbps 的 burst(%d) 应远大于 8MB/s 的(%d)", high, low)
	}
}

// TestKBpsToBytesPerSec D-07：净换算必须是 bytes/sec，不是 bit/sec。
//
// 换算错 8 倍是这块的经典 bug：8MB/s = 8192 KB/s = 8388608 bytes/sec。
// 若误写成 bit/sec 得到 67108864，限速会放宽 8 倍。
func TestKBpsToBytesPerSec(t *testing.T) {
	cases := []struct{ kbps, want int64 }{
		{8192, 8388608},
		{1024, 1048576},
		{0, 0},
		{-1, 0},
	}
	for _, c := range cases {
		if got := KBpsToBytesPerSec(c.kbps); got != uint64(c.want) {
			t.Fatalf("KBpsToBytesPerSec(%d) = %d，期望 %d", c.kbps, got, c.want)
		}
	}
	// 与 bit 版本必须差 8 倍
	if KBpsToBitsPerSec(8192) != int64(KBpsToBytesPerSec(8192))*8 {
		t.Fatal("bytes/sec 与 bit/sec 之间必须正好差 8 倍")
	}
}

// TestFilterPrefSegmentsDisjoint D-17 / §3.5.6②：下载与上传 pref 区段必须不相交。
//
// 单臂网关下两方向的 filter 落在同一个 qdisc 上，pref 重叠会被
// `tc filter replace` 互相覆盖，导致某一方向限速静默失效。
func TestFilterPrefSegmentsDisjoint(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := DownloadPref(i)
		u := UploadPref(i)
		if d < 2 || d > 998 {
			t.Fatalf("下载 pref %d 越界（应在 2..998）", d)
		}
		if u < 1002 || u > 1998 {
			t.Fatalf("上传 pref %d 越界（应在 1002..1998）", u)
		}
		if d == u {
			t.Fatalf("索引 %d 的下载/上传 pref 相同（%d）", i, d)
		}
	}
	// 两个区段的边界必须不重叠
	if DownloadPref(int(PrefSpan)-1) >= UploadPref(0) {
		t.Fatalf("下载区段最大值 %d 不应 >= 上传区段最小值 %d",
			DownloadPref(int(PrefSpan)-1), UploadPref(0))
	}
}

// TestPrefNeverZero pref 不许为 0（tc 保留值）。
func TestPrefNeverZero(t *testing.T) {
	for i := 0; i < 100; i++ {
		if DownloadPref(i) == 0 || UploadPref(i) == 0 {
			t.Fatalf("索引 %d 产生了 pref 0", i)
		}
	}
}

// TestCompileTcUploadMatchesSrc D-16 / C-17：上传方向必须 match ip src。
//
// 现网事故：写成 dst → 包进 ifb 后 daddr 是公网服务器、saddr 才是客户端，
// filter 永不命中 → 全走 default → 实测 8MB/s 配置跑出 118.51MB/s（14.8 倍）。
func TestCompileTcUploadMatchesSrc(t *testing.T) {
	plan, err := CompileTcOnly(8192, 1024,
		[]string{"192.168.10.152", "192.168.10.151"},
		"eth0", "eth0", "ifb-hw1")
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}

	var uploadClassify, downloadClassify, ingressRedirect int
	for _, f := range plan.Filters {
		switch {
		case f.Device == "ifb-hw1" && f.Parent == "1:":
			uploadClassify++
			if !f.MatchSrc {
				t.Fatalf("★ ifb 侧分类 filter 必须 match ip src，实际 match ip %s（D-16 事故写法）", f.Dir())
			}
		case f.Device == "eth0" && f.Parent == "1:":
			downloadClassify++
			if f.MatchSrc {
				t.Fatalf("★ 下载方向必须 match ip dst，实际 match ip %s", f.Dir())
			}
		case f.Device == "eth0" && f.Parent == "ffff:":
			ingressRedirect++
			if !f.MatchSrc {
				t.Fatalf("ingress 重定向必须 match ip src，实际 %s", f.Dir())
			}
		}
	}
	if uploadClassify != 2 {
		t.Fatalf("应有 2 条 ifb 分类 filter，实际 %d", uploadClassify)
	}
	if downloadClassify != 2 {
		t.Fatalf("应有 2 条下载分类 filter，实际 %d", downloadClassify)
	}
	if ingressRedirect != 2 {
		t.Fatalf("应有 2 条 ingress 重定向 filter，实际 %d", ingressRedirect)
	}
}

// TestCompileTcDefaultIsLeaf D-06 / §3.2：default 必须指向叶子兜底类。
//
// 实测反证：default 指向挂了子类的内层类 1:100 时，未命中 filter 的包
// 进不了任何队列，内核走 direct queue 绕过整棵树（2828.79 MB/s vs 配置 8）。
func TestCompileTcDefaultIsLeaf(t *testing.T) {
	plan, err := CompileTcOnly(8192, 1024, []string{"192.168.10.152"}, "eth0", "eth0", "ifb-hw1")
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	for _, q := range plan.Qdiscs {
		if q.Kind != "htb" {
			continue
		}
		if q.Default != TcFallbackMinor {
			t.Fatalf("%s 的 default 应为兜底叶子类 1:%d，实际 1:%d",
				q.Device, TcFallbackMinor, q.Default)
		}
		if q.Default == TcTotalMinor {
			t.Fatalf("%s 的 default 指向了总额父类 1:100——该类挂子类后是内层类，"+
				"未分类流量会走 direct 绕过整棵树", q.Device)
		}
	}
	// defaultdict 的类必须存在且 IsLeaf
	var fallbackOK bool
	for _, c := range plan.Classes {
		if c.ClassID == TcFallbackClass {
			fallbackOK = c.IsLeaf
		}
	}
	if !fallbackOK {
		t.Fatal("兜底类 1:199 必须存在且标记 IsLeaf（否则要挂 fq_codel 会失败）")
	}
}

// TestCompileTcTotalClassNotLeaf 总额父类 1:100 必须是内层类（不挂 fq_codel）。
//
// 实测：`tc qdisc add ... parent 1:100 fq_codel` 返回
// `RTNETLINK answers: Invalid argument`。
func TestCompileTcTotalClassNotLeaf(t *testing.T) {
	plan, err := CompileTcOnly(8192, 1024, []string{"192.168.10.152"}, "eth0", "eth0", "ifb-hw1")
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	for _, c := range plan.Classes {
		if c.ClassID == TcTotalClass && c.IsLeaf {
			t.Fatal("总额父类 1:100 不能标 IsLeaf（挂 fq_codel 会 EINVAL）")
		}
	}
}

// TestCompileTcSourceClassesAvoidReserved D-01：每源子类必须避开 1:30/1:100/1:199。
//
// 事故：清理循环从 1:2 到 1:249 把刚建好的 1:100 删掉，default 指向不存在的
// class，8MB/s 配置跑出 24MB/s。
func TestCompileTcSourceClassesAvoidReserved(t *testing.T) {
	reserved := map[uint32]string{
		TcBypassMinor:   "1:30 占位类",
		TcTotalMinor:    "1:100 总额父类",
		TcFallbackMinor: "1:199 兜底叶子类",
	}
	sources := make([]string, 0, 20)
	for i := 1; i <= 20; i++ {
		sources = append(sources, "192.168.10."+strconv.Itoa(i))
	}
	plan, err := CompileTcOnly(8192, 1024, sources, "eth0", "eth0", "ifb-hw1")
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	for _, c := range plan.Classes {
		minor := c.ClassID & 0xFFFF
		// 保留类本身（1:100 / 1:199）是设计上必须存在的，跳过；
		// 这里要验的是「每源子类」不占用它们。
		if c.ClassID == TcTotalClass || c.ClassID == TcFallbackClass {
			continue
		}
		if what, bad := reserved[minor]; bad {
			t.Fatalf("每源子类命中了保留类 %s（minor=%d）", what, minor)
		}
		if minor < TcSourceClassBase {
			t.Fatalf("每源子类 minor=%d 应 >= %d", minor, TcSourceClassBase)
		}
	}
}

// TestTcPlanValidateCatchesInnerDefault Validate 必须拦住「default 指向内层类」。
func TestTcPlanValidateCatchesInnerDefault(t *testing.T) {
	p := TcPlan{
		Qdiscs: []TcQdiscSpec{{Device: "eth0", Parent: "root", Handle: "1:", Kind: "htb", Default: 100}},
		Classes: []TcClassSpec{
			{ClassID: TcTotalClass, IsLeaf: false},
			{ClassID: RootMinor(201), ParentClassID: TcTotalClass, IsLeaf: true},
		},
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("default 指向内层类时 Validate 必须报错")
	}
	if !strings.Contains(err.Error(), "内层类") && !strings.Contains(err.Error(), "direct") {
		t.Fatalf("错误消息应指出内层类/direct 问题，实际: %v", err)
	}
}

// TestTcPlanValidateCatchesLeafWithChildren 内层类标 IsLeaf 必须被拦住。
func TestTcPlanValidateCatchesLeafWithChildren(t *testing.T) {
	p := TcPlan{
		Classes: []TcClassSpec{
			{ClassID: TcTotalClass, IsLeaf: true}, // 错：它有子类
			{ClassID: RootMinor(201), ParentClassID: TcTotalClass, IsLeaf: true},
		},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("内层类标 IsLeaf 时必须报错（挂 fq_codel 会 EINVAL）")
	}
}

// TestTcPlanValidateCatchesFilterToInnerClass filter 指向内层类必须被拦住。
//
// 实测 Case C5：filter 指向内层 1:100 时，该流跑出 983.56 MB/s，
// 流量落到 default 而不是目标 class。
func TestTcPlanValidateCatchesFilterToInnerClass(t *testing.T) {
	p := TcPlan{
		Classes: []TcClassSpec{
			{ClassID: TcTotalClass, IsLeaf: false},
			{ClassID: RootMinor(201), ParentClassID: TcTotalClass, IsLeaf: true},
		},
		Filters: []TcFilterSpec{
			{Device: "eth0", Parent: "1:", Pref: 5, MatchSrc: false, FlowID: "1:100"},
		},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("filter 指向内层类时必须报错")
	}
}

// TestTcPlanValidateCatchesMissingFlowID filter 指向不存在的类必须被拦住。
func TestTcPlanValidateCatchesMissingFlowID(t *testing.T) {
	p := TcPlan{
		Classes: []TcClassSpec{{ClassID: TcTotalClass, IsLeaf: false}},
		Filters: []TcFilterSpec{
			{Device: "eth0", Parent: "1:", Pref: 5, MatchSrc: false, FlowID: "1:250"},
		},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("filter 指向不存在的类时必须报错")
	}
}

// TestTcPlanValidateCatchesZeroPref pref=0 是 tc 保留值。
func TestTcPlanValidateCatchesZeroPref(t *testing.T) {
	p := TcPlan{
		Classes: []TcClassSpec{
			{ClassID: TcTotalClass, IsLeaf: false},
			{ClassID: RootMinor(201), ParentClassID: TcTotalClass, IsLeaf: true},
		},
		Filters: []TcFilterSpec{
			{Device: "eth0", Parent: "1:", Pref: 0, MatchSrc: false, FlowID: "1:201"},
		},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("pref=0 必须报错")
	}
}

// TestCompileTcZeroTotalIsEmpty 总额为 0 表示不限速，返回空计划。
func TestCompileTcZeroTotalIsEmpty(t *testing.T) {
	plan, err := CompileTcOnly(0, 1024, []string{"10.0.0.1"}, "eth0", "eth0", "ifb-hw1")
	if err != nil {
		t.Fatalf("不限速不应报错: %v", err)
	}
	if !plan.Empty() {
		t.Fatalf("总额为 0 应返回空计划，实际 %d qdisc / %d class / %d filter",
			len(plan.Qdiscs), len(plan.Classes), len(plan.Filters))
	}
}

// TestCompileTcNoSourcesIsEmpty 无源同样不限速。
func TestCompileTcNoSourcesIsEmpty(t *testing.T) {
	plan, err := CompileTcOnly(8192, 1024, nil, "eth0", "eth0", "ifb-hw1")
	if err != nil {
		t.Fatalf("无源不应报错: %v", err)
	}
	if !plan.Empty() {
		t.Fatal("无源应返回空计划")
	}
}

// TestCompileTcPrefixExpansion 单 IP 必须展开成 /32，网段保留原掩码。
func TestCompileTcPrefixExpansion(t *testing.T) {
	plan, err := CompileTcOnly(8192, 1024,
		[]string{"192.168.10.152", "192.168.11.0/24"}, "eth0", "eth0", "ifb-hw1")
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	var sawHost, sawNet bool
	for _, f := range plan.Filters {
		if f.Parent != "1:" || f.MatchSrc {
			continue // 只看下载侧
		}
		switch f.Match.Bits() {
		case 32:
			sawHost = true
		case 24:
			sawNet = true
			// 网段必须带真实掩码，不能是 /32（历史 bug：只匹配网络地址一个 IP）
			if f.Match.Masked() != f.Match {
				t.Fatalf("网段 %s 未归零", f.Match)
			}
		}
	}
	if !sawHost {
		t.Fatal("单 IP 应展开成 /32")
	}
	if !sawNet {
		t.Fatal("网段应保留 /24 掩码")
	}
}

// RootMinor 便于测试构造 1:NNN。
func RootMinor(minor uint32) uint32 { return TcRootMajor | minor }
