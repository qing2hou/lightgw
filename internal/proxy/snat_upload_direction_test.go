package proxy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestIFBFilterMatchesSrc_D16 D-16 / C-17：ifb 侧分类 filter 必须 match ip src。
//
// 这是现网 14 倍超速的直接原因，也是本项目踩过最贵的一次坑：
//
//	配置 8MB/s → 实测 112.2485MB/s（超 14 倍）
//	所有子类 Sent = 0，direct_packets_stat 增量与总包数完全相等
//
// 失效机制：上传包经 mirred 重定向进 ifb 后，**daddr 是公网服务器、
// saddr 才是客户端**。写成 `match ip dst <客户端>` 永不命中 → 包落到
// `default` 类 → 整棵每源保底子类不承载任何流量。
//
// 本测试用源码扫描固化方向，因为 runQuiet 的参数是运行时拼的，
// 没有可断言的中间结构。扫描是这类「命令行参数顺序」约束唯一可靠的护栏。
func TestIFBFilterMatchesSrc_D16(t *testing.T) {
	src, err := os.ReadFile("snat.go")
	if err != nil {
		t.Fatalf("读取 snat.go 失败: %v", err)
	}
	body := string(src)

	// 定位 applyIngressLimit 函数体（ifb 侧分类 filter 所在）
	start := strings.Index(body, "func (m *Manager) applyIngressLimit(")
	if start < 0 {
		t.Fatal("找不到 applyIngressLimit 函数")
	}
	rest := body[start:]
	// 函数结束：下一个顶层 func
	if i := strings.Index(rest[1:], "\nfunc "); i >= 0 {
		rest = rest[:i+1]
	}

	// ★ 核心断言：这个函数里不能出现 `"match", "ip", "dst"`
	if strings.Contains(rest, `"match", "ip", "dst"`) {
		t.Fatal("★ D-16 违规：applyIngressLimit 里出现了 match ip dst。" +
			"ifb 侧分类必须用 src —— 上传包进 ifb 后 daddr 是公网服务器、" +
			"saddr 才是客户端，用 dst 会 100% 不命中（实测 8MB/s 配置跑出 112MB/s）")
	}

	// 必须出现 match ip src（两个用途：ingress 重定向 + ifb 分类）
	srcCount := strings.Count(rest, `"match", "ip", "src"`)
	if srcCount < 2 {
		t.Fatalf("★ applyIngressLimit 应至少有 2 处 match ip src"+
			"（ingress 重定向 + ifb 侧分类），实际 %d 处", srcCount)
	}
}

// TestUploadFilterPrefNotHardcoded_D17 D-17：上传侧 pref 必须用 uploadFilterPref 派生。
//
// 单臂网关下上传 filter 与下载 filter 落在同一个 qdisc 上，
// pref 必须分段（下载 2..998 / 上传 1002..1998），否则 `tc filter replace`
// 按 pref 互相覆盖，导致某一方向限速静默失效。
func TestUploadFilterPrefNotHardcoded_D17(t *testing.T) {
	src, err := os.ReadFile("snat.go")
	if err != nil {
		t.Fatalf("读取 snat.go 失败: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (m *Manager) applyIngressLimit(")
	if start < 0 {
		t.Fatal("找不到 applyIngressLimit 函数")
	}
	rest := body[start:]
	if i := strings.Index(rest[1:], "\nfunc "); i >= 0 {
		rest = rest[:i+1]
	}

	// 不允许出现 "prio", "10"（下载侧的历史写法）
	if strings.Contains(rest, `"prio", "10"`) {
		t.Fatal("★ D-17 违规：applyIngressLimit 里出现硬编码 prio 10。" +
			"必须用 uploadFilterPref(src) 派生（区段 1002..1998）")
	}
	// 必须用 uploadFilterPref
	if !strings.Contains(rest, "uploadFilterPref(") {
		t.Fatal("★ applyIngressLimit 必须用 uploadFilterPref 派生 pref")
	}
}

// TestUploadPrefInUploadSegment uploadFilterPref 必须落在 1002..1998。
func TestUploadPrefInUploadSegment(t *testing.T) {
	// 与 tc.go 的常量保持一致（const UploadPrefBase = 1002, PrefSpan = 997）
	for _, s := range []string{"192.168.10.152", "192.168.10.151", "10.0.0.0/8", "0.0.0.0/0"} {
		p := uploadFilterPref(s)
		if p < 1002 || p > 1998 {
			t.Fatalf("源 %s 的 uploadFilterPref = %d，越出 1002..1998 区段", s, p)
		}
		// 且与下载侧不重叠
		if d := srcFilterPref(s); d >= 1002 {
			t.Fatalf("源 %s 的 srcFilterPref = %d 侵入了上传区段", s, d)
		}
	}
}

// TestNoHardcodedPrioTenInUploadPath 整个上传路径都不许硬编码 prio 10。
func TestNoHardcodedPrioTenInUploadPath(t *testing.T) {
	src, err := os.ReadFile("snat.go")
	if err != nil {
		t.Fatal(err)
	}
	// 统计 "prio", "10" 出现次数；下载侧（applyHTBLimit）允许保留历史写法，
	// 但上传侧（applyIngressLimit）不允许——已在上面单独断言。
	re := regexp.MustCompile(`"prio",\s*"10"`)
	all := re.FindAllIndex(src, -1)
	t.Logf("snat.go 中 \"prio\", \"10\" 出现 %d 处（下载侧历史写法，暂不动）", len(all))
}
