// HTB 结构的硬约束回归测试（AGENTS.md「踩过的坑」带宽包条目，约束 2/3）。
//
// 这两条约束都有**真机实测反证**，被违反时不会报错、只会静默失效：
//
//	约束 2：`htb default` 必须指向叶子类，不能指向挂了子类的内层类。
//	        实测：default→1:100（内层）2057.4724 MB/s，direct_packets_stat
//	        增量 = 总包数（一个包都没进 HTB）；default→叶子 7.6559 MB/s。
//	约束 3：`fq_codel` 只能挂叶子类。挂内层 1:100 时内核直接
//	        `RTNETLINK answers: Invalid argument`（生产机已复现）。
//
// 两条的共同特征是：tc 命令可能"看起来成功"（或被 `_ = runQuiet` 吞掉），
// 而限速实际不存在。所以这里做源码级断言，改回去就红。
package proxy

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// reservedClassIDs 是 htb 树里**被占用**的 class ID：任何 per-源子类都不得
// 产出这些值，否则 `tc class replace classid <保留号>` 会覆盖保留类的语义。
var reservedClassIDs = map[string]string{
	"1:30":  "ensureEgressHTB 的全速占位类",
	"1:100": "bwGroupClassID 带宽包总额父类",
	"1:250": "leafClassID 叶子兜底类（default 目标）",
}

// TestHTBDefaultPointsToLeafClass_Constraint2 断言所有 `htb default` 都不指向 1:100。
//
// 1:100 是挂子类的内层类，`default` 指它 = 未分类流量完全绕过 HTB。
func TestHTBDefaultPointsToLeafClass_Constraint2(t *testing.T) {
	body := readSnatGo(t)

	// 扫出所有 `htb` + `default` 组合里 default 的取值。
	// 形态：`"htb", "default", "100"` 或 `"htb",\n "default", strconv.Itoa(leafClassIDNum)`
	bad := []string{
		`"htb", "default", "100"`, // 老代码：指向内层父类
		`"htb", "default", "199"`, // 中间稿：1:199 与 srcClassID 区间冲突
		`"htb", "default", "30"`,  // 1:30 是全速旁路，用于限速树 = 不限速
	}
	for _, pat := range bad {
		if strings.Contains(body, pat) {
			t.Fatalf("★ 约束2 违规：发现 %s。\n"+
				"htb default 必须指向叶子兜底类 1:250（leafClassID）。\n"+
				"指向内层类时包完全绕过 HTB：实测 8MB/s 配置跑出 2057.4724 MB/s，"+
				"direct_packets_stat 增量等于总包数（一个包都没进 HTB）。", pat)
		}
	}

	// 必须存在"用 leafClassIDNum 构造 default"的位置（至少 ensureHTB + applyIngressLimit）
	if !strings.Contains(body, "default\", strconv.Itoa(leafClassIDNum)") &&
		!strings.Contains(body, `"default", strconv.Itoa(leafClassIDNum)`) {
		t.Fatal("★ 约束2 违规：找不到用 leafClassIDNum 设置 htb default 的代码。\n" +
			"`htb default` 必须以 leafClassIDNum(250) 为目标，否则未分类流量无限速。")
	}
}

// TestFqCodelOnlyOnLeafClass_Constraint3 断言 fq_codel 不挂在 bwGroupClassID(1:100)。
func TestFqCodelOnlyOnLeafClass_Constraint3(t *testing.T) {
	body := readSnatGo(t)

	// fq_codel 的 parent 参数不能是 bwGroupClassID
	if strings.Contains(body, `"parent", bwGroupClassID,`+"\n"+`				"handle", "100:", "fq_codel"`) ||
		strings.Contains(body, `"parent", bwGroupClassID,
				"handle", "100:", "fq_codel"`) {
		t.Fatal("★ 约束3 违规：fq_codel 挂在 bwGroupClassID(1:100) 上。\n" +
			"内层类不能挂叶子 qdisc，内核直接 `RTNETLINK answers: Invalid argument`" +
			"（生产机 192.168.10.170 已实测复现）。必须挂叶子类 leafClassID。")
	}

	// 必须存在"fq_codel 挂 leafClassID"的代码
	if !strings.Contains(body, `"parent", leafClassID,`) {
		t.Fatal("★ 约束3 违规：找不到 fq_codel 挂 leafClassID 的代码。\n" +
			"fq_codel 必须挂在叶子类上（流级公平），且挂载失败要记日志不能静默吞掉。")
	}
}

// TestSrcClassIDAvoidsReservedIDs 断言 srcClassID 永不产出保留 class ID。
//
// 早期版本 `1+h%248` 会产出 1:100 —— 源哈希到它时
// `tc class replace classid 1:100` 把带宽包总额父类替换成该源保底子类，
// 整包总额失效（父类 rate 从 8192KB/s 变成 MinKBps）。
func TestSrcClassIDAvoidsReservedIDs(t *testing.T) {
	// 直接调函数做穷举：取足够多的源地址覆盖全 248 槽
	seen := map[string]string{}
	for i := 0; i < 4000; i++ {
		src := "10." + itoa(i/256%256) + "." + itoa(i%256) + ".1"
		id := srcClassID(src)
		if why, bad := reservedClassIDs[id]; bad {
			t.Fatalf("★ srcClassID(%q) = %s，与保留类冲突（%s）。\n"+
				"per-源子类不得占用保留号段：1:30 / 1:100 / 1:250。", src, id, why)
		}
		seen[id] = src
	}
	// 容量：248 个槽应几乎用满（FNV 分布均匀）
	if len(seen) < 200 {
		t.Fatalf("★ srcClassID 槽位利用率过低：4000 个源只用了 %d 个 class ID（预期 ≥200）", len(seen))
	}
}

// TestSrcClassIDStable 断言同一源恒得同一 class ID（幂等拆除依赖此性质）。
func TestSrcClassIDStable(t *testing.T) {
	for _, src := range []string{"192.168.10.151", "192.168.10.152", "10.0.0.1"} {
		a, b := srcClassID(src), srcClassID(src)
		if a != b {
			t.Fatalf("★ srcClassID(%q) 不稳定：%s != %s", src, a, b)
		}
	}
}

func readSnatGo(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("snat.go")
	if err != nil {
		t.Fatalf("读取 snat.go 失败: %v", err)
	}
	return string(src)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestHTBDefaultTokenMatchesKernel 断言幂等判定用的 token 与内核实际打印一致。
//
// 生产机实测（Linux 6.8，`tc qdisc add ... htb default 250`）：
//
//	qdisc htb 1: root refcnt 2 r2q 10 default 0x250 direct_packets_stat 0 ...
//
// 写成 `0x%x` 会得到 0xfa，永远匹配不上 → 每个 apply 周期重建 qdisc。
func TestHTBDefaultTokenMatchesKernel(t *testing.T) {
	const kernelOutput = "qdisc htb 1: root refcnt 2 r2q 10 default 0x250 direct_packets_stat 0 direct_qlen 1000"
	tok := htbDefaultToken()
	if !strings.Contains(kernelOutput, tok) {
		t.Fatalf("★ htbDefaultToken() = %q 在内核实际输出里匹配不到。\n"+
			"内核输出: %s\n"+
			"这会导致幂等判定永远失败、每个周期重建 qdisc（重建期短暂无限速）。",
			tok, kernelOutput)
	}
}

// TestLeafClassIDConsistentWithToken 断言 leafClassID 与 htbDefaultToken 同源，
// 避免有人只改一个常量导致 default 装到 A 类、幂等判定却查 B 类。
func TestLeafClassIDConsistentWithToken(t *testing.T) {
	wantTok := "default 0x" + strings.TrimPrefix(leafClassID, "1:")
	if htbDefaultToken() != wantTok {
		t.Fatalf("★ leafClassID=%s 推导出 %q，但 htbDefaultToken() 返回 %q，两者必须一致",
			leafClassID, wantTok, htbDefaultToken())
	}
	if leafClassID != fmt.Sprintf("1:%d", leafClassIDNum) {
		t.Fatalf("★ leafClassID=%s 与 leafClassIDNum=%d 不一致", leafClassID, leafClassIDNum)
	}
}

// TestLeafClassIsPassthrough 断言叶子兜底类**不限速**。
//
// 回归（2026-11-01 生产实测）：叶子类曾用带宽包总额（8192KB/s），
// 导致 eth0 上所有未分类流量被这 8MB/s 桶收走——端口映射 #33
// （172.16.40.10:2222 → 172.16.30.20:22，规则自身「不限/不限」）
// 实测只有 6.98 MB/s（= 上限的 85%，差额是 TCP/IP 开销）。
//
// 带宽包是「绑定它的规则」的额度，不是整卡限速：
// 规则没绑包 = 不限速，这条语义必须在 tc 层成立。
func TestLeafClassIsPassthrough(t *testing.T) {
	if leafClassRateBits != "10gbit" {
		t.Fatalf("★ 叶子兜底类必须直通（10gbit），实际 %q。\n"+
			"用带宽包总额会让同网卡上未绑包的流量（如端口映射）被误限。", leafClassRateBits)
	}
	// 代码里叶子类建类时不能再用 totalBits。
	// 取"每个 classid=leafClassID 建类语句往后 300 字节"作为断言窗口——
	// 语句本体跨 3~4 行，300 字节足够覆盖且不会误伤远处代码。
	body := readSnatGo(t)
	const anchor = `"classid", leafClassID, "htb"`
	if !strings.Contains(body, anchor) {
		t.Fatal("找不到叶子类建类语句")
	}
	found := 0
	for rest := body; ; {
		i := strings.Index(rest, anchor)
		if i < 0 {
			break
		}
		found++
		end := i + 300
		if end > len(rest) {
			end = len(rest)
		}
		win := rest[i:end]
		if strings.Contains(win, "totalBits") {
			t.Fatalf("★ 叶子兜底类的 rate/ceil 不能用带宽包总额 totalBits。\n"+
				"它就是那个把端口映射限到 6.98MB/s 的 bug。片段:\n%s", win)
		}
		if !strings.Contains(win, "leafClassRateBits") {
			t.Fatalf("★ 叶子兜底类的 rate 应为 leafClassRateBits。片段:\n%s", win)
		}
		rest = rest[i+len(anchor):]
	}
	if found < 2 {
		t.Fatalf("★ 应有两处建叶子类（applyHTBLimit + applyIngressLimit），实际 %d 处", found)
	}
}

// TestBothHTBSitesUsePassthroughLeaf 断言两处建 HTB 的地方（egress 与 ifb）
// 都用直通叶子类——只改一处会留下同一个 bug 的另一个入口。
func TestBothHTBSitesUsePassthroughLeaf(t *testing.T) {
	body := readSnatGo(t)
	n := strings.Count(body, "leafClassRateBits")
	// 1 处是常量定义，其余是使用点：applyHTBLimit + applyIngressLimit 至少 2 处
	if n < 3 {
		t.Fatalf("★ leafClassRateBits 出现 %d 次（含定义），"+
			"applyHTBLimit 与 applyIngressLimit 都应使用它", n)
	}
	if strings.Contains(body, `"rate", totalBits, "ceil", totalBits,
		"burst", "16k", "cburst", "32k"`) {
		t.Fatal("★ 仍有地方用 totalBits 建叶子类（应为 leafClassRateBits）")
	}
}
