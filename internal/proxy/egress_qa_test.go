//go:build qa

// QA P5 一次性验证（M3 AC-4.2 去抖语义与切换触发）。构建标签 qa 隔离，
// 不进入常规 make test。跑法：go test -tags=qa -run TestQAEgress ./internal/proxy/
package proxy

import (
	"testing"

	"haproxyweb/internal/model"
)

// 场景：接口不存在 → 连续 FailCount 次失败才判 down、翻转才触发 reapply。
// 双通道验证：EgressUp 状态翻转 + egressDirty 标记（切换执行的触发器 B1）。
func TestQAEgressDebounceAndFailoverTrigger(t *testing.T) {
	if testing.Short() {
		t.Skip("qa 场景测试")
	}
	m := newFullManager(t, Options{})
	if err := m.db.AutoMigrate(&model.Egress{}, &model.FwPolicy{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	// 出口指向不存在的网卡：ProbeEgressOnce 立即失败（链路 down 分支）
	e := model.Egress{Name: "qa-e1", Iface: "qa-noif0", GatewayV4: "10.99.0.1",
		ProbeMode: "icmp-gw", IntervalSec: 3, FailCount: 2, UpCount: 2, Weight: 1, Priority: 10, Enabled: true}
	if err := m.db.Create(&e).Error; err != nil {
		t.Fatalf("建出口失败: %v", err)
	}

	// 初始状态：无状态记录按 up（保守语义）
	if !EgressUp(e.ID) {
		t.Fatalf("新出口初始应按 up（保守语义）")
	}

	// 第 1 次失败：FailCount=2 未到阈值 → 不翻转（去抖）
	m.egressDirty.Store(false)
	m.probeEgress(e)
	if !EgressUp(e.ID) {
		t.Fatalf("第 1 次失败后不应判 down（FailCount=2 去抖）")
	}
	if m.egressDirty.Load() {
		t.Fatalf("未翻转不应触发 reapply 脏标记")
	}
	// 第 2 次失败：达到阈值 → 翻转 down + 触发切换执行（dirty 标记）
	m.probeEgress(e)
	if EgressUp(e.ID) {
		t.Fatalf("连续第 2 次失败后应判 down")
	}
	if !m.egressDirty.Load() {
		t.Fatalf("down 翻转应触发 reapply 脏标记（切换执行）")
	}
	info := EgressInfoOf(e.ID)
	if info.DownReason == "" {
		t.Fatalf("判 down 应带原因")
	}

	// 恢复路径：换成 lo 接口（永远 up）+ icmp-gw 指向网关不存在会失败，
	// 改 none 模式（lo 在）恒成功——验证 UpCount=2 去抖回 up。
	e2 := e
	e2.ProbeMode = "none"
	e2.Iface = "lo"
	m.egressDirty.Store(false)
	m.probeEgress(e2)
	if EgressUp(e.ID) {
		t.Fatalf("第 1 次成功后不应立即回 up（UpCount=2 去抖）")
	}
	m.probeEgress(e2)
	if !EgressUp(e.ID) {
		t.Fatalf("连续第 2 次成功后应回 up")
	}
	if !m.egressDirty.Load() {
		t.Fatalf("回 up 翻转应触发 reapply 脏标记（回切执行）")
	}
	info = EgressInfoOf(e.ID)
	if info.LastSwitch == 0 {
		t.Fatalf("翻转应记录 lastSwitch")
	}
}

// 场景：egressNexthops 的层选择——主层有活口只返主层；主层全 down 落到备层。
func TestQAEgressNexthopLayering(t *testing.T) {
	m := newFullManager(t, Options{})
	if err := m.db.AutoMigrate(&model.Egress{}, &model.FwPolicy{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	mk := func(name, iface, gw string, prio, w int) model.Egress {
		e := model.Egress{Name: name, Iface: iface, GatewayV4: gw, Priority: prio, Weight: w,
			ProbeMode: "none", IntervalSec: 3, FailCount: 2, UpCount: 2, Enabled: true}
		if err := m.db.Create(&e).Error; err != nil {
			t.Fatalf("建出口失败: %v", err)
		}
		return e
	}
	mk("qa-p1", "lo", "10.1.0.1", 10, 1)       // 主层1
	mk("qa-p2", "lo", "10.2.0.1", 10, 3)       // 主层2（同层加权）
	b1 := mk("qa-b1", "lo", "10.3.0.1", 20, 1) // 备层

	// 主层两口均 up（none 模式 + lo 在 → 常活）→ 返回主层两口
	nh := m.egressNexthops(999, nil)
	if len(nh) != 2 {
		t.Fatalf("主层应返回 2 个 nexthop，得 %d", len(nh))
	}
	if !(nh[0].Gw.String() == "10.1.0.1" && nh[1].Gw.String() == "10.2.0.1") {
		t.Fatalf("主层 nexthop 不符: %+v", nh)
	}

	// 主层 down（探测失败翻转）→ 落到备层单口
	st := egressStateOf(1)
	st.up.Store(false)
	st = egressStateOf(2)
	st.up.Store(false)
	_ = b1
	nh = m.egressNexthops(999, nil)
	if len(nh) != 1 || nh[0].Gw.String() != "10.3.0.1" {
		t.Fatalf("主层全 down 应落备层（10.3.0.1），得 %d %v", len(nh), nh)
	}
}

// 场景：egressIDsOfRule 解析（空=全部出口；JSON 解析）。
func TestQAEgressIDsOfRule(t *testing.T) {
	if got := egressIDsOfRule(model.ForwardRule{}); got != nil {
		t.Fatalf("空绑定应为 nil")
	}
	if got := egressIDsOfRule(model.ForwardRule{EgressIDs: `[1,2]`}); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("JSON 绑定解析不符: %v", got)
	}
	if got := egressIDsOfRule(model.ForwardRule{EgressIDs: `bad`}); got != nil {
		t.Fatalf("非法 JSON 应返回 nil: %v", got)
	}
}
