package proxy

import (
	"testing"

	"haproxyweb/internal/model"
)

// newDenyTestManager 建一个只含规则/出口表的管理面（不接内核：辖区计算是纯读）。
func newDenyTestManager(t *testing.T) *Manager {
	t.Helper()
	m := newFullManager(t, Options{})
	if err := m.db.AutoMigrate(&model.Egress{}, &model.AclGroup{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	return m
}

// TestDefaultDenySurvivesDisabledSnat 停用最后一条 snat 规则后，默认拒绝
// 必须继续生效（辖区覆盖含停用规则）——否则整机会静默退化为全放行路由器。
// 这是用户反馈的实际事故：停用规则后发现 152 仍能上网，实为 ip_forward 直通。
func TestDefaultDenySurvivesDisabledSnat(t *testing.T) {
	m := newDenyTestManager(t)
	r := model.ForwardRule{
		Name: "snat-a", Protocol: model.ProtocolSNAT,
		ListenAddr: "eth0", TargetAddr: "eth1",
		AclMode: model.AclModeWhitelist, AllowList: `["192.168.10.0/24"]`,
		Enabled: false, // 停用
	}
	if err := m.db.Create(&r).Error; err != nil {
		t.Fatal(err)
	}
	ifaces, _, denied, err := m.computeDefaultDenySets()
	if err != nil {
		t.Fatal(err)
	}
	if !denied {
		t.Fatal("存在停用的 snat 规则时默认拒绝必须仍然生效（否则整机退化为全放行）")
	}
	if len(ifaces) != 1 || ifaces[0] != "eth0" {
		t.Fatalf("辖区应含停用规则的入口网卡 eth0，实际 %v", ifaces)
	}
}

// TestDefaultDenyFromEgressOnly 只有出口实体、没有 snat 规则时也要拒绝。
func TestDefaultDenyFromEgressOnly(t *testing.T) {
	m := newDenyTestManager(t)
	eg := model.Egress{Name: "e1", Iface: "eth0", GatewayV4: "192.168.10.1", Enabled: true}
	if err := m.db.Create(&eg).Error; err != nil {
		t.Fatal(err)
	}
	ifaces, _, denied, err := m.computeDefaultDenySets()
	if err != nil {
		t.Fatal(err)
	}
	if !denied {
		t.Fatal("存在出口实体时应启用默认拒绝")
	}
	if len(ifaces) != 1 || ifaces[0] != "eth0" {
		t.Fatalf("辖区应取出口实体网卡 eth0，实际 %v", ifaces)
	}
}

// TestNoRulesNoDeny 完全空白（无 snat 规则、无出口）时不应装默认拒绝，
// 保持"本机不承担网关职责时不干预转发"的原有语义。
func TestNoRulesNoDeny(t *testing.T) {
	m := newDenyTestManager(t)
	_, _, denied, err := m.computeDefaultDenySets()
	if err != nil {
		t.Fatal(err)
	}
	if denied {
		t.Fatal("无规则无出口时不应启用默认拒绝")
	}
}

// TestDisabledEgressStillDeniesViaRule snat 规则存在时，辖区以规则入口为准，
// 不用出口网卡兜底（不额外扩大拒绝面）。
func TestDisabledEgressStillDeniesViaRule(t *testing.T) {
	m := newDenyTestManager(t)
	r := model.ForwardRule{
		Name: "snat-b", Protocol: model.ProtocolSNAT,
		ListenAddr: "eth0", TargetAddr: "eth1",
		AclMode: model.AclModeWhitelist, AllowList: `["192.168.10.0/24"]`,
		Enabled: true,
	}
	if err := m.db.Create(&r).Error; err != nil {
		t.Fatal(err)
	}
	// 出口在 eth1，但规则入口是 eth0：辖区应只有 eth0
	eg := model.Egress{Name: "e2", Iface: "eth1", GatewayV4: "172.16.40.1", Enabled: true}
	if err := m.db.Create(&eg).Error; err != nil {
		t.Fatal(err)
	}
	ifaces, _, denied, err := m.computeDefaultDenySets()
	if err != nil {
		t.Fatal(err)
	}
	if !denied {
		t.Fatal("有 snat 规则时应启用默认拒绝")
	}
	if len(ifaces) != 1 || ifaces[0] != "eth0" {
		t.Fatalf("有规则时辖区应只含规则入口 eth0（不用出口网卡扩大），实际 %v", ifaces)
	}
}

// TestDnatBackendScopeOnlyEnabled 停用的 dnat 规则不进后端辖区。
func TestDnatBackendScopeOnlyEnabled(t *testing.T) {
	m := newDenyTestManager(t)
	on := model.ForwardRule{
		Name: "d1", Protocol: model.ProtocolDNAT,
		ListenAddr: "172.16.40.10:1022", TargetAddr: "192.168.10.152:22", Enabled: true,
	}
	off := model.ForwardRule{
		Name: "d2", Protocol: model.ProtocolDNAT,
		ListenAddr: "172.16.40.10:1023", TargetAddr: "192.168.10.199:22", Enabled: false,
	}
	for _, r := range []model.ForwardRule{on, off} {
		rr := r
		if err := m.db.Create(&rr).Error; err != nil {
			t.Fatal(err)
		}
	}
	_, backends, denied, err := m.computeDefaultDenySets()
	if err != nil {
		t.Fatal(err)
	}
	if !denied {
		t.Fatal("有启用的 dnat 规则时应启用默认拒绝")
	}
	if len(backends) != 1 || backends[0] != "192.168.10.152" {
		t.Fatalf("后端辖区应只含启用规则的后端，实际 %v", backends)
	}
}
