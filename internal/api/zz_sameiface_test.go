package api

import (
	"testing"

	"haproxyweb/internal/model"
)

// TestSnatSameIfaceAllowed 单臂网关：入口与出口可以是同一张网卡。
func TestSnatSameIfaceAllowed(t *testing.T) {
	h := &handlers{}
	h.DB = newTestDB(t)
	lo, out := twoUpIfaces(t)

	// 同卡
	in := &ruleInput{
		Name: "snat-same", Protocol: model.ProtocolSNAT,
		ListenAddr: lo, TargetAddr: lo,
		AclMode: model.AclModeWhitelist, AllowList: `["192.168.10.0/24"]`,
		SnatMode: "fixed",
	}
	if err := in.validate(h); err != nil {
		t.Fatalf("同卡 SNAT 应通过校验: %v", err)
	}
	// 双卡仍应通过（回归）
	in.TargetAddr = out
	if err := in.validate(h); err != nil {
		t.Fatalf("双卡 SNAT 应通过校验: %v", err)
	}
	// 同卡 + 出口网关：网关须在该网卡网段内（沿用原校验）
	in = &ruleInput{
		Name: "snat-same-gw", Protocol: model.ProtocolSNAT,
		ListenAddr: lo, TargetAddr: lo,
		EgressGw: "10.255.255.1",
		AclMode:  model.AclModeWhitelist, AllowList: `["192.168.10.0/24"]`,
		SnatMode: "fixed",
	}
	if err := in.validate(h); err == nil {
		t.Fatal("网关不在网卡网段内应被拒绝（同卡也一样）")
	}
}
