package proxy

import "testing"

// TestTCFilterPrefSegmentsDisjoint 单臂网关（入口==出口同卡）时下载与上传
// filter 落在同一 qdisc，pref 必须严格分段不相交，否则 tc filter replace
// 会按 pref 互相覆盖，导致某一方向限速静默失效。
func TestTCFilterPrefSegmentsDisjoint(t *testing.T) {
	samples := []string{
		"192.168.10.0/24", "192.168.10.152", "172.16.40.10", "10.0.0.1",
		"0.0.0.0/32", "255.255.255.255", "203.0.113.7", "1.1.1.1",
	}
	for _, s := range samples {
		down, up := srcFilterPref(s), uploadFilterPref(s)
		if down >= 1002 {
			t.Fatalf("下载 pref %d 侵入上传区段（源 %s）", down, s)
		}
		if up < 1002 {
			t.Fatalf("上传 pref %d 未落在上传区段（源 %s）", up, s)
		}
		if down == up {
			t.Fatalf("源 %s 的下载/上传 pref 相同（%d）", s, down)
		}
	}
	// 同一源在两方向必须得到不同 pref（同卡时是两个独立 filter）
	if srcFilterPref("172.16.40.10") == uploadFilterPref("172.16.40.10") {
		t.Fatal("同一源的两方向 pref 冲突")
	}
}

// TestTCFilterPrefStable 下载侧 pref 必须保持历史公式不变——已部署规则的
// 旧 filter 靠它做精确拆除，改了会留下僵尸 filter。
func TestTCFilterPrefStable(t *testing.T) {
	// 历史公式：2 + sum(bytes) % 997
	for _, s := range []string{"192.168.10.152", "172.16.40.10", "10.0.0.0/8"} {
		sum := 0
		for _, b := range []byte(s) {
			sum += int(b)
		}
		want := 2 + sum%997
		if got := srcFilterPref(s); got != want {
			t.Fatalf("源 %s 的下载 pref 变为 %d（历史值 %d）——会残留旧 filter", s, got, want)
		}
	}
}
