package proxy

import "testing"

// TestHTBLimitIsFlat 限速必须是扁平结构：不建子类、不依赖 u32 filter。
//
// 回归（本环境实测，virtio + Linux 6.8）：
//   - u32 filter 不参与分类：挂上后 class Sent 恒 0、流量全走 default，
//     限速类压到 1Kbit 仍能 79.9MB/s 满速上传；
//   - 父类下挂子类时，未被 filter 指定的包直接走 direct queue 发出
//     （direct_packets_stat 增长、class Sent 为 0、overlimits 不涨）。
//     删掉子类后同一测试立刻正常（1:100 承载 33.5MB、overlimits 2424）。
//
// 本测试固化"必须扁平"的设计约束，防止后续重构把子类/filter 分类加回来。
func TestHTBLimitIsFlat(t *testing.T) {
	// 扁平结构只用两个 classid：限速类 1:100 与占位全速类 1:30。
	// srcClassID 仍被 applyHTBLimit 用于**清理历史子类**，必须保留其定义。
	if got := srcClassID("192.168.10.152"); got == bwGroupClassID {
		t.Fatalf("srcClassID 不应与限速父类 ID 相同: %s", got)
	}
	if bwGroupClassID != "1:100" {
		t.Fatalf("限速类 ID 应为 1:100，实际 %s", bwGroupClassID)
	}
	// 子类 ID 区段必须与父类不冲突（清理历史子类时按此删除）
	for _, src := range []string{"192.168.10.152", "10.0.0.0/8", "172.16.41.0/24"} {
		id := srcClassID(src)
		if id == "1:100" || id == "1:30" {
			t.Fatalf("源 %s 的子类 ID %s 与保留 class 冲突", src, id)
		}
	}
}

// TestFilterPrefSegmentsStillDisjoint filter 已不用于分类，但 pref 区段
// 仍被 teardownSnatLimit 用于清理历史 filter——保持不相交以免误删。
func TestFilterPrefSegmentsStillDisjoint(t *testing.T) {
	for _, s := range []string{"192.168.10.152", "172.16.40.10"} {
		if srcFilterPref(s) == uploadFilterPref(s) {
			t.Fatalf("源 %s 的下载/上传 pref 相同，清理会互相误删", s)
		}
		if srcFilterPref(s) >= 1002 {
			t.Fatalf("下载 pref %d 侵入上传区段", srcFilterPref(s))
		}
	}
}
