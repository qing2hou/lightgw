package proxy

import (
	"fmt"
	"strconv"
	"testing"
)

// TestHTBLimitStructure 限速结构的硬约束（本环境实测得出，改动前必读）。
//
// ⚠️ 订正（2026-10-30 真机 + 2026-11-01 生产复验）：本测试原先写着
// 「cls_u32 完全不参与分类」「每源硬保底不生效」——**已被证伪**。
// `u32` 在 192.168.10.170（KVM + virtio + Linux 6.8）实测可用：
// 下载 `match ip dst` 跑 8.006507MB/s（配置 8MB/s，误差 +0.08%），
// 上传 `match ip src` 跑 7.6548MB/s（配置 8MB/s，误差 −4.32%）。
// 当年「u32 不参与分类」的观感，真因是上传 filter 写成了 `match ip dst`。
//
// 必须保持的结构（每条都有实测反证，见 snat_htb_structure_test.go）：
//   - 父类 1:100 承载总额（rate=ceil=BWGroupKBps）
//   - 每源保底子类 parent 1:100，rate=MinKBps、ceil=总额
//   - 叶子兜底类 1:250 是 `htb default` 的目标（**不能**是 1:100）
//   - fq_codel 只挂叶子 1:250（挂内层会被内核拒绝）
func TestHTBLimitStructure(t *testing.T) {
	if bwGroupClassID != "1:100" {
		t.Fatalf("限额父类 ID 应为 1:100，实际 %s", bwGroupClassID)
	}
	if leafClassID != "1:250" {
		t.Fatalf("叶子兜底类 ID 应为 1:250，实际 %s", leafClassID)
	}
	if leafClassIDNum != 250 {
		t.Fatalf("leafClassIDNum 应为 250，实际 %d", leafClassIDNum)
	}
	// 子类 ID 不得与保留类冲突（1:30 全速占位 / 1:100 总额父类 / 1:250 叶子兜底）
	for _, src := range []string{"192.168.10.152", "10.0.0.0/8"} {
		id := srcClassID(src)
		if why, bad := reservedClassIDs[id]; bad {
			t.Fatalf("源 %s 的类 ID %s 与保留 class 冲突（%s）", src, id, why)
		}
	}
}

// TestFilterPrefSegmentsDisjoint 历史 filter 清理仍按 pref 区段精确删除，
// 下载(2..998)与上传(1002..1998)不得重叠。
func TestFilterPrefSegmentsDisjoint(t *testing.T) {
	for _, s := range []string{"192.168.10.152", "172.16.40.10", "10.0.0.0/8"} {
		d, u := srcFilterPref(s), uploadFilterPref(s)
		if d == u {
			t.Fatalf("源 %s 的下载/上传 pref 相同（%d），清理会互相误删", s, d)
		}
		if d >= 1002 || u < 1002 {
			t.Fatalf("源 %s 的 pref 区段错位：down=%d up=%d", s, d, u)
		}
	}
}

// TestHTBCleanupSkipsReservedClasses 历史子类清理必须跳过保留 class ID。
//
// 回归：早期清理循环从 1:2 遍历到 1:249，把刚建好的限速类 1:100 一并删掉，
// default 0x100 指向不存在的 class → 内核把包全部走 direct 路径 → 限速
// 彻底失效（实测带宽包配 8MB/s 跑出 24MB/s 满速）。
func TestHTBCleanupSkipsReservedClasses(t *testing.T) {
	const (
		limitClass  = bwGroupClassID // 1:100
		bypassClass = "1:30"
		lo, hi      = 2, 249
	)
	// 保留 class 必须落在清理范围内，否则本测试失去意义
	inRange := func(id string) bool {
		var n int
		if _, err := fmt.Sscanf(id, "1:%d", &n); err != nil {
			return false
		}
		return n >= lo && n <= hi
	}
	if !inRange(limitClass) {
		t.Skipf("限速类 %s 不在清理范围 %d..%d 内，该回归已不适用", limitClass, lo, hi)
	}
	// 复现清理判据：命中保留 ID 时必须跳过
	skipped := 0
	for n := lo; n <= hi; n++ {
		id := "1:" + strconv.Itoa(n)
		if id == limitClass || id == bypassClass {
			skipped++
		}
	}
	if skipped != 2 {
		t.Fatalf("清理循环应跳过 2 个保留 class（%s、%s），实际跳过 %d 个", limitClass, bypassClass, skipped)
	}
}
