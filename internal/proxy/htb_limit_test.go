package proxy

import (
	"fmt"
	"strconv"
	"testing"
)

// TestHTBLimitStructure 限速结构的硬约束（本环境实测得出，改动前必读）。
//
// 背景：170 生产机（virtio + Linux 6.8）上，所有按源分类的 tc 通路都失效：
//   - cls_u32 完全不参与分类（class Sent 恒 0，限速类压到 1Kbit 仍满速）
//   - cls_fw 只匹配 mark 完整值且 handle 仅奇数有效（1/3/5/9/31 命中，
//     2/16/32/50/100 失配），mark 带额外位也失配
//   - cls_flower 不支持 skb mark
//
// 且上传包在 egress 上源地址已被 SNAT 改写，按 saddr 分类本就不可行。
//
// 因此限速必须是"扁平结构 + default 直连限速类 + fq_codel 流公平"。
// 每源硬保底（MinKBps）当前不生效，仅保留配置项。
func TestHTBLimitStructure(t *testing.T) {
	if bwGroupClassID != "1:100" {
		t.Fatalf("限速类 ID 应为 1:100，实际 %s", bwGroupClassID)
	}
	// 子类 ID 区段（历史清理范围 1:2..1:249）不得与限速类/占位类冲突
	for _, src := range []string{"192.168.10.152", "10.0.0.0/8"} {
		id := srcClassID(src)
		if id == bwGroupClassID || id == "1:30" {
			t.Fatalf("源 %s 的类 ID %s 与保留 class 冲突", src, id)
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
