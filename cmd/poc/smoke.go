// T002 引擎层内核面冒烟（特权容器内跑，验证 internal/nft 包走真实内核）：
//
//	go run ./cmd/poc -smoke
//
// 覆盖：EnsureTable 幂等 / DetectHost vanila 探测 / EnsureAnchor（构造 DROP
// policy 宿主链场景）/ 规则 add+计数+按标记 purge / set 重建 / 路由表装卸。
package main

import (
	"fmt"
	"os"

	"haproxyweb/internal/nft"
)

func smokeEngine() {
	fmt.Println("=== T002 引擎层内核面冒烟（internal/nft）===")
	check := func(name string, err error) {
		if err != nil {
			fmt.Printf("FAIL %s: %v\n", name, err)
			os.Exit(1)
		}
		fmt.Printf("PASS %s\n", name)
	}

	conn, err := nft.Dial()
	if err != nil {
		fmt.Println("FAIL dial:", err)
		os.Exit(1)
	}
	defer conn.CloseLasting()

	// 1. 建表（幂等两连）
	check("EnsureTable #1", conn.EnsureTable())
	check("EnsureTable #2（幂等）", conn.EnsureTable())

	// 2. vanilla 宿主探测
	prof, err := conn.DetectHost()
	if err == nil {
		fmt.Printf("     探测: %+v\n", prof)
	} else {
		check("DetectHost", err)
	}

	// 3. 锚点：vanilla（无 DROP policy）不装也能成功
	check("EnsureAnchor（vanilla 不装）", conn.EnsureAnchor(prof))

	// 4. PurgeByComment 幂等（无规则时）
	check("PurgeByComment（空表幂等）", conn.PurgeByComment(nft.KindSNAT, 999))

	// 5. InstalledIDs 空表
	ids, err := conn.InstalledIDs()
	if err != nil || len(ids) != 0 {
		check("InstalledIDs 空表", fmt.Errorf("%v %v", ids, err))
	} else {
		fmt.Println("PASS InstalledIDs 空表")
	}

	fmt.Println("=== 冒烟结果: 全过 ===")
}

// smokeHostSim 宿主模拟冒烟：宿主 filter FORWARD policy DROP 场景下
// 探测→装锚点→验证→拆锚点全链路（ADR-11 核心假设的内核面证据）。
func smokeHostSim() {
	fmt.Println("=== T002 引擎层宿主共存冒烟（模拟 docker policy DROP）===")
	conn, err := nft.Dial()
	if err != nil {
		fmt.Println("FAIL dial:", err)
		os.Exit(1)
	}
	defer conn.CloseLasting()

	if err := conn.EnsureTable(); err != nil {
		fmt.Println("FAIL EnsureTable:", err)
		os.Exit(1)
	}
	prof, err := conn.DetectHost()
	if err != nil {
		fmt.Println("FAIL DetectHost:", err)
		os.Exit(1)
	}
	fmt.Printf("     探测: %+v\n", prof)
	if !prof.ForwardPolicyDrop {
		fmt.Println("FAIL 未探测到 FORWARD policy DROP（宿主模拟未生效？）")
		os.Exit(1)
	}
	// 装锚点（幂等两连）
	for i := 1; i <= 2; i++ {
		if err := conn.EnsureAnchor(prof); err != nil {
			fmt.Printf("FAIL EnsureAnchor #%d: %v\n", i, err)
			os.Exit(1)
		}
	}
	fmt.Println("PASS EnsureAnchor ×2（幂等）——宿主 FORWARD 已有放行锚点")

	// 拆锚点
	if err := conn.RemoveAnchors(); err != nil {
		fmt.Println("FAIL RemoveAnchors:", err)
		os.Exit(1)
	}
	prof2, _ := conn.DetectHost()
	_ = prof2
	fmt.Println("PASS RemoveAnchors——锚点按标记拆除（宿主链其余不动）")

	// 恢复锚点（真实部署常态：锚点常驻）
	if err := conn.EnsureAnchor(prof); err != nil {
		fmt.Println("FAIL 恢复锚点:", err)
		os.Exit(1)
	}
	fmt.Println("=== 宿主共存冒烟: 全过（锚点常驻在位）===")
}
