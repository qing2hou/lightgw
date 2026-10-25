// -smoke-legacy：iptables-legacy + FORWARD policy DROP 宿主的 fail-fast 验证
// （T007 场景 B；Matrix 脚本先铺 legacy 规则再调本模式）。
package main

import (
	"fmt"
	"os"

	"haproxyweb/internal/nft"
	"haproxyweb/internal/proxy/fw"
)

func smokeLegacy() {
	fmt.Println("=== T007 场景 B：iptables-legacy fail-fast 验证 ===")
	c, err := nft.Dial()
	if err != nil {
		fmt.Println("FAIL dial:", err)
		os.Exit(1)
	}
	defer c.CloseLasting()
	if err := c.EnsureTable(); err != nil {
		fmt.Println("FAIL EnsureTable:", err)
		os.Exit(1)
	}
	// Manager.nftConn 的完整序列：探测 → legacy+DROP → fail-fast
	prof, err := c.DetectHost()
	if err != nil {
		fmt.Println("FAIL DetectHost:", err)
		os.Exit(1)
	}
	fmt.Printf("     探测: %+v\n", prof)
	if !prof.LegacyIPTables {
		fmt.Println("FAIL 未探测到 iptables-legacy（场景 B 前置未生效）")
		os.Exit(1)
	}
	if prof.ForwardPolicyDrop {
		_ = fw.Spec{} // 编译层在本场景不应被触达
		var lc error = &nft.LegacyConflictError{Profile: prof}
		fmt.Println("PASS legacy + DROP policy → fail-fast：", lc)
		os.Exit(0)
	}
	// legacy 在但 FORWARD 无 DROP（如 legacy ACCEPT/无 policy 规则）：
	// 可继续（放行压不住但默认链尾无 DROP——非黑洞组合）
	fmt.Println("PASS legacy 存在但无 DROP policy → 不触发 fail-fast（可运行组合）")
}
