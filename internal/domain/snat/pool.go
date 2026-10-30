// Package snat 提供 SNAT 地址池的成员选择算法。
//
// 采用 Rendezvous Hashing（HRW，最高随机权重）：对每个源地址，选「权重最高」
// 的池成员。它的关键性质是**最小重排**——池从 N 增到 N+1 时，只有那些
// 「新成员权重更高」的源会迁移，比例约为 1/(N+1)；删除成员时只影响原本
// 落在它上面的源，约 1/N。
//
// 对比取模哈希（旧实现 `h % len(pool)`）：池 4→5 时约 75% 的源会换 IP。
//
// 纯函数层：零 IO。不 import os/net/os-exec/netlink/database-sql（C-12）。
package snat

import (
	"math"
	"net/netip"
)

// Pick 为给定源地址选择池成员。
//
// 返回值 ok=false 表示池为空（调用方据此决定「不做 SNAT」）。
//
// 纯函数：同一 (pool, src) 恒返回同一结果，与调用顺序、并发无关。
// pool 的顺序不影响结果（内部按权重比较，不依赖遍历顺序）。
func Pick(pool []netip.Addr, src string) (member string, ok bool) {
	if len(pool) == 0 {
		return "", false
	}
	addr, err := netip.ParseAddr(src)
	if err != nil {
		// 源不是合法地址时退化为「第一个成员」——确定性，且不会 panic。
		// 真实调用路径上 src 已由 Validate 校验过，这里只是防御。
		return pool[0].String(), true
	}
	return PickAddr(pool, addr).String(), true
}

// PickAddr 是 Pick 的类型安全版本。
//
// pool 为空时返回零值 Addr（调用方应先判 len(pool)==0）。
func PickAddr(pool []netip.Addr, src netip.Addr) netip.Addr {
	if len(pool) == 0 {
		return netip.Addr{}
	}
	if len(pool) == 1 {
		return pool[0]
	}
	var best netip.Addr
	var bestScore uint64
	chosen := false
	for _, m := range pool {
		s := score(src, m)
		// 严格大于：并列时保留先遍历到的。由于 score 是 64 位哈希，
		// 并列概率约 1/2^64，工程上可忽略。
		if !chosen || s > bestScore {
			best, bestScore, chosen = m, s, true
		}
	}
	return best
}

// score 计算 (src, member) 对的权重。
//
// 实现要点（这里踩过坑，改动前必读）：
//
//  1. 用 FNV-1a 64 位而不是标准库 maphash：maphash 每次进程启动种子不同，
//     不能用于需要跨重启保持一致的选择（池成员选择必须粘性）。
//
//  2. **FNV 之后必须再跑一次 fmix64 扩散**。起因：IPv4 的 As16() 是
//     v4-in-v6 形式（前 10 字节全 0、后 2 字节 0xff），所以「同一 src 对不同
//     member」的输入字节**只有最后 1~4 个字节不同**。FNV-1a 是流式哈希，
//     前面 28 字节的处理结果完全相同，末尾字节只影响低位 → 各成员分数高度
//     相关，最大值几乎恒定落在同一个成员上。
//     实测症状：5 成员池的分布退化成 25%/25%/25%/25%/0%（有一个成员永远
//     选不到），重排率也失真为 0.25。加 fmix64 后恢复均匀（各 20%±2%）。
func score(src, member netip.Addr) uint64 {
	var buf [32]byte
	s := src.As16()
	m := member.As16()
	copy(buf[:16], s[:])
	copy(buf[16:], m[:])

	// 内联 FNV-1a（避免 hash.Hash 接口调用与分配）
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, b := range buf {
		h ^= uint64(b)
		h *= prime64
	}
	return fmix64(h)
}

// fmix64 是 MurmurHash3 的 64 位终混函数（与 splitmix64 同源）。
//
// 作用：让输入的每一个比特影响输出的每一个比特（雪崩效应）。对
// 「输入只差末尾几字节」的场景是必需的，见 score 的注释。
func fmix64(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}

// Distribution 统计每个成员被选中的源数量，用于均匀性验收。
//
// 返回 map[成员字符串]源数量。
func Distribution(pool []netip.Addr, sources []netip.Addr) map[string]int {
	out := make(map[string]int, len(pool))
	if len(pool) == 0 {
		return out
	}
	for _, s := range sources {
		out[PickAddr(pool, s).String()]++
	}
	return out
}

// ReshuffleRate 计算两个池之间的重排率。
//
// 定义：在 sources 上，选择结果发生变化的源占比。
// 空池参与比较时返回 NaN（无意义），调用方应避免。
func ReshuffleRate(oldPool, newPool []netip.Addr, sources []netip.Addr) float64 {
	if len(oldPool) == 0 || len(newPool) == 0 || len(sources) == 0 {
		return math.NaN()
	}
	changed := 0
	for _, s := range sources {
		if PickAddr(oldPool, s) != PickAddr(newPool, s) {
			changed++
		}
	}
	return float64(changed) / float64(len(sources))
}
