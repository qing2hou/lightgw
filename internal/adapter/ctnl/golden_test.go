package ctnl

import (
	"encoding/hex"
	"testing"
)

// 真机 dump 的原始字节（192.168.10.170，root，网关上实测抓取）。
//
// 这些 golden 数据的价值：自造消息用自造常量永远往返一致，**常量错位
// 在自造测试里发现不了**。只有把内核真实发出的字节喂进解析器，才能验证
// 常量与内核头一致。
//
// 曾因按记忆写 CTA_STATUS=4（实际 3）、CTA_COUNTERS=7（实际 9/10）导致
// 所有会话显示「未建立」、所有字节数为 0，而自造往返测试全绿。
const (
	// goldenMsg0 是一条 ICMP 会话（172.16.40.10 -> 172.16.40.1），
	// status=0x18a（IPS_SEEN_REPLY|IPS_CONFIRMED|0x180），timeout=19。
	goldenMsg0 = "02000000" +
		"3c000180" + // CTA_TUPLE_ORIG nested
		"14000180" + "08000100ac10280a" + "08000200ac102801" + // IP src/dst
		"24000280" + "0500010001000000" + "060004002fa70000" + "0500050008000000" + "0500060000000000" + // proto
		"3c000280" + // CTA_TUPLE_REPLY nested
		"14000180" + "08000100ac102801" + "08000200ac10280a" +
		"24000280" + "0500010001000000" + "060004002fa70000" + "0500050000000000" + "0500060000000000" +
		"08000300" + "0000018a" + // CTA_STATUS = 0x18a
		"08000800" + "00000000" + // CTA_PROTOINFO
		"08000c00" + "001c83bf" + // CTA_ID
		"08000b00" + "00000001" + // CTA_USE
		"08000700" + "00000013" // CTA_TIMEOUT = 19

	// goldenMsg1 是一条 TCP 会话（192.168.10.151 -> 34.120.177.193:443），
	// status=0x19e，带 CTA_TUPLE_MASTER（ICMP 相关）。
	goldenMsg1 = "02000000" +
		"34000180" + "14000180" + "08000100c0a80a97" + "080002002278b1c1" +
		"1c000280" + "0500010006000000" + "06000200e6dc0000" + "0600030001bb0000" +
		"34000280" + "14000180" + "080001002278b1c1" + "08000200c0a80aaa" +
		"1c000280" + "0500010006000000" + "0600020001bb0000" + "06000300e6dc0000" +
		"08000300" + "0000019e" + // CTA_STATUS = 0x19e
		"08000800" + "00000000" +
		"08000c00" + "30f8b1d5" +
		"08000b00" + "00000001" +
		"08000700" + "00000012" + // CTA_TIMEOUT = 18
		"30000480" + "2c000180" + "0500010007000000" + "0500020007000000" +
		"0500030008000000" + "0600040027000000" + "0600050023000000" // CTA_TUPLE_MASTER
)

// TestGoldenICMPFlow 用真机字节验证 ICMP 会话解析。
//
// 断言要点：
//   - status 必须是 0x18a（若 CTAStatus 常量错位，会读成 0 或别的属性的值）
//   - timeout 必须是 19（若 CTAATimeout 错位则读不到）
//   - IPS_SEEN_REPLY 位必须被识别 → IsEstablished() == true
func TestGoldenICMPFlow(t *testing.T) {
	raw, err := hex.DecodeString(goldenMsg0)
	if err != nil {
		t.Fatalf("golden 数据非法: %v", err)
	}
	f, err := ParseFlow(raw)
	if err != nil {
		t.Fatalf("解析真机消息失败: %v", err)
	}
	if f.Orig.SrcAddr.String() != "172.16.40.10" {
		t.Fatalf("源地址错误: %s（期望 172.16.40.10）", f.Orig.SrcAddr)
	}
	if f.Orig.DstAddr.String() != "172.16.40.1" {
		t.Fatalf("目的地址错误: %s", f.Orig.DstAddr)
	}
	if f.Orig.Proto != 1 {
		t.Fatalf("协议应为 1(icmp)，实际 %d", f.Orig.Proto)
	}
	// ★ 关键断言：这一条会抓住 CTA_STATUS 常量错位
	if f.Status != 0x18a {
		t.Fatalf("★ status 应为 0x18a，实际 0x%x —— CTA_STATUS 常量可能错位"+
			"（内核头是 3，不是 4）", f.Status)
	}
	if !f.IsEstablished() {
		t.Fatal("★ 0x18a 含 IPS_SEEN_REPLY，IsEstablished 必须为 true")
	}
	if !f.IsAssured() == false {
		// 0x18a 的 bit2 是 0，不是 assured
		if f.IsAssured() {
			t.Fatal("0x18a 不含 IPS_ASSURED")
		}
	}
	// ★ CTA_TIMEOUT 常量错位测试（内核头是 7，不是 8）
	if f.Timeout != 19 {
		t.Fatalf("★ timeout 应为 19，实际 %d —— CTA_TIMEOUT 常量可能错位"+
			"（内核头是 7）", f.Timeout)
	}
	// 应答方向
	if f.Reply.SrcAddr.String() != "172.16.40.1" {
		t.Fatalf("应答方向源地址错误: %s", f.Reply.SrcAddr)
	}
}

// TestGoldenTCPFlow 用真机字节验证 TCP 会话解析（含 mov 的 NAT 场景）。
func TestGoldenTCPFlow(t *testing.T) {
	raw, err := hex.DecodeString(goldenMsg1)
	if err != nil {
		t.Fatalf("golden 数据非法: %v", err)
	}
	f, err := ParseFlow(raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if f.Orig.SrcAddr.String() != "192.168.10.151" {
		t.Fatalf("源地址错误: %s", f.Orig.SrcAddr)
	}
	if f.Orig.DstAddr.String() != "34.120.177.193" {
		t.Fatalf("目的地址错误: %s", f.Orig.DstAddr)
	}
	if f.Orig.SrcPort != 0xe6dc {
		t.Fatalf("源端口应为 %d，实际 %d", 0xe6dc, f.Orig.SrcPort)
	}
	if f.Orig.DstPort != 443 {
		t.Fatalf("目的端口应为 443，实际 %d", f.Orig.DstPort)
	}
	if f.Orig.Proto != 6 {
		t.Fatalf("协议应为 6(tcp)，实际 %d", f.Orig.Proto)
	}
	// status 0x19e = SEEN_REPLY|CONFIRMED|ASSURED? 逐位核对
	if f.Status != 0x19e {
		t.Fatalf("★ status 应为 0x19e，实际 0x%x", f.Status)
	}
	if !f.IsEstablished() {
		t.Fatal("0x19e 含 IPS_SEEN_REPLY，应为 established")
	}
	if f.Timeout != 18 {
		t.Fatalf("★ timeout 应为 18，实际 %d", f.Timeout)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("真机会话应通过校验: %v", err)
	}
}

// TestGoldenValidateAccepted 真机会话必须全部通过 Validate（不能过度过滤）。
func TestGoldenValidateAccepted(t *testing.T) {
	for name, hexStr := range map[string]string{
		"icmp": goldenMsg0,
		"tcp":  goldenMsg1,
	} {
		raw, _ := hex.DecodeString(hexStr)
		f, err := ParseFlow(raw)
		if err != nil {
			t.Fatalf("%s 解析失败: %v", name, err)
		}
		if err := f.Validate(); err != nil {
			t.Fatalf("%s 真机会话不应被拒: %v", name, err)
		}
	}
}

// TestCountersNotRequested 说明：默认 dump **不返回 counters**。
//
// 真机 dump 的原始字节里没有 CTA_COUNTERS_ORIG/REPLY 属性，
// 所以 Packets/Bytes 恒为 0。要拿计数必须：
//   - 在 dump 请求里带 CTA_FLAGS + CTA_FLAGS_COUNTER，或
//   - 用 event 订阅（NEW/UPDATE 事件带 counters）
//
// 本测试固化这个事实，避免有人误以为「解析器漏读了 counters」。
func TestCountersNotRequested(t *testing.T) {
	raw, _ := hex.DecodeString(goldenMsg0)
	f, err := ParseFlow(raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// 真机 dump 无 counters → 0
	if f.Packets != 0 || f.Bytes != 0 {
		t.Fatalf("默认 dump 不应有 counters（实测为 0），实际 pkts=%d bytes=%d",
			f.Packets, f.Bytes)
	}
}
