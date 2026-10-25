// T001 PoC：google/nftables v0.3.0 + vishvananda/netlink 能力验证器。
// 在特权容器内运行（宿主 WSL2 无 CAP_NET_ADMIN）：
//
//	docker run --rm --privileged -v /home/qingzhou/haproxyweb:/src -w /src \
//	  -e GOPROXY=https://goproxy.cn,direct golang:1.25 \
//	  go run ./cmd/poc
//
// 验证清单（对应 docs/design-fwgateway.md 的全部内核面依赖，任一 FAIL → 触发 ADR 备选）：
//  1. netlink 连接                      2. inet 表 + 4 条 hook 链（含自定义 priority -10）
//  3. 规则 CRUD + counter + UserData    4. nft set + 规则内 Lookup 引用
//  5. DNAT（prerouting，addr+port）    6. SNAT（postrouting）
//  7. fwmark set + 位测试               8. multipath 路由 + ip rule
//  9. conntrack dump（nfnetlink）
//
// 10. 批次语义（netlink batch 无跨消息原子性 → 引擎层自证半装状态可检测）
package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const pocTable = "haweb-poc"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-smoke-legacy" {
		smokeLegacy()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "-smoke-hostsim" {
		smokeHostSim()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "-e2e" {
		e2eTransit()
		e2eTeardown()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "-e2e-dnat" {
		e2eDNAT()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "-smoke-migrate" {
		smokeMigrate()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "-smoke" {
		smokeEngine()
		return
	}
	checks := []struct {
		name string
		fn   func() (string, error)
	}{
		{"netlink 连接与表枚举", checkConn},
		{"inet 表 + 4 条 hook 链", checkChains},
		{"规则 CRUD + counter + UserData 标记", checkRules},
		{"nft set（interval）+ 规则 Lookup 引用", checkSets},
		{"DNAT（目的地址+端口改写）", checkDNAT},
		{"SNAT（源地址改写）", checkSNAT},
		{"fwmark set + 位测试", checkMark},
		{"multipath 路由 + ip rule", checkMultipath},
		{"conntrack dump（nfnetlink）", checkConntrack},
		{"批次语义（部分失败的残留检测）", checkBatchResidue},
	}

	fmt.Println("=== fwgateway T001 PoC：google/nftables v0.3.0 ===")
	pass, fail := 0, 0
	for i, c := range checks {
		ev, err := c.fn()
		if err != nil {
			fail++
			fmt.Printf("FAIL %2d. %s\n        %v\n", i+1, c.name, err)
		} else {
			pass++
			fmt.Printf("PASS %2d. %s\n        %s\n", i+1, c.name, ev)
		}
	}
	fmt.Printf("\n=== PoC 结果: PASS %d / FAIL %d / 共 %d ===\n", pass, fail, len(checks))
	if fail > 0 {
		os.Exit(1)
	}
}

// openNFT 开连接并保证 PoC 表清零。
func openNFT(cleanup bool) (*nftables.Conn, *nftables.Table, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, nil, fmt.Errorf("netlink: %w", err)
	}
	if cleanup {
		c.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: pocTable})
		_ = c.Flush() // 表不存在时的 ENOENT 忽略
	}
	tbl := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: pocTable})
	return c, tbl, nil
}

func closeNFT(c *nftables.Conn, tbl *nftables.Table) {
	c.DelTable(tbl)
	_ = c.Flush()
	c.CloseLasting()
}

// inetPrio 自定义 priority 的指针包装。
func inetPrio(v nftables.ChainPriority) *nftables.ChainPriority { return &v }

func checkConn() (string, error) {
	c, err := nftables.New()
	if err != nil {
		return "", err
	}
	defer c.CloseLasting()
	tables, err := c.ListTables()
	if err != nil {
		return "", fmt.Errorf("ListTables: %w", err)
	}
	names := make([]string, 0, len(tables))
	for _, t := range tables {
		names = append(names, t.Name)
	}
	return fmt.Sprintf("现有表: [%s]", strings.Join(names, " ")), nil
}

func checkChains() (string, error) {
	c, tbl, err := openNFT(true)
	if err != nil {
		return "", err
	}
	defer closeNFT(c, tbl)

	type HP struct {
		hook nftables.ChainHook
		prio nftables.ChainPriority
	}
	mk := func(name string, typ nftables.ChainType, hp HP) *nftables.Chain {
		return c.AddChain(&nftables.Chain{
			Name: name, Table: tbl, Type: typ, Hooknum: &hp.hook, Priority: &hp.prio,
		})
	}
	pre, mangle := nftables.ChainHookPrerouting, (*nftables.ChainPriorityMangle)
	pre2, natD := nftables.ChainHookPrerouting, (*nftables.ChainPriorityNATDest)
	fwd, fwdP := nftables.ChainHookForward, nftables.ChainPriorityRef(-10)
	post, natS := nftables.ChainHookPostrouting, (*nftables.ChainPriorityNATSource)

	mk("pre_mark", nftables.ChainTypeFilter, HP{*pre, mangle})
	mk("dstnat", nftables.ChainTypeNAT, HP{*pre2, natD})
	mk("fwd", nftables.ChainTypeFilter, HP{*fwd, *fwdP})
	mk("srcnat", nftables.ChainTypeNAT, HP{*post, natS})
	if err := c.Flush(); err != nil {
		return "", fmt.Errorf("建链 flush: %w", err)
	}
	got, err := c.ListChains()
	if err != nil {
		return "", fmt.Errorf("ListChains: %w", err)
	}
	n := 0
	ev := []string{}
	for _, ch := range got {
		if ch.Table != nil && ch.Table.Name == pocTable {
			n++
			ev = append(ev, fmt.Sprintf("%s(%+d)", ch.Name, *ch.Priority))
		}
	}
	if n != 4 {
		return "", fmt.Errorf("PoC 表链数 %d != 4", n)
	}
	return strings.Join(ev, " "), nil
}

func checkRules() (string, error) {
	c, tbl, err := openNFT(true)
	if err != nil {
		return "", err
	}
	defer closeNFT(c, tbl)
	hook, prio := *nftables.ChainHookInput, (*nftables.ChainPriorityFilter)
	ch := c.AddChain(&nftables.Chain{Name: "poc_r", Table: tbl, Type: nftables.ChainTypeFilter, Hooknum: &hook, Priority: &prio})
	_ = c.Flush()

	const ud = "haweb-nft:poc:1"
	c.AddRule(&nftables.Rule{
		Table: tbl, Chain: ch, UserData: []byte(ud),
		Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}},
	})
	if err := c.Flush(); err != nil {
		return "", fmt.Errorf("AddRule: %w", err)
	}
	rules, err := c.GetRules(tbl, ch)
	if err != nil {
		return "", fmt.Errorf("GetRules: %w", err)
	}
	var found *nftables.Rule
	for _, r := range rules {
		if string(r.UserData) == ud {
			found = r
		}
	}
	if found == nil {
		return "", fmt.Errorf("UserData 规则未回读到")
	}
	// 拆除：GetRules 回读的规则带 Handle
	if err := c.DelRule(found); err != nil {
		return "", fmt.Errorf("DelRule: %w", err)
	}
	if err := c.Flush(); err != nil {
		return "", fmt.Errorf("DelRule flush: %w", err)
	}
	after, _ := c.GetRules(tbl, ch)
	if len(after) != 0 {
		return "", fmt.Errorf("删后残留 %d 条", len(after))
	}
	return "增/查/删全过，handle 定位删除 OK", nil
}

func checkSets() (string, error) {
	c, tbl, err := openNFT(true)
	if err != nil {
		return "", err
	}
	defer closeNFT(c, tbl)
	hook, prio := *nftables.ChainHookInput, (*nftables.ChainPriorityFilter)
	ch := c.AddChain(&nftables.Chain{Name: "poc_s", Table: tbl, Type: nftables.ChainTypeFilter, Hooknum: &hook, Priority: &prio})

	set := &nftables.Set{
		Table: tbl, Name: "poc_srcs",
		KeyType: nftables.TypeIPAddr, Interval: true,
	}
	if err := c.AddSet(set, []nftables.SetElement{
		{Key: net.ParseIP("192.168.1.10").To4()},
	}); err != nil {
		return "", fmt.Errorf("AddSet: %w", err)
	}
	// 网段元素（interval）：SetAddElements 追加 /24 段
	if err := c.SetAddElements(set, []nftables.SetElement{
		{Key: net.ParseIP("10.0.0.0").To4()},
		{Key: net.ParseIP("10.0.0.255").To4(), IntervalEnd: true},
	}); err != nil {
		return "", fmt.Errorf("SetAddElements: %w", err)
	}
	c.AddRule(&nftables.Rule{
		Table: tbl, Chain: ch, UserData: []byte("haweb-nft:poc:lookup"),
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: set.Name},
			&expr.Counter{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	if err := c.Flush(); err != nil {
		return "", fmt.Errorf("flush: %w", err)
	}
	els, err := c.GetSetElements(set)
	if err != nil {
		return "", fmt.Errorf("GetSetElements: %w", err)
	}
	rules, _ := c.GetRules(tbl, ch)
	if len(els) < 2 || len(rules) != 1 {
		return "", fmt.Errorf("set 元素 %d / 规则 %d", len(els), len(rules))
	}
	return fmt.Sprintf("interval set %d 元素 + Lookup 规则 1 条", len(els)), nil
}

func checkDNAT() (string, error) {
	c, tbl, err := openNFT(true)
	if err != nil {
		return "", err
	}
	defer closeNFT(c, tbl)
	hook, prio := *nftables.ChainHookPrerouting, (*nftables.ChainPriorityNATDest)
	ch := c.AddChain(&nftables.Chain{Name: "poc_dn", Table: tbl, Type: nftables.ChainTypeNAT, Hooknum: &hook, Priority: &prio})

	c.AddRule(&nftables.Rule{
		Table: tbl, Chain: ch, UserData: []byte("haweb-nft:poc:dnat"),
		Exprs: []expr.Any{
			// 目的 IP = 203.0.113.10
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: net.ParseIP("203.0.113.10").To4()},
			// TCP dport = 443
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(443)},
			// DNAT → 10.0.1.5:8443
			&expr.Immediate{Register: 1, Data: net.ParseIP("10.0.1.5").To4()},
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(8443)},
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.AF_INET,
				RegAddrMin: 1, RegAddrMax: 1, RegProtoMin: 2, RegProtoMax: 2},
		},
	})
	if err := c.Flush(); err != nil {
		return "", fmt.Errorf("DNAT flush: %w", err)
	}
	n, _ := c.GetRules(tbl, ch)
	if len(n) != 1 {
		return "", fmt.Errorf("DNAT 规则 %d 条", len(n))
	}
	return "daddr+dport 匹配 → reg DNAT（addr+port）装载 OK", nil
}

func checkSNAT() (string, error) {
	c, tbl, err := openNFT(true)
	if err != nil {
		return "", err
	}
	defer closeNFT(c, tbl)
	hook, prio := *nftables.ChainHookPostrouting, (*nftables.ChainPriorityNATSource)
	ch := c.AddChain(&nftables.Chain{Name: "poc_sn", Table: tbl, Type: nftables.ChainTypeNAT, Hooknum: &hook, Priority: &prio})

	c.AddRule(&nftables.Rule{
		Table: tbl, Chain: ch, UserData: []byte("haweb-nft:poc:snat"),
		Exprs: []expr.Any{
			&expr.Immediate{Register: 1, Data: net.ParseIP("172.16.40.9").To4()},
			&expr.NAT{Type: expr.NATTypeSourceNAT, Family: unix.AF_INET, RegAddrMin: 1, RegAddrMax: 1},
		},
	})
	if err := c.Flush(); err != nil {
		return "", fmt.Errorf("SNAT flush: %w", err)
	}
	n, _ := c.GetRules(tbl, ch)
	if len(n) != 1 {
		return "", fmt.Errorf("SNAT 规则 %d 条", len(n))
	}
	return "固定源 SNAT 装载 OK（池形态=同结构多规则扇出）", nil
}

func checkMark() (string, error) {
	c, tbl, err := openNFT(true)
	if err != nil {
		return "", err
	}
	defer closeNFT(c, tbl)
	hook, prio := *nftables.ChainHookPrerouting, (*nftables.ChainPriorityMangle)
	ch := c.AddChain(&nftables.Chain{Name: "poc_mk", Table: tbl, Type: nftables.ChainTypeFilter, Hooknum: &hook, Priority: &prio})

	// meta mark set 0x1
	c.AddRule(&nftables.Rule{
		Table: tbl, Chain: ch, UserData: []byte("haweb-nft:poc:mark"),
		Exprs: []expr.Any{
			&expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(1)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
		},
	})
	// mark & 0x1 == 0x1 → accept：load → AND mask → cmp neq 0
	c.AddRule(&nftables.Rule{
		Table: tbl, Chain: ch, UserData: []byte("haweb-nft:poc:marktest"),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(1), Xor: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	if err := c.Flush(); err != nil {
		return "", fmt.Errorf("mark flush: %w", err)
	}
	n, _ := c.GetRules(tbl, ch)
	if len(n) != 2 {
		return "", fmt.Errorf("mark 规则 %d 条", len(n))
	}
	return "meta mark set + 位测试(AND+cmp) 装载 OK", nil
}

func checkMultipath() (string, error) {
	lo, err := vnetlink.LinkByName("lo")
	if err != nil {
		return "", fmt.Errorf("lo: %w", err)
	}
	const tbl = 250
	_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
	mp := []*vnetlink.NexthopInfo{
		{LinkIndex: lo.Attrs().Index, Hops: 0, Gw: net.ParseIP("127.0.0.2")}, // Weight 存储值 = 配置值-1
		{LinkIndex: lo.Attrs().Index, Hops: 1, Gw: net.ParseIP("127.0.0.3")},
	}
	delRule := func() {
		r := vnetlink.NewRule()
		r.Table, r.Priority = tbl, 32100
		_ = vnetlink.RuleDel(r)
	}
	cleanup := func() {
		_ = vnetlink.RouteDel(&vnetlink.Route{Table: tbl, Dst: defaultNet, MultiPath: mp})
		delRule()
	}
	cleanup()
	if err := vnetlink.RouteReplace(&vnetlink.Route{
		Table: tbl, LinkIndex: lo.Attrs().Index, Dst: defaultNet, MultiPath: mp,
	}); err != nil {
		return "", fmt.Errorf("RouteReplace multipath: %w", err)
	}
	// NewRule() 而非裸字面量：Goto/Flow/Suppress* 零值会被 vishvananda 编码成
	// FR_ACT_GOTO 0 / suppress 全路由（内核 EINVAL——已实测）
	rule := vnetlink.NewRule()
	rule.Table, rule.Priority = tbl, 32100
	if err := vnetlink.RuleAdd(rule); err != nil {
		return "", fmt.Errorf("RuleAdd: %w", err)
	}
	routes, err := vnetlink.RouteListFiltered(vnetlink.FAMILY_V4, &vnetlink.Route{Table: tbl}, vnetlink.RT_FILTER_TABLE)
	if err != nil {
		return "", fmt.Errorf("RouteListFiltered: %w", err)
	}
	defer cleanup()
	nh := 0
	weights := []string{}
	for _, r := range routes {
		if len(r.MultiPath) >= nh {
			nh = len(r.MultiPath)
			weights = weights[:0]
			for _, h := range r.MultiPath {
				weights = append(weights, fmt.Sprintf("%d", h.Hops+1))
			}
		}
	}
	if nh != 2 {
		return "", fmt.Errorf("nexthop 数 %d != 2", nh)
	}
	return fmt.Sprintf("multipath 路由（weights %s）+ rule 表 %d 在位", strings.Join(weights, ":"), tbl), nil
}

func checkConntrack() (string, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return "", fmt.Errorf("NETLINK_NETFILTER: %w", err)
	}
	defer conn.Close()
	// nfnetlink 头（nfgenmsg）：family=AF_INET(v4 dump), version=0, res_id=0
	const ipctlMsgCTGet = 1 // IPCTNL_MSG_CT_GET
	msg := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_CTNETLINK<<8 | ipctlMsgCTGet),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: []byte{byte(unix.AF_INET), 0, 0, 0},
	}
	if _, err := conn.Send(msg); err != nil {
		return "", fmt.Errorf("send: %w", err)
	}
	n := 0
	msgs, err := conn.Receive()
	if err != nil {
		return "", fmt.Errorf("receive: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Type&0xFF == ipctlMsgCTGet {
			n++
		}
	}
	if n == 0 {
		return "dump 通道 OK（容器内空表或 lo 流量未加载模块）", nil
	}
	return fmt.Sprintf("dump %d 条 conntrack 表项", n), nil
}

// checkBatchResidue 验证 netlink batch **部分失败**时的残留语义：
// google/nftables 的 Flush 是单 netlink batch（BEGIN..END），内核逐消息处理，
// 中途失败前面消息已生效——验证“失败后残留可检测、可清理”。
func checkBatchResidue() (string, error) {
	c, tbl, err := openNFT(true)
	if err != nil {
		return "", err
	}
	defer closeNFT(c, tbl)
	hook, prio := *nftables.ChainHookInput, (*nftables.ChainPriorityFilter)
	ch := c.AddChain(&nftables.Chain{Name: "poc_b", Table: tbl, Type: nftables.ChainTypeFilter, Hooknum: &hook, Priority: &prio})
	_ = c.Flush()

	// 同 batch：合法规则 + 非法规则（引用不存在的 set）
	c.AddRule(&nftables.Rule{
		Table: tbl, Chain: ch, UserData: []byte("haweb-nft:poc:good"),
		Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept}},
	})
	c.AddRule(&nftables.Rule{
		Table: tbl, Chain: ch, UserData: []byte("haweb-nft:poc:bad"),
		Exprs: []expr.Any{
			&expr.Lookup{SourceRegister: 1, SetName: "no-such-set"},
		},
	})
	err = c.Flush()
	if err == nil {
		return "batch 未产生失败（非法 set 引用被库或内核接受？需人工复核）", fmt.Errorf("期望失败未发生")
	}
	// 部分失败：合法规则是否残留？
	rules, rerr := c.GetRules(tbl, ch)
	if rerr != nil {
		return "", fmt.Errorf("残留检查 GetRules: %w", rerr)
	}
	good := 0
	for _, r := range rules {
		if strings.Contains(string(r.UserData), ":good") {
			good++
		}
	}
	if good == 1 {
		return "验证结论：batch 部分失败时合法规则残留（引擎层必须实现补偿删除——已计入 design ADR）", nil
	}
	return "batch 失败后无残留（内核回滚了整批——引擎层可依赖原子性）", nil
}
