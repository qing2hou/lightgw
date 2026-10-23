package proxy

import (
	"strings"
	"testing"

	"haproxyweb/internal/model"
)

// 命令拼装：三段式（SNAT/ACCEPT/DROP）形态与标记正确；无名单时无 DROP 行。
// sameForwarding 快速路径判定矩阵：转发形态一致（含顺序无关的名单集合）→ true；
// 网卡/SNAT 源/出口网关/名单任一变化或首次应用（entry 缺失）→ false；
// 限速参数变化不影响判定（走 tc 热替换，不断流）。
func TestSnatSameForwarding(t *testing.T) {
	base := func() *snatRuleSpec {
		return &snatRuleSpec{ID: 5, IfIn: "eth0", IfOut: "eth1", OutIP: "172.16.40.10",
			EgressGw: "172.16.40.1", AllowSrcs: []string{"192.168.10.0/24", "192.168.20.5"},
			DstAclMode: "blacklist", DstDeny: []string{"10.0.0.0/8"}}
	}
	e := &snatEntry{ifIn: "eth0", ifOut: "eth1", outIP: "172.16.40.10", egressGw: "172.16.40.1",
		allowSrcs: []string{"192.168.20.5", "192.168.10.0/24"}, // 顺序不同=同集合
		dstMode: "blacklist", dstDeny: []string{"10.0.0.0/8"}}

	if !e.sameForwarding(base()) {
		t.Fatal("形态完全一致（名单顺序不同）应走快速路径")
	}
	// 限速参数变化（额度/保底）不影响判定
	s := base()
	s.BWGroupKBps, s.MinKBps = 999999, 100
	if !e.sameForwarding(s) {
		t.Fatal("限速参数变化不应触发 iptables 重建")
	}
	for name, mut := range map[string]func(*snatRuleSpec){
		"入口网卡":   func(s *snatRuleSpec) { s.IfIn = "eth9" },
		"出口网卡":   func(s *snatRuleSpec) { s.IfOut = "eth9" },
		"SNAT 源":  func(s *snatRuleSpec) { s.OutIP = "172.16.40.11" },
		"出口网关":   func(s *snatRuleSpec) { s.EgressGw = "" },
		"源名单增条":  func(s *snatRuleSpec) { s.AllowSrcs = append(s.AllowSrcs, "1.2.3.4") },
		"源名单减条":  func(s *snatRuleSpec) { s.AllowSrcs = s.AllowSrcs[:1] },
		"目标模式变更": func(s *snatRuleSpec) { s.DstAclMode = "off"; s.DstDeny = nil },
		"目标黑名单增条": func(s *snatRuleSpec) { s.DstDeny = append(s.DstDeny, "11.0.0.0/8") },
	} {
		s := base()
		mut(s)
		if e.sameForwarding(s) {
			t.Errorf("%s 变化不应走快速路径", name)
		}
	}
	// 目标白名单集合比对
	e2 := &snatEntry{ifIn: "eth0", ifOut: "eth1", outIP: "172.16.40.10", egressGw: "172.16.40.1",
		allowSrcs: []string{"192.168.10.0/24", "192.168.20.5"}, dstMode: "whitelist",
		dstAllow: []string{"8.8.8.8", "1.1.1.0/24"}}
	s2 := base()
	s2.DstAclMode, s2.DstDeny = "whitelist", nil
	s2.DstAllow = []string{"1.1.1.0/24", "8.8.8.8"}
	if !e2.sameForwarding(s2) {
		t.Error("目标白名单同集合（顺序不同）应走快速路径")
	}
}

// nf_conntrack 解析：标准行形态取全字段（orig/reply 四元组）。
func TestParseConntrackLine(t *testing.T) {
	ln := "tcp 6 431997 ESTABLISHED src=192.168.10.162 dst=27.222.18.147 sport=45488 dport=443 src=172.16.40.10 dst=27.222.18.147 sport=45488 dport=443 [ASSURED] mark=0 use=1"
	c, ok := parseConntrackLine(ln)
	if !ok {
		t.Fatal("标准行解析失败")
	}
	if c.proto != "tcp" || c.origSrc != "192.168.10.162" || c.origDst != "27.222.18.147" ||
		c.origSPort != "45488" || c.origDPort != "443" {
		t.Fatalf("orig 四元组不符: %+v", c)
	}
	if c.replySrc != "172.16.40.10" || c.replyDst != "27.222.18.147" {
		t.Fatalf("reply 四元组不符: %+v", c)
	}
	// udp 行 + 无 [ASSURED]
	c2, ok := parseConntrackLine("udp 17 30 src=192.168.10.2 dst=8.8.8.8 sport=512 dport=53 src=172.16.40.10 dst=8.8.8.8 sport=512 dport=53 mark=0 use=1")
	if !ok || c2.proto != "udp" || c2.origSrc != "192.168.10.2" || c2.replySrc != "172.16.40.10" {
		t.Fatalf("udp 行解析不符: %+v ok=%v", c2, ok)
	}
	// 畸形行
	if _, ok := parseConntrackLine("tcp 6 431997 ESTABLISHED src=1.2.3.4"); ok {
		t.Fatal("残行不应解析成功")
	}
	if _, ok := parseConntrackLine("icmp 1 0 src=1.2.3.4 dst=5.6.7.8 type=0"); ok {
		t.Fatal("非 tcp/udp 不解析")
	}
}

// 停用掐断归属判定 + 跨规则源排除矩阵。
func TestOwnsCTSessionAndSubtract(t *testing.T) {
	// A 维度：reply 源 = SNAT 源
	c := &ctSession{proto: "tcp", origSrc: "192.168.10.162", replySrc: "172.16.40.10"}
	if !ownsCTSession(c, "172.16.40.10", nil) {
		t.Fatal("A 维度（reply源=OutIP）应归属")
	}
	if ownsCTSession(c, "172.16.40.11", nil) {
		t.Fatal("reply 源不同且无 B 维度来源——不应归属")
	}
	// B 维度：orig 源 ∈ 独占源段
	c2 := &ctSession{proto: "tcp", origSrc: "192.168.10.2", replySrc: "192.168.10.2"} // 探测自身目标（经放行但未改源）
	if !ownsCTSession(c2, "172.16.40.10", []string{"192.168.10.0/24"}) {
		t.Fatal("B 维度（独占网段内源）应归属")
	}
	// 跨规则源重叠：源段被其他规则同时持有 → 剔除（宁漏杀不错杀）
	got := subtractSrcs([]string{"192.168.10.0/24", "10.1.1.0/24"}, []string{"192.168.10.0/24", "10.9.9.1"})
	if len(got) != 1 || got[0] != "10.1.1.0/24" {
		t.Fatalf("跨规则交集应剔除: %v", got)
	}
	if ownsCTSession(c2, "172.16.40.10", subtractSrcs([]string{"192.168.10.0/24"}, []string{"192.168.10.0/24"})) {
		t.Fatal("源段与他规则重叠时不应归属（宁漏杀）")
	}
	// 无跨规则：原样保留
	if got := subtractSrcs([]string{"a", "b"}, nil); len(got) != 2 {
		t.Fatalf("无跨规则时不应剔除: %v", got)
	}
	// ipInList：单 IP 与 CIDR
	if !ipInList("10.1.1.5", []string{"10.1.1.0/24"}) || ipInList("10.2.1.5", []string{"10.1.1.0/24"}) {
		t.Fatal("ipInList CIDR 判断不符")
	}
	if !ipInList("1.2.3.4", []string{"1.2.3.4"}) || ipInList("", []string{"1.2.3.4"}) {
		t.Fatal("ipInList 单 IP/空判断不符")
	}
}

func TestSnatIptablesArgs(t *testing.T) {
	s := &snatRuleSpec{ID: 7, IfIn: "ens19", IfOut: "eth0", OutIP: "192.168.10.161",
		AllowSrcs: []string{"172.16.40.0/24"}}

	rules := s.iptablesArgs()
	if len(rules) != 3 {
		t.Fatalf("白名单形态应 3 条规则（数组序 SNAT/conntrack/ACCEPT-s；兜底 DROP 已移除交给 policy DROP），实际 %d", len(rules))
	}
	joined := ""
	for _, r := range rules {
		joined += strings.Join(r, " ") + "\n"
		// 每条都带 comment 标记（ADR-4）
		if !contains(strJoin(r), "haweb-sn:7") {
			t.Errorf("规则缺 comment 标记: %v", r)
		}
	}
	if !contains(strJoin(rules[0]), "-t nat -I POSTROUTING 1 -o eth0 -s 172.16.40.0/24") ||
		!contains(strJoin(rules[0]), "-j SNAT --to-source 192.168.10.161") {
		t.Errorf("SNAT 规则形态不符: %v", rules[0])
	}
	// conntrack 回程（数组中段）
	if !contains(strJoin(rules[1]), "ESTABLISHED,RELATED") {
		t.Errorf("回程行应在数组[1]: %v", rules[1])
	}
	// 数组序（DROP 移除后）：[2] = 白名单 ACCEPT（链首）
	if !contains(strJoin(rules[2]), "-i ens19 -o eth0 -s 172.16.40.0/24") || !contains(strJoin(rules[2]), "-j ACCEPT") {
		t.Errorf("白名单 ACCEPT 形态不符: %v", rules[2])
	}

	// 无名单：nat1 + conntrack1 + ACCEPT1 = 3（无 -s）
	s2 := &snatRuleSpec{ID: 8, IfIn: "ens19", IfOut: "eth0", OutIP: "1.2.3.4"}
	if got := len(s2.iptablesArgs()); got != 3 {
		t.Errorf("无名单形态应 3 条规则，实际 %d", got)
	}
	for _, r := range s2.iptablesArgs() {
		if contains(strJoin(r), "-s ") {
			t.Errorf("无名单形态不应有 -s: %v", r)
		}
	}
}

// 多源多目标笛卡尔积逐条展开：iptables -s/-d 是单值参数（多次出现报
// multiple flags not allowed），多值必须拆成多行（链上多行 = OR 语义）。
func TestSnatMultiValueExpansion(t *testing.T) {
	// 2 源 1 目标黑名单：nat2 + conntrack1 + ACCEPT2 + DROP(2×1)=2 → 7 行
	s := &snatRuleSpec{ID: 21, IfIn: "eth0", IfOut: "eth1", OutIP: "172.16.40.10",
		AllowSrcs: []string{"192.168.10.162", "192.168.10.2"},
		DstAclMode: "blacklist", DstDeny: []string{"10.0.0.0/8"}}
	rules := s.iptablesArgs()
	if len(rules) != 7 {
		t.Fatalf("2源+1目标黑名单应 7 行（nat2/ct1/acc2/drop2），实际 %d", len(rules))
	}
	natN, accN, dropN := 0, 0, 0
	for _, r := range rules {
		j := strJoin(r)
		switch {
		case contains(j, "-j SNAT"):
			natN++
			if !contains(j, "-s 192.168.10.162") && !contains(j, "-s 192.168.10.2") {
				t.Errorf("nat 行缺源: %s", j)
			}
		case contains(j, "-j DROP"):
			dropN++
		case contains(j, "-j ACCEPT") && !contains(j, "conntrack"):
			accN++
		}
	}
	if natN != 2 || accN != 2 || dropN != 2 {
		t.Fatalf("行数分布不符 nat=%d acc=%d drop=%d", natN, accN, dropN)
	}
	// 1 源 2 目标白名单：nat1 + ct1 + acc(1×2)=2 → 4 行；每行单 -d
	s2 := &snatRuleSpec{ID: 22, IfIn: "eth0", IfOut: "eth1", OutIP: "172.16.40.10",
		AllowSrcs: []string{"192.168.10.162"}, DstAclMode: "whitelist",
		DstAllow: []string{"223.5.5.5", "119.29.29.29"}}
	rules2 := s2.iptablesArgs()
	if len(rules2) != 4 {
		t.Fatalf("1源2目标白名单应 4 行，实际 %d", len(rules2))
	}
	accRows := 0
	for _, r := range rules2 {
		j := strJoin(r)
		if contains(j, "-j ACCEPT") && !contains(j, "conntrack") {
			accRows++
			if !contains(j, "-d 223.5.5.5") && !contains(j, "-d 119.29.29.29") {
				t.Errorf("白名单 ACCEPT 行缺 -d: %s", j)
			}
			if strings.Count(j, "-d ") != 1 {
				t.Errorf("ACCEPT 行应单 -d（多 -d 非法）: %s", j)
			}
		}
	}
	if accRows != 2 {
		t.Fatalf("白名单 ACCEPT 应 2 行，实际 %d", accRows)
	}
	// 单行 -s/-d 不重复出现（multiple flags 防御断言）
	for _, r := range append(rules, rules2...) {
		j := strJoin(r)
		if n := strings.Count(j, "-s "); n > 1 {
			t.Errorf("单行出现 %d 个 -s（iptables 不允许）: %s", n, j)
		}
		if n := strings.Count(j, "-d "); n > 1 {
			t.Errorf("单行出现 %d 个 -d（iptables 不允许）: %s", n, j)
		}
	}
}

// 目标黑名单：每目标一行 -j DROP，带 -s 本规则源、-d 目标、comment 标记；
// 排在数组 ACCEPT 之后（执行后位于链首——拒绝优先于放行）。
func TestSnatDstBlacklistArgs(t *testing.T) {
	s := &snatRuleSpec{ID: 11, IfIn: "eth0", IfOut: "ens19", OutIP: "172.16.40.10",
		AllowSrcs: []string{"192.168.10.0/24"}, DstAclMode: "blacklist",
		DstDeny: []string{"10.0.0.0/8", "172.16.31.5"}}

	rules := s.iptablesArgs()
	// 3 基础行（SNAT/conntrack/ACCEPT）+ 2 目标 DROP
	if len(rules) != 5 {
		t.Fatalf("目标黑名单形态应 5 条规则，实际 %d", len(rules))
	}
	for i, d := range []string{"10.0.0.0/8", "172.16.31.5"} {
		drop := strJoin(rules[3+i])
		if !contains(drop, "-i eth0 -o ens19 -s 192.168.10.0/24") {
			t.Errorf("目标 DROP 缺源匹配（会误伤他规则白名单源）: %s", drop)
		}
		if !contains(drop, "-d "+d) || !contains(drop, "-j DROP") || !contains(drop, "haweb-sn:11") {
			t.Errorf("目标 DROP 形态不符（%s）: %s", d, drop)
		}
		// ACCEPT 行在数组前部 → 链上位于 DROP 之下（拒绝优先）
		acc := strJoin(rules[2])
		if !contains(acc, "-j ACCEPT") {
			t.Errorf("ACCEPT 应在数组 [2]: %v", rules[2])
		}
	}
	// 拆除形态含当前 DROP 行（teardownArgs 基于 iptablesArgs 生成，天然覆盖）
	all := s.teardownArgs()
	joined := ""
	for _, r := range all {
		joined += strJoin(r) + "\n"
	}
	if !contains(joined, "-d 10.0.0.0/8") || !contains(joined, "-j DROP") {
		t.Errorf("拆除形态应含目标 DROP: %s", joined)
	}
}

// 目标白名单：源×目标逐行展开（每行单 -d）；无 DROP 行。
func TestSnatDstWhitelistArgs(t *testing.T) {
	s := &snatRuleSpec{ID: 12, IfIn: "eth0", IfOut: "ens19", OutIP: "172.16.40.10",
		AllowSrcs: []string{"192.168.10.0/24"}, DstAclMode: "whitelist",
		DstAllow: []string{"172.16.41.0/24", "8.8.8.8"}}

	rules := s.iptablesArgs()
	// nat1 + conntrack1 + ACCEPT(1源×2目标)=2 → 4 行
	if len(rules) != 4 {
		t.Fatalf("目标白名单形态应 4 条规则（1源2目标展开），实际 %d", len(rules))
	}
	accRows := 0
	for _, r := range rules {
		j := strJoin(r)
		if contains(j, "-j DROP") {
			t.Errorf("目标白名单不应有 DROP 行: %s", j)
		}
		if contains(j, "-j ACCEPT") && !contains(j, "conntrack") {
			accRows++
			if !contains(j, "-s 192.168.10.0/24") {
				t.Errorf("目标白名单 ACCEPT 应含 -s 源: %s", j)
			}
			if !contains(j, "-d 172.16.41.0/24") && !contains(j, "-d 8.8.8.8") {
				t.Errorf("目标白名单 ACCEPT 行缺目标: %s", j)
			}
		}
	}
	if accRows != 2 {
		t.Fatalf("目标白名单 ACCEPT 应 2 行，实际 %d", accRows)
	}
	// 拆除补历史形态：无 -d 的旧 ACCEPT（曾未配置目标名单的迁移场景）
	all := s.teardownArgs()
	joined := ""
	for _, r := range all {
		joined += strJoin(r) + "\n"
	}
	if !contains(joined, "-D FORWARD -i eth0 -o ens19 -m comment --comment haweb-sn:12 -j ACCEPT") {
		t.Errorf("拆除形态应含无 -d 的历史 ACCEPT: %s", joined)
	}
}

// 旧规则兼容：off 模式（或空 DstAclMode）+ 两维名单为空 → 形态与旧版完全一致。
func TestSnatDstOffCompat(t *testing.T) {
	for _, mode := range []string{"", "off"} {
		s := &snatRuleSpec{ID: 13, IfIn: "eth0", IfOut: "ens19", OutIP: "172.16.40.10",
			AllowSrcs: []string{"192.168.10.0/24"}, DstAclMode: mode}
		rules := s.iptablesArgs()
		if len(rules) != 3 {
			t.Fatalf("off/空模式形态应 3 条（与旧版一致），模式 %q 实际 %d", mode, len(rules))
		}
		acc := strJoin(rules[2])
		if contains(acc, "-d ") {
			t.Errorf("off 模式 ACCEPT 不应含 -d: %s", acc)
		}
	}
}

// buildSnatSpec 目标名单解析：JSON 数组进 spec；非法 JSON 降级为空（引擎侧兜底，
// API 层已强校验——这里是直改库数据的容错路径）。
// 含 M2 防御回归：off 源模式 + 目标黑名单（API 直调被拒）在引擎侧兜底为
// 黑洞源名单——绝不落地为无源 DROP（跨规则误伤，v2 事故同型）。
func TestSnatSpecDstLists(t *testing.T) {
	m := &Manager{}
	rule := model.ForwardRule{ListenAddr: "a", TargetAddr: "b", Protocol: model.ProtocolSNAT,
		DstAclMode:   "blacklist",
		DstDenyList:  `["10.0.0.0/8","172.16.31.5"]`,
		DstAllowList: ""}
	spec := m.buildSnatSpec(rule)
	if len(spec.DstDeny) != 2 || spec.DstDeny[0] != "10.0.0.0/8" {
		t.Fatalf("目标黑名单解析不符: %v", spec.DstDeny)
	}
	if spec.DstAclMode != "blacklist" {
		t.Fatalf("目标模式解析不符: %q", spec.DstAclMode)
	}
	// M2 黑洞兜底：off 源 + 目标黑名单 → AllowSrcs 得到黑洞名单（不是空）
	if len(spec.AllowSrcs) == 0 {
		t.Fatalf("目标黑名单在 off 源模式下应黑洞化源名单（防无源 DROP 误伤）：AllowSrcs 为空")
	}
	if spec.AllowSrcs[0] != "0.0.0.0/32" {
		t.Fatalf("黑洞名单形态应为 0.0.0.0/32: %v", spec.AllowSrcs)
	}
	// DROP 行带 -s（无源 DROP 防御的最终断言）
	drops := 0
	for _, r := range spec.iptablesArgs() {
		j := strJoin(r)
		if contains(j, "-j DROP") {
			drops++
			if !contains(j, "-s 0.0.0.0/32") {
				t.Fatalf("DROP 行必须带源匹配（无源 DROP 跨规则误伤）: %s", j)
			}
		}
	}
	if drops != 2 {
		t.Fatalf("两目标黑名单应 2 条 DROP 行，实际 %d", drops)
	}
	// 非法 JSON 容错：空串返回 nil、坏 JSON 返回 nil（不 panic）
	rule2 := model.ForwardRule{ListenAddr: "a", TargetAddr: "b", Protocol: model.ProtocolSNAT,
		DstAclMode: "whitelist", DstAllowList: "not-json"}
	if spec2 := m.buildSnatSpec(rule2); len(spec2.DstAllow) != 0 {
		t.Fatalf("非法 JSON 应降级为空: %v", spec2.DstAllow)
	}
}

// 拆除形态：含当前形态 + 无源匹配的历史形态（off→whitelist 迁移场景）。
func TestSnatTeardownArgs(t *testing.T) {
	s := &snatRuleSpec{ID: 9, IfIn: "a", IfOut: "b", OutIP: "1.1.1.1", AllowSrcs: []string{"10.0.0.0/8"}}
	all := s.teardownArgs()
	joined := ""
	for _, r := range all {
		joined += strJoin(r) + "\n"
	}
	// 三类 -D 全在（SNAT/ACCEPT/DROP 的带源与不带源形态）
	for _, want := range []string{"-t nat -D POSTROUTING", "-D FORWARD", "-j DROP", "-j ACCEPT", "--to-source 1.1.1.1"} {
		if !contains(joined, want) {
			t.Errorf("拆除形态缺少 %q:\n%s", want, joined)
		}
	}
}

// 计数解析：iptables -L -v -x 标准输出形态下按 comment 归集 ACCEPT/DROP。
func TestReadSnatCountersParse(t *testing.T) {
	sample := `Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target prot opt in     out    source       destination
 1000 50000 ACCEPT all  --  ens19  eth0   0.0.0.0/0    0.0.0.0/0   /* haweb-sn:7 */
 12   600   DROP   all  --  ens19  eth0   0.0.0.0/0    0.0.0.0/0   /* haweb-sn:7 */
 999  49999 ACCEPT all  --  other  eth0   0.0.0.0/0    0.0.0.0/0   /* haweb-sn:99 */`

	c := parseSnatCountersOutput(sample, "haweb-sn:7")
	if c == nil {
		t.Fatal("解析失败")
	}
	if c.PktsAccept != 1000 || c.BytesAccept != 50000 {
		t.Errorf("ACCEPT 计数不符: %+v", c)
	}
	if c.PktsDrop != 12 || c.BytesDrop != 600 {
		t.Errorf("DROP 计数不符: %+v", c)
	}
	// 其他规则行不受影响
	c2 := parseSnatCountersOutput(sample, "haweb-sn:99")
	if c2.PktsAccept != 999 {
		t.Errorf("规则 99 计数不符: %+v", c2)
	}
}

// 目标黑名单多目标计数：同 comment 的 N 条 DROP 行求和（不能只留最后一行）。
func TestReadSnatCountersMultiDropSum(t *testing.T) {
	sample := `Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target prot opt in     out    source          destination
 5    300   DROP   all  --  eth0   ens19  192.168.10.162  172.16.30.0/24   /* haweb-sn:61 */
 7    400   DROP   all  --  eth0   ens19  192.168.10.162  172.16.31.5      /* haweb-sn:61 */
 20   2000  ACCEPT all  --  eth0   ens19  192.168.10.162  0.0.0.0/0        /* haweb-sn:61 */
 99   9900  ACCEPT all  --  *      *      0.0.0.0/0        0.0.0.0/0        ctstate RELATED,ESTABLISHED /* haweb-sn:61 */`

	c := parseSnatCountersOutput(sample, "haweb-sn:61")
	if c == nil {
		t.Fatal("解析失败")
	}
	if c.PktsDrop != 12 || c.BytesDrop != 700 {
		t.Fatalf("多目标 DROP 应求和得 12 包/700B，实际: %+v", c)
	}
	// ACCEPT 同 comment 多行（白名单 ACCEPT + conntrack 回程）同样求和：
	// 差分口径下 conntrack 行计数被基线吸收，增长只来自活跃穿越
	if c.PktsAccept != 119 || c.BytesAccept != 11900 {
		t.Fatalf("ACCEPT 多行应求和（20+99 包 / 2000+9900B）: %+v", c)
	}
}

// 对账标记提取：iptables-save 输出中收集 haweb-sn: ID。
func TestSnatInstalledRuleIDs(t *testing.T) {
	sample := `-A POSTROUTING -o eth0 -j SNAT --to-source 1.2.3.4 -m comment --comment haweb-sn:7
-A FORWARD -i a -o b -j ACCEPT -m comment --comment haweb-sn:7
-A FORWARD -j DOCKER
-A FORWARD -i a -o b -j ACCEPT -m comment --comment haweb-sn:12
`
	ids := snatIDsFromSave(sample)
	if len(ids) != 2 || !ids[7] || !ids[12] {
		t.Fatalf("对账 ID 集合不符: %v", ids)
	}
}

func strJoin(ss []string) string { return strings.Join(ss, " ") }

func contains(s, sub string) bool { return len(s) >= len(sub) && strings.Contains(s, sub) }

// 显式 SNAT 源 IP 优先：rule.SnatIP 非空时 spec.OutIP 用它；空时自动取出口网卡首地址。
func TestSnatSpecExplicitIP(t *testing.T) {
	m := &Manager{}
	rule := model.ForwardRule{
		ListenAddr: "a", TargetAddr: "lo", Protocol: model.ProtocolSNAT,
		SnatIP: "10.0.0.99",
	}
	spec := m.buildSnatSpec(rule)
	if spec.OutIP != "10.0.0.99" {
		t.Fatalf("显式 SnatIP 应优先生效: %q", spec.OutIP)
	}
	// 自动档：出口网卡（lo 的 IPv4 是 127.0.0.1，被排除——用 eth0/存在的网卡不可移植，
	// 改验证空 SnatIP 走 ipv4Of 的回退路径：命名一个不存在的网卡得空串，spec 里 OutIP 空由
	// installSnat 报错拦截（applySNAT 流程内已有校验））
	rule2 := model.ForwardRule{ListenAddr: "a", TargetAddr: "no-such-if", Protocol: model.ProtocolSNAT}
	if s2 := m.buildSnatSpec(rule2); s2.OutIP != "" {
		t.Fatalf("不存在的出口网卡自动档应为空串: %q", s2.OutIP)
	}
}
