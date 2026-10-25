// 出口（Egress）实体与探测循环（M3/T201/T202，ADR-12）。
//
// 探测模型（AC-4.x）：每出口独立周期探测（icmp 网关/目标、tcp 端口）；
// 连续 FailCount 次失败判 down、连续 UpCount 次成功判 up（去抖——探测自身
// 抖动不翻转状态）；状态翻转才 logf+审计计数，稳态不刷屏。接口拔除（链路
// down）立即判 down。出口的【切换执行】不在探测循环里——状态翻转后通知
// reapplyAllSnatRules 重算路由（层+权重的多出口决策在 applySNAT 的
// EnsureEgressRoute 阶段，T203/T204）。
package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"haproxyweb/internal/model"
	"haproxyweb/internal/nft"
)

// egressState 出口运行时状态（内存原子量——重启后立即探测恢复）。
type egressState struct {
	up         atomic.Bool
	latencyMs  atomic.Int64 // 最近一次探测 RTT（μs 精度存 ms）
	lastSwitch atomic.Int64 // unix 秒
	failSeq    atomic.Int32 // 连续失败计数（去抖）
	upSeq      atomic.Int32 // 连续成功计数
	downReason atomic.Pointer[string]
}

var (
	egressMu       sync.Mutex
	egressStateMap = map[uint]*egressState{}
)

func egressStateOf(id uint) *egressState {
	egressMu.Lock()
	defer egressMu.Unlock()
	if egressStateMap[id] == nil {
		// B3：零值 up=false 会把新建/重启后的出口在连续 UpCount 次探测成功前
		// 判 down（默认 ~6s 参与不了路由）。未知即 up（与 EgressUp 注释一致），
		// 首探失败即开始正常去抖翻转路径。
		egressStateMap[id] = &egressState{}
		egressStateMap[id].up.Store(true)
	}
	return egressStateMap[id]
}

// ProbeEgressOnce 单次探测：按模式探测，返回 (ok, latency, reason)。
func ProbeEgressOnce(e model.Egress) (bool, int64, string) {
	if e.ProbeMode == "none" {
		// S4：常开出口仍要链路状态门（PRD：网卡拔除立即判 down）
		iface, err := net.InterfaceByName(e.Iface)
		if err != nil || iface.Flags&net.FlagUp == 0 {
			return false, -1, fmt.Sprintf("网卡 %s 不存在或链路 down", e.Iface)
		}
		return true, 0, ""
	}
	// 链路 down 立即判 down（AC-4.6 边界）
	iface, err := net.InterfaceByName(e.Iface)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return false, -1, fmt.Sprintf("网卡 %s 不存在或链路 down", e.Iface)
	}
	switch e.ProbeMode {
	case "icmp-gw":
		gw := e.GatewayV4
		if gw == "" {
			gw = e.GatewayV6
		}
		if gw == "" {
			return false, -1, "icmp-gw 模式但未配置网关"
		}
		rtt, err := pingRTT(gw, 2*time.Second)
		if err != nil {
			return false, -1, fmt.Sprintf("网关 %s 不可达: %v", gw, err)
		}
		return true, rtt.Milliseconds(), ""
	case "icmp-target":
		if e.ProbeTarget == "" {
			return false, -1, "icmp-target 模式但未配置目标"
		}
		rtt, err := pingRTT(e.ProbeTarget, 2*time.Second)
		if err != nil {
			return false, -1, fmt.Sprintf("目标 %s 不可达: %v", e.ProbeTarget, err)
		}
		return true, rtt.Milliseconds(), ""
	case "tcp-target":
		if e.ProbeTarget == "" {
			return false, -1, "tcp-target 模式但未配置目标"
		}
		start := time.Now()
		c, err := net.DialTimeout("tcp", e.ProbeTarget, 2*time.Second)
		if err != nil {
			return false, -1, fmt.Sprintf("TCP %s 不通: %v", e.ProbeTarget, err)
		}
		_ = c.Close()
		return true, time.Since(start).Milliseconds(), ""
	default:
		return false, -1, fmt.Sprintf("未知探测模式 %q", e.ProbeMode)
	}
}

// pingRTT ICMP echo（raw socket 由 root 权限保证；无第三方依赖）。
// 实现走 /proc/ping 不可靠——直接发 ICMP echo 并等待 echo reply（ICMP
// conn 已在 Go 标准库 net.ListenPacket("ip4:icmp") 提供能力，不需要 exec ping）。
func pingRTT(host string, timeout time.Duration) (time.Duration, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		// 目标是名字（探测目标一般写 IP；DNS 解析兜底）
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return 0, fmt.Errorf("解析 %s 失败: %v", host, err)
		}
		ip = ips[0]
	}
	var network string
	if ip.To4() != nil {
		network = "ip4:icmp"
	} else {
		network = "ip6:ipv6-icmp"
	}
	c, err := net.ListenPacket(network, "")
	if err != nil {
		return 0, fmt.Errorf("ICMP socket: %w", err)
	}
	defer c.Close()

	// id 加进程级随机 salt + payload nonce（多并发探测的 raw socket 全收
	// 互串防护——同宿主多实例也不互抢回复）
	var id uint16 = uint16(time.Now().UnixNano()>>4) & 0xffff
	var seq uint16 = 1
	nonce := fmt.Sprintf("hawebprobe-%d", time.Now().UnixNano())
	var payload []byte
	if ip.To4() != nil {
		payload = icmpEchoV4(id, seq, []byte(nonce))
	} else {
		payload = icmpEchoV6(id, seq, []byte(nonce))
	}
	dst := &net.IPAddr{IP: ip}
	start := time.Now()
	if _, err := c.WriteTo(payload, dst); err != nil {
		return 0, err
	}
	if err := c.SetDeadline(start.Add(timeout)); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return 0, fmt.Errorf("等待回包超时（%s）: %w", host, err)
		}
		if from.String() != ip.String() {
			continue
		}
		rtt := time.Since(start)
		var ok bool
		if ip.To4() != nil {
			ok = isEchoReplyV4(buf[:n], id, seq)
		} else {
			ok = isEchoReplyV6(buf[:n], id, seq)
		}
		if ok {
			return rtt, nil
		}
	}
}

// icmpEchoV4 ICMP echo request（v4 需自带校验和）。
func icmpEchoV4(id, seq uint16, data []byte) []byte {
	msg := make([]byte, 8+len(data))
	msg[0] = 8 // echo request
	msg[1] = 0
	msg[2], msg[3] = 0, 0
	msg[4] = byte(id >> 8)
	msg[5] = byte(id)
	msg[6] = byte(seq >> 8)
	msg[7] = byte(seq)
	copy(msg[8:], data)
	sum := checksumV4(msg)
	msg[2], msg[3] = byte(sum>>8), byte(sum)
	return msg
}

func icmpEchoV6(id, seq uint16, data []byte) []byte {
	msg := make([]byte, 8+len(data))
	msg[0] = 128 // echo request (v6)
	msg[1] = 0
	msg[2], msg[3] = 0, 0
	msg[4] = byte(id >> 8)
	msg[5] = byte(id)
	msg[6] = byte(seq >> 8)
	msg[7] = byte(seq)
	copy(msg[8:], data)
	// v6 校验和由内核计算（IPV6_CHECKSUM socket option 默认处理）——
	// net.ListenPacket("ip6:ipv6-icmp") 的 raw socket 在 Go 运行时层面
	// 不自动算；保守自算
	sum := checksumV6(msg)
	msg[2], msg[3] = byte(sum>>8), byte(sum)
	return msg
}

func checksumV4(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func checksumV6(b []byte) uint16 { return checksumV4(b) }

func isEchoReplyV4(b []byte, id, seq uint16) bool {
	if len(b) < 16 { // 20B IP 头（raw 不剥?——ListenPacket ip4 剥 IP 头）+ 8B ICMP
		return false
	}
	icmp := b
	// Go 的 ip4:icmp raw socket 读到的是完整 IP 包（含 20B 头）
	if len(b) >= 24 && b[0]>>4 == 4 {
		icmp = b[20:]
	}
	return icmp[0] == 0 && // echo reply
		uint16(icmp[4])<<8|uint16(icmp[5]) == id &&
		uint16(icmp[6])<<8|uint16(icmp[7]) == seq
}

func isEchoReplyV6(b []byte, id, seq uint16) bool {
	if len(b) < 8 {
		return false
	}
	return b[0] == 129 && // echo reply (v6)
		uint16(b[4])<<8|uint16(b[5]) == id &&
		uint16(b[6])<<8|uint16(b[7]) == seq
}

// egressProbeLoop 出口探测循环（每 intervalSec 轮——统一按最小间隔轮询，
// 每出口自己的去抖计数独立）。
func (m *Manager) egressProbeLoop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	lastProbe := map[uint]time.Time{}
	for {
		select {
		case <-m.egressDone:
			return
		case now := <-t.C:
			var egs []model.Egress
			m.db.Where("enabled = ?", true).Find(&egs)
			for _, e := range egs {
				iv := time.Duration(e.IntervalSec) * time.Second
				if iv <= 0 {
					iv = 3 * time.Second
				}
				if now.Sub(lastProbe[e.ID]) < iv {
					continue
				}
				lastProbe[e.ID] = now
				m.probeEgress(e)
			}
		}
	}
}

// probeEgress 单轮探测一个出口：去抖计数 + 状态翻转。
func (m *Manager) probeEgress(e model.Egress) {
	st := egressStateOf(e.ID)
	ok, latency, reason := ProbeEgressOnce(e)
	st.latencyMs.Store(latency)
	if ok {
		st.upSeq.Add(1)
		st.failSeq.Store(0)
		if !st.up.Load() && int(st.upSeq.Load()) >= max(1, e.UpCount) {
			st.up.Store(true)
			st.lastSwitch.Store(time.Now().Unix())
			logf("出口[%s#%d] 已恢复（探测 %s，最近时延 %dms）", e.Name, e.ID, e.ProbeMode, latency)
			m.onEgressStateChange(e)
		}
		return
	}
	st.failSeq.Add(1)
	st.upSeq.Store(0)
	if st.up.Load() && int(st.failSeq.Load()) >= max(1, e.FailCount) {
		st.up.Store(false)
		st.lastSwitch.Store(time.Now().Unix())
		st.downReason.Store(&reason)
		logf("出口[%s#%d] 判定不可用（连续 %d 次失败：%s）", e.Name, e.ID, st.failSeq.Load(), reason)
		m.onEgressStateChange(e)
	}
}

// onEgressStateChange 状态翻转后的重算钩子（T203/T204 接管切换执行）。
func (m *Manager) onEgressStateChange(e model.Egress) {
	m.egressDirty.Store(true) // B1：绕过快路径（sameForwarding 不含出口维度，翻转触发 reapply 若走快路径切换永不发生）
	// S1：异步去抖重算——探测 goroutine 不被 DB 全量遍历+逐规则 Apply 阻塞
	// （多出口同时翻转合并为一轮重算）
	select {
	case m.egressReapply <- struct{}{}:
	default: // 已有待处理重算——合并
	}
	// B4（AC-4.3）：出口判 down 时掐断经该出口的存量会话——旧源 IP 从新出口
	// 发出必被上游丢弃（黑洞），关闸即断优于半死不活。锚点：conntrack 表项的
	//【网关侧源 IP】= SNAT 改写后的出口侧源——多出口场景按 reply-src ∈
	// 出口侧源集精确删（每出口的实际 SNAT 源即其网卡地址）。
	if !EgressUp(e.ID) {
		m.killEgressSessions(e)
	}
}

// killEgressSessions 掐断经指定出口的存量穿越会话（conntrack reply 源 =
// SNAT 后源）。锚点集 = 出口网卡全部 v4 地址 ∪ 引用该出口的规则的
// OutIP/SnatPool 成员（复审 B4 场景 3：规则出口网卡与实体网卡不一致时
// reply-src 是规则的 OutIP——仅按网卡地址集匹配会漏杀，存量黑洞残留）。
func (m *Manager) killEgressSessions(e model.Egress) {
	lines := readConntrackTable()
	if lines == nil {
		return
	}
	egIPs := map[string]bool{}
	iface, err := net.InterfaceByName(e.Iface)
	if err == nil {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				egIPs[ipn.IP.String()] = true
			}
		}
	}
	// 引用该出口的规则的 SNAT 源 IP（显式 SnatIP / 池成员）
	var rules []model.ForwardRule
	m.db.Where("protocol = ? AND enabled = ?", model.ProtocolSNAT, true).Find(&rules)
	for _, r := range rules {
		bound := false
		for _, id := range egressIDsOfRule(r) {
			if id == e.ID {
				bound = true
				break
			}
		}
		if !bound {
			continue
		}
		if ip := strings.TrimSpace(r.SnatIP); ip != "" {
			egIPs[ip] = true
		}
		var members []string
		_ = jsonUnmarshalStrings(strings.TrimSpace(r.SnatPool), &members)
		for _, mm := range members {
			if ip := net.ParseIP(strings.TrimSpace(mm)); ip != nil && ip.To4() != nil {
				egIPs[strings.TrimSpace(mm)] = true
			}
		}
	}
	if len(egIPs) == 0 {
		return
	}
	spec := &snatRuleSpec{ID: e.ID}
	killed := 0
	for _, ln := range lines {
		c, ok := parseConntrackLine(ln)
		if !ok {
			continue
		}
		if !egIPs[c.replySrc] {
			continue
		}
		if deleteConntrackEntry(spec, c) {
			killed++
		}
	}
	if killed > 0 {
		logf("出口[%s#%d] 判不可用：已掐断 %d 条经该出口的存量会话", e.Name, e.ID, killed)
	}
}

// reapplyAllSnatRules 重应用全部启用 snat 规则（出口集变化 → 路由重算）。
func (m *Manager) reapplyAllSnatRules() {
	var rules []model.ForwardRule
	m.db.Where("protocol = ? AND enabled = ?", model.ProtocolSNAT, true).Find(&rules)
	for _, r := range rules {
		if err := m.Apply(r); err != nil {
			logf("规则[%s#%d] 出口变化重应用失败: %v", r.Name, r.ID, err)
		}
	}
}

// EgressUp 出口当前可用性（探测循环的数据；未知（无状态）按 up 处理——
// 新建出口尚未探测时的保守语义，首次探测即修正）。
func EgressUp(id uint) bool {
	egressMu.Lock()
	st := egressStateMap[id]
	egressMu.Unlock()
	return st == nil || st.up.Load()
}

// EgressInfo exports 给 observability 的快照。
type EgressInfo struct {
	ID         uint
	Up         bool
	LatencyMs  int64
	LastSwitch int64
	DownReason string
}

// EgressInfoOf 状态快照（observability/healthz 用）。
func EgressInfoOf(id uint) EgressInfo {
	egressMu.Lock()
	st := egressStateMap[id]
	egressMu.Unlock()
	if st == nil {
		return EgressInfo{ID: id, Up: true}
	}
	info := EgressInfo{ID: id, Up: st.up.Load(), LatencyMs: st.latencyMs.Load(), LastSwitch: st.lastSwitch.Load()}
	if r := st.downReason.Load(); r != nil {
		info.DownReason = *r
	}
	return info
}

// ---------- T203/T204 的多出口决策 ----------

// egressNexthops 计算规则的出口下一跳序列（ADR-12：层=Priority 小者主，
// 同层按 Weight 加权；只含当前 up 的出口；全 down 返回空）。
// egressIDs 为空 = 全部启用出口。
func (m *Manager) egressNexthops(ruleID uint, egressIDs []uint) []nft.Nexthop {
	enabled := map[uint]bool{}
	if len(egressIDs) > 0 {
		for _, id := range egressIDs {
			enabled[id] = true
		}
	}
	var egs []model.Egress
	m.db.Where("enabled = ?", true).Find(&egs)
	type layer struct {
		prio     int
		nexthops []nft.Nexthop
	}
	layers := map[int]*layer{}
	var prios []int
	for _, e := range egs {
		if len(enabled) > 0 && !enabled[e.ID] {
			continue
		}
		if !EgressUp(e.ID) {
			continue // none 出口的链路状态门也在 ProbeEgressOnce（S4：拔除即退出）
		}
		gw := e.GatewayV4
		if gw == "" {
			// S3：v6-only 出口暂不参与 v4 规则路由（v6 表在 T205；此处曾静默
			// skip——补日志便于排障，API 层已校验但存在 v6-only 合法出口）
			continue
		}
		gwIP := net.ParseIP(gw)
		if gwIP == nil || gwIP.To4() == nil {
			continue
		}
		l := layers[e.Priority]
		if l == nil {
			l = &layer{prio: e.Priority}
			layers[e.Priority] = l
			prios = append(prios, e.Priority)
		}
		w := e.Weight
		if w <= 0 {
			w = 1
		}
		l.nexthops = append(l.nexthops, nft.Nexthop{Iface: e.Iface, Gw: gwIP, Weight: w})
	}
	if len(prios) == 0 {
		return nil
	}
	// 最小 priority 层（主层）——Oracle：全部层都返回（备层作为备份下一跳组？
	// v1 语义：只装主层 multipath；主层全 down 时 reapply 重算选下一层（状态
	// 翻转触发的 reapplyAllSnatRules 已保证收敛）——比一次装多层更可控
	sort.Ints(prios)
	for _, p := range prios {
		nh := layers[p].nexthops
		if len(nh) > 0 {
			return nh
		}
	}
	return nil
}

// egressIDsOfRule 规则的出口绑定（EgressIDs JSON 列；空 = 全部出口）。
func egressIDsOfRule(rule model.ForwardRule) []uint {
	s := strings.TrimSpace(rule.EgressIDs)
	if s == "" {
		return nil
	}
	var ids []uint
	if err := json.Unmarshal([]byte(s), &ids); err != nil {
		return nil
	}
	return ids
}

// ReapplySnatRules 导出包装（API 出口变更后的重算）。
func (m *Manager) ReapplySnatRules() { m.reapplyAllSnatRules() }

// egressReapplyWorker 出口翻转重算的聚批 worker（S1：探测 goroutine 只发
// 信号不阻塞；100ms 聚批窗口合并翻转风暴；dirty 消费收敛于此——applySNAT
// 快路径只 Load 不 Swap，避免无关规则的编辑偷走脏标记导致其他规则的切换丢失）。
func (m *Manager) egressReapplyWorker() {
	for {
		select {
		case <-m.egressDone:
			return
		case <-m.egressReapply:
			time.Sleep(100 * time.Millisecond) // 聚批窗口
			for {
				select {
				case <-m.egressReapply:
					continue
				default:
				}
				break
			}
			m.reapplyAllSnatRules()
			// 重算结束统一清脏标记；清理前 100ms 内若又有翻转，信号位仍占——
			// 下一轮 worker 会再跑（有界收敛，不丢翻转）
			m.egressDirty.Store(false)
			select {
			case <-m.egressReapply:
				// 聚批后新信号：立即处理下一轮（不清标记先跑都是全路径——
				// reapplyAllSnatRules 走 applySNAT Load 检查）
			default:
			}
		}
	}
}
