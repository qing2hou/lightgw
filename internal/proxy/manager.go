package proxy

import (
	"fmt"
	"net"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"haproxyweb/internal/model"
	"haproxyweb/internal/nft"
	"haproxyweb/internal/ratelimit"
	"haproxyweb/internal/trafficlog"
)

// Manager 管理全部转发规则的生命周期：启动监听、热更新配置、停止。
// TCP/UDP 规则一条一个监听。
type Manager struct {
	// opts 运行参数，SIGHUP 热加载时原子替换（copy.go Options）
	optsStore atomic.Pointer[Options]

	db      *gorm.DB
	tlog    *trafficlog.Writer
	webPort int

	mu          sync.Mutex
	tcpRules    map[uint]*tcpEntry
	udpRules    map[uint]*udpEntry
	webListener net.Listener          // 管理后台监听（升级时随 fd 交接）
	adoptedTCP  map[uint]net.Listener // 升级继承的监听（StartAll 消费）
	adoptedUDP  map[uint]*net.UDPConn

	sessions   sync.Map // int64 -> *session
	sessionSeq atomic.Int64

	// snat 规则（内核 iptables/tc 转发，不经代理进程）
	snatRules map[uint]*snatEntry

	// nftables 引擎连接（snat/dnat 的内核面；懒加载——无相关规则的部署零开销）
	nftMu          sync.Mutex
	nft            *nft.Conn
	nftHostProfile *nft.HostProfile
	// nftApplyMu 装载序列互斥（purge→add→flush 跨 Flush 原子——评审 M9；
	// 独立于 nftMu：探测/建连接不阻塞装载）
	nftApplyMu sync.Mutex

	// 出口探测循环（M3/T202）
	egressDone      chan struct{}
	egressStartOnce sync.Once

	// 带宽包共享令牌桶（ADR-9：包ID -> Limiter；tcp/udp 成员规则注入；额度变更重建）
	bwMu       sync.Mutex
	bwLimiters map[uint]*ratelimit.Limiter

	// snat 计数轮询（ADR-3）
	snatMu        sync.Mutex
	snatBase      map[uint]*snatBaseline
	snatAcc       map[uint]int64
	snatDone      chan struct{}
	snatStartOnce sync.Once
	snatStopOnce  sync.Once

	bufs    *bufferPool // TCP 拷贝缓冲池
	udpBufs sync.Pool   // UDP 65535 数据报缓冲池

	globalConns    *connLimiter                      // 进程级连接总上限，nil = 不限
	globalLimiter  atomic.Pointer[ratelimit.Limiter] // 整机带宽限速器（双向，Disabled=不限）
	rejectedGlobal atomic.Int64                      // 全局上限拒绝计数（/metrics 暴露）
	rejectedRule   atomic.Int64                      // 规则级上限拒绝计数（/metrics 暴露）
	acceptErrors   atomic.Int64                      // accept 临时错误计数（退避重试，/metrics 暴露）
	panics         atomic.Int64                      // 转发路径 panic 计数（已隔离，/metrics 暴露）

	statsMu sync.Mutex
	stats   map[uint]*ruleStats // 规则级指标，/metrics 数据源

	healthMu       sync.Mutex
	health         map[uint]*ruleHealth // TCP 规则后端健康状态（health.go）
	healthDone     chan struct{}
	healthStopOnce sync.Once
	checking       atomic.Bool // 一轮健康检查进行中标记

	deniedMu   sync.Mutex
	deniedLast map[string]time.Time // "ruleID|ip" -> 上次记录时间，去重防止刷日志
}

func NewManager(db *gorm.DB, tlog *trafficlog.Writer, webPort int, opts Options) *Manager {
	if opts.BufferSize <= 0 {
		opts.BufferSize = 32768
	}
	if opts.TCPDialTimeout <= 0 {
		opts.TCPDialTimeout = 10 * time.Second
	}
	m := &Manager{
		db:          db,
		tlog:        tlog,
		webPort:     webPort,
		tcpRules:    map[uint]*tcpEntry{},
		udpRules:    map[uint]*udpEntry{},
		snatRules:   map[uint]*snatEntry{},
		snatBase:    map[uint]*snatBaseline{},
		bwLimiters:  map[uint]*ratelimit.Limiter{},
		snatAcc:     map[uint]int64{},
		snatDone:    make(chan struct{}),
		adoptedTCP:  map[uint]net.Listener{},
		adoptedUDP:  map[uint]*net.UDPConn{},
		bufs:        newBufferPool(opts.BufferSize),
		udpBufs:     sync.Pool{New: func() any { b := make([]byte, 65535); return &b }},
		globalConns: newConnLimiter(opts.MaxGlobalConns),
		stats:       map[uint]*ruleStats{},
		health:      map[uint]*ruleHealth{},
		healthDone:  make(chan struct{}),
		deniedLast:  map[string]time.Time{},
		egressDone:  make(chan struct{}),
	}
	m.optsStore.Store(&opts)
	m.globalLimiter.Store(ratelimit.New(opts.GlobalUploadKBps*1024, opts.GlobalDownloadKBps*1024))
	return m
}

// opts 返回当前运行参数快照（热加载下每次读取最新值）。
func (m *Manager) opts() Options {
	return *m.optsStore.Load()
}

// ApplyOptions 热应用新的运行参数（SIGHUP 重载配置）：重建整机限速器并
// 原子替换各规则的运行时配置；存量连接继续使用旧配置直到结束。
// buffer_size 变更不在此列（缓冲池随进程构建，需重启）。
func (m *Manager) ApplyOptions(opts Options) {
	if opts.BufferSize <= 0 {
		opts.BufferSize = 32768
	}
	if opts.TCPDialTimeout <= 0 {
		opts.TCPDialTimeout = 10 * time.Second
	}
	m.optsStore.Store(&opts)
	m.globalLimiter.Store(ratelimit.New(opts.GlobalUploadKBps*1024, opts.GlobalDownloadKBps*1024))

	m.mu.Lock()
	defer m.mu.Unlock()
	for id, e := range m.tcpRules {
		e.cfg.Store(m.buildRuleConfig(e.cfg.Load().rule))
		_ = id
	}
	for id, e := range m.udpRules {
		e.cfg.Store(m.buildRuleConfig(e.cfg.Load().rule))
		_ = id
	}
}

// ruleConfig 规则运行时配置快照，更新时原子替换，连接级零中断。
type ruleConfig struct {
	rule         model.ForwardRule
	acl          *ACL
	limiter      *ratelimit.Limiter
	conns        *connLimiter
	idleTimeout  time.Duration // 生效的 TCP 空闲超时（规则覆盖优先于全局），0 = 禁用
	dialSourceIP string        // 连接后端时绑定的本机源 IP（空 = 路由自动）；后端看到的来源
}

// connLimiter 并发连接信号量。nil 表示不限。
type connLimiter struct{ ch chan struct{} }

func newConnLimiter(cap int) *connLimiter {
	if cap <= 0 {
		return nil
	}
	return &connLimiter{ch: make(chan struct{}, cap)}
}

func (l *connLimiter) tryAcquire() bool {
	if l == nil {
		return true
	}
	select {
	case l.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *connLimiter) release() {
	if l == nil {
		return
	}
	<-l.ch
}

// bwLimiter 带宽包共享令牌桶（懒建：额度读调用时刻的 DB；包编辑后 applyBWMembers
// 先 ResetBWLimiters 再逐成员 Apply，各配置重建取新桶）。
func (m *Manager) bwLimiter(bwGroupID uint) *ratelimit.Limiter {
	if bwGroupID == 0 {
		return nil
	}
	m.bwMu.Lock()
	defer m.bwMu.Unlock()
	if l, ok := m.bwLimiters[bwGroupID]; ok {
		return l
	}
	var bg model.BWGroup
	if err := m.db.First(&bg, bwGroupID).Error; err != nil {
		return nil
	}
	l := ratelimit.NewSharedTotal(bg.TotalKBps * 1024)
	m.bwLimiters[bwGroupID] = l
	return l
}

// ResetBWLimiters 包额度/成员变更后失效全部包令牌桶（各规则 Apply 时懒重建）。
func (m *Manager) ResetBWLimiters() {
	m.bwMu.Lock()
	m.bwLimiters = map[uint]*ratelimit.Limiter{}
	m.bwMu.Unlock()
}

func (m *Manager) buildRuleConfig(rule model.ForwardRule) *ruleConfig {
	// 引用名单组时展开组条目：whitelist 模式取组的条目作白名单，
	// blacklist 模式取组的条目作黑名单（组语义与规则模式一致性由 API 层保存时校验）
	allowJSON, denyJSON := rule.AllowList, rule.DenyList
	if rule.AclGroupID != 0 {
		var group model.AclGroup
		if err := m.db.First(&group, rule.AclGroupID).Error; err == nil && group.Mode == rule.AclMode {
			if rule.AclMode == model.AclModeWhitelist {
				allowJSON = group.Entries
			} else if rule.AclMode == model.AclModeBlacklist {
				denyJSON = group.Entries
			}
		} else {
			// 组被外部改动/删除（正常 API 路径创建/更新/删除都有联动与校验，这里
			// 是兜底）：维持直配名单展开。直配在保存时被强制为空——whitelist 下
			// 等于拒绝所有、blacklist 下等于全放行，都属高危状态，必须留下日志线索。
			logf("规则[%s#%d] 引用的名单组#%d 失效（不存在或模式不匹配），回退直配名单", rule.Name, rule.ID, rule.AclGroupID)
		}
	}
	acl, err := ParseACL(rule.AclMode, allowJSON, denyJSON)
	if err != nil {
		// 保存时已校验，这里防御性兜底
		acl = AllowAll
	}
	idle := m.opts().TCPIdleTimeout
	if rule.IdleTimeoutSec > 0 {
		idle = time.Duration(rule.IdleTimeoutSec) * time.Second
	}
	// 入包的 tcp/udp 成员：限速器替换为包共享令牌桶（自身限速字段忽略——ADR-9）
	limiter := ratelimit.New(rule.UploadLimitKBps*1024, rule.DownloadLimitKBps*1024)
	if rule.BWGroupID != 0 {
		if shared := m.bwLimiter(rule.BWGroupID); shared != nil {
			limiter = shared
		}
	}
	return &ruleConfig{
		rule:         rule,
		acl:          acl,
		limiter:      limiter,
		conns:        newConnLimiter(rule.MaxConns),
		idleTimeout:  idle,
		dialSourceIP: strings.TrimSpace(rule.SourceIP),
	}
}

// ApplyAclGroup 名单组条目变更后的联动：重应用所有引用该组且模式匹配的
// 启用规则（组展开发生在 buildRuleConfig，重应用即完成名单热更新）。
// 组删除时联动不调用（删除前 API 层已拦截存在引用的场景）。
func (m *Manager) ApplyAclGroup(groupID uint) {
	var rules []model.ForwardRule
	if err := m.db.Where("acl_group_id = ? AND enabled = ?", groupID, true).Find(&rules).Error; err != nil {
		logf("名单组#%d 联动查询引用规则失败: %v", groupID, err)
		return
	}
	for _, r := range rules {
		if err := m.Apply(r); err != nil {
			logf("名单组#%d 联动重应用规则[%s#%d]失败: %v", groupID, r.Name, r.ID, err)
		}
	}
}

// ReferencedByAclGroup 返回引用指定名单组的规则 ID 列表（API 删除组前校验）。
func (m *Manager) ReferencedByAclGroup(groupID uint) []uint {
	var rules []model.ForwardRule
	m.db.Where("acl_group_id = ?", groupID).Find(&rules)
	ids := make([]uint, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	return ids
}

// StartAll 进程启动时加载所有启用规则。单条失败不影响其余规则，
// 失败原因写入规则的 last_error，管理端可见。
func (m *Manager) StartAll() error {
	// snat 启动对账：tc 全清（安全窗口）+ iptables 孤儿（haweb-sn: 标记、DB 无对应启用规则）清零
	m.ReconcileSnatTC()
	if purged := m.PurgeOrphanSnatRules(); len(purged) > 0 {
		logf("[snat] 已清扫 %d 条孤儿 iptables 规则: %v", len(purged), purged)
	}
	// T006 旧形态迁移：haweb-sn: iptables 规则整体拆除（双份叠加防除——
	// nft 新形态装在位前先清旧形态；iptables-legacy 直写的规则此路径够不到，
	// 由 DetectHost 的 legacy fail-fast 拦截）
	if n, err := m.migrateLegacyIPTables(); err != nil {
		logf("[snat] 旧 iptables 形态迁移检查失败（不阻塞启动）: %v", err)
	} else if n > 0 {
		logf("[snat] 已迁移拆除 %d 条旧 iptables 形态规则（nftables 后端接管）", n)
	}
	m.purgeOrphanNFTRules()
	// 策略段装载（fwd 链；重启恢复——与规则装载独立）
	if err := m.ReinstallPolicies(); err != nil {
		logf("[fw-policy] 策略装载失败（不阻塞规则启动）: %v", err)
	}
	// 出口探测循环启动（M3/T202：先对全部启用出口做一轮首探——立即建立初态）
	m.StartEgressProbing()
	var rules []model.ForwardRule
	if err := m.db.Where("enabled = ?", true).Find(&rules).Error; err != nil {
		return err
	}
	failures := 0
	for _, r := range rules {
		if err := m.Apply(r); err != nil {
			logf("规则[%s#%d]启动失败: %v", r.Name, r.ID, err)
			failures++
		}
	}
	if failures > 0 {
		logf("共 %d 条规则启动失败，详情见规则列表的异常标记", failures)
	}
	return nil
}

// Apply 热应用一条规则（新建/更新/启停统一入口）。
// 监听地址不变时仅原子替换配置；变化时先绑定新监听再关闭旧的，失败则保持旧状态。
// 成功时清空规则的 last_error，失败时写入，供管理端展示启动失败原因。
func (m *Manager) Apply(rule model.ForwardRule) error {
	m.stopStaleProtocol(rule)

	err := func() error {
		switch rule.Protocol {
		case model.ProtocolTCP:
			return m.applyTCP(rule)
		case model.ProtocolUDP:
			return m.applyUDP(rule)
		case model.ProtocolSNAT:
			return m.applySNAT(rule)
		case model.ProtocolDNAT:
			return m.applyDNAT(rule)
		default:
			return fmt.Errorf("未知协议: %s", rule.Protocol)
		}
	}()
	if err != nil {
		m.setRuleError(rule.ID, err.Error())
		return err
	}
	m.setRuleError(rule.ID, "")
	return nil
}

// setRuleError 记录/清空规则的应用失败原因。ID 为 0（尚未入库）时跳过。
func (m *Manager) setRuleError(id uint, msg string) {
	if id == 0 {
		return
	}
	if msg != "" {
		msg = truncate(msg, 512)
	}
	if err := m.db.Model(&model.ForwardRule{}).Where("id = ?", id).Update("last_error", msg).Error; err != nil {
		logf("规则#%d 状态写入失败: %v", id, err)
	}
}

// stopStaleProtocol 规则变更协议时，关闭旧协议遗留的监听。
// 关闭动作统一在 Manager 锁外执行，避免阻塞其他规则的管理操作。
func (m *Manager) stopStaleProtocol(rule model.ForwardRule) {
	m.mu.Lock()
	var staleTCP *tcpEntry
	var staleUDP *udpEntry
	var staleSNAT *snatRuleSpec
	if rule.Protocol != model.ProtocolTCP {
		if e, ok := m.tcpRules[rule.ID]; ok {
			staleTCP = e
			delete(m.tcpRules, rule.ID)
		}
	}
	if rule.Protocol != model.ProtocolUDP {
		if e, ok := m.udpRules[rule.ID]; ok {
			staleUDP = e
			delete(m.udpRules, rule.ID)
		}
	}
	if rule.Protocol != model.ProtocolSNAT && rule.Protocol != model.ProtocolDNAT {
		if e, ok := m.snatRules[rule.ID]; ok {
			delete(m.snatRules, rule.ID)
			staleSNAT = e.spec()
		}
	}
	m.mu.Unlock()

	if staleTCP != nil {
		_ = staleTCP.listener.Close()
	}
	if staleUDP != nil {
		m.udpCloseEntry(staleUDP)
	}
	if staleSNAT != nil {
		staleSNAT.teardownSnat()
		m.teardownSnatNFT(rule.ID) // nft 形态同拆（评审 M4——漏拆则残留到下次重启）
		_ = staleSNAT.teardownSnatLimit()
		staleSNAT.teardownEgressRoute()
	}
}

// SetWebListener 注册管理后台监听（升级 fd 交接需要）。
func (m *Manager) SetWebListener(ln net.Listener) {
	m.mu.Lock()
	m.webListener = ln
	m.mu.Unlock()
}

// StopHealthChecks 停止后端健康检查循环（升级交接时父进程停止探测，
// 由子进程接手，避免双进程重复探测）。
func (m *Manager) StopHealthChecks() {
	m.healthStopOnce.Do(func() { close(m.healthDone) })
}

// takeAllEntries 摘走全部规则条目（调用方持有并负责关闭）。
func (m *Manager) takeAllEntries() ([]*tcpEntry, []*udpEntry) {
	m.mu.Lock()
	tcpEntries := make([]*tcpEntry, 0, len(m.tcpRules))
	for id, e := range m.tcpRules {
		tcpEntries = append(tcpEntries, e)
		delete(m.tcpRules, id)
	}
	udpEntries := make([]*udpEntry, 0, len(m.udpRules))
	for id, e := range m.udpRules {
		udpEntries = append(udpEntries, e)
		delete(m.udpRules, id)
	}
	m.mu.Unlock()
	return tcpEntries, udpEntries
}

// StopAccepting 升级交接第一步：关闭全部监听与 UDP 入口（存量 TCP 连接
// 继续由本进程服务直到自然结束），返回剩余活跃会话数。
func (m *Manager) StopAccepting() int {
	m.mu.Lock()
	tcpEntries := make([]*tcpEntry, 0, len(m.tcpRules))
	for id, e := range m.tcpRules {
		tcpEntries = append(tcpEntries, e)
		delete(m.tcpRules, id)
	}
	udpEntries := make([]*udpEntry, 0, len(m.udpRules))
	for id, e := range m.udpRules {
		udpEntries = append(udpEntries, e)
		delete(m.udpRules, id)
	}
	web := m.webListener
	m.webListener = nil
	m.mu.Unlock()

	for _, e := range tcpEntries {
		_ = e.listener.Close()
	}
	for _, e := range udpEntries {
		m.udpCloseEntry(e)
	}
	if web != nil {
		_ = web.Close()
	}
	return int(m.EngineCounters().SessionsActive)
}

// StopAll 停止全部转发监听与后端健康检查，进程退出前调用。
// TCP 存量连接先排空（等待自然结束至 DrainTimeout，超时强制关闭），
// 保证其流量日志在 tlog.Close() 前落库；UDP 会话由 udpCloseEntry 同步收尾。
func (m *Manager) StopAll() {
	m.StopHealthChecks()

	m.mu.Lock()
	tcpEntries := make([]*tcpEntry, 0, len(m.tcpRules))
	for id, e := range m.tcpRules {
		tcpEntries = append(tcpEntries, e)
		delete(m.tcpRules, id)
	}
	udpEntries := make([]*udpEntry, 0, len(m.udpRules))
	for id, e := range m.udpRules {
		udpEntries = append(udpEntries, e)
		delete(m.udpRules, id)
	}
	m.mu.Unlock()

	for _, e := range tcpEntries {
		_ = e.listener.Close()
	}
	for _, e := range udpEntries {
		m.udpCloseEntry(e)
	}

	m.drainTCP(tcpEntries)
}

// drainTCP 等待存量 TCP 连接自然结束；超时强制关闭连接并再给一个收尾窗口，
// 让对应 goroutine 完成流量日志落库与名额释放。
func (m *Manager) drainTCP(entries []*tcpEntry) {
	drain := m.opts().DrainTimeout
	if drain <= 0 || len(entries) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, e := range entries {
		wg.Add(1)
		go func(e *tcpEntry) {
			defer wg.Done()
			e.wg.Wait()
		}(e)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logf("存量连接已全部排空")
		return
	case <-time.After(drain):
		logf("排空宽限 %v 已到，强制关闭存量连接", drain)
	}
	for _, e := range entries {
		e.conns.Range(func(k, _ any) bool {
			_ = k.(net.Conn).Close()
			return true
		})
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		logf("强制关闭后仍有连接未收尾，放弃等待")
	}
}

// Stop 停止一条规则（删除/禁用时调用）。
func (m *Manager) Stop(rule model.ForwardRule) {
	rule.Enabled = false
	_ = m.Apply(rule)
}

// ---------- 活跃会话 ----------

type session struct {
	id         int64
	rule       model.ForwardRule
	stats      *ruleStats // 规则级指标，可能为 nil（旧测试构造）
	srcIP      string
	srcPort    int
	listenIP   string
	listenPort int // 客户端访问的入口（本机侧 IP:端口）
	start      time.Time
	up         atomic.Int64
	down       atomic.Int64
	// lastActive 连接级最后活动时刻（unix nano）。TCP 空闲超时按连接级判定：
	// 任一方向有数据都刷新——纯下行/纯上行会话不因对向无数据被误杀
	// （原实现两方向各自维护 deadline，纯下载会话的上行方向 60s 必死）。
	lastActive atomic.Int64
	// cfgPtr 规则运行时配置的原子指针（TCP[tcpEntry.cfg] / 该指针变化时存量
	// 会话的热跟随通道）。nil 时 currentLimiter 走快照回退（测试构造兼容）。
	cfgPtr *atomic.Pointer[ruleConfig]
}

// touch 更新连接级活动时刻（任一方向收到数据即调用）。
func (s *session) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

// activeAt 返回连接级最后活动时刻（零值=未记录，调用方兜底为会话开始时刻）。
func (s *session) activeAt() time.Time {
	if n := s.lastActive.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return s.start
}

// currentLimiter 会话当前应使用的限速器：优先从原子指针取最新配置
// （带宽包/规则更新 → cfg.Store → 存量连接下一块即用新额度，零中断热跟随）；
// 指针为空（测试构造）时回退 nil 由调用方保持旧值。
func (s *session) currentLimiter() *ratelimit.Limiter {
	if s.cfgPtr == nil {
		return nil
	}
	if cfg := s.cfgPtr.Load(); cfg != nil {
		return cfg.limiter
	}
	return nil
}

func (m *Manager) registerSession(cfg *ruleConfig, srcIP string, srcPort int, listenIP string, listenPort int) *session {
	s := &session{
		id:         m.sessionSeq.Add(1),
		rule:       cfg.rule,
		stats:      m.statsFor(cfg.rule),
		srcIP:      srcIP,
		srcPort:    srcPort,
		listenIP:   listenIP,
		listenPort: listenPort,
		start:      time.Now(),
	}
	m.sessions.Store(s.id, s)
	s.stats.ConnCurrent.Add(1)
	s.stats.ConnTotal.Add(1)
	return s
}

func (m *Manager) removeSession(s *session) {
	m.sessions.Delete(s.id)
	s.stats.ConnCurrent.Add(-1)
}

// ActiveSessions 返回当前活跃会话快照。
func (m *Manager) ActiveSessions() []model.SessionInfo {
	var out []model.SessionInfo
	m.sessions.Range(func(_, v any) bool {
		s := v.(*session)
		out = append(out, model.SessionInfo{
			ID:            s.id,
			RuleID:        s.rule.ID,
			RuleName:      s.rule.Name,
			Protocol:      s.rule.Protocol,
			SourceIP:      s.srcIP,
			SourcePort:    s.srcPort,
			ListenIP:      s.listenIP,
			ListenPort:    s.listenPort,
			TargetAddr:    s.rule.TargetAddr,
			UploadBytes:   s.up.Load(),
			DownloadBytes: s.down.Load(),
			StartedAt:     s.start,
		})
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RuleLiveStat 规则实时统计（内存中的活跃会话 + 最近窗口速率）。
type RuleLiveStat struct {
	ActiveConns   int   `json:"active_conns"`
	UploadBytes   int64 `json:"upload_bytes"`
	DownloadBytes int64 `json:"download_bytes"`
	// 实时速率（最近 10 秒滑动窗口平均，B/s；由 API 层从 RuleMetrics 填充）
	RateUpBps   int64 `json:"rate_up_bps"`
	RateDownBps int64 `json:"rate_down_bps"`
}

func (m *Manager) LiveStats() map[uint]*RuleLiveStat {
	out := map[uint]*RuleLiveStat{}
	m.sessions.Range(func(_, v any) bool {
		s := v.(*session)
		st, ok := out[s.rule.ID]
		if !ok {
			st = &RuleLiveStat{}
			out[s.rule.ID] = st
		}
		st.ActiveConns++
		st.UploadBytes += s.up.Load()
		st.DownloadBytes += s.down.Load()
		return true
	})
	return out
}

// ---------- 拒绝日志去重 ----------

// logDenied 记录一条 denied 流量日志；同一规则同一来源 IP 每分钟最多一条，
// 防止扫描行为刷爆日志表。
func (m *Manager) logDenied(rule model.ForwardRule, acl *ACL, srcIP string, srcPort int) {
	key := fmt.Sprintf("%d|%s", rule.ID, srcIP)
	m.deniedMu.Lock()
	if t, ok := m.deniedLast[key]; ok && time.Since(t) < time.Minute {
		m.deniedMu.Unlock()
		return
	}
	m.deniedLast[key] = time.Now()
	if len(m.deniedLast) > 10000 {
		m.deniedLast = map[string]time.Time{}
	}
	m.deniedMu.Unlock()

	now := time.Now()
	if st := m.statsFor(rule); st != nil {
		st.Denied.Add(1)
	}
	m.tlog.Log(model.TrafficLog{
		RuleID:     rule.ID,
		RuleName:   rule.Name,
		Protocol:   rule.Protocol,
		SourceIP:   srcIP,
		SourcePort: srcPort,
		ListenPort: 0, // 拒绝路径无 established 本地端口可查（与 NAT 端口无从对应）
		TargetAddr: rule.TargetAddr,
		Status:     model.StatusDenied,
		ErrorMsg:   acl.DenyMessage(),
		StartedAt:  now,
		EndedAt:    &now,
	})
}

// ---------- 通用辅助 ----------

// splitAddr "1.2.3.4:5678" -> ("1.2.3.4", 5678)
func splitAddr(s string) (string, int) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// normalizeListen 规范化监听地址为 "host:port"（空 host 保留为 ""）。
func normalizeListen(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("监听地址格式错误（应为 host:port 或 :port）: %s", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("监听端口无效: %s", port)
	}
	return host, port, nil
}

// listenKey 统一的监听标识（TCP 监听键）。
func listenKey(host, port string) string {
	if host == "" {
		return ":" + port
	}
	return net.JoinHostPort(host, port)
}

// sameListen 判断两个监听地址是否等价（":9000" 与 "0.0.0.0:9000" 视为相同）。
func sameListen(a, b string) bool {
	ha, pa, errA := normalizeListen(a)
	hb, pb, errB := normalizeListen(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return normalizeHost(ha) == normalizeHost(hb) && pa == pb
}

func normalizeHost(h string) string {
	if h == "" || h == "0.0.0.0" || h == "::" {
		return "*"
	}
	return h
}

func logf(format string, args ...any) {
	fmt.Printf("[proxy] "+format+"\n", args...)
}

// logPanic 记录被隔离的 panic 详情并计数。注意 recover() 必须由各挂载点的
// defer 函数体直接调用，本方法只负责记录。
func (m *Manager) logPanic(where string, r any) {
	m.panics.Add(1)
	logf("[panic] %s 发生 panic（已隔离，进程继续运行）: %v\n%s", where, r, debug.Stack())
}

// StartEgressProbing 启动出口探测循环（main 启动序列一次；升级交接时由
// 子进程重启循环——父进程的循环随退出终止）。
func (m *Manager) StartEgressProbing() {
	m.egressStartOnce.Do(func() { go m.egressProbeLoop() })
}

// StopEgressProbing 停止探测循环（优雅关闭路径）。
func (m *Manager) StopEgressProbing() {
	select {
	case <-m.egressDone:
	default:
		close(m.egressDone)
	}
}
