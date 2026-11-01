package proxy

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"haproxyweb/internal/model"
)

const (
	udpJanitorInterval = 10 * time.Second
)

type udpEntry struct {
	conn *net.UDPConn
	cfg  atomic.Pointer[ruleConfig]

	mu       sync.Mutex
	sessions map[string]*udpSession // 客户端地址 -> 会话
	closed   bool
}

type udpSession struct {
	clientAddr *net.UDPAddr
	backend    *net.UDPConn
	cfg        *ruleConfig
	sess       *session
	lastActive atomic.Int64 // unix nano
	dropped    atomic.Int64 // 因限速丢弃的包数
}

func (m *Manager) applyUDP(rule model.ForwardRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := m.udpRules[rule.ID]
	if !rule.Enabled {
		if conn, ok := m.adoptedUDP[rule.ID]; ok {
			delete(m.adoptedUDP, rule.ID)
			_ = conn.Close()
		}
		if entry != nil {
			m.udpCloseEntry(entry)
			delete(m.udpRules, rule.ID)
			logf("UDP 规则[%s#%d]已停止监听 %s", rule.Name, rule.ID, rule.ListenAddr)
		}
		return nil
	}

	cfg := m.buildRuleConfig(rule)
	// 升级交接：使用父进程继承的 socket，不重新监听
	if conn, ok := m.adoptedUDP[rule.ID]; ok {
		delete(m.adoptedUDP, rule.ID)
		if entry != nil {
			m.udpCloseEntry(entry)
		}
		e := &udpEntry{conn: conn, sessions: map[string]*udpSession{}}
		e.cfg.Store(cfg)
		m.udpRules[rule.ID] = e
		logf("UDP 规则[%s#%d]接管升级继承监听 %s", rule.Name, rule.ID, rule.ListenAddr)
		go m.udpListenLoop(e)
		go m.udpJanitor(e)
		return nil
	}
	if entry != nil {
		if old := entry.cfg.Load(); sameListen(old.rule.ListenAddr, rule.ListenAddr) {
			entry.cfg.Store(cfg)
			// ACL 收紧后断开不再允许的存量会话（与 TCP 同语义，
			// 见 applyTCP 里的详细说明）。后台协程：Apply 持 m.mu。
			go m.closeDeniedSessions(rule.ID, cfg.acl)
			return nil
		}
	}

	host, port, err := normalizeListen(rule.ListenAddr)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", listenKey(host, port))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", rule.ListenAddr, err)
	}
	if entry != nil {
		m.udpCloseEntry(entry)
		delete(m.udpRules, rule.ID)
	}
	e := &udpEntry{conn: conn, sessions: map[string]*udpSession{}}
	e.cfg.Store(cfg)
	m.udpRules[rule.ID] = e
	logf("UDP 规则[%s#%d]监听 %s -> %s", rule.Name, rule.ID, rule.ListenAddr, rule.TargetAddr)
	go m.udpListenLoop(e)
	go m.udpJanitor(e)
	return nil
}

// udpCloseEntry 关闭 UDP 入口：停止监听，全部会话按关闭落库并释放。
func (m *Manager) udpCloseEntry(e *udpEntry) {
	e.mu.Lock()
	e.closed = true
	sessions := make([]*udpSession, 0, len(e.sessions))
	for _, s := range e.sessions {
		sessions = append(sessions, s)
	}
	e.sessions = map[string]*udpSession{}
	e.mu.Unlock()
	_ = e.conn.Close()
	for _, s := range sessions {
		m.udpFinishSession(s, model.StatusClosed, "")
	}
}

func (m *Manager) udpListenLoop(e *udpEntry) {
	defer func() {
		if r := recover(); r != nil {
			m.logPanic("UDP 监听循环", r)
		}
	}()
	// 缓冲入池：万级 UDP 规则频繁启停时避免反复分配 64KB（活跃规则仍各持一份，
	// 这是接收最大数据报的协议下限，无法再省）
	buf := m.udpBufs.Get().(*[]byte)
	defer m.udpBufs.Put(buf)
	for {
		n, addr, err := e.conn.ReadFromUDP(*buf)
		if err != nil {
			return
		}
		cfg := e.cfg.Load()
		srcIP, srcPort := splitAddr(addr.String())
		if !cfg.acl.Allowed(parseIPOrZero(srcIP)) {
			m.logDenied(cfg.rule, cfg.acl, srcIP, srcPort)
			continue
		}
		s := m.udpGetOrCreateSession(e, addr, cfg, srcIP, srcPort)
		if s == nil {
			continue
		}
		// 上传限速：短时间内拿不到配额则丢包（规则限速 + 整机带宽上限）
		if !cfg.limiter.TryWaitUpload(n, m.opts().UDPLimiterMaxWait) {
			s.dropped.Add(1)
			continue
		}
		if gl := m.globalBandwidth(); !gl.Disabled() && !gl.TryWaitUpload(n, m.opts().UDPLimiterMaxWait) {
			s.dropped.Add(1)
			continue
		}
		s.sess.addBytes(false, int64(n))
		s.touch()
		if _, err := s.backend.Write((*buf)[:n]); err != nil {
			m.udpCloseSession(e, s, model.StatusError, "后端写入失败: "+err.Error())
		}
	}
}

func (m *Manager) udpGetOrCreateSession(e *udpEntry, addr *net.UDPAddr, cfg *ruleConfig, srcIP string, srcPort int) *udpSession {
	key := addr.String()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	if s, ok := e.sessions[key]; ok {
		e.mu.Unlock()
		return s
	}
	e.mu.Unlock()

	// 连接后端：可绑定规则指定的本机源 IP（后端看到的来源；空 = 路由自动）
	var backend net.Conn
	var err error
	if cfg.dialSourceIP != "" {
		d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(cfg.dialSourceIP)}}
		backend, err = d.Dial("udp", cfg.rule.TargetAddr)
	} else {
		backend, err = net.Dial("udp", cfg.rule.TargetAddr)
	}
	if err != nil {
		return nil
	}
	// 先占全局名额再占规则名额，两者都在 udpFinishSession / 失败路径配对释放
	if !m.globalConns.tryAcquire() {
		// 进程级会话总量已达上限：丢弃新客户端的包
		_ = backend.Close()
		m.rejectedGlobal.Add(1)
		return nil
	}
	if !cfg.conns.tryAcquire() {
		// 并发会话已达规则上限：丢弃新客户端的包，现有会话不受影响
		_ = backend.Close()
		m.globalConns.release()
		m.rejectedRule.Add(1)
		return nil
	}
	listenIP, listenPort := "", 0
	if lh, lp, err := net.SplitHostPort(e.conn.LocalAddr().String()); err == nil {
		listenIP = lh
		listenPort, _ = strconv.Atoi(lp)
	}
	s := &udpSession{
		clientAddr: addr,
		backend:    backend.(*net.UDPConn),
		cfg:        cfg,
		sess:       m.registerSession(cfg, srcIP, srcPort, listenIP, listenPort),
	}
	s.sess.cfgPtr = &e.cfg // 热跟随通道（tcpPipeBackend 同源：每包取当前限速器）
	// 注册强制断开钩子（会话表"掐断"与 ACL 变更共用）。
	//
	// UDP 没有"客户端连接"可关（监听 socket 是多会话共享的），但关掉
	// backend 会让 udpPipeBackend 的 Read 返回错误并走 udpFinishSession
	// 收尾——这正是会话结束的既有路径，信号量与流量日志都会被正确
	// 释放/记录。不要在这里直接调 udpFinishSession：会重复释放信号量。
	s.sess.setCloser(func() {
		_ = s.backend.Close()
	})
	s.touch()

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		_ = backend.Close()
		m.removeSession(s.sess)
		cfg.conns.release()
		m.globalConns.release()
		return nil
	}
	if existing, ok := e.sessions[key]; ok {
		// 同一客户端的并发首包：另一调用已完成创建，复用现有会话，
		// 丢弃本次多余的 dial，否则被覆盖的会话会泄漏且永不落库
		e.mu.Unlock()
		_ = backend.Close()
		m.removeSession(s.sess)
		cfg.conns.release()
		m.globalConns.release()
		return existing
	}
	e.sessions[key] = s
	e.mu.Unlock()

	go m.udpPipeBackend(e, s)
	return s
}

// udpPipeBackend 后端 -> 客户端方向的读循环。缓冲取自进程级池，会话结束时归还。
func (m *Manager) udpPipeBackend(e *udpEntry, s *udpSession) {
	buf := m.udpBufs.Get().(*[]byte)
	defer m.udpBufs.Put(buf)
	defer func() {
		if r := recover(); r != nil {
			m.logPanic("UDP 后端管道", r)
			// 会话异常终止：按错误收尾（落库 + 释放名额），与写失败路径同语义
			m.udpCloseSession(e, s, model.StatusError, "内部错误：转发协程异常退出")
		}
	}()
	for {
		n, err := s.backend.Read(*buf)
		if err != nil {
			return
		}
		// 下载限速（超时丢包）。热跟随：每包从 entry 原子指针取当前配置——
		// 带宽包编辑/规则更新后存量会话立即按新额度整形（整机带宽上限同其后）
		if !e.cfg.Load().limiter.TryWaitDownload(n, m.opts().UDPLimiterMaxWait) {
			continue
		}
		if gl := m.globalBandwidth(); !gl.Disabled() && !gl.TryWaitDownload(n, m.opts().UDPLimiterMaxWait) {
			continue
		}
		s.sess.addBytes(true, int64(n))
		s.touch()
		if _, err := e.conn.WriteToUDP((*buf)[:n], s.clientAddr); err != nil {
			return
		}
	}
}

func (s *udpSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

// udpJanitor 定期回收空闲会话并落库。
func (m *Manager) udpJanitor(e *udpEntry) {
	ticker := time.NewTicker(udpJanitorInterval)
	defer ticker.Stop()
	for range ticker.C {
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return
		}
		var expired []*udpSession
		now := time.Now().UnixNano()
		for k, s := range e.sessions {
			if time.Duration(now-s.lastActive.Load()) > m.opts().UDPSessionIdle {
				expired = append(expired, s)
				delete(e.sessions, k)
			}
		}
		e.mu.Unlock()
		for _, s := range expired {
			m.udpFinishSession(s, model.StatusClosed, "")
		}
	}
}

func (m *Manager) udpCloseSession(e *udpEntry, s *udpSession, status, errMsg string) {
	e.mu.Lock()
	if cur, ok := e.sessions[s.clientAddr.String()]; ok && cur == s {
		delete(e.sessions, s.clientAddr.String())
	}
	e.mu.Unlock()
	m.udpFinishSession(s, status, errMsg)
}

func (m *Manager) udpFinishSession(s *udpSession, status, errMsg string) {
	_ = s.backend.Close()
	m.removeSession(s.sess)
	s.cfg.conns.release()
	m.globalConns.release()
	m.finishSession(s.sess, s.sess.start, status, errMsg)
}
