package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"haproxyweb/internal/model"
)

type tcpEntry struct {
	listener net.Listener
	cfg      atomic.Pointer[ruleConfig]

	// 存量连接注册表：StopAll 排空时等待 wg 归零，超时则强制关闭注册的连接
	conns sync.Map // net.Conn -> struct{}
	wg    sync.WaitGroup
}

func (m *Manager) applyTCP(rule model.ForwardRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := m.tcpRules[rule.ID]
	if !rule.Enabled {
		if ln, ok := m.adoptedTCP[rule.ID]; ok {
			delete(m.adoptedTCP, rule.ID)
			_ = ln.Close() // 升级继承的监听：规则已停用则直接关闭
		}
		if entry != nil {
			delete(m.tcpRules, rule.ID)
			_ = entry.listener.Close()
			logf("TCP 规则[%s#%d]已停止监听 %s", rule.Name, rule.ID, rule.ListenAddr)
			// 停用即关闸：监听关闭只挡新连接，存量连接会继续跑到自然结束
			// （实测：停用后 scp 长传继续走完，用户语义"关了还在传"不可接受
			// ——与 SNAT 停用掐断对齐）。排空放后台协程：与 StopAll 同语义
			// （等 DrainTimeout 自然排空、超时强制关闭）但不阻塞停用 API。
			go m.drainTCP([]*tcpEntry{entry})
		}
		return nil
	}

	cfg := m.buildRuleConfig(rule)
	// 升级交接：使用父进程继承的监听，不重新 net.Listen
	if ln, ok := m.adoptedTCP[rule.ID]; ok {
		delete(m.adoptedTCP, rule.ID)
		if entry != nil {
			_ = entry.listener.Close()
		}
		e := &tcpEntry{listener: ln}
		e.cfg.Store(cfg)
		m.tcpRules[rule.ID] = e
		logf("TCP 规则[%s#%d]接管升级继承监听 %s", rule.Name, rule.ID, rule.ListenAddr)
		go m.acceptTCP(e)
		if healthCheckOn(rule) && m.opts().HealthCheckInterval > 0 {
			go m.probeBackend(rule.ID, rule)
		}
		return nil
	}
	// 监听地址未变：原子替换配置即可，新连接立即用新配置
	if entry != nil {
		if old := entry.cfg.Load(); sameListen(old.rule.ListenAddr, rule.ListenAddr) {
			entry.cfg.Store(cfg)
			// ACL 收紧后，**存量连接**也要按新名单复核并断开不合规的。
			//
			// 为什么必须做：ACL 原本只在 accept 时判定一次，改了白名单
			// 只影响新连接，正在跑的长传（scp/rsync/备份）会照常传完。
			// 用户改了白名单期待"立刻没人能连"，实际看到的却是"还在传"
			// ——安全控制给出错误的安全感比没有控制更危险。
			// 与"停用规则即断流"（DrainTimeout 排空/强制关闭）同一语义。
			//
			// 放后台协程：断开可能涉及大量连接，不能阻塞 Apply（持 m.mu）。
			go m.closeDeniedSessions(rule.ID, cfg.acl)
			if healthCheckOn(rule) && m.opts().HealthCheckInterval > 0 {
				go m.probeBackend(rule.ID, rule) // 目标可能已变，立即探测一次
			}
			return nil
		}
	}

	host, port, err := normalizeListen(rule.ListenAddr)
	if err != nil {
		return err
	}
	// 先关旧监听再听新地址：*:port 与 IP:port 在内核共享同一端口槽位，
	// 不先释放会导致 bind: address already in use（先听后关的旧顺序在
	// "全网卡 ↔ 指定IP" 切换时必现）。
	if entry != nil {
		_ = entry.listener.Close()
		delete(m.tcpRules, rule.ID)
	}
	ln, err := net.Listen("tcp", listenKey(host, port))
	if err != nil {
		// 新地址失败：尽力恢复旧监听（旧地址可能与新地址相同槽位——恢复也可能
		// 失败，此时规则留在 last_error 状态由管理端可见，不中断存量连接之外的服务）
		if entry != nil {
			if oh, op, oerr := normalizeListen(entry.cfg.Load().rule.ListenAddr); oerr == nil {
				if oln, lerr := net.Listen("tcp", listenKey(oh, op)); lerr == nil {
					restored := &tcpEntry{listener: oln}
					restored.cfg.Store(entry.cfg.Load())
					m.tcpRules[rule.ID] = restored
					go m.acceptTCP(restored)
					logf("TCP 规则[%s#%d]新监听失败已恢复旧地址 %s", rule.Name, rule.ID, entry.cfg.Load().rule.ListenAddr)
				}
			}
		}
		return fmt.Errorf("监听 %s 失败: %w", rule.ListenAddr, err)
	}
	e := &tcpEntry{listener: ln}
	e.cfg.Store(cfg)
	m.tcpRules[rule.ID] = e
	logf("TCP 规则[%s#%d]监听 %s -> %s", rule.Name, rule.ID, rule.ListenAddr, rule.TargetAddr)
	go m.acceptTCP(e)
	if healthCheckOn(rule) && m.opts().HealthCheckInterval > 0 {
		go m.probeBackend(rule.ID, rule) // 新规则不等下一个周期，立即出健康状态
	}
	return nil
}

func (m *Manager) acceptTCP(e *tcpEntry) {
	defer func() {
		if r := recover(); r != nil {
			m.logPanic("TCP accept 循环", r)
		}
	}()
	var backoff time.Duration
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // 监听器已主动关闭
			}
			// 临时错误（如 EMFILE/ENFILE）：退避后重试，避免规则静默死亡或忙循环
			m.acceptErrors.Add(1)
			if backoff == 0 {
				backoff = 100 * time.Millisecond
			} else if backoff < time.Second {
				backoff *= 2
			}
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			m.handleTCPConn(e, conn)
		}()
	}
}

func (m *Manager) handleTCPConn(e *tcpEntry, client net.Conn) {
	e.conns.Store(client, struct{}{})
	defer e.conns.Delete(client)

	cfg := e.cfg.Load()
	srcIP, srcPort := splitAddr(client.RemoteAddr().String())
	listenIP, listenPort := "", 0
	if lh, lp, err := net.SplitHostPort(client.LocalAddr().String()); err == nil {
		listenIP = lh
		listenPort, _ = strconv.Atoi(lp)
	}
	if !cfg.acl.Allowed(parseIPOrZero(srcIP)) {
		_ = client.Close()
		m.logDenied(cfg.rule, cfg.acl, srcIP, srcPort)
		return
	}
	// 先占全局名额再占规则名额，两者都在会话结束路径配对释放
	if !m.globalConns.tryAcquire() {
		// 进程级连接总量已达上限：直接断开，防止 FD 耗尽拖垮管理面
		_ = client.Close()
		m.rejectedGlobal.Add(1)
		return
	}
	defer m.globalConns.release()
	if !cfg.conns.tryAcquire() {
		// 并发连接已达规则上限：直接断开，防止 FD 耗尽
		_ = client.Close()
		m.rejectedRule.Add(1)
		return
	}
	defer cfg.conns.release()

	sess := m.registerSession(cfg, srcIP, srcPort, listenIP, listenPort)
	sess.cfgPtr = &e.cfg // 热跟随通道：带宽包/规则更新后存量连接即时用新限速器
	defer m.removeSession(sess)
	start := time.Now()

	// 无论后端拨号成败都必须关闭客户端连接：失败路径若不关闭，连接会悬挂到
	// GC 终结器才回收，客户端表现为长时间无响应，高失败率下还会堆积 FD
	defer client.Close()
	// 连接后端：可绑定规则指定的本机源 IP（后端看到的来源；空 = 路由自动）
	var backend net.Conn
	var err error
	if cfg.dialSourceIP != "" {
		d := net.Dialer{Timeout: m.opts().TCPDialTimeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(cfg.dialSourceIP)}}
		backend, err = d.Dial("tcp", cfg.rule.TargetAddr)
	} else {
		backend, err = net.DialTimeout("tcp", cfg.rule.TargetAddr, m.opts().TCPDialTimeout)
	}
	if err != nil {
		m.finishSession(sess, start, model.StatusError, "连接后端失败: "+err.Error())
		return
	}
	defer backend.Close()
	// 记录 dial 的本地端口：会话表据此把 conntrack 的入向段与出向段合并成
	// 一条（端口映射是用户态转发，内核里是两条独立连接）。
	// 出向段的源 ip 恒为网关本机地址，端口才是区分不同连接的键。
	if la, ok := backend.LocalAddr().(*net.TCPAddr); ok {
		sess.dialLocalPort.Store(int64(la.Port))
	}
	// panic 隔离：转发协程异常退出时补记一条流量日志，不让进程崩溃
	defer func() {
		if r := recover(); r != nil {
			m.logPanic("TCP 会话处理", r)
			m.tlog.Log(finishLog(sess, start, model.StatusError, "内部错误：转发协程异常退出"))
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 注册强制断开钩子（会话表"掐断"与 ACL 变更都要用它）。
	//
	// 只按 conntrack -D 删表项断不了端口映射：copyTCP/copyFast 协程
	// 持有 client 与 backend 两个 socket，删表项后它们照常搬数据，
	// 内核立刻重建 conntrack 条目——用户看到"掐断了还在传"。
	// 必须真正 Close。cancel() 负责解除限速等待等可取消的阻塞点，
	// Close 负责打断 Read/Write（copyFast 的 splice 不响应 ctx）。
	sess.setCloser(func() {
		cancel()
		_ = client.Close()
		_ = backend.Close()
	})

	var wg sync.WaitGroup
	var upErr, downErr error
	wg.Add(2)

	fast := m.spliceEligible(cfg)

	// 上传方向：客户端 -> 后端
	go func() {
		defer wg.Done()
		var err error
		if fast {
			err = m.copyFast(backend, client, sess, false)
		} else {
			err = m.copyTCP(backend, client, cfg, sess, false, ctx)
		}
		if err != nil {
			upErr = err
			cancel() // 异常时解除另一方向可能的限速等待
			_ = client.Close()
			_ = backend.Close()
			return
		}
		// 正常半关闭：通知后端客户端数据发完了，另一方向继续收尾
		if tc, ok := backend.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = backend.Close()
		}
	}()

	// 下载方向：后端 -> 客户端
	go func() {
		defer wg.Done()
		var err error
		if fast {
			err = m.copyFast(client, backend, sess, true)
		} else {
			err = m.copyTCP(client, backend, cfg, sess, true, ctx)
		}
		if err != nil {
			downErr = err
			cancel()
			_ = client.Close()
			_ = backend.Close()
			return
		}
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = client.Close()
		}
	}()

	wg.Wait()
	// 结束原因按严重度取舍：真实故障 > 对端重置/主动关闭 > 空闲超时
	err = pickError(upErr, downErr)
	status := model.StatusClosed
	msg := ""
	if err != nil {
		switch classifyConnErr(err) {
		case connErrReset:
			// 对端 RST/断开、本端主动关闭属常见正常收尾（如 SSH 客户端传完即退），
			// 不计为错误；原话保留在说明列供排查
			msg = err.Error()
		case connErrIdle:
			msg = errIdleTimeout.Error()
		default:
			status = model.StatusError
			msg = err.Error()
		}
	}
	m.finishSession(sess, start, status, msg)
}

// connErrClass 连接结束原因分级。
type connErrClass int

const (
	connErrNone  connErrClass = iota
	connErrIdle               // 空闲超时
	connErrReset              // 对端重置/断开、本端主动关闭（正常收尾的常见形态）
	connErrReal               // 其余：真实故障
)

// classifyConnErr 归类连接结束原因。ECONNRESET/EPIPE（对端强制关闭，常见于
// 客户端传完即退、关窗口）与 net.ErrClosed（本端排空/停规则时主动关闭）
// 都属于正常收尾，不应把整次传输标成「出错」。
func classifyConnErr(err error) connErrClass {
	switch {
	case err == nil:
		return connErrNone
	case errors.Is(err, errIdleTimeout):
		return connErrIdle
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, net.ErrClosed):
		return connErrReset
	default:
		return connErrReal
	}
}

// pickError 按严重度挑选会话的代表性结束原因。
func pickError(errs ...error) error {
	var reset, idle error
	for _, e := range errs {
		if e == nil {
			continue
		}
		switch classifyConnErr(e) {
		case connErrReal:
			return e
		case connErrReset:
			if reset == nil {
				reset = e
			}
		case connErrIdle:
			if idle == nil {
				idle = e
			}
		}
	}
	if reset != nil {
		return reset
	}
	return idle
}

// finishLog 生成会话结束时的流量日志。
func finishLog(s *session, start time.Time, status, errMsg string) model.TrafficLog {
	end := time.Now()
	return model.TrafficLog{
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
		Status:        status,
		ErrorMsg:      truncate(errMsg, 512),
		StartedAt:     start,
		EndedAt:       &end,
		DurationMs:    end.Sub(start).Milliseconds(),
	}
}

// truncate 按字节截断（DB 列按字节限长），回退到 UTF-8 字符边界避免切断多字节字符。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}
