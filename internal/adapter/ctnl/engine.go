package ctnl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// ReconcileInterval 是全量对账周期。
//
// 为什么需要：netlink 多播在缓冲区溢出时**丢弃事件而不是阻塞**
// （内核不能因为用户态跟不上就卡住 conntrack）。所以内存表会漂移，
// 必须定期用全量 dump 修正。60 秒是「漂移可接受」与「dump 开销」的折中。
const ReconcileInterval = 60 * time.Second

// 关于「事件通道」的说明（设计中提到但本实现没有引入）：
//
// 技术方案 §4 的伪代码用 `events := make(chan conntrack.Event, 4096)` 缓冲。
// 本实现直接在当前 goroutine 里同步处理 netlink 消息，**不引入中间通道**，
// 理由是：
//   - 中间通道只有在「解析慢于读取」时才有意义，而解析是纯 CPU 的
//     微秒级操作，瓶颈不在这里
//   - 引入通道反而多一层「通道满怎么办」的决策（丢事件 → 计数 → 靠对账修）
//   - 内核侧的 netlink 接收缓冲（约 200KB）满了同样会丢事件，两种丢弃
//     的后果与修正手段完全一样，没必要区分
//
// 真正的保护是「60 秒全量对账」+「dropped 计数上报」，两者都已实现。

// Engine 是 conntrack 事件订阅引擎。
type Engine struct {
	table *Table

	mu sync.RWMutex
	// dial 可注入以便测试（生产路径用真实 nfnetlink 连接）。
	dial func() (req, ev netlinkConn, err error)
	// conn 是**请求/响应**连接（dump、delete），不订阅多播。
	conn netlinkConn
	// evConn 是**多播事件**连接，只收不请求。
	//
	// 为什么要两条连接（真机实测得出）：
	// 同一条 netlink socket 上订阅多播后，异步事件会与 dump 的响应
	// 混在一起，`Execute` 的序列号校验会失败，报
	// "netlink validate: mismatched sequence in netlink reply"。
	// 内核文档的建议也是「请求通道与通知通道分开」。
	evConn netlinkConn

	// 指标（atomic 读取）
	dropped    uint64
	reconciled uint64
	lastErr    error
}

// netlinkConn 是本包使用的最小 netlink 接口。
//
// 注意：多播组**不能在拨号后动态订阅**（mdlayher/netlink 的 Config.Groups
// 只在 Dial 时生效，没有 JoinGroups 方法）。所以 dialReal 必须在建立连接
// 时就带上三个组号。
//
// 抽成接口的理由与 adapter/nftables 的 connAPI 一致：事件循环的
// 「通道满时丢弃」「ctx 取消」「连接断开重连」这些行为必须能在 CI 里验证，
// 而真实 nfnetlink 需要 CAP_NET_ADMIN。
type netlinkConn interface {
	// Execute 发送请求并等待响应（用于 dump 与 delete）。
	Execute(m netlink.Message) ([]netlink.Message, error)
	// Receive 阻塞读一条多播消息。
	Receive() ([]netlink.Message, error)
	Close() error
}

// NewEngine 创建引擎。
func NewEngine() *Engine {
	return &Engine{
		table: NewTable(),
		dial:  dialPair,
	}
}

// NewEngineWith 供测试注入自定义连接（单连接同时用于请求与事件）。
func NewEngineWith(dial func() (netlinkConn, error)) *Engine {
	return &Engine{
		table: NewTable(),
		dial: func() (netlinkConn, netlinkConn, error) {
			c, err := dial()
			return c, c, err
		},
	}
}

// NewEngineWithPair 供测试分别注入请求连接与事件连接。
func NewEngineWithPair(dial func() (req, ev netlinkConn, err error)) *Engine {
	return &Engine{table: NewTable(), dial: dial}
}

// Table 暴露会话表（只读用途；写入只能通过 Run 事件循环）。
func (e *Engine) Table() *Table { return e.table }

// Dropped 返回累计丢弃的事件数。
//
// **必须出现在 /metrics 与 /healthz**（技术方案 §4）：丢弃数持续增长
// 说明内核事件速率超过消费能力，会话统计已不可信。
func (e *Engine) Dropped() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dropped
}

// Reconciles 返回累计对账次数。
func (e *Engine) Reconciles() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.reconciled
}

// LastError 返回最近一次非致命错误（供 UI 展示降级状态）。
func (e *Engine) LastError() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastErr
}

// Run 启动事件循环，阻塞直到 ctx 取消。
//
// 流程（技术方案 §4）：
//  1. 首次全量 dump 建立基线
//  2. 订阅 NEW/UPDATE/DESTROY 多播组
//  3. 事件循环：NEW/UPDATE → Put，DESTROY → Delete
//  4. 每 60s 全量对账一次，修正事件丢失造成的漂移
//
// 任何一步失败都返回错误（调用方决定是否降级为轮询模式）。
func (e *Engine) Run(ctx context.Context) error {
	conn, evConn, err := e.dial()
	if err != nil {
		return fmt.Errorf("连接 conntrack netlink 失败: %w", err)
	}
	e.mu.Lock()
	e.conn = conn
	e.evConn = evConn
	e.mu.Unlock()
	defer func() {
		_ = conn.Close()
		_ = evConn.Close()
		e.mu.Lock()
		e.conn = nil
		e.evConn = nil
		e.mu.Unlock()
	}()

	// ① 基线
	flows, err := e.dump(conn)
	if err != nil {
		return fmt.Errorf("首次全量 dump 失败: %w", err)
	}
	e.table.ReplaceAll(flows)

	// ② 多播组已在 dialReal 里随连接订阅（Config.Groups），此处无需再做。

	// ③ 事件循环
	//
	// 结构说明：Receive 带 1 秒读超时（realConn.Receive 里设 deadline），
	// 所以循环体每秒至少醒一次——ctx 取消与对账定时器都能在一个周期内生效。
	// 不用 select + default（会变成忙等，把一个核心吃满）。
	lastReconcile := time.Now()
	for {
		if ctx.Err() != nil {
			return nil
		}
		// 到点先对账（放在读之前：即使事件持续涌入也能按时对账）
		if time.Since(lastReconcile) >= ReconcileInterval {
			if err := e.reconcile(conn); err != nil {
				// 对账失败不是致命错误：下一轮重试
				e.setLastError(fmt.Errorf("会话表对账失败: %w", err))
			} else {
				e.mu.Lock()
				e.reconciled++
				e.lastErr = nil
				e.mu.Unlock()
			}
			lastReconcile = time.Now()
		}

		msgs, err := evConn.Receive()
		if err != nil {
			if isTimeout(err) {
				continue // 超时是正常节奏：让 ctx 与对账定时器有机会生效
			}
			if ctx.Err() != nil {
				return nil
			}
			e.setLastError(fmt.Errorf("读取 conntrack 事件失败: %w", err))
			return fmt.Errorf("读取 conntrack 事件失败: %w", err)
		}
		for _, m := range msgs {
			e.handleMessage(m)
		}
	}
}

// handleMessage 处理一条多播消息。
//
// 单条消息解析失败**不影响后续消息**——内核可能发来我们不认识的类型。
// 解析失败计入 dropped：它意味着「有条事件没能进入会话表」，
// 与通道满丢事件的后果相同（内存表与内核表不一致，靠 60s 对账修正）。
func (e *Engine) handleMessage(m netlink.Message) {
	t, err := eventTypeOf(uint16(m.Header.Type))
	if err != nil {
		// 非 conntrack 事件（同一套接字上可能有其他子系统消息），不计入丢弃
		return
	}
	// netlink 消息体 = nfgenmsg(4B) + attributes
	flow, err := ParseFlow(m.Data)
	if err != nil {
		e.noteDrop(err)
		return
	}
	// NEW/DESTROY 也可能带不完整信息，DESTROY 只需 key
	if t == EventDestroy {
		// 即使 Validate 失败也要尝试删除（key 可能部分有效）
		if flow.Orig.SrcAddr.IsValid() && flow.Orig.DstAddr.IsValid() && flow.Orig.Proto != 0 {
			e.table.Delete(KeyOf(flow))
		}
		return
	}
	if err := flow.Validate(); err != nil {
		// 期望连接/模板是**正常**的，不算丢弃
		return
	}
	e.table.Put(flow)
}

// eventTypeOf 从 netlink 消息类型解析事件类型。
//
// 消息类型 = subsys<<8 | msgtype。子系统的低 8 位消息号与多播组号一致
// （NEW=0、UPDATE=1、DESTROY=2 是消息号；组号是 1/2/3）。
func eventTypeOf(msgType uint16) (EventType, error) {
	subsys := msgType >> 8
	if subsys != NFNLSubsysCtnetlink {
		return 0, fmt.Errorf("非 conntrack 消息（子系统 %d）", subsys)
	}
	switch msgType & 0xff {
	case IPCTNLMsgNew:
		return EventNew, nil
	case IPCTNLMsgDelete:
		return EventDestroy, nil
	case IPCTNLMsgGet:
		// GET 用于响应 dump；在事件流里等价于 UPDATE
		return EventUpdate, nil
	}
	return 0, fmt.Errorf("未知的 conntrack 消息类型 %d", msgType&0xff)
}

// reconcile 执行一次全量对账。
func (e *Engine) reconcile(conn netlinkConn) error {
	flows, err := e.dump(conn)
	if err != nil {
		return err
	}
	e.table.ReplaceAll(flows)
	return nil
}

// dump 请求一次全量 conntrack 表。
//
// 请求是一个「nfgenmsg + 无属性」的 DUMP 消息。
func (e *Engine) dump(conn netlinkConn) ([]Flow, error) {
	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(MessageType(IPCTNLMsgDump)),
			Flags: netlink.Request | netlink.Dump,
		},
		// nfgenmsg: family=AF_UNSPEC(0) 表示「所有地址族」
		Data: []byte{0, NFNetlinkV0, 0, 0},
	}
	msgs, err := conn.Execute(req)
	if err != nil {
		return nil, err
	}
	out := make([]Flow, 0, len(msgs))
	for _, m := range msgs {
		f, err := ParseFlow(m.Data)
		if err != nil {
			continue // 单条坏消息跳过
		}
		if err := f.Validate(); err != nil {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// KillSession 删除一条 conntrack 表项。
//
// **不走 `conntrack -D` exec**（D-08 / 技术方案 §6.3）：
//   - CLI 不存在时静默失败
//   - 拼参数有注入面（`-s ... -d ...`）
//
// 直接发 IPCTNL_MSG_DELETE，带上原始方向的五元组。
func (e *Engine) KillSession(k SessionKey) error {
	e.mu.RLock()
	conn := e.conn
	e.mu.RUnlock()
	if conn == nil {
		return fmt.Errorf("删除会话失败: conntrack 引擎未启动")
	}
	// 先查本地表拿到完整表项（reply tuple / status / timeout / mark 都要用到）。
	// 本地缺失时用 orig 镜像补齐 reply，其余字段给零值——内核按五元组匹配，
	// 只要求属性存在，不要求值精确。
	var sess Session
	if s, ok := e.table.Get(k); ok {
		sess = s
	}
	orig := Tuple{
		SrcAddr: k.SrcAddr,
		DstAddr: k.DstAddr,
		SrcPort: k.SrcPort,
		DstPort: k.DstPort,
		Proto:   k.Proto,
	}
	reply := Tuple{
		SrcAddr: sess.Flow.Reply.SrcAddr,
		DstAddr: sess.Flow.Reply.DstAddr,
		SrcPort: sess.Flow.Reply.SrcPort,
		DstPort: sess.Flow.Reply.DstPort,
		Proto:   k.Proto,
	}
	body, err := BuildDeleteRequest(orig, reply, sess.Flow.Status, sess.Flow.Timeout, 0)
	if err != nil {
		return fmt.Errorf("删除会话失败: %w", err)
	}
	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(MessageType(IPCTNLMsgDelete)),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: body,
	}
	if _, err := conn.Execute(req); err != nil {
		return fmt.Errorf("删除会话 %s 失败: %w", k.String(), err)
	}
	// 本地表同步删除，避免 UI 在下次对账前仍显示它
	e.table.Delete(k)
	return nil
}

// String 便于日志。
func (k SessionKey) String() string {
	return fmt.Sprintf("%d %s:%d -> %s:%d", k.Proto, k.SrcAddr, k.SrcPort, k.DstAddr, k.DstPort)
}

func (e *Engine) setLastError(err error) {
	e.mu.Lock()
	e.lastErr = err
	e.mu.Unlock()
}

// noteDrop 记录一次事件丢弃并保存原因。
//
// 与 setLastError 分开：丢弃是**计数**（要出现在 metrics 与 healthz），
// 而 lastErr 只保留最近一条原因，两者用途不同。
func (e *Engine) noteDrop(err error) {
	e.mu.Lock()
	e.dropped++
	e.lastErr = err
	e.mu.Unlock()
}

// isTimeout 识别「读超时」——这是本包事件循环的正常节奏，不是错误。
//
// 实测：mdlayher/netlink 在 SetReadDeadline 到期后返回的错误
// **不是 EAGAIN**，而是 "netlink receive: i/o timeout"（内部是
// os.ErrDeadlineExceeded）。早期只判 EAGAIN 导致超时被当成致命错误、
// Run 直接退出、KillSession 报「引擎未启动」。
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, unix.EAGAIN) {
		return true
	}
	// 兜底：部分版本把超时包装成普通 error，字符串匹配
	return strings.Contains(err.Error(), "i/o timeout") ||
		strings.Contains(err.Error(), "timeout")
}

// dialPair 是生产路径的拨号函数：返回（请求连接, 事件连接）。
func dialPair() (netlinkConn, netlinkConn, error) {
	// 请求连接：不订阅任何组
	req, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("打开 NETLINK_NETFILTER（请求通道）失败: %w", err)
	}
	// 事件连接：订阅 NEW/UPDATE/DESTROY
	// Groups 是位掩码，组号 N 对应第 N 位（1-based）
	groups := uint32(1<<NFNLGrpConntrackNew |
		1<<NFNLGrpConntrackUpdate |
		1<<NFNLGrpConntrackDestroy)
	ev, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{Groups: groups})
	if err != nil {
		_ = req.Close()
		return nil, nil, fmt.Errorf("打开 NETLINK_NETFILTER（事件通道）失败: %w", err)
	}
	return &realConn{Conn: req, readTimeout: 0}, &realConn{Conn: ev, readTimeout: time.Second}, nil
}

// dialReal 建立真实的 nfnetlink 连接并订阅多播组。
//
// 说明：多播组通过 setsockopt(NETLINK_ADD_MEMBERSHIP) 订阅，
// mdlayher/netlink 的 SetReadDeadline 用于让 ctx 取消能生效。
func dialReal() (netlinkConn, error) {
	// Groups 是**位掩码**：组号 N 对应第 N 位（1-based）。
	//   NFNLGRP_CONNTRACK_NEW     = 1 → 1<<1
	//   NFNLGRP_CONNTRACK_UPDATE  = 2 → 1<<2
	//   NFNLGRP_CONNTRACK_DESTROY = 3 → 1<<3
	groups := uint32(1<<NFNLGrpConntrackNew |
		1<<NFNLGrpConntrackUpdate |
		1<<NFNLGrpConntrackDestroy)
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{Groups: groups})
	if err != nil {
		return nil, fmt.Errorf("打开 NETLINK_NETFILTER 套接字失败: %w", err)
	}
	return &realConn{Conn: c}, nil
}

// realConn 是 netlinkConn 的真实实现。
type realConn struct {
	*netlink.Conn
	// readTimeout 为 0 表示不设读超时（请求通道用）。
	// 事件通道设 1 秒，使 ctx 取消能在一个周期内生效。
	readTimeout time.Duration
}

func (r *realConn) Receive() ([]netlink.Message, error) {
	if r.readTimeout > 0 {
		if err := r.Conn.SetReadDeadline(time.Now().Add(r.readTimeout)); err != nil {
			return nil, err
		}
	}
	return r.Conn.Receive()
}

// DropStats 返回事件丢弃统计的稳定快照（供指标层）。
func (e *Engine) DropStats() (dropped uint64, reconciled uint64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dropped, e.reconciled
}
