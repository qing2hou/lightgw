// Package nftables 实现 nftables 表的双表热切换。
//
// 核心机制（技术方案 §3.1）：稳定锚点 + 影子链。
//
//	table inet haweb {
//	    chain dispatch_fwd  { type filter hook forward priority -10; jump fwd_a }
//	    chain fwd_a { ... }   # 当前生效
//	    chain fwd_b { }       # 影子，装新规则
//	}
//
// 切换分三步，每步一个 netlink batch：
//  1. 装新规则到影子链 —— 失败则旧规则完好，业务无感
//  2. 一个 batch 内「删旧 jump + 加新 jump」—— 原子，转发面只会看到「跳 a」或「跳 b」
//  3. 清理旧链规则 —— 无影响（已无引用）
//
// 为什么第 2 步是原子的：nftables 的 netlink 有 BATCH_BEGIN/BATCH_END 语义，
// `google/nftables` 的 `Flush()` 把暂存区打成 batch 一次提交，内核保证
// batch 内全成功或全失败。所以转发面没有「两条都不跳」的瞬间。
//
// 这一点已在真机实测（docs/poc-result.md §6.3）：60 次翻转 / 0 异常 /
// jump 恒为 1 / 客户端 300 秒零 reset（104.79 MB/s）。
//
// ⚠️ 但那次 PoC 的工作链里只放 counter，装什么都不会影响转发。**影子链装配
// 失败时旧链仍在服务**这条保护本包必须自己实现并被测试覆盖（S1 DoD 第 3 条）。
package nftables

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/nftables"
)

// 链名常量。
//
// dispatch_* 是稳定锚点：每条 hook 只有一个 jump，平时不动，只在切换时被
// 原子替换。工作链按 a/b 后缀交替，用 ChainSuffix 构造。
const (
	TableName = "haweb"

	// 四个 hook 各自的稳定锚点。
	DispatchPre  = "dispatch_pre"  // prerouting, priority mangle (-150)
	DispatchDnat = "dispatch_dnat" // prerouting, priority dstnat (-100)
	DispatchFwd  = "dispatch_fwd"  // forward,    priority -10
	DispatchSnat = "dispatch_snat" // postrouting, priority 100

	// 工作链的逻辑名（不含 a/b 后缀）。
	WorkPre  = "pre"
	WorkDnat = "dnat"
	WorkFwd  = "fwd"
	WorkSnat = "snat"

	// 固定链：MSS 与 input 不参与版本化（内容稳定，无需热切换）。
	ChainMSS   = "mss"
	ChainInput = "input"
)

// 链的 priority 取值（与 compile 包保持一致，此处用 int32 供 netlink 使用）。
const (
	PriorityPre  int32 = -150
	PriorityDnat int32 = -100
	PriorityMSS  int32 = -20
	PriorityFwd  int32 = -10
	PrioritySnat int32 = 100
)

// Slot 是工作链的版本槽。
type Slot string

const (
	SlotA Slot = "a"
	SlotB Slot = "b"
)

// Other 返回另一个槽。
func (s Slot) Other() Slot {
	if s == SlotA {
		return SlotB
	}
	return SlotA
}

// Valid 报告槽名是否合法。
func (s Slot) Valid() bool { return s == SlotA || s == SlotB }

// ChainName 构造工作链名：fwd + a = "fwd_a"。
func ChainName(work string, slot Slot) string {
	return work + "_" + string(slot)
}

// 四个工作链的逻辑名清单（用于遍历）。
var workChains = []string{WorkPre, WorkDnat, WorkFwd, WorkSnat}

// 锚点与工作链的映射。
var dispatchOf = map[string]string{
	WorkPre:  DispatchPre,
	WorkDnat: DispatchDnat,
	WorkFwd:  DispatchFwd,
	WorkSnat: DispatchSnat,
}

// hookOf 是一个工作链对应的 hook 参数（用于建 dispatch 链）。
type hookSpec struct {
	hook     *nftables.ChainHook
	priority *nftables.ChainPriority
	typ      nftables.ChainType
}

var hookOf = map[string]hookSpec{
	WorkPre: {
		hook:     nftables.ChainHookPrerouting,
		priority: nftables.ChainPriorityMangle,
		typ:      nftables.ChainTypeFilter,
	},
	WorkDnat: {
		hook:     nftables.ChainHookPrerouting,
		priority: nftables.ChainPriorityNATDest,
		typ:      nftables.ChainTypeNAT,
	},
	WorkFwd: {
		hook:     nftables.ChainHookForward,
		priority: nftables.ChainPriorityRef(nftables.ChainPriority(PriorityFwd)),
		typ:      nftables.ChainTypeFilter,
	},
	WorkSnat: {
		hook:     nftables.ChainHookPostrouting,
		priority: nftables.ChainPriorityNATSource,
		typ:      nftables.ChainTypeNAT,
	},
}

// ErrNotReady 表示引擎尚未完成初始化。
var ErrNotReady = errors.New("nftables 引擎尚未初始化")

// Engine 是 nftables 表的操作引擎。
//
// 并发约束：CommitShadow 内部的「装载 → 自检 → 切换 → 清理」必须串行，
// 否则两次并发切换会互相覆盖影子链。用 mu 保护。**但 mu 不能覆盖
// Flush 之外的长阻塞**（本包的 Flush 是 netlink 请求，毫秒级）。
type Engine struct {
	mu sync.Mutex

	conn connAPI
	tbl  *nftables.Table

	// active 是当前生效的槽，shadow 是下一次切换的目标槽。
	active Slot
	shadow Slot

	// 每个工作链的 dispatch jump handle 缓存（切换时按 handle 删）。
	jumpHandles map[string]uint64

	// 可注入的钩子，供测试模拟「装配失败」与「自检失败」。
	// 生产路径为 nil。
	failInstall func(work string) error
	failVerify  func(work string) error
}

// NewEngine 创建引擎并确保表与链结构存在。
//
// 熔断保护（C-10）：初始化只做「确保结构存在」，**不删除任何已有规则**。
// 已有的 active 槽内容保持不变，避免重启瞬间清空转发面。
func NewEngine(conn connAPI) (*Engine, error) {
	if conn == nil {
		return nil, fmt.Errorf("创建 nftables 引擎失败: 连接为 nil")
	}
	e := &Engine{
		conn:        conn,
		active:      SlotA,
		shadow:      SlotB,
		jumpHandles: make(map[string]uint64, 4),
	}
	if err := e.ensureStructure(); err != nil {
		return nil, err
	}
	return e, nil
}

// ensureStructure 确保表、4 个锚点链、8 个工作链、MSS/input 链都存在。
//
// 全部走 ListChains 判存在，不存在才 Add。**绝不删除**。
func (e *Engine) ensureStructure() error {
	e.tbl = e.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   TableName,
	})

	existing, err := e.conn.ListChains()
	if err != nil {
		return fmt.Errorf("列出现有链失败: %w", err)
	}
	have := make(map[string]bool, len(existing))
	for _, c := range existing {
		if c.Table != nil && c.Table.Name == TableName {
			have[c.Name] = true
		}
	}

	add := func(name string, spec *hookSpec) {
		if have[name] {
			return
		}
		c := &nftables.Chain{Name: name, Table: e.tbl}
		if spec != nil {
			c.Type = spec.typ
			c.Hooknum = spec.hook
			c.Priority = spec.priority
		}
		e.conn.AddChain(c)
	}

	// 4 个锚点（挂 hook）
	for work, disp := range dispatchOf {
		sp := hookOf[work]
		add(disp, &sp)
	}
	// 8 个工作链（不挂 hook，只能被 jump 进入）
	for _, work := range workChains {
		add(ChainName(work, SlotA), nil)
		add(ChainName(work, SlotB), nil)
	}
	// 固定链
	mssSpec := hookSpec{
		hook:     nftables.ChainHookForward,
		priority: nftables.ChainPriorityRef(nftables.ChainPriority(PriorityMSS)),
		typ:      nftables.ChainTypeFilter,
	}
	add(ChainMSS, &mssSpec)
	inputSpec := hookSpec{
		hook:     nftables.ChainHookPrerouting,
		priority: nftables.ChainPriorityRef(nftables.ChainPriority(PriorityPre)),
		typ:      nftables.ChainTypeFilter,
	}
	add(ChainInput, &inputSpec)

	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("创建表结构失败: %w", err)
	}
	return nil
}

// Active 返回当前生效的槽。
func (e *Engine) Active() Slot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.active
}

// Shadow 返回下一次切换的目标槽。
func (e *Engine) Shadow() Slot {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.shadow
}

// SetFailHooks 注入失败钩子（仅供测试模拟装配/自检失败）。
func (e *Engine) SetFailHooks(install, verify func(work string) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failInstall = install
	e.failVerify = verify
}

// Table 暴露底层 table（供同包的规则构造使用）。
func (e *Engine) Table() *nftables.Table { return e.tbl }

// Conn 暴露底层连接（供上层读计数器等只读操作）。
// Conn 已不可导出：调用方不应绕过 Engine 直接操作连接。

// Close 关闭底层连接。只应在进程退出时调用。
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn == nil {
		return nil
	}
	err := e.conn.CloseLasting()
	e.conn = nil
	return err
}

// ctxCheck 是 context 取消的统一检查点。
//
// 长流程（装载上千条规则）要能被打断，否则一次 HTTP 取消会卡住整个控制面。
func ctxCheck(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("操作被取消: %w", ctx.Err())
	default:
		return nil
	}
}
