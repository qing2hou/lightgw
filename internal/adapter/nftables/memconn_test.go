package nftables

import (
	"fmt"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// memConn 是 connAPI 的内存实现，模拟 netlink 的批处理语义。
//
// 关键语义（必须与真实内核一致，否则测试就是自欺）：
//   - AddRule / DelRule / FlushChain 只是**暂存**，不立即生效
//   - Flush() 把暂存区一次性提交；**提交失败则整批回滚**（与 netlink
//     BATCH_BEGIN/BATCH_END 的原子语义一致）
//   - handle 在提交时分配（从 1 递增）
//
// 这样可以验证「装配失败时半装内容不会留在内核」，而这正是 P0 Task C
// 没能覆盖的那条保护。
type memConn struct {
	mu sync.Mutex

	nextHandle uint64
	nextChain  uint64

	// 已提交状态
	chains []*nftables.Chain
	rules  map[string][]*nftables.Rule // chainName -> rules

	// 暂存区
	pendingAdds  []pendingRule
	pendingDels  []uint64
	pendingFlush []string // 待清空的链名

	// failNextFlush 为 true 时下一次 Flush 返回错误并丢弃整批暂存
	failNextFlush error
	closed        bool
}

type pendingRule struct {
	chain string
	exprs []expr.Any
}

func newMemConn() *memConn {
	return &memConn{
		nextHandle: 1,
		rules:      make(map[string][]*nftables.Rule),
	}
}

func (m *memConn) AddTable(t *nftables.Table) *nftables.Table { return t }

func (m *memConn) AddChain(c *nftables.Chain) *nftables.Chain {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.chains {
		if ex.Name == c.Name {
			return c // 幂等
		}
	}
	m.nextChain++
	m.chains = append(m.chains, c)
	return c
}

func (m *memConn) ListChains() ([]*nftables.Chain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*nftables.Chain, len(m.chains))
	copy(out, m.chains)
	return out, nil
}

func (m *memConn) AddRule(r *nftables.Rule) *nftables.Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	name := ""
	if r.Chain != nil {
		name = r.Chain.Name
	}
	m.pendingAdds = append(m.pendingAdds, pendingRule{chain: name, exprs: r.Exprs})
	return r
}

func (m *memConn) DelRule(r *nftables.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pendingDels = append(m.pendingDels, r.Handle)
	return nil
}

func (m *memConn) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("链为 nil")
	}
	src := m.rules[c.Name]
	out := make([]*nftables.Rule, len(src))
	copy(out, src)
	return out, nil
}

func (m *memConn) FlushChain(c *nftables.Chain) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c != nil {
		m.pendingFlush = append(m.pendingFlush, c.Name)
	}
}

// Flush 提交整批。失败时**整批丢弃**（模拟内核 batch 回滚）。
func (m *memConn) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("连接已关闭")
	}
	if m.failNextFlush != nil {
		err := m.failNextFlush
		m.failNextFlush = nil
		// 整批回滚：丢弃暂存，不触碰已提交状态
		m.pendingAdds = nil
		m.pendingDels = nil
		m.pendingFlush = nil
		return err
	}
	// 1) 清空
	for _, name := range m.pendingFlush {
		delete(m.rules, name)
	}
	// 2) 删除
	if len(m.pendingDels) > 0 {
		del := make(map[uint64]bool, len(m.pendingDels))
		for _, h := range m.pendingDels {
			del[h] = true
		}
		for name, rs := range m.rules {
			kept := rs[:0]
			for _, r := range rs {
				if !del[r.Handle] {
					kept = append(kept, r)
				}
			}
			m.rules[name] = kept
		}
	}
	// 3) 新增（分配 handle）
	for _, a := range m.pendingAdds {
		h := m.nextHandle
		m.nextHandle++
		m.rules[a.chain] = append(m.rules[a.chain], &nftables.Rule{
			Handle: h,
			Exprs:  a.exprs,
		})
	}
	m.pendingAdds = nil
	m.pendingDels = nil
	m.pendingFlush = nil
	return nil
}

func (m *memConn) CloseLasting() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// setFailNextFlush 让下一次 Flush 失败（模拟内核拒绝整批）。
func (m *memConn) setFailNextFlush(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNextFlush = err
}
