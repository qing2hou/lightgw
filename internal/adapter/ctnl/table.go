package ctnl

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// SessionKey 是会话的唯一标识：原始方向的五元组。
//
// 为什么用原始方向而非应答方向：NAT 会改写应答方向的地址/端口，
// 而原始方向在连接生命周期内不变，是稳定的标识。
type SessionKey struct {
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// KeyOf 从 Flow 提取会话键。
func KeyOf(f Flow) SessionKey {
	return SessionKey{
		SrcAddr: f.Orig.SrcAddr,
		DstAddr: f.Orig.DstAddr,
		SrcPort: f.Orig.SrcPort,
		DstPort: f.Orig.DstPort,
		Proto:   f.Orig.Proto,
	}
}

// Session 是会话表中存储的条目。
type Session struct {
	Key SessionKey
	// Flow 是最近一次已知的表项状态。
	Flow Flow
	// FirstSeen / LastSeen 由本包维护（内核只给剩余 timeout）。
	FirstSeen time.Time
	LastSeen  time.Time
}

// shards 是分片数。32 分片的理由：事件订阅是单 goroutine 写入，但
// Snapshot（UI/API 读）是并发读，分片能把读写争用降到 1/32。
//
// **这是唯一允许在 adapter 层用锁的地方**——它是事件驱动的写侧，
// 不在数据面 hot path（C-11 的约束针对的是包转发路径）。
const shards = 32

// Table 是并发安全的会话表。
//
// 不变量：
//   - 每个分片独立加锁，跨分片不保证一致性（快照是「近似瞬时」的）
//   - Put 幂等（同一 key 重复写入只更新）
//   - Delete 对不存在的 key 无副作用
type Table struct {
	sh [shards]struct {
		mu sync.RWMutex
		m  map[SessionKey]*Session
	}
	// now 可注入以便测试时间相关逻辑。
	now func() time.Time
}

// NewTable 创建会话表。
func NewTable() *Table {
	t := &Table{now: time.Now}
	for i := range t.sh {
		t.sh[i].m = make(map[SessionKey]*Session, 64)
	}
	return t
}

// shardOf 把 key 映射到分片。
//
// 用源地址+端口+协议的简单混合——分布均匀性只影响锁争用，不影响正确性。
func shardOf(k SessionKey) int {
	var h uint32 = 2166136261
	b := k.SrcAddr.As16()
	for _, v := range b {
		h = (h ^ uint32(v)) * 16777619
	}
	h = (h ^ uint32(k.SrcPort)) * 16777619
	h = (h ^ uint32(k.DstPort)) * 16777619
	h = (h ^ uint32(k.Proto)) * 16777619
	return int(h % shards)
}

// Put 插入或更新一条会话。
//
// FirstSeen 只在首次插入时设置——事件订阅会重复推送 UPDATE，
// 每次都覆盖 FirstSeen 会让「会话持续时长」永远显示为 0。
func (t *Table) Put(f Flow) {
	k := KeyOf(f)
	s := &t.sh[shardOf(k)]
	now := t.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.m[k]; ok {
		old.Flow = f
		old.LastSeen = now
		return
	}
	s.m[k] = &Session{Key: k, Flow: f, FirstSeen: now, LastSeen: now}
}

// Delete 删除一条会话。
func (t *Table) Delete(k SessionKey) {
	s := &t.sh[shardOf(k)]
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
}

// Get 读取一条会话（返回副本，调用方无法修改表内状态）。
func (t *Table) Get(k SessionKey) (Session, bool) {
	s := &t.sh[shardOf(k)]
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[k]
	if !ok {
		return Session{}, false
	}
	return *v, true
}

// Len 返回会话总数。
func (t *Table) Len() int {
	n := 0
	for i := range t.sh {
		t.sh[i].mu.RLock()
		n += len(t.sh[i].m)
		t.sh[i].mu.RUnlock()
	}
	return n
}

// Snapshot 返回全部会话的不可变副本，按「先建先出」排序（FirstSeen 升序）。
//
// 排序必要性：UI 与 API 都需要稳定顺序，否则每次轮询的行序都在变，
// 前端 diff 会产生无谓的整表重绘。
func (t *Table) Snapshot() []Session {
	out := make([]Session, 0, t.Len())
	for i := range t.sh {
		t.sh[i].mu.RLock()
		for _, v := range t.sh[i].m {
			out = append(out, *v)
		}
		t.sh[i].mu.RUnlock()
	}
	slices.SortFunc(out, func(a, b Session) int {
		if !a.FirstSeen.Equal(b.FirstSeen) {
			if a.FirstSeen.Before(b.FirstSeen) {
				return -1
			}
			return 1
		}
		// FirstSeen 相同时按 key 兜底，保证完全确定
		return compareKey(a.Key, b.Key)
	})
	return out
}

func compareKey(a, b SessionKey) int {
	if c := a.SrcAddr.Compare(b.SrcAddr); c != 0 {
		return c
	}
	if c := a.DstAddr.Compare(b.DstAddr); c != 0 {
		return c
	}
	if a.SrcPort != b.SrcPort {
		if a.SrcPort < b.SrcPort {
			return -1
		}
		return 1
	}
	if a.DstPort != b.DstPort {
		if a.DstPort < b.DstPort {
			return -1
		}
		return 1
	}
	if a.Proto != b.Proto {
		if a.Proto < b.Proto {
			return -1
		}
		return 1
	}
	return 0
}

// ReplaceAll 用一次全量 dump 的结果整体替换表内容（对账用）。
//
// 实现为「逐个 Put + 删除 dump 里没有的」而不是「清空后重建」：
// 后者会让并发的 Snapshot 读到空表（UI 闪一下 0 会话）。
func (t *Table) ReplaceAll(flows []Flow) {
	keep := make(map[SessionKey]struct{}, len(flows))
	for _, f := range flows {
		if err := f.Validate(); err != nil {
			continue
		}
		t.Put(f)
		keep[KeyOf(f)] = struct{}{}
	}
	// 删除内核上已不存在的
	for i := range t.sh {
		t.sh[i].mu.Lock()
		for k := range t.sh[i].m {
			if _, ok := keep[k]; !ok {
				delete(t.sh[i].m, k)
			}
		}
		t.sh[i].mu.Unlock()
	}
}

// Stats 是会话表的汇总统计（供 UI/metrics）。
type Stats struct {
	Total       int
	Established int
	Natted      int
	TotalBytes  uint64
	TotalPkts   uint64
}

// Stats 计算汇总统计（单次遍历，避免多次 Snapshot）。
func (t *Table) Stats() Stats {
	var st Stats
	for i := range t.sh {
		t.sh[i].mu.RLock()
		for _, v := range t.sh[i].m {
			st.Total++
			if v.Flow.IsEstablished() {
				st.Established++
			}
			if v.Flow.IsNatted() {
				st.Natted++
			}
			st.TotalBytes += v.Flow.Bytes
			st.TotalPkts += v.Flow.Packets
		}
		t.sh[i].mu.RUnlock()
	}
	return st
}
