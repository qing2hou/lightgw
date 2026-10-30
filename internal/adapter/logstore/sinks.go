package logstore

import (
	"context"
	"fmt"
	"sync"

	"haproxyweb/internal/adapter/sqlite"
)

// SQLiteSink 把日志写入分表。
//
// 分表路由规则（playbook §7.2）：按 Entry.At 的日期选表，
// **表不存在时先建表**——否则跨天零点后的第一条日志会因表不存在而丢失。
//
// 这是本包唯一 import sqlite 的地方：Writer 本身不依赖任何具体存储，
// 保持「只负责存」的职责边界。
type SQLiteSink struct {
	db *sqlite.DB
	// ensureChecked 记录已确认存在的表，避免每批都查一次 sqlite_master
	ensured map[string]bool
}

// NewSQLiteSink 创建 sqlite sink。
func NewSQLiteSink(db *sqlite.DB) *SQLiteSink {
	return &SQLiteSink{db: db, ensured: make(map[string]bool, 8)}
}

// Name 实现 Sink。
func (s *SQLiteSink) Name() string { return "sqlite" }

// WriteBatch 把一批 Entry 写入对应的分表。
//
// 同一批里可能跨天（凌晨那一批），所以要按表名分组。
func (s *SQLiteSink) WriteBatch(ctx context.Context, batch []Entry) error {
	if s.db == nil || len(batch) == 0 {
		return nil
	}
	// 按分表分组
	byTable := make(map[string][]sqlite.TrafficLogRow, 2)
	for _, e := range batch {
		if e.Kind != "traffic" {
			continue // 其它类别由别的 sink 处理（audit/health 不分表）
		}
		row, ok := e.Data.(sqlite.TrafficLogRow)
		if !ok {
			continue // 载荷类型不符：跳过而不是 panic
		}
		table := sqlite.TrafficTableName(e.At)
		byTable[table] = append(byTable[table], row)
	}
	var firstErr error
	for table, rows := range byTable {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("写入流量日志被取消: %w", err)
		}
		// 建表是幂等的，但仍缓存一下避免每批都执行 DDL
		if !s.ensured[table] {
			if err := s.db.EnsureTrafficTable(table); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			s.ensured[table] = true
		}
		if err := s.db.InsertTrafficBatch(table, rows); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Close 实现 Sink（sqlite 连接由 DB 的所有者关闭，这里不做事）。
func (s *SQLiteSink) Close() error { return nil }

// MemorySink 是内存 sink，仅用于测试与「无持久化」场景。
//
// 它实现了与生产 sink 相同的接口，让 Writer 的行为可以在没有数据库的
// 情况下被完整验证（尤其是「通道满时丢弃」这条）。
//
// **计数器必须加锁**：WriteBatch 在 sinkLoop goroutine 里执行，
// Counts 在测试 goroutine 里读——无锁会是真实数据竞态
// （`go test -race` 抓到过）。
type MemorySink struct {
	name string
	// WriteFn 若非 nil 则替代默认的「只计数」行为，用于模拟慢 sink。
	WriteFn func(ctx context.Context, batch []Entry) error

	mu      sync.Mutex
	batches int
	entries int
	closed  bool
}

// NewMemorySink 创建内存 sink。
func NewMemorySink(name string) *MemorySink {
	return &MemorySink{name: name}
}

// Name 实现 Sink。
func (s *MemorySink) Name() string {
	if s.name == "" {
		return "memory"
	}
	return s.name
}

// WriteBatch 实现 Sink。
func (s *MemorySink) WriteBatch(ctx context.Context, batch []Entry) error {
	if s.WriteFn != nil {
		return s.WriteFn(ctx, batch)
	}
	s.mu.Lock()
	s.batches++
	s.entries += len(batch)
	s.mu.Unlock()
	return nil
}

// Close 实现 Sink。
func (s *MemorySink) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

// Counts 返回（批次数, 条目数, 是否已关闭）。
func (s *MemorySink) Counts() (batches, entries int, closed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.batches, s.entries, s.closed
}
