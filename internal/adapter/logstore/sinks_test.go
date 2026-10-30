package logstore

import (
	"context"
	"testing"
	"time"

	"haproxyweb/internal/adapter/sqlite"
)

func openDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(t.TempDir())
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	return db
}

func trafficRow(i int) sqlite.TrafficLogRow {
	return sqlite.TrafficLogRow{
		RuleID:    1,
		RuleName:  "r1",
		SrcIP:     "192.168.10.152",
		DstIP:     "172.16.30.10",
		SrcPort:   uint16(10000 + i),
		DstPort:   9098,
		Proto:     "tcp",
		BytesIn:   100,
		BytesOut:  50,
		StartedAt: time.Now().Unix(),
	}
}

// TestSQLiteSinkRoutesByDay 按 Entry.At 的日期路由到对应分表。
func TestSQLiteSinkRoutesByDay(t *testing.T) {
	db := openDB(t)
	defer db.Close()
	s := NewSQLiteSink(db)

	d1 := time.Date(2026, 10, 30, 23, 0, 0, 0, time.UTC)
	d2 := time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)
	batch := []Entry{
		{Kind: "traffic", At: d1, Data: trafficRow(1)},
		{Kind: "traffic", At: d1, Data: trafficRow(2)},
		{Kind: "traffic", At: d2, Data: trafficRow(3)},
	}
	if err := s.WriteBatch(context.Background(), batch); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	// 应自动建出两张分表
	tables, err := db.TrafficTables()
	if err != nil {
		t.Fatalf("列分表失败: %v", err)
	}
	if len(tables) != 2 {
		t.Fatalf("跨天应建 2 张分表，实际 %d: %v", len(tables), tables)
	}
	// 行数分别正确
	for _, tc := range []struct {
		name string
		want int64
	}{
		{"traffic_log_20261030", 2},
		{"traffic_log_20261031", 1},
	} {
		var cnt int64
		if err := db.Log.Raw("SELECT COUNT(*) FROM " + tc.name).Scan(&cnt).Error; err != nil {
			t.Fatalf("统计 %s 失败: %v", tc.name, err)
		}
		if cnt != tc.want {
			t.Fatalf("%s 应有 %d 行，实际 %d", tc.name, tc.want, cnt)
		}
	}
}

// TestSQLiteSinkSkipsNonTraffic 非 traffic 类别的条目必须被跳过（由别的 sink 处理）。
func TestSQLiteSinkSkipsNonTraffic(t *testing.T) {
	db := openDB(t)
	defer db.Close()
	s := NewSQLiteSink(db)
	batch := []Entry{
		{Kind: "audit", At: time.Now(), Data: "audit-row"},
		{Kind: "health", At: time.Now(), Data: "health-row"},
	}
	if err := s.WriteBatch(context.Background(), batch); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	tables, _ := db.TrafficTables()
	if len(tables) != 0 {
		t.Fatalf("非 traffic 条目不应建分表，实际 %v", tables)
	}
}

// TestSQLiteSinkSkipsWrongPayload 载荷类型不符必须跳过而不是 panic。
func TestSQLiteSinkSkipsWrongPayload(t *testing.T) {
	db := openDB(t)
	defer db.Close()
	s := NewSQLiteSink(db)
	batch := []Entry{
		{Kind: "traffic", At: time.Now(), Data: "不是 TrafficLogRow"},
	}
	if err := s.WriteBatch(context.Background(), batch); err != nil {
		t.Fatalf("类型不符应跳过而非报错，实际: %v", err)
	}
}

// TestSQLiteSinkNilDB nil DB 不 panic。
func TestSQLiteSinkNilDB(t *testing.T) {
	s := NewSQLiteSink(nil)
	if err := s.WriteBatch(context.Background(), []Entry{{Kind: "traffic"}}); err != nil {
		t.Fatalf("nil DB 应安全返回: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close 应安全: %v", err)
	}
}

// TestSQLiteSinkContextCancel ctx 取消必须中断写入。
func TestSQLiteSinkContextCancel(t *testing.T) {
	db := openDB(t)
	defer db.Close()
	s := NewSQLiteSink(db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.WriteBatch(ctx, []Entry{
		{Kind: "traffic", At: time.Now(), Data: trafficRow(1)},
	})
	if err == nil {
		t.Fatal("已取消的 ctx 应返回错误")
	}
}

// TestWriterWithSQLiteSink 端到端：Writer + SQLiteSink 落库成功。
func TestWriterWithSQLiteSink(t *testing.T) {
	db := openDB(t)
	defer db.Close()
	sink := NewSQLiteSink(db)
	w := New(sink)

	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	const n = BatchSize + 10 // 跨过一批的边界
	for i := 0; i < n; i++ {
		if !w.Record(Entry{Kind: "traffic", At: at, Data: trafficRow(i)}) {
			t.Fatalf("第 %d 条被丢弃（不应发生：缓冲足够）", i)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	// 全部落库
	name := sqlite.TrafficTableName(at)
	var cnt int64
	if err := db.Log.Raw("SELECT COUNT(*) FROM " + name).Scan(&cnt).Error; err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if cnt != int64(n) {
		t.Fatalf("应落库 %d 行，实际 %d（关闭时是否漏刷？）", n, cnt)
	}
	if w.Dropped() != 0 {
		t.Fatalf("缓冲足够时不应有丢弃，实际 %d", w.Dropped())
	}
}
