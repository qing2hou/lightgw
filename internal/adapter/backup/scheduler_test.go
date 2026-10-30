package backup

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewSchedulerDisabled 间隔 <= 0 或 svc 为 nil 时返回 nil（不启用）。
func TestNewSchedulerDisabled(t *testing.T) {
	if NewScheduler(&Service{}, 0, Options{}, nil) != nil {
		t.Fatal("间隔为 0 应返回 nil")
	}
	if NewScheduler(nil, time.Hour, Options{}, nil) != nil {
		t.Fatal("svc 为 nil 应返回 nil")
	}
}

// TestSchedulerNilSafe nil Scheduler 的方法必须安全（不 panic）。
func TestSchedulerNilSafe(t *testing.T) {
	var s *Scheduler
	s.Run(context.Background()) // 应立即返回
	if s.NextDelay() != 0 {
		t.Fatal("nil 的 NextDelay 应为 0")
	}
	if s.Describe() != "未启用" {
		t.Fatalf("nil 的 Describe 应为「未启用」，实际 %q", s.Describe())
	}
}

// TestSchedulerRunsAndReports 调度器按间隔执行并回调。
func TestSchedulerRunsAndReports(t *testing.T) {
	dir := t.TempDir()
	sink := newCountingSink("local")
	svc := New(filepath.Join(dir, "config.db"), dir, writeSnapshot("x"), sink)
	var calls atomic.Int64
	sch := NewScheduler(svc, 30*time.Millisecond, Options{Source: "config"},
		func(res *Result, err error) {
			calls.Add(1)
		})
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	sch.Run(ctx)
	if calls.Load() == 0 {
		t.Fatal("调度器应至少执行一轮")
	}
	if len(sink.puts) == 0 {
		t.Fatal("应至少上传一份备份")
	}
}

// TestSchedulerContinuesAfterError 单轮失败后继续下一轮（不退出）。
func TestSchedulerContinuesAfterError(t *testing.T) {
	dir := t.TempDir()
	// vacuum 第一次失败，之后成功
	var count atomic.Int64
	vac := func(ctx context.Context, dest string) error {
		if count.Add(1) == 1 {
			return errors.New("模拟首轮失败")
		}
		return writeSnapshot("x")(ctx, dest)
	}
	sink := newCountingSink("local")
	svc := New(filepath.Join(dir, "config.db"), dir, vac, sink)
	var failures atomic.Int64
	sch := NewScheduler(svc, 25*time.Millisecond, Options{Source: "config"},
		func(res *Result, err error) {
			if err != nil {
				failures.Add(1)
			}
		})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	sch.Run(ctx)
	if failures.Load() == 0 {
		t.Fatal("应记录到首轮失败")
	}
	if len(sink.puts) == 0 {
		t.Fatal("★ 首轮失败后必须继续执行后续轮次（失败不该让调度退出）")
	}
}

// TestSchedulerDoesNotOverlap 上一轮未完成时不堆积（ticker + 非阻塞）。
//
// 验证方式：每轮耗时 100ms 而间隔 10ms，最终执行次数应远小于 30
// （若堆积会是 30 次左右）。
func TestSchedulerDoesNotOverlap(t *testing.T) {
	dir := t.TempDir()
	var count atomic.Int64
	vac := func(ctx context.Context, dest string) error {
		count.Add(1)
		time.Sleep(100 * time.Millisecond)
		return writeSnapshot("x")(ctx, dest)
	}
	svc := New(filepath.Join(dir, "config.db"), dir, vac, newCountingSink("local"))
	sch := NewScheduler(svc, 10*time.Millisecond, Options{Source: "config"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	sch.Run(ctx)
	// 350ms / 100ms ≈ 3 轮；允许少量余量
	if got := count.Load(); got > 5 {
		t.Fatalf("★ 执行了 %d 轮，说明轮次在堆积（单轮 100ms、间隔 10ms 应约 3 轮）", got)
	}
}

// TestSchedulerDescribe 描述文本。
func TestSchedulerDescribe(t *testing.T) {
	sch := NewScheduler(&Service{}, time.Hour, Options{Keep: 7}, nil)
	got := sch.Describe()
	if got == "" || got == "未启用" {
		t.Fatalf("应返回描述，实际 %q", got)
	}
}
