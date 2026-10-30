package backup

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Scheduler 按固定间隔执行备份。
//
// 设计要点：
//   - 单 goroutine 串行执行，**不并发**（两个 VACUUM 同时跑会互相锁库）
//   - 失败只记日志并继续下一轮（备份失败不该让进程退出）
//   - 上一轮没跑完时跳过本轮（用 ticker + 非阻塞 select，不堆积）
//   - ctx 取消时等待当前轮完成再退出（避免半个快照文件残留）
type Scheduler struct {
	svc      *Service
	interval time.Duration
	opt      Options
	// onResult 是每轮结束后的回调（供指标/审计接入）。
	onResult func(res *Result, err error)
}

// NewScheduler 创建调度器。
//
// interval <= 0 时返回 nil（表示不启用定时备份）——调用方据此跳过启动。
func NewScheduler(svc *Service, interval time.Duration, opt Options,
	onResult func(res *Result, err error)) *Scheduler {
	if svc == nil || interval <= 0 {
		return nil
	}
	return &Scheduler{svc: svc, interval: interval, opt: opt, onResult: onResult}
}

// Run 启动调度循环，阻塞直到 ctx 取消。
func (s *Scheduler) Run(ctx context.Context) {
	if s == nil {
		return
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	// 启动时不立即跑一轮：重启风暴时多个实例同时 VACUUM 会互相锁库。
	// 等第一个 interval 周期。
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce 执行一轮备份。
func (s *Scheduler) runOnce(ctx context.Context) {
	// 单轮超时：备份卡死不能永久占住调度 goroutine。
	// 10 分钟对 100MB 级的库绰绰有余。
	rctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	res, err := s.svc.Run(rctx, s.opt)
	if err != nil {
		log.Printf("[backup] 定时备份失败: %v", err)
	} else if len(res.Failures) > 0 {
		// 部分目标失败：备份本身算成功，但要明确告警
		log.Printf("[backup] 定时备份部分失败（成功目标 %v）: %v", res.Sinks, res.Failures)
	} else {
		log.Printf("[backup] 定时备份完成: %s（%d 字节，目标 %v）",
			res.Name, res.Size, res.Sinks)
	}
	if s.onResult != nil {
		s.onResult(res, err)
	}
}

// NextDelay 返回距离下次备份的间隔（供 UI 显示）。
func (s *Scheduler) NextDelay() time.Duration {
	if s == nil {
		return 0
	}
	return s.interval
}

// Describe 返回供日志/UI 用的描述。
func (s *Scheduler) Describe() string {
	if s == nil {
		return "未启用"
	}
	return fmt.Sprintf("每 %s 备份一次，保留 %d 份", s.interval, s.opt.Keep)
}
