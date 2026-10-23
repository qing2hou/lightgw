package trafficlog

import (
	"log"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"haproxyweb/internal/model"
)

// Writer 流量日志异步批量落库 + 按保留天数定时清理。
// channel 满时丢弃并计数，转发路径绝不因写日志而阻塞。
type Writer struct {
	ch              chan model.TrafficLog
	done            chan struct{}
	stopped         chan struct{}
	dropped         atomic.Int64
	retention       atomic.Int32 // 保留天数（SIGHUP 可热更）
	cleanupFailures atomic.Int64
}

func New(db *gorm.DB, retentionDays int) *Writer {
	w := &Writer{
		ch:      make(chan model.TrafficLog, 4096),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	w.retention.Store(int32(retentionDays))
	go w.run(db)
	go w.cleanup(db)
	return w
}

// SetRetention 热更新保留天数（SIGHUP 重载配置）；<=0 表示永久保留。
func (w *Writer) SetRetention(days int) {
	w.retention.Store(int32(days))
}

// Log 提交一条流量日志（非阻塞）；队列满时丢弃并计数。
func (w *Writer) Log(l model.TrafficLog) {
	select {
	case w.ch <- l:
	default:
		w.dropped.Add(1)
	}
}

// Dropped 返回因队列满被丢弃的日志条数。
func (w *Writer) Dropped() int64 {
	return w.dropped.Load()
}

// Queued 当前队列中待落库的条数（水位观测）。
func (w *Writer) Queued() int {
	return len(w.ch)
}

// CleanupFailures 保留期清理失败次数（非零说明需查日志）。
func (w *Writer) CleanupFailures() int64 {
	return w.cleanupFailures.Load()
}

// Close 停止写入并落库残余日志后返回，进程退出前调用；只能调用一次。
// 已在队列中的最后几条若与排空过程并发写入，可能不被包含在最终批次中。
func (w *Writer) Close() {
	close(w.done)
	<-w.stopped
}

func (w *Writer) run(db *gorm.DB) {
	defer close(w.stopped)
	batch := make([]model.TrafficLog, 0, 256)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := db.CreateInBatches(batch, 256).Error; err != nil {
			log.Printf("[trafficlog] 落库失败，丢失 %d 条日志: %v", len(batch), err)
		}
		batch = batch[:0]
	}
	absorb := func(l model.TrafficLog) {
		batch = append(batch, l)
		if len(batch) >= 256 {
			flush()
		}
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case l := <-w.ch:
			absorb(l)
		case <-ticker.C:
			flush()
		case <-w.done:
			for {
				select {
				case l := <-w.ch:
					absorb(l)
				default:
					flush()
					return
				}
			}
		}
	}
}

// cleanup 按保留天数删除过期流量日志并回收 WAL 空间；每小时执行一次，
// 每轮读取最新保留天数（热加载即时生效），<=0 跳过本轮。清理失败计数并记日志，绝不静默。
func (w *Writer) cleanup(db *gorm.DB) {
	run := func() {
		days := int(w.retention.Load())
		if days <= 0 {
			return
		}
		cutoff := time.Now().AddDate(0, 0, -days)
		res := db.Where("started_at < ?", cutoff).Delete(&model.TrafficLog{})
		if res.Error != nil {
			w.cleanupFailures.Add(1)
			log.Printf("[trafficlog] 保留期清理失败: %v", res.Error)
			return
		}
		if res.RowsAffected > 0 {
			log.Printf("[trafficlog] 已清理 %d 条过期流量日志", res.RowsAffected)
			// 删除后收缩 WAL，防止库文件只增不减（失败可忽略，仅影响空间回收）
			_ = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error
		}
	}
	run()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			run()
		case <-w.done:
			return
		}
	}
}
