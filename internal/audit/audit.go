package audit

import (
	"log"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"haproxyweb/internal/model"
)

// Writer 操作审计异步写入器。channel 满时丢弃并计数，不阻塞业务请求。
type Writer struct {
	ch      chan model.AuditLog
	done    chan struct{}
	stopped chan struct{}
	dropped atomic.Int64

	retention       atomic.Int32 // 保留天数，0 = 永久保留（SIGHUP 可热更）
	cleanupFailures atomic.Int64
}

func New(db *gorm.DB, retentionDays int) *Writer {
	w := &Writer{
		ch:      make(chan model.AuditLog, 256),
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

// Record 记录一条操作审计。detail 为 JSON 字符串，可为空。
func (w *Writer) Record(username, action, detail, ip string) {
	select {
	case w.ch <- model.AuditLog{Username: username, Action: action, Detail: detail, IP: ip, CreatedAt: time.Now()}:
	default:
		w.dropped.Add(1)
	}
}

// Dropped 返回因队列满被丢弃的审计条数。
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

// cleanup 按保留天数删除过期审计并回收 WAL 空间；启动时先执行一次，之后每小时一次。
// 清理失败计数并记日志，绝不静默。
func (w *Writer) cleanup(db *gorm.DB) {
	run := func() {
		days := int(w.retention.Load())
		if days <= 0 {
			return
		}
		cutoff := time.Now().AddDate(0, 0, -days)
		res := db.Where("created_at < ?", cutoff).Delete(&model.AuditLog{})
		if res.Error != nil {
			w.cleanupFailures.Add(1)
			log.Printf("[audit] 保留期清理失败: %v", res.Error)
			return
		}
		if res.RowsAffected > 0 {
			log.Printf("[audit] 已清理 %d 条过期审计", res.RowsAffected)
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

// Close 停止写入并落库残余审计后返回，进程退出前调用；只能调用一次。
func (w *Writer) Close() {
	close(w.done)
	<-w.stopped
}

func (w *Writer) run(db *gorm.DB) {
	defer close(w.stopped)
	batch := make([]model.AuditLog, 0, 64)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := db.Create(&batch).Error; err != nil {
			log.Printf("[audit] 落库失败，丢失 %d 条审计: %v", len(batch), err)
		}
		batch = batch[:0]
	}
	absorb := func(l model.AuditLog) {
		batch = append(batch, l)
		if len(batch) >= 64 {
			flush()
		}
	}
	ticker := time.NewTicker(2 * time.Second)
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
