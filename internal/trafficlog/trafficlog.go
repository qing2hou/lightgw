package trafficlog

import (
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"gorm.io/gorm"

	"haproxyweb/internal/model"
)

// Writer 流量日志异步批量落库 + 三档自动轮转：
//  1. 时间维度：按保留天数删除过期行（传统清理）
//  2. 容量维度：库文件超过 maxDiskMB 时按时间序淘汰最老行（自动轮转，
//     与保留天数取交集——写入速率暴增时未过期也会被轮转，防打爆）
//  3. 水位维度：数据目录所在卷使用率超过 watermarkPct 时紧急淘汰最老行
//     （兜底：卷被其他文件占满时日志让路）
//
// channel 满时丢弃并计数，转发路径绝不因写日志而阻塞。
type Writer struct {
	ch              chan model.TrafficLog
	done            chan struct{}
	stopped         chan struct{}
	dropped         atomic.Int64
	retention       atomic.Int32 // 保留天数（SIGHUP 可热更）
	maxDiskMB       atomic.Int32 // 库文件轮转上限 MB，0 = 不限（SIGHUP 可热更）
	watermarkPct    atomic.Int32 // 数据卷使用率水位 %，超限紧急淘汰
	cleanupFailures atomic.Int64
	rotated         atomic.Int64 // 累计因容量/水位轮转删除的行数
	dbPath          string       // 库主文件路径（容量轮转的大小观测对象）
	dataDir         string       // 数据目录（水位观测的挂载点）
}

// Options Writer 构造参数。
type Options struct {
	RetentionDays int // 保留天数，<=0 = 30
	MaxDiskMB     int // 库文件轮转上限 MB，0 = 不限
	WatermarkPct  int // 数据卷水位 %，<=0 = 90
	DataDir       string // 数据目录（库文件所在；水位 + 容量观测）
}

func New(db *gorm.DB, opts Options) *Writer {
	if opts.RetentionDays <= 0 {
		opts.RetentionDays = 30
	}
	if opts.WatermarkPct <= 0 {
		opts.WatermarkPct = 90
	}
	w := &Writer{
		ch:      make(chan model.TrafficLog, 4096),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
		dbPath:  filepath.Join(opts.DataDir, "haproxyweb.db"),
		dataDir: opts.DataDir,
	}
	w.retention.Store(int32(opts.RetentionDays))
	w.maxDiskMB.Store(int32(opts.MaxDiskMB))
	w.watermarkPct.Store(int32(opts.WatermarkPct))
	go w.run(db)
	go w.cleanup(db)
	return w
}

// SetRetention 热更新保留天数（SIGHUP 重载配置）；<=0 表示永久保留。
func (w *Writer) SetRetention(days int) {
	w.retention.Store(int32(days))
}

// SetRotation 热更新容量轮转与磁盘水位（SIGHUP 重载配置）。
func (w *Writer) SetRotation(maxDiskMB, watermarkPct int) {
	if maxDiskMB >= 0 {
		w.maxDiskMB.Store(int32(maxDiskMB))
	}
	if watermarkPct > 0 && watermarkPct <= 100 {
		w.watermarkPct.Store(int32(watermarkPct))
	}
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

// Rotated 累计因容量/水位触发的轮转删除行数（healthz 观测自动轮转是否发生过）。
func (w *Writer) Rotated() int64 {
	return w.rotated.Load()
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

// cleanup 每小时执行一轮三档轮转：时间过期 → 容量上限 → 磁盘水位。
// 每轮读取最新配置（热加载即时生效）。清理失败计数并记日志，绝不静默。
func (w *Writer) cleanup(db *gorm.DB) {
	run := func() {
		w.expireByAge(db)
		// 容量档：库文件字节超限 → 按行数配额淘汰（SQLite 删除不缩文件，
		// 文件大小只作触发器与日志展示，收敛判据用行数——删后行数立即回落）
		if mb := int(w.maxDiskMB.Load()); mb > 0 && w.currentDBBytes() > int64(mb)*1024*1024 {
			w.rotateToRowsCap(db, int64(mb)*1024*1024/avgRowBytes, "容量")
		}
		// 水位档：数据卷使用率超限 → 紧急按当前行数 60% 淘汰最老
		if pct := diskUsagePct(w.dataDir); pct >= 0 && pct > int(w.watermarkPct.Load()) {
			var total int64
			if err := db.Model(&model.TrafficLog{}).Count(&total).Error; err == nil && total > 0 {
				w.rotateToRowsCap(db, total*60/100, "水位")
			}
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

// expireByAge 时间维度：删除保留期外的行 + 收缩 WAL。
func (w *Writer) expireByAge(db *gorm.DB) {
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
		_ = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error
	}
}

// avgRowBytes 行均字节估算（含索引与页开销，保守值）——MB 配额换算行数上限用。
const avgRowBytes = 512

// rotateToRowsCap 容量/水位维度：行数超 cap 时删最老 (total - cap*0.9) 行，
// 一次事务到位（删到 cap 的 90%，留缓冲避免每轮都触发）；随后 checkpoint 收缩 WAL。
// 判据用行数而非文件大小：SQLite 删除后文件不收缩（空闲页复用，增量止住），
// 文件大小永不收敛会退化成"白删轮"。
// reason 仅用于日志定位（容量/水位）。
func (w *Writer) rotateToRowsCap(db *gorm.DB, capRows int64, reason string) {
	if capRows <= 0 {
		return
	}
	var total int64
	if err := db.Model(&model.TrafficLog{}).Count(&total).Error; err != nil || total <= capRows {
		return
	}
	del := total - capRows*9/10
	if del <= 0 {
		return
	}
	// 定位第 del 老的边界时间，按时间删除（兼容 SQLite 的无子查询删除）
	var bounds []time.Time
	if err := db.Model(&model.TrafficLog{}).Order("started_at ASC").Offset(int(del - 1)).Limit(1).
		Pluck("started_at", &bounds).Error; err != nil || len(bounds) == 0 {
		return
	}
	res := db.Where("started_at <= ?", bounds[0]).Delete(&model.TrafficLog{})
	if res.Error != nil {
		w.cleanupFailures.Add(1)
		log.Printf("[trafficlog] %s轮转删除失败: %v", reason, res.Error)
		return
	}
	w.rotated.Add(res.RowsAffected)
	_ = db.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error
	log.Printf("[trafficlog] %s轮转：行数 %d 超配额 %d，已淘汰最老 %d 条（累计 %d；库文件 %dMB，删除后空闲页复用不再增长）",
		reason, total, capRows, res.RowsAffected, w.rotated.Load(), w.currentDBBytes()/1024/1024)
}

// currentDBBytes 库主文件 + WAL 当前占用的字节数（WAL 也是磁盘消耗）。
func (w *Writer) currentDBBytes() int64 {
	var total int64
	for _, p := range []string{w.dbPath, w.dbPath + "-wal"} {
		if st, err := os.Stat(p); err == nil {
			total += st.Size()
		}
	}
	return total
}

// diskUsagePct 数据目录所在卷的使用率（%）；不可测返回 -1。
func diskUsagePct(dir string) int {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return -1
	}
	if st.Blocks == 0 {
		return -1
	}
	used := st.Blocks - st.Bfree
	return int(used * 100 / st.Blocks)
}
