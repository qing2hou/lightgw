package proxy

import (
	"sync"
	"time"
)

// rateMeter 滑动窗口速率计：10 个 1 秒槽的环形缓冲，写入时把字节数记入
// 当前秒槽；读取时求全部槽之和除以窗口长度即"最近 10 秒平均速率"（B/s）。
// 语义与实现权衡：
//   - 锁保护的朴素实现而非 atomic 分槽：每次 Add 只有一次锁竞争，
//     转发热路径上 ns 级开销，远小于一次 32KB 拷贝
//   - 换槽由写入/读取方惰性推进（无后台 goroutine）；过期槽清零，
//     静止规则读到 0 而非历史残留
type rateMeter struct {
	mu          sync.Mutex
	slots       [10]int64 // 最近 10 秒的字节数，下标 = unix 秒 % 10
	stamp       int64     // 最近一次换槽对齐到的 unix 秒
	initialized bool
	now         func() int64 // 时钟，测试注入用；nil 用系统时钟
}

func (r *rateMeter) clock() int64 {
	if r.now != nil {
		return r.now()
	}
	return time.Now().Unix()
}

// advance 惰性换槽：把 stamp 之后到 now 的秒槽依次清零（那些秒没有数据）。
// 调用方持有锁。
func (r *rateMeter) advance(now int64) {
	if !r.initialized {
		r.stamp = now
		r.initialized = true
		return
	}
	delta := now - r.stamp
	if delta <= 0 {
		return
	}
	if delta >= int64(len(r.slots)) {
		// 距上次写入超过整个窗口：全部清零
		for i := range r.slots {
			r.slots[i] = 0
		}
	} else {
		for i := int64(1); i <= delta; i++ {
			r.slots[(r.stamp+i)%int64(len(r.slots))] = 0
		}
	}
	r.stamp = now
}

// Add 记录 n 字节进当前秒槽。
func (r *rateMeter) Add(n int64) {
	now := r.clock()
	r.mu.Lock()
	r.advance(now)
	r.slots[now%int64(len(r.slots))] += n
	r.mu.Unlock()
}

// Rate 返回最近窗口内的平均速率（B/s）。过期的旧槽在读取时清零。
func (r *rateMeter) Rate() int64 {
	now := r.clock()
	r.mu.Lock()
	r.advance(now)
	var sum int64
	for _, v := range r.slots {
		sum += v
	}
	r.mu.Unlock()
	return sum / int64(len(r.slots))
}
