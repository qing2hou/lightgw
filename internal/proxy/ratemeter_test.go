package proxy

import "testing"

// 注入时钟的确定性测试：窗口平均、换槽清零、静止归零。
func TestRateMeterSlidingWindow(t *testing.T) {
	var r rateMeter
	cur := int64(1000)
	r.now = func() int64 { return cur }

	// 第 1 秒写 1000B：窗口均摊 1000/10 = 100 B/s
	r.Add(1000)
	if got := r.Rate(); got != 100 {
		t.Fatalf("写 1000B 后窗口速率应为 100 B/s，实际 %d", got)
	}

	// 同秒再写 1000B：2000/10 = 200
	r.Add(1000)
	if got := r.Rate(); got != 200 {
		t.Fatalf("同秒累计 2000B 应为 200 B/s，实际 %d", got)
	}

	// 下一秒写 3000B：5000/10 = 500
	cur++
	r.Add(3000)
	if got := r.Rate(); got != 500 {
		t.Fatalf("+1s 写 3000B 应为 500 B/s，实际 %d", got)
	}

	// 静止 9 秒后读：此刻第 2 秒距 now 9 秒仍在窗口，第 1 秒距 now 10 秒
	// 恰好滑出（advance 以 now-stamp 差值清槽，边界为本槽出窗）
	cur += 9
	if got := r.Rate(); got != 300 {
		t.Fatalf("静止 9 秒后仅第 2 秒的 3000B 在窗，应为 300 B/s，实际 %d", got)
	}

	// 再过 2 秒（超过窗口）：全部衰减为 0
	cur += 2
	if got := r.Rate(); got != 0 {
		t.Fatalf("超过窗口后速率应衰减为 0，实际 %d", got)
	}
}

// 环形复用：跨一个整圈后旧槽被正确覆盖。
func TestRateMeterRingWrap(t *testing.T) {
	var r rateMeter
	cur := int64(5000)
	r.now = func() int64 { return cur }

	r.Add(10000) // 5000s 槽：10000
	cur += 10    // 5010s：5000s 槽被 advance 清零路径覆盖前先清
	r.Add(5000)  // 5010s 槽：5000
	if got := r.Rate(); got != 500 {
		t.Fatalf("跨窗口写入后应为 500 B/s，实际 %d", got)
	}
	cur += 11 // 5021s：5010 槽也出窗
	if got := r.Rate(); got != 0 {
		t.Fatalf("全部出窗后应为 0，实际 %d", got)
	}
}

// 并发安全：多 goroutine 同时 Add + Rate 不崩溃、总和守恒。
func TestRateMeterConcurrent(t *testing.T) {
	var r rateMeter
	const workers = 16
	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				r.Add(10)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < workers; i++ {
		<-done
	}
	// 全部写入同一秒：16000B / 10s = 1600 B/s
	if got := r.Rate(); got != 1600 {
		t.Fatalf("并发 16000B 同秒写入应得 1600 B/s，实际 %d", got)
	}
}
