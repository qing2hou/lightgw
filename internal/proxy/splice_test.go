package proxy

import (
	"bytes"
	"io"
	"testing"
	"time"

	"haproxyweb/internal/model"
	"haproxyweb/internal/ratelimit"
)

// spliceEligible：全局开关 + 规则不限速两个条件缺一不可。
func TestSpliceEligible(t *testing.T) {
	m := &Manager{}
	m.optsStore.Store(&Options{Splice: true})
	cfg := m.buildRuleConfig(model.ForwardRule{Protocol: model.ProtocolTCP})
	if !m.spliceEligible(cfg) {
		t.Error("开启 splice 且不限速时应可用")
	}

	m2 := &Manager{}
	m2.optsStore.Store(&Options{Splice: false})
	if m2.spliceEligible(cfg) {
		t.Error("全局开关关闭时不应可用")
	}

	m3 := &Manager{}
	m3.optsStore.Store(&Options{Splice: true})
	limited := m3.buildRuleConfig(model.ForwardRule{Protocol: model.ProtocolTCP, DownloadLimitKBps: 1024})
	if m3.spliceEligible(limited) {
		t.Error("限速规则不应走快路径")
	}
	if limited.limiter.Disabled() {
		t.Error("限速规则 Disabled 应为 false")
	}
	var zero ratelimit.Limiter
	if !zero.Disabled() {
		t.Error("零值 Limiter 应视为不限速")
	}
}

// 快路径计数与 EOF 语义应与慢路径一致（测试环境走 splice 或用户态回退均可）。
func TestCopyFastCountsAndEOF(t *testing.T) {
	m := &Manager{}
	m.optsStore.Store(&Options{Splice: true})
	srcC, srcS := dialPair(t)
	dstC, dstS := dialPair(t)
	go func() { _, _ = io.Copy(io.Discard, dstS) }()

	sess := m.registerSession(m.buildRuleConfig(model.ForwardRule{Protocol: model.ProtocolTCP}), "1.2.3.4", 12345, "", 0)
	payload := bytes.Repeat([]byte("f"), 256000)
	done := make(chan error, 1)
	go func() { done <- m.copyFast(dstC, srcC, sess, false) }()

	if _, err := srcS.Write(payload); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	_ = srcS.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("快路径拷贝应正常结束，实际: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("快路径拷贝未在预期时间内结束")
	}
	if got := sess.up.Load(); got != int64(len(payload)) {
		t.Fatalf("计数不符: got %d want %d", got, len(payload))
	}
}
