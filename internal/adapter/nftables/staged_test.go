package nftables

import (
	"context"
	"strings"
	"testing"
)

// TestStagedHappyPath 四阶段按序推进，最终 active 槽切换。
func TestStagedHappyPath(t *testing.T) {
	e := newTestEngine(t)
	set := setWith(3)
	sess, err := e.BeginStage()
	if err != nil {
		t.Fatalf("开始会话失败: %v", err)
	}
	from, target := sess.From(), sess.Target()
	if from == target {
		t.Fatal("from 与 target 不能相同")
	}
	if err := sess.StageLoad(context.Background(), set); err != nil {
		t.Fatalf("装载失败: %v", err)
	}
	if err := sess.StageVerify(context.Background()); err != nil {
		t.Fatalf("自检失败: %v", err)
	}
	if err := sess.StageCommit(context.Background()); err != nil {
		t.Fatalf("切换失败: %v", err)
	}
	if !sess.Committed() {
		t.Fatal("提交后 Committed 应为 true")
	}
	if err := sess.StageCleanup(context.Background()); err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	// active 应切到 target
	if e.Active() != target {
		t.Fatalf("active 应为 %s，实际 %s", target, e.Active())
	}
	// dispatch 仍恒 1 条 jump
	counts, err := e.AllJumpCounts()
	if err != nil {
		t.Fatal(err)
	}
	for disp, n := range counts {
		if n != 1 {
			t.Fatalf("%s 的 jump 数应为 1，实际 %d", disp, n)
		}
	}
}

// TestStagedLoadFailureAborts 装载失败后 Abort 必须清空影子链。
func TestStagedLoadFailureAborts(t *testing.T) {
	e := newTestEngine(t)
	// 先建立一份生效配置
	if _, err := e.CommitShadow(context.Background(), setWith(2)); err != nil {
		t.Fatal(err)
	}
	activeBefore := e.Active()

	e.SetFailHooks(func(work string) error {
		if work == WorkFwd {
			return errTestLoad
		}
		return nil
	}, nil)
	sess, err := e.BeginStage()
	if err != nil {
		t.Fatalf("开始会话失败: %v", err)
	}
	err = sess.StageLoad(context.Background(), setWith(9))
	if err == nil {
		t.Fatal("装载应失败")
	}
	if !strings.Contains(err.Error(), "旧规则继续生效") {
		t.Fatalf("错误消息应说明旧规则仍生效，实际: %v", err)
	}
	// Abort 清理
	if err := sess.StageAbort(context.Background()); err != nil {
		t.Fatalf("Abort 失败: %v", err)
	}
	// active 未变，旧规则仍在
	if e.Active() != activeBefore {
		t.Fatal("失败的装载不应改变 active")
	}
	for _, work := range workChains {
		n, _ := e.ChainRuleCount(ChainName(work, activeBefore))
		if n != 2 {
			t.Fatalf("%s 旧规则应保持 2 条，实际 %d", work, n)
		}
	}
	// 影子槽必须干净
	for _, work := range workChains {
		n, _ := e.ChainRuleCount(ChainName(work, sess.Target()))
		if n != 0 {
			t.Fatalf("影子槽 %s 残留 %d 条", work, n)
		}
	}
}

// TestStagedVerifyFailureAborts 自检失败后 Abort，旧配置不受影响。
func TestStagedVerifyFailureAborts(t *testing.T) {
	e := newTestEngine(t)
	if _, err := e.CommitShadow(context.Background(), setWith(2)); err != nil {
		t.Fatal(err)
	}
	activeBefore := e.Active()

	e.SetFailHooks(nil, func(work string) error { return errTestVerify })
	sess, _ := e.BeginStage()
	if err := sess.StageLoad(context.Background(), setWith(5)); err != nil {
		t.Fatalf("装载应成功: %v", err)
	}
	if err := sess.StageVerify(context.Background()); err == nil {
		t.Fatal("自检应失败")
	}
	_ = sess.StageAbort(context.Background())
	if e.Active() != activeBefore {
		t.Fatal("自检失败不应改变 active")
	}
}

// TestStagedCommitTwiceRejected 重复提交必须被拒（防重复切换）。
func TestStagedCommitTwiceRejected(t *testing.T) {
	e := newTestEngine(t)
	sess, _ := e.BeginStage()
	_ = sess.StageLoad(context.Background(), setWith(1))
	if err := sess.StageCommit(context.Background()); err != nil {
		t.Fatalf("首次提交应成功: %v", err)
	}
	if err := sess.StageCommit(context.Background()); err == nil {
		t.Fatal("★ 重复提交必须被拒（否则会切换两次，槽位错乱）")
	}
}

// TestStagedCommitWithoutLoad 未装载就提交必须被拒。
func TestStagedCommitWithoutLoad(t *testing.T) {
	e := newTestEngine(t)
	sess, _ := e.BeginStage()
	if err := sess.StageCommit(context.Background()); err == nil {
		t.Fatal("未装载就提交应被拒")
	}
	if err := sess.StageVerify(context.Background()); err == nil {
		t.Fatal("未装载就自检应被拒")
	}
}

// TestStagedAbortAfterCommitIsNoop 已提交后 Abort 不能清掉正在服务的槽。
func TestStagedAbortAfterCommitIsNoop(t *testing.T) {
	e := newTestEngine(t)
	sess, _ := e.BeginStage()
	_ = sess.StageLoad(context.Background(), setWith(3))
	if err := sess.StageCommit(context.Background()); err != nil {
		t.Fatal(err)
	}
	active := e.Active()
	// 已提交后 Abort 应是 no-op
	if err := sess.StageAbort(context.Background()); err != nil {
		t.Fatalf("Abort 应安全返回: %v", err)
	}
	if e.Active() != active {
		t.Fatal("已提交后 Abort 不应改变 active")
	}
	// 规则必须还在（这是关键：清掉就是断网）
	for _, work := range workChains {
		n, _ := e.ChainRuleCount(ChainName(work, active))
		if n != 3 {
			t.Fatalf("★ 已提交的槽被 Abort 清掉了：%s 剩 %d 条", work, n)
		}
	}
}

// TestStagedCleanupWithoutCommit 未提交就清理必须被拒。
func TestStagedCleanupWithoutCommit(t *testing.T) {
	e := newTestEngine(t)
	sess, _ := e.BeginStage()
	if err := sess.StageCleanup(context.Background()); err == nil {
		t.Fatal("未提交就清理应被拒（会把正在服务的旧链清掉）")
	}
}

// TestBeginStageNilConn 未初始化时 BeginStage 返回 ErrNotReady。
func TestBeginStageNilConn(t *testing.T) {
	e := &Engine{}
	if _, err := e.BeginStage(); err == nil {
		t.Fatal("未初始化应报错")
	}
}

// TestStagedEquivToCommitShadow 分阶段流程与一体化 CommitShadow 结果等价。
//
// 这是「拆开导出没有改变语义」的核心证据。
func TestStagedEquivToCommitShadow(t *testing.T) {
	// 用一体化
	e1 := newTestEngine(t)
	if _, err := e1.CommitShadow(context.Background(), setWith(4)); err != nil {
		t.Fatalf("一体化失败: %v", err)
	}
	// 用分阶段
	e2 := newTestEngine(t)
	sess, _ := e2.BeginStage()
	if err := sess.StageLoad(context.Background(), setWith(4)); err != nil {
		t.Fatal(err)
	}
	if err := sess.StageVerify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sess.StageCommit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sess.StageCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 两者 active 槽与各链规则数应完全一致
	if e1.Active() != e2.Active() {
		t.Fatalf("active 不一致: %s vs %s", e1.Active(), e2.Active())
	}
	for _, work := range workChains {
		n1, _ := e1.ChainRuleCount(ChainName(work, e1.Active()))
		n2, _ := e2.ChainRuleCount(ChainName(work, e2.Active()))
		if n1 != n2 {
			t.Fatalf("%s 规则数不一致: %d vs %d", work, n1, n2)
		}
	}
}

var (
	errTestLoad   = &testErr{"模拟装载失败"}
	errTestVerify = &testErr{"模拟自检失败"}
)

type testErr struct{ msg string }

func (e *testErr) Error() string { return e.msg }
