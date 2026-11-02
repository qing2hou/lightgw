// 带宽包归属的回归（2026-11-02）。
//
// 历史缺陷（用户实际踩到）：规则表单里"加带宽包"完全无效。
//   1. ruleInput 没有 bw_group_id 字段 → 创建/更新请求里的值被静默丢弃
//   2. 更新路径把 BWGroupID 从 Select 白名单排除，还回填旧值
//   3. 前端规则表单没有带宽包选择器，只有一句"加入带宽包后由包统一配置"
// 结果：用户以为绑了包，实际 bw_group_id=0，限速永远不生效。
package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/model"
)

// newTestHandlersWithDB 造一个带独立 SQLite 的 handlers（只需 DB）。
func newTestHandlersWithDB(t *testing.T) *handlers {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "t.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.BWGroup{}, &model.ForwardRule{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	return &handlers{Deps{DB: db}}
}

// readRulesGo 读 rules.go 源码（用于源码级断言 GORM Select 白名单）。
func readRulesGo(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("读 rules.go 失败: %v", err)
	}
	return string(b)
}

// TestRuleInputCarriesBWGroupID 请求体里的 bw_group_id 必须流到 model。
func TestRuleInputCarriesBWGroupID(t *testing.T) {
	in := &ruleInput{
		Name: "bw", Protocol: model.ProtocolTCP,
		ListenAddr: ":8080", TargetAddr: "192.168.10.151:80",
		BWGroupID: 7,
	}
	r := in.toRule()
	if r.BWGroupID != 7 {
		t.Fatalf("★ toRule 丢弃了 bw_group_id：期望 7，实际 %d", r.BWGroupID)
	}
}

// TestBWGroupIDInUpdateWhitelist 更新路径的 Select 白名单必须含 BWGroupID。
//
// 这条是源码级断言：GORM 的 Select 白名单漏列 = 编辑静默丢字段
// （AGENTS.md 已记录的坑，这里又栽了一次）。
func TestBWGroupIDInUpdateWhitelist(t *testing.T) {
	body := readRulesGo(t)
	idx := strings.Index(body, "func (h *handlers) updateRule")
	if idx < 0 {
		t.Fatal("找不到 updateRule")
	}
	seg := body[idx:]
	if end := strings.Index(seg, "\nfunc "); end > 0 {
		seg = seg[:end]
	}
	if !strings.Contains(seg, `"BWGroupID"`) {
		t.Fatal("★ updateRule 的 Select 白名单缺少 BWGroupID：编辑规则时带宽包归属会被静默丢弃")
	}
	// 反向断言：不能再有"回填旧值"的写法
	if strings.Contains(seg, "rule.BWGroupID = old.BWGroupID") {
		t.Fatal("★ updateRule 仍在回填旧 BWGroupID：用户改的归属会被覆盖")
	}
}

// TestBWGroupIDValidated 绑不存在的带宽包必须 400，不能静默绑到空包上。
//
// 静默失效是最坏的结果：界面显示"已绑定"，实际引擎查库失败 → 不限速。
func TestBWGroupIDValidated(t *testing.T) {
	h := newTestHandlersWithDB(t)
	// 空库：没有任何带宽包
	in := &ruleInput{
		Name: "bw", Protocol: model.ProtocolTCP,
		ListenAddr: "192.168.10.170:18080", TargetAddr: "192.168.10.151:80",
		BWGroupID: 999,
	}
	err := in.validate(h)
	if err == nil {
		t.Fatal("★ 绑定不存在的带宽包应被拒绝，实际通过了校验")
	}
	if !strings.Contains(err.Error(), "带宽包") {
		t.Fatalf("错误消息应说明是带宽包问题，实际: %v", err)
	}
}

// TestZeroBWGroupIDAlwaysOK 不绑包（0）不受校验影响。
func TestZeroBWGroupIDAlwaysOK(t *testing.T) {
	h := newTestHandlersWithDB(t)
	in := &ruleInput{
		Name: "nobw", Protocol: model.ProtocolTCP,
		ListenAddr: "192.168.10.170:18081", TargetAddr: "192.168.10.151:80",
		BWGroupID: 0,
	}
	if err := in.validate(h); err != nil {
		t.Fatalf("不绑包应通过校验，实际: %v", err)
	}
}
