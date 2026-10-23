package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/audit"
	"haproxyweb/internal/config"
	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
	"haproxyweb/internal/trafficlog"
)

func newBackupHandlers(t *testing.T) (*handlers, *gorm.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "t.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.ForwardRule{}, &model.TrafficLog{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	tlog := trafficlog.New(db, trafficlog.Options{RetentionDays: 1})
	t.Cleanup(func() { tlog.Close() })
	auditW := audit.New(db, 90)
	t.Cleanup(func() { auditW.Close() })
	mgr := proxy.NewManager(db, tlog, 8080, proxy.Options{})
	t.Cleanup(func() { mgr.StopAll() })
	cfg := &config.Config{}
	cfg.Web.Listen = ":8080"
	cfg.Web.DataDir = dir
	return &handlers{Deps{DB: db, Audit: auditW, TLog: tlog, Mgr: mgr, Cfg: cfg, Version: "test"}}, db
}

func callHandler(h *handlers, method, path string, body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	c.Request = req
	switch method {
	case http.MethodGet:
		if path == "/api/rules/export" {
			h.exportRules(c)
		} else {
			h.backupDB(c)
		}
	case http.MethodPost:
		h.importRules(c)
	}
	return w
}

func countRules(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.ForwardRule{}).Count(&n).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	return n
}

// 导出 → 清库 → 导入（merge）应完整还原规则。
func TestExportImportRoundtrip(t *testing.T) {
	h, db := newBackupHandlers(t)
	src := model.ForwardRule{
		Name: "MySQL", Protocol: model.ProtocolTCP, ListenAddr: ":13306",
		TargetAddr: "10.0.0.5:3306", AclMode: model.AclModeBlacklist,
		DenyList: `["1.2.3.4"]`, UploadLimitKBps: 0, MaxConns: 100, IdleTimeoutSec: 60,
	}
	if err := db.Create(&src).Error; err != nil {
		t.Fatalf("建规则失败: %v", err)
	}

	// 导出
	w := callHandler(h, http.MethodGet, "/api/rules/export", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("导出状态码 %d: %s", w.Code, w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); cd == "" {
		t.Error("导出应带附件头")
	}
	var exported struct {
		Rules []model.ForwardRule `json:"rules"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &exported); err != nil {
		t.Fatalf("导出内容非法: %v", err)
	}
	if len(exported.Rules) != 1 || exported.Rules[0].Name != "MySQL" {
		t.Fatalf("导出内容不符: %+v", exported)
	}

	// 清库后导入
	if err := db.Where("id > 0").Delete(&model.ForwardRule{}).Error; err != nil {
		t.Fatalf("清库失败: %v", err)
	}
	w = callHandler(h, http.MethodPost, "/api/rules/import?mode=merge", w.Body.Bytes())
	if w.Code != http.StatusOK {
		t.Fatalf("导入状态码 %d: %s", w.Code, w.Body.String())
	}
	var result struct {
		Total    int `json:"total"`
		Imported int `json:"imported"`
		Failed   int `json:"failed"`
		Items    []struct {
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("导入响应非法: %v", err)
	}
	if result.Total != 1 || result.Imported != 1 || result.Failed != 0 || result.Items[0].Status != "imported" {
		t.Fatalf("导入结果不符: %+v", result)
	}

	var restored model.ForwardRule
	if err := db.First(&restored).Error; err != nil {
		t.Fatalf("导入的规则不存在: %v", err)
	}
	if restored.Name != src.Name || restored.ListenAddr != src.ListenAddr ||
		restored.TargetAddr != src.TargetAddr || restored.DenyList != src.DenyList ||
		restored.UploadLimitKBps != src.UploadLimitKBps || restored.IdleTimeoutSec != src.IdleTimeoutSec {
		t.Errorf("还原内容不符: got %+v want %+v", restored, src)
	}
	if restored.LastError != "" {
		t.Errorf("last_error 不应导出: %q", restored.LastError)
	}
}

// merge 导入：同协议同端口的规则应跳过并逐条报告。
func TestImportMergeConflictSkip(t *testing.T) {
	h, db := newBackupHandlers(t)
	port := freePortForTest(t)
	rules := []ruleInput{
		{Name: "A", Protocol: "tcp", ListenAddr: ":" + strconv.Itoa(port), TargetAddr: "10.0.0.1:80", Enabled: true},
		{Name: "B", Protocol: "tcp", ListenAddr: ":" + strconv.Itoa(port), TargetAddr: "10.0.0.2:80", Enabled: true},
	}
	body, _ := json.Marshal(map[string]any{"rules": rules})
	w := callHandler(h, http.MethodPost, "/api/rules/import?mode=merge", body)
	var result struct {
		Imported int `json:"imported"`
		Skipped  int `json:"skipped"`
		Items    []struct {
			Index  int    `json:"index"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("响应非法: %v", err)
	}
	if result.Imported != 1 || result.Skipped != 1 {
		t.Fatalf("应导入 1 条跳过 1 条: %+v", result)
	}
	if result.Items[1].Status != "skipped" {
		t.Errorf("第二条应 skipped: %+v", result.Items)
	}
	if countRules(t, db) != 1 {
		t.Errorf("库中应只有 1 条规则")
	}
}

// dry_run：只校验不落库。
func TestImportDryRun(t *testing.T) {
	h, db := newBackupHandlers(t)
	rules := []ruleInput{
		{Name: "OK", Protocol: "tcp", ListenAddr: ":13401", TargetAddr: "10.0.0.1:80", Enabled: false},
		{Name: "", Protocol: "tcp", ListenAddr: ":13402", TargetAddr: "10.0.0.1:80", Enabled: false},
	}
	body, _ := json.Marshal(rules)
	w := callHandler(h, http.MethodPost, "/api/rules/import?dry_run=true", body)
	var result struct {
		DryRun   bool `json:"dry_run"`
		Imported int  `json:"imported"`
		Failed   int  `json:"failed"`
		Items    []struct {
			Status string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("响应非法: %v", err)
	}
	if !result.DryRun || result.Imported != 1 || result.Failed != 1 {
		t.Fatalf("dry_run 结果不符: %+v", result)
	}
	if result.Items[0].Status != "would_import" || result.Items[1].Status != "invalid" {
		t.Errorf("条目状态不符: %+v", result.Items)
	}
	if countRules(t, db) != 0 {
		t.Error("dry_run 不应写入任何规则")
	}
}

// replace 导入：清空现有规则后导入新集合。
func TestImportReplace(t *testing.T) {
	h, db := newBackupHandlers(t)
	if err := db.Create(&model.ForwardRule{Name: "旧规则", Protocol: "tcp", ListenAddr: ":13501", TargetAddr: "10.0.0.9:80"}).Error; err != nil {
		t.Fatalf("建旧规则失败: %v", err)
	}
	rules := []ruleInput{{Name: "新规则", Protocol: "udp", ListenAddr: ":13502", TargetAddr: "10.0.0.8:53", Enabled: false}}
	body, _ := json.Marshal(map[string]any{"rules": rules})
	w := callHandler(h, http.MethodPost, "/api/rules/import?mode=replace", body)
	var result struct {
		Imported int `json:"imported"`
		Skipped  int `json:"skipped"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("响应非法: %v", err)
	}
	if result.Imported != 1 || result.Skipped != 0 {
		t.Fatalf("replace 结果不符: %+v", result)
	}
	var names []string
	db.Model(&model.ForwardRule{}).Pluck("name", &names)
	if len(names) != 1 || names[0] != "新规则" {
		t.Fatalf("replace 后应只剩新规则: %v", names)
	}
}

// 全库快照：下载内容应是可打开的 SQLite，且包含规则数据。
func TestBackupDB(t *testing.T) {
	h, db := newBackupHandlers(t)
	if err := db.Create(&model.ForwardRule{Name: "S", Protocol: "tcp", ListenAddr: ":13601", TargetAddr: "10.0.0.1:80"}).Error; err != nil {
		t.Fatalf("建规则失败: %v", err)
	}
	w := callHandler(h, http.MethodGet, "/api/backup/db", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("快照状态码 %d: %s", w.Code, w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); cd == "" {
		t.Error("快照应带附件头")
	}
	// 快照文件可打开且含数据
	snapPath := filepath.Join(t.TempDir(), "snap.db")
	if err := os.WriteFile(snapPath, w.Body.Bytes(), 0600); err != nil {
		t.Fatalf("写快照失败: %v", err)
	}
	snap, err := gorm.Open(sqlite.Open(snapPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("快照无法打开: %v", err)
	}
	var n int64
	if err := snap.Model(&model.ForwardRule{}).Count(&n).Error; err != nil {
		t.Fatalf("快照缺 forward_rules 表: %v", err)
	}
	if n != 1 {
		t.Errorf("快照应含 1 条规则，实际 %d", n)
	}
}

func freePortForTest(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("借用端口失败: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
