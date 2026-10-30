package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"haproxyweb/internal/adapter/backup"
	"haproxyweb/internal/api"
	"haproxyweb/internal/audit"
	"haproxyweb/internal/auth"
	"haproxyweb/internal/config"
	"haproxyweb/internal/model"
	"haproxyweb/internal/platform/caps"
	"haproxyweb/internal/proxy"
	"haproxyweb/internal/store"
	"haproxyweb/internal/trafficlog"
)

// Options 是启动参数。
type Options struct {
	ConfigPath string
	CheckOnly  bool
	Version    string
	WebAssets  fs.FS
}

// Run 是完整的启动流程（S5 DoD：main.go ≤ 100 行，装配逻辑搬到这里）。
//
// 顺序（技术方案 §9.3）：
// 加载配置 → 建数据目录 → 恢复继承监听 → 打开库 → 探测能力 →
// 建引擎 → 启 HTTP → 启信号处理。
//
// 与旧 main.go 的差异只有两处：
//  1. 增加了能力探测（caps.Probe），结果打印在启动横幅里——
//     **缺失必须在启动时可见**（§9.2），不能只写日志
//  2. 参数从命令行 flag 改成 Options（可被测试直接构造）
//
// 其余逻辑（含 SIGHUP 热加载、SIGUSR2 升级、优雅关闭序列）**行为不变**。
func Run(opt Options) error {
	cfg, err := config.Load(opt.ConfigPath)
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}
	// 数据目录含 SQLite 与 JWT 密钥，仅属主可访问
	if err := os.MkdirAll(cfg.Web.DataDir, 0700); err != nil {
		return fmt.Errorf("创建数据目录失败: %w", err)
	}

	// 双进程零中断升级：子进程从环境变量还原父进程传递的监听 fd
	var inherited *proxy.InheritedListeners
	if os.Getenv(proxy.EnvUpgradeChild) == "1" {
		var err error
		inherited, err = proxy.UpgradeInheritedFromEnv()
		if err != nil {
			return fmt.Errorf("升级子进程继承监听失败: %w", err)
		}
	}

	db, err := store.Open(cfg.Web.DataDir)
	if err != nil {
		return fmt.Errorf("初始化数据库失败: %w", err)
	}

	// -check：校验配置与数据库后退出，供升级脚本在替换二进制后、启动前调用
	if opt.CheckOnly {
		var rules, users int64
		_ = db.Model(&model.ForwardRule{}).Count(&rules)
		_ = db.Model(&model.User{}).Count(&users)
		probe := filepath.Join(cfg.Web.DataDir, ".check-tmp")
		if err := os.WriteFile(probe, []byte("ok"), 0600); err != nil {
			log.Fatalf("数据目录不可写: %v", err)
		}
		_ = os.Remove(probe)
		tlsState := "关闭（明文 HTTP）"
		if cfg.TLSEnabled() {
			tlsState = "启用"
		}
		fmt.Printf("配置校验通过\n  监听地址: %s\n  数据目录: %s（可写）\n  数据库: OK（规则 %d 条 / 用户 %d 个，schema 已就绪）\n  TLS: %s\n",
			cfg.Web.Listen, cfg.Web.DataDir, rules, users, tlsState)
		// -check 在校验完配置与库后退出，**不做能力探测**。
		// 理由：这个模式会在替换二进制后、正式启动前由升级脚本调用，
		// 常见于无 CAP_NET_ADMIN 的校验环境（CI、容器、非 root）。
		// 把能力探测放进来会让「配置没问题」被误判成「无法启动」。
		return nil
	}

	// 能力探测（技术方案 §9.2）：**缺失必须在启动输出里可见**。
	// 不阻断启动，但 nftables 缺失会拒绝——数据面完全不能工作的进程不该跑起来。
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 15*time.Second)
	capsSnap := caps.Probe(probeCtx, caps.DefaultProber())
	probeCancel()
	if err := capsSnap.Critical(); err != nil {
		return err
	}
	for _, w := range capsSnap.Warnings() {
		log.Printf("[caps] 降级: %s", w)
	}

	authSvc, err := auth.New(cfg.Web.DataDir, db)
	if err != nil {
		return fmt.Errorf("初始化认证服务失败: %w", err)
	}

	tlog := trafficlog.New(db, trafficlog.Options{
		RetentionDays: cfg.Web.LogRetentionDays,
		MaxDiskMB:     cfg.Web.LogMaxDiskMB,
		WatermarkPct:  cfg.Web.LogDiskWatermarkPc,
		DataDir:       cfg.Web.DataDir,
	})
	auditW := audit.New(db, cfg.Web.AuditRetentionDays)

	mgr := proxy.NewManager(db, tlog, cfg.ListenPort(), BuildProxyOptions(cfg))
	// 实例 ID：让「本实例装的 nft 规则」可以被证明。
	// 事故后修复（方案 A）：对账只认本 ID 的规则，别人的（含旧格式）一律不碰。
	// 加载失败是**致命**的——没有实例 ID 就无法安全对账，宁可拒绝启动。
	instID, err := proxy.LoadOrCreateInstanceID(cfg.Web.DataDir)
	if err != nil {
		return fmt.Errorf("加载实例标识失败: %w", err)
	}
	if err := mgr.SetInstanceID(instID); err != nil {
		return fmt.Errorf("设置实例标识失败: %w", err)
	}
	log.Printf("[proxy] 实例标识: %s（nft 对账只处理本实例的规则）", instID)
	if inherited != nil {
		mgr.AdoptListeners(inherited)
	}
	if err := mgr.StartAll(); err != nil {
		log.Printf("加载转发规则失败: %v", err)
	}
	// 后端健康检查：每分钟对运行中的 TCP 规则做一次连接探测（启动时立即执行一轮）
	mgr.StartHealthChecks()
	mgr.StartSnatPolling() // snat 内核计数轮询（iptables 计数 → 速率/统计）

	// 定时备份（若配置了目标与间隔）。失败只记日志，不影响主流程。
	startBackupScheduler(cfg, opt.Version)

	var webFS fs.FS = opt.WebAssets
	deps := api.Deps{
		DB:      db,
		Auth:    authSvc,
		Audit:   auditW,
		TLog:    tlog,
		Mgr:     mgr,
		Cfg:     cfg,
		Version: opt.Version,
		// 能力快照：/api/status 与 /api/capabilities 的数据源（§9.2）
		Caps: &capsSnap,
	}
	r, err := api.NewRouter(deps, webFS)
	if err != nil {
		return fmt.Errorf("初始化 Web 服务失败: %w", err)
	}

	var webLn net.Listener
	if inherited != nil && inherited.Web != nil {
		webLn = inherited.Web
		log.Printf("[upgrade] 已接管父进程的管理后台监听")
	} else {
		webLn, err = net.Listen("tcp", cfg.Web.Listen)
		if err != nil {
			return fmt.Errorf("监听 %s 失败: %w", cfg.Web.Listen, err)
		}
	}
	mgr.SetWebListener(webLn)

	srv := &http.Server{
		Handler: r,
		// 管理面超时：防止慢速攻击（slowloris 变体）挂住连接耗尽句柄。
		// WriteTimeout 需覆盖最慢响应（快照下载/规则导入），IdleTimeout 释放
		// 空闲 keep-alive 连接。pprof 长响应（trace/profile）由 Handler 内
		// 自身的 http.Server 无关——gin handler 写响应时 WriteTimeout 生效，
		// 故取值留足余量。
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}

	scheme := "http"
	if cfg.TLSEnabled() {
		scheme = "https"
	}
	fmt.Printf("========================================\n")
	fmt.Printf(" 轻量专线网关 已启动 (版本 %s)\n", opt.Version)
	fmt.Printf(" 管理后台: %s://%s\n", scheme, cfg.Web.Listen)
	fmt.Printf(" 数据目录: %s\n", cfg.Web.DataDir)
	fmt.Printf(" 能力: nft=%v conntrack=%v tc=%v ifb=%v per_src=%v wal=%v\n",
		capsSnap.Nftables.Available, capsSnap.Conntrack.Available,
		capsSnap.Tc.Available, capsSnap.Ifb.Available,
		capsSnap.PerSrcLimit.Available, capsSnap.SqliteWAL.Available)
	for _, w := range capsSnap.Warnings() {
		fmt.Printf(" [警告] %s\n", w)
	}
	fmt.Printf("========================================\n")
	if !cfg.TLSEnabled() {
		if cfg.Web.AllowInsecure {
			log.Printf("[web] 警告：allow_insecure 已启用且未配置 TLS，管理后台为明文 HTTP，仅限隔离内网/临时调试使用")
		} else {
			log.Printf("[web] 提示：当前为回环明文监听（仅本机可访问）；对外监听必须配置 TLS（web.cert_file / web.key_file）")
		}
	}

	// SIGHUP 热加载：重新读取配置文件，tuning/保留期/可信代理/webhook 即时生效；
	// 监听地址、数据目录、证书属于连接级参数，变更后提示需重启进程
	lastApplied := *cfg
	applyReload := func() {
		cfg2, err := config.Load(opt.ConfigPath)
		if err != nil {
			log.Printf("[reload] 配置重载失败，保留当前配置: %v", err)
			return
		}
		var needRestart []string
		if cfg2.Web.Listen != lastApplied.Web.Listen {
			needRestart = append(needRestart, "web.listen")
		}
		if cfg2.Web.DataDir != lastApplied.Web.DataDir {
			needRestart = append(needRestart, "web.data_dir")
		}
		if cfg2.Web.CertFile != lastApplied.Web.CertFile || cfg2.Web.KeyFile != lastApplied.Web.KeyFile {
			needRestart = append(needRestart, "web.cert_file/key_file")
		}
		if !slices.Equal(cfg2.Web.TrustedProxies, lastApplied.Web.TrustedProxies) {
			tp := cfg2.Web.TrustedProxies
			if len(tp) == 0 {
				tp = nil
			}
			if err := r.SetTrustedProxies(tp); err != nil {
				log.Printf("[reload] 可信代理更新失败: %v", err)
			} else {
				log.Printf("[reload] 可信代理已更新（%d 项）", len(cfg2.Web.TrustedProxies))
			}
		}
		tlog.SetRetention(cfg2.Web.LogRetentionDays)
		tlog.SetRotation(cfg2.Web.LogMaxDiskMB, cfg2.Web.LogDiskWatermarkPc)
		auditW.SetRetention(cfg2.Web.AuditRetentionDays)
		mgr.ApplyOptions(BuildProxyOptions(cfg2))
		// 记录已热应用的字段供下次 diff（handlers 持有的 cfg 不动，避免数据竞争）
		lastApplied.Web.LogRetentionDays = cfg2.Web.LogRetentionDays
		lastApplied.Web.LogMaxDiskMB = cfg2.Web.LogMaxDiskMB
		lastApplied.Web.LogDiskWatermarkPc = cfg2.Web.LogDiskWatermarkPc
		lastApplied.Web.AuditRetentionDays = cfg2.Web.AuditRetentionDays
		lastApplied.Web.HealthWebhookURL = cfg2.Web.HealthWebhookURL
		lastApplied.Tuning = cfg2.Tuning
		if len(needRestart) > 0 {
			log.Printf("[reload] 配置已热加载；以下参数需重启进程生效: %s", strings.Join(needRestart, ", "))
		} else {
			log.Printf("[reload] 配置已热加载并全部生效")
		}
	}
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			log.Printf("收到 SIGHUP，开始重载配置……")
			applyReload()
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		if cfg.TLSEnabled() {
			serveErr <- srv.ServeTLS(webLn, cfg.Web.CertFile, cfg.Web.KeyFile)
		} else {
			serveErr <- srv.Serve(webLn)
		}
	}()

	// sd_notify：Type=notify 单元需要 READY=1 才算启动完成。
	// 子进程在 READY 之前先声明 MAINPID（避免 systemd 仍绑定着已退出的旧主进程），
	// 随后 READY=1 + 再次 MAINPID 巩固；父进程（升级中）仅声明新 MAINPID。
	if inherited != nil {
		SDNotify("MAINPID=" + strconv.Itoa(os.Getpid()))
	} else {
		SDNotify("READY=1\nMAINPID=" + strconv.Itoa(os.Getpid()))
	}

	// 子进程模式：管理后台与转发监听均已就绪，通知 systemd 与父进程
	if inherited != nil {
		if v := os.Getenv("HAWEB_UPGRADE_SYNC_FD"); v != "" {
			if off, err := strconv.Atoi(v); err == nil {
				if f := os.NewFile(uintptr(3+off), "upgrade-sync"); f != nil {
					_, _ = f.WriteString("ready")
					_ = f.Close()
				}
			}
		}
	}

	// SIGUSR2 双进程零中断升级：新进程继承监听接管新连接，
	// 本进程继续服务存量连接直到自然结束（详见 README「升级与维护窗口」）
	upgrading := atomic.Bool{}
	usr2 := make(chan os.Signal, 1)
	signal.Notify(usr2, syscall.SIGUSR2)
	go func() {
		for range usr2 {
			if !upgrading.CompareAndSwap(false, true) {
				log.Printf("[upgrade] 已有升级在进行，忽略本次信号")
				continue
			}
			if err := UpgradeProcess(opt.ConfigPath, mgr, webLn, tlog, auditW); err != nil {
				upgrading.Store(false)
				log.Printf("[upgrade] 零中断升级失败（继续使用当前进程）: %v", err)
				continue
			}
			os.Exit(0) // 存量连接已排空、日志已落库（upgradeProcess 内完成）
		}
	}()

	// shutdown 统一的退出清理序列：先停 Web 接入，再排空转发连接，最后落库日志。
	// 顺序保证 StopAll 排空期间产生的流量日志在写入器关闭前落库。
	shutdown := func(cause string) {
		log.Printf("%s，开始优雅关闭……", cause)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("Web 服务关闭超时，强制关闭: %v", err)
			_ = srv.Close()
		}
		mgr.StopAll()
		tlog.Close()
		auditW.Close()
	}

	for {
		select {
		case err := <-serveErr:
			if upgrading.Load() {
				// 升级交接中：监听已由新进程持有，本进程进入存量连接排空
				log.Printf("[upgrade] 监听已移交，本进程继续服务存量连接直至排空")
				continue
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				// Web 面崩溃也要走完整清理：否则转发连接被硬切、日志不落库
				shutdown(fmt.Sprintf("Web 服务异常退出: %v", err))
				return fmt.Errorf("Web 服务异常退出: %w", err)
			}
		case <-ctx.Done():
			shutdown("收到退出信号")
			log.Printf("已退出")
			return nil
		}
	}
}

// startBackupScheduler 按配置启动定时备份。未配置时是 no-op。
//
// 为什么放在启动流程里而不是单独的守护进程：
//   - 备份需要与主进程共享数据目录与库路径（配置已经解析好了）
//   - 备份失败只记日志（定时任务不该让主进程退出）
//   - 单实例串行执行（Scheduler 内部保证不重叠）
func startBackupScheduler(cfg *config.Config, version string) {
	if cfg == nil {
		return
	}
	// 配置项：backup.interval_hours / backup.keep / backup.local_dir
	// 未配置（interval<=0 或 local_dir 为空）时静默跳过——备份不是必选项。
	if cfg.Backup.IntervalHours <= 0 || cfg.Backup.LocalDir == "" {
		return
	}
	interval := time.Duration(cfg.Backup.IntervalHours) * time.Hour
	sink, err := backup.NewLocalSink(cfg.Backup.LocalDir)
	if err != nil {
		log.Printf("[backup] 本地备份目标初始化失败，定时备份未启用: %v", err)
		return
	}
	dbPath := filepath.Join(cfg.Web.DataDir, "config.db")
	svc := backup.New(dbPath, cfg.Web.DataDir, func(ctx context.Context, dest string) error {
		// VACUUM INTO 由调用方注入：本包不 import gorm。
		// 这里用一个独立的只读连接执行，避免与主库的长事务互相阻塞。
		gdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			return fmt.Errorf("打开配置库失败: %w", err)
		}
		sqlDB, err := gdb.DB()
		if err != nil {
			return fmt.Errorf("获取底层连接失败: %w", err)
		}
		defer sqlDB.Close()
		if err := gdb.Exec("VACUUM INTO ?", dest).Error; err != nil {
			return fmt.Errorf("VACUUM INTO 失败: %w", err)
		}
		return nil
	}, sink)

	sch := backup.NewScheduler(svc, interval, backup.Options{
		Keep:   cfg.Backup.Keep,
		Source: "config",
	}, nil)
	if sch == nil {
		return
	}
	log.Printf("[backup] 定时备份已启用: %s", sch.Describe())
	go sch.Run(context.Background())
}
