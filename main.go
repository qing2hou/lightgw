package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"haproxyweb/internal/api"
	"haproxyweb/internal/audit"
	"haproxyweb/internal/auth"
	"haproxyweb/internal/config"
	"haproxyweb/internal/model"
	"haproxyweb/internal/proxy"
	"haproxyweb/internal/store"
	"haproxyweb/internal/trafficlog"
)

//go:embed all:web/dist
var distFS embed.FS

// version 由构建时 -ldflags 注入（git describe），开发态为 dev。
var version = "dev"

func main() {
	configPath := flag.String("c", "", "配置文件路径（默认 ./config.yaml）")
	checkMode := flag.Bool("check", false, "校验配置与数据库后退出（升级/改配置前使用）")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	// 数据目录含 SQLite 与 JWT 密钥，仅属主可访问
	if err := os.MkdirAll(cfg.Web.DataDir, 0700); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}

	// 双进程零中断升级：子进程从环境变量还原父进程传递的监听 fd
	var inherited *proxy.InheritedListeners
	if os.Getenv(proxy.EnvUpgradeChild) == "1" {
		var err error
		inherited, err = proxy.UpgradeInheritedFromEnv()
		if err != nil {
			log.Fatalf("升级子进程继承监听失败: %v", err)
		}
	}

	db, err := store.Open(cfg.Web.DataDir)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}

	// -check：校验配置与数据库后退出，供升级脚本在替换二进制后、启动前调用
	if *checkMode {
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
		return
	}

	authSvc, err := auth.New(cfg.Web.DataDir, db)
	if err != nil {
		log.Fatalf("初始化认证服务失败: %v", err)
	}

	tlog := trafficlog.New(db, cfg.Web.LogRetentionDays)
	auditW := audit.New(db, cfg.Web.AuditRetentionDays)

	mgr := proxy.NewManager(db, tlog, cfg.ListenPort(), buildProxyOptions(cfg))
	if inherited != nil {
		mgr.AdoptListeners(inherited)
	}
	if err := mgr.StartAll(); err != nil {
		log.Printf("加载转发规则失败: %v", err)
	}
	// 后端健康检查：每分钟对运行中的 TCP 规则做一次连接探测（启动时立即执行一轮）
	mgr.StartHealthChecks()
	mgr.StartSnatPolling() // snat 内核计数轮询（iptables 计数 → 速率/统计）

	var webFS fs.FS = distFS
	deps := api.Deps{
		DB:      db,
		Auth:    authSvc,
		Audit:   auditW,
		TLog:    tlog,
		Mgr:     mgr,
		Cfg:     cfg,
		Version: version,
	}
	r, err := api.NewRouter(deps, webFS)
	if err != nil {
		log.Fatalf("初始化 Web 服务失败: %v", err)
	}

	var webLn net.Listener
	if inherited != nil && inherited.Web != nil {
		webLn = inherited.Web
		log.Printf("[upgrade] 已接管父进程的管理后台监听")
	} else {
		webLn, err = net.Listen("tcp", cfg.Web.Listen)
		if err != nil {
			log.Fatalf("监听 %s 失败: %v", cfg.Web.Listen, err)
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
	fmt.Printf(" 轻量专线网关 已启动 (版本 %s)\n", version)
	fmt.Printf(" 管理后台: %s://%s\n", scheme, cfg.Web.Listen)
	fmt.Printf(" 数据目录: %s\n", cfg.Web.DataDir)
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
		cfg2, err := config.Load(*configPath)
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
		auditW.SetRetention(cfg2.Web.AuditRetentionDays)
		mgr.ApplyOptions(buildProxyOptions(cfg2))
		// 记录已热应用的字段供下次 diff（handlers 持有的 cfg 不动，避免数据竞争）
		lastApplied.Web.LogRetentionDays = cfg2.Web.LogRetentionDays
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
		sdNotify("MAINPID=" + strconv.Itoa(os.Getpid()))
	} else {
		sdNotify("READY=1\nMAINPID=" + strconv.Itoa(os.Getpid()))
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
			if err := upgradeProcess(*configPath, mgr, webLn, tlog, auditW); err != nil {
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
				log.Fatalf("Web 服务异常退出: %v", err)
			}
		case <-ctx.Done():
			shutdown("收到退出信号")
			log.Printf("已退出")
			return
		}
	}
}

// upgradeProcess SIGUSR2 双进程零中断升级：
//  1. 将全部监听（管理后台 + 各规则）以 fd 传递给磁盘上的新二进制
//  2. 新进程接管监听并就绪后，本进程关闭监听副本、停止接入
//  3. 存量连接继续由本进程服务，全部自然结束后落库日志并退出（不强制断开）
func upgradeProcess(configPath string, mgr *proxy.Manager, webLn net.Listener, tlog *trafficlog.Writer, auditW *audit.Writer) error {
	if !mgr.AdoptsAvailable() {
		return errors.New("没有可交接的监听")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	web, tcpLns, udpConns := mgr.GatherListeners()
	fdsJSON, files, err := proxy.MarshalListeners(web, tcpLns, udpConns)
	if err != nil {
		return err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pw.Close()
	defer pr.Close()

	cmd := exec.Command(self, "-c", configPath)
	cmd.Env = append(os.Environ(), proxy.EnvUpgradeChild+"=1", proxy.EnvUpgradeFDs+"="+fdsJSON, "HAWEB_UPGRADE_SYNC_FD="+strconv.Itoa(len(files)))
	cmd.ExtraFiles = append(files, pw)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	pw.Close() // 父进程关写端：子进程提前退出时读到 EOF
	log.Printf("[upgrade] 升级子进程已启动 (pid %d)，等待其接管监听……", cmd.Process.Pid)

	ready := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		n, rerr := pr.Read(buf)
		if rerr != nil {
			ready <- rerr
		} else if string(buf[:n]) != "ready" {
			ready <- fmt.Errorf("非法就绪信号: %q", buf[:n])
		} else {
			ready <- nil
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return fmt.Errorf("子进程未就绪: %w", err)
		}
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return errors.New("子进程就绪超时（15s）")
	}

	// 子进程已接管同一 socket 的副本：本进程关闭监听副本、停止接入与探测，
	// 存量 TCP 连接继续由本进程服务直到自然结束（不强制断开）。
	// 先让 systemd 重新绑定主进程再继续——否则本进程退出时 systemd 会把
	// 整个 cgroup（含子进程与存量连接）一并回收
	mgr.StopHealthChecks()
	mgr.StopSnatPolling()
	sdNotify("MAINPID=" + strconv.Itoa(cmd.Process.Pid))
	remaining := mgr.StopAccepting()
	log.Printf("[upgrade] 子进程已接管监听，本进程继续服务 %d 条存量连接直至自然结束……", remaining)
	for mgr.EngineCounters().SessionsActive > 0 {
		time.Sleep(500 * time.Millisecond)
	}
	tlog.Close()
	auditW.Close()
	log.Printf("[upgrade] 存量连接已全部结束，日志落库完成，本进程退出")
	return nil
}

// sdNotify 向 systemd 发送就绪/主进程通知（sd_notify 协议）。
// Type=notify + NotifyAccess=all 的单元依赖它完成升级后的主进程移交；
// 非 systemd 环境（NOTIFY_SOCKET 未设置）为 no-op。
func sdNotify(state string) {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return
	}
	conn, err := net.Dial("unixgram", sock)
	if err != nil {
		log.Printf("[upgrade] sd_notify 连接失败: %v", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte(state))
}

// buildProxyOptions 从配置构建转发引擎运行参数（启动与 SIGHUP 热加载共用）。
func buildProxyOptions(cfg *config.Config) proxy.Options {
	return proxy.Options{
		MaxGlobalConns:      cfg.Tuning.MaxGlobalConns,
		TCPIdleTimeout:      time.Duration(cfg.Tuning.TCPIdleTimeoutSec) * time.Second,
		TCPDialTimeout:      time.Duration(cfg.Tuning.TCPDialTimeoutSec) * time.Second,
		UDPSessionIdle:      time.Duration(cfg.Tuning.UDPSessionIdleSec) * time.Second,
		UDPLimiterMaxWait:   time.Duration(cfg.Tuning.UDPLimiterMaxWaitMs) * time.Millisecond,
		BufferSize:          cfg.Tuning.BufferSize,
		Splice:              cfg.Tuning.Splice,
		DrainTimeout:        time.Duration(cfg.Tuning.DrainTimeoutSec) * time.Second,
		HealthCheckInterval: time.Duration(cfg.Tuning.HealthCheckIntervalSec) * time.Second,
		HealthWebhookURL:    cfg.Web.HealthWebhookURL,
		GlobalUploadKBps:    int64(cfg.Tuning.GlobalUploadKBps),
		GlobalDownloadKBps:  int64(cfg.Tuning.GlobalDownloadKBps),
		HealthLogRetentionDays: func() int {
			// -1 = 跟随流量日志保留天数
			if cfg.Tuning.HealthLogRetentionDays < 0 {
				return cfg.Web.LogRetentionDays
			}
			return cfg.Tuning.HealthLogRetentionDays
		}(),
	}
}
