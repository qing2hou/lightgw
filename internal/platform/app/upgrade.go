package app

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"haproxyweb/internal/audit"
	"haproxyweb/internal/config"
	"haproxyweb/internal/proxy"
	"haproxyweb/internal/trafficlog"
)

// 本文件从旧的 main.go 搬来：双进程零中断升级、sd_notify、转发引擎参数装配。
//
// 搬家的理由（S5 DoD：main.go ≤ 100 行）：这三块逻辑与 main 的启动流程
// 无关，它们是「运行期能力」，应该能在测试里被单独引用。
// **行为一字未改**——这是纯搬迁，不是重写。

// upgradeProcess SIGUSR2 双进程零中断升级：
//  1. 将全部监听（管理后台 + 各规则）以 fd 传递给磁盘上的新二进制
//  2. 新进程接管监听并就绪后，本进程关闭监听副本、停止接入
//  3. 存量连接继续由本进程服务，全部自然结束后落库日志并退出（不强制断开）
func UpgradeProcess(configPath string, mgr *proxy.Manager, webLn net.Listener, tlog *trafficlog.Writer, auditW *audit.Writer) error {
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
	SDNotify("MAINPID=" + strconv.Itoa(cmd.Process.Pid))
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
func SDNotify(state string) {
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
func BuildProxyOptions(cfg *config.Config) proxy.Options {
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
		NFTPurgeOrphans:     cfg.Tuning.NFTPurgeOrphans,
		HealthLogRetentionDays: func() int {
			// -1 = 跟随流量日志保留天数
			if cfg.Tuning.HealthLogRetentionDays < 0 {
				return cfg.Web.LogRetentionDays
			}
			return cfg.Tuning.HealthLogRetentionDays
		}(),
	}
}
