package caps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"golang.org/x/sys/unix"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ConntrackProbe 尝试打开 NETLINK_NETFILTER 并订阅 conntrack 多播组。
//
// 为什么只「打开并订阅」而不真收事件：真收事件要等流量，可能一直阻塞。
// 订阅成功已经证明了两件事：① 有 nf_conntrack 模块 ② 有权限加入该多播组。
// 这两条正是本项要验的。
func ConntrackProbe(ctx context.Context) error {
	// 用 raw syscall 而不是 netlink 库：只需要 socket + setsockopt，
	// 引库反而多一层。
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("创建 NETLINK_NETFILTER 套接字失败（缺 nf_conntrack 模块或 CAP_NET_ADMIN）: %w", err)
	}
	defer unix.Close(fd)

	// NFNLGRP_CONNTRACK_NEW = 1（组号从 1 开始）
	const grpNew = 1
	if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, grpNew); err != nil {
		return fmt.Errorf("订阅 conntrack NEW 多播组失败（缺 nf_conntrack 模块或 CAP_NET_ADMIN）: %w", err)
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("探测被取消: %w", ctx.Err())
	default:
	}
	return nil
}

// SqliteWALProbe 在临时目录打开一个库并把 journal_mode 设成 WAL，
// 然后**读回**验证。
//
// 为什么必须读回：某些文件系统（如部分网络 FS）会忽略 WAL 设置并
// 静默回落 delete 模式。只看 Exec 是否报错会漏掉这个降级。
func SqliteWALProbe(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "haweb-caps-")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "wal-probe.db")
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return fmt.Errorf("打开临时库失败: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("获取底层连接失败: %w", err)
	}
	defer sqlDB.Close()

	if err := db.Exec("PRAGMA journal_mode = WAL").Error; err != nil {
		return fmt.Errorf("设置 WAL 失败: %w", err)
	}
	var mode string
	if err := db.Raw("PRAGMA journal_mode").Scan(&mode).Error; err != nil {
		return fmt.Errorf("读回 journal_mode 失败: %w", err)
	}
	if mode != "wal" {
		return fmt.Errorf("WAL 未生效（读回 %q，应为 \"wal\"）；该文件系统可能不支持共享内存", mode)
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("探测被取消: %w", ctx.Err())
	default:
	}
	return nil
}

// DefaultProber 返回生产用的探测后端。
func DefaultProber() Prober { return realProber{} }

// realProber 是真实现。
type realProber struct{}

func (realProber) ProbeNftables(ctx context.Context) error  { return NftProbe(ctx) }
func (realProber) ProbeConntrack(ctx context.Context) error { return ConntrackProbe(ctx) }
func (realProber) ProbeTc(ctx context.Context) error        { return TcProbe(ctx) }
func (realProber) ProbeIfb(ctx context.Context) error       { return IfbProbe(ctx) }
func (realProber) ProbeSqliteWAL(ctx context.Context) error { return SqliteWALProbe(ctx) }
