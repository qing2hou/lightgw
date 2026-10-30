// Package caps 探测运行时能力，并把结果暴露给 UI。
//
// 设计原则（技术方案 §9.2）：**能力缺失必须可见**。
// 宁可首页红条警告，也不能静默降级——「限速配了但没生效」这种故障
// 如果只写日志，运维永远不会发现。
//
// 探测方式全部是「试一下」，不看配置也不猜：
//   - nftables：建临时表再删
//   - conntrack：尝试连 netlink 多播组
//   - tc：LookPath + 试列 qdisc
//   - ifb：建临时 ifb 设备再删
//   - CAP_NET_ADMIN：由 nftables 探测的结果推导（建表需要它）
//   - sqlite WAL：PRAGMA journal_mode 读回
package caps

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Status 是单项能力的探测结果。
type Status struct {
	// Available 表示该能力可用。
	Available bool `json:"available"`
	// Detail 是人类可读的说明（成功时说「怎么验的」，失败时说「缺什么」）。
	//
	// 必须是中文且可执行：用户看到「tc 不可用」时应同时知道
	// 「装 iproute2」——所以失败时 Detail 要给出修复线索。
	Detail string `json:"detail,omitempty"`
}

// Caps 是全量能力快照。
//
// 不变量：构造后不可变。启动时探测一次，之后只读
// （能力不会在运行中变化，除了 tc/ifb 这类可以手动装的——那些需要重启）。
type Caps struct {
	Nftables    Status `json:"nftables"`
	Conntrack   Status `json:"conntrack"`
	Tc          Status `json:"tc"`
	Ifb         Status `json:"ifb"`
	CapNetAdmin Status `json:"cap_net_admin"`
	SqliteWAL   Status `json:"sqlite_wal"`
	// PerSrcLimit 表示能否按源分类限速。
	//
	// 由 Tc + Ifb 推导：缺 ifb 时上传方向只能限总额，没有每源保底。
	// 单独一项是因为 UI 要显示「每源保底是否真的生效」。
	PerSrcLimit Status `json:"per_src_limit"`
	// ProbedAt 是探测时刻（unix 秒），供 UI 显示快照时间。
	ProbedAt int64 `json:"probed_at"`
}

// Prober 是可注入的探测后端。
//
// 抽成接口的理由：真实探测需要 CAP_NET_ADMIN 与 root，CI 跑不了。
// 单测用假 Prober 验证「缺失时如何降级与提示」的逻辑。
type Prober interface {
	// ProbeNftables 建临时表再删。
	ProbeNftables(ctx context.Context) error
	// ProbeConntrack 尝试订阅 conntrack 多播组。
	ProbeConntrack(ctx context.Context) error
	// ProbeTc 检查 tc 命令与 netlink 可用性。
	ProbeTc(ctx context.Context) error
	// ProbeIfb 建临时 ifb 设备再删。
	ProbeIfb(ctx context.Context) error
	// ProbeSqliteWAL 打开临时库并读回 journal_mode。
	ProbeSqliteWAL(ctx context.Context) error
}

// Probe 执行全量探测。
//
// 单项失败**不影响其它项**：tc 不可用不应阻止 nftables 被判定为可用。
// 这与「探测失败就整体失败」相反，是有意的——运维需要看到完整的能力图。
func Probe(ctx context.Context, p Prober) Caps {
	var c Caps
	c.ProbedAt = time.Now().Unix()

	c.Nftables = run(ctx, "nftables", p.ProbeNftables,
		"建立临时 nft 表成功",
		"无法建立 nft 表（需要 CAP_NET_ADMIN 与 nf_tables 内核模块）；此项失败会导致服务无法启动")
	// CAP_NET_ADMIN 由 nftables 探测推导：建表是它最简单可靠的验证，
	// 不需要额外跑 capget（capget 只证明「进程有这个 capability」，
	// 而建表成功证明「这个 capability 在目标 netns 里真的生效」）。
	if c.Nftables.Available {
		c.CapNetAdmin = Status{Available: true, Detail: "建立 nft 表成功，说明具备 CAP_NET_ADMIN"}
	} else {
		c.CapNetAdmin = Status{
			Available: false,
			Detail:    "缺少 CAP_NET_ADMIN 或 nf_tables 模块；请检查 systemd 单元的 CapabilityBoundingSet",
		}
	}

	c.Conntrack = run(ctx, "conntrack", p.ProbeConntrack,
		"conntrack netlink 多播订阅成功",
		"无法订阅 conntrack 事件（缺 nf_conntrack 模块或权限）；会话表将降级为轮询 /proc/net/nf_conntrack")

	c.Tc = run(ctx, "tc", p.ProbeTc,
		"tc 命令与 netlink 可用",
		"tc 不可用（缺 iproute2 或权限）；所有限速将不生效")

	c.Ifb = run(ctx, "ifb", p.ProbeIfb,
		"临时 ifb 设备创建成功",
		"ifb 不可用（缺 ifb 内核模块或权限）；上传方向只能限总额，无每源保底")

	switch {
	case c.Tc.Available && c.Ifb.Available:
		c.PerSrcLimit = Status{Available: true, Detail: "tc 与 ifb 均可用，支持每源保底"}
	case c.Tc.Available:
		c.PerSrcLimit = Status{
			Available: false,
			Detail:    "ifb 不可用，上传方向只能限总额（无每源保底）；下载方向仍可按源分类",
		}
	default:
		c.PerSrcLimit = Status{Available: false, Detail: "tc 不可用，所有限速均不生效"}
	}

	c.SqliteWAL = run(ctx, "sqlite WAL", p.ProbeSqliteWAL,
		"SQLite 已启用 WAL 模式",
		"SQLite 无法启用 WAL（可能在不支持共享内存的文件系统上）；并发写将降级")

	return c
}

// run 执行一项探测并包装成 Status。
//
// 分离成独立函数是为了让五处探测的包装逻辑完全一致——
// 之前手写五遍时漏掉过 context 超时处理。
func run(ctx context.Context, name string, fn func(context.Context) error, okDetail, failDetail string) Status {
	// 单项探测超时 3 秒：探测失败不能拖慢启动。
	// 用 WithTimeout 而不是依赖调用方的 ctx：启动阶段的 ctx 通常没有 deadline。
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := fn(cctx); err != nil {
		return Status{
			Available: false,
			Detail:    fmt.Sprintf("%s。具体错误: %s", failDetail, trimErr(err)),
		}
	}
	return Status{Available: true, Detail: okDetail}
}

// trimErr 把错误压成一行短描述（避免把栈或多行输出塞进 UI）。
func trimErr(err error) string {
	if err == nil {
		return ""
	}
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const max = 160
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// Critical 报告是否有「无法启动」级别的能力缺失。
//
// nftables 缺失意味着数据面完全不能工作——调用方据此决定拒绝启动
// 而不是带着一个不能转发的进程跑。
func (c Caps) Critical() error {
	if !c.Nftables.Available {
		return fmt.Errorf("能力探测失败，无法启动: %s", c.Nftables.Detail)
	}
	return nil
}

// Warnings 返回需要显示在 UI 上的降级警告（不含 critical 项）。
//
// 顺序固定（nftables 之外按名称），保证 UI 每次渲染的行序一致。
func (c Caps) Warnings() []string {
	// 初始化成空切片而不是 nil：JSON 序列化时空切片是 []，nil 是 null。
	// 前端对 null 做 .length / .map 会直接抛错（AGENTS.md 的 JSON 坑）。
	out := make([]string, 0, 5)
	for _, item := range []struct {
		name string
		st   Status
	}{
		{"conntrack", c.Conntrack},
		{"tc", c.Tc},
		{"ifb", c.Ifb},
		{"per_src_limit", c.PerSrcLimit},
		{"sqlite_wal", c.SqliteWAL},
	} {
		if !item.st.Available {
			out = append(out, fmt.Sprintf("%s 不可用: %s", item.name, item.st.Detail))
		}
	}
	return out
}

// NftProbe 用真实 nft 命令探测。
//
// 用 exec 而不是 netlink：建表/删表的 CLI 行为最稳定，且这个探测
// 每进程只跑一次，性能无所谓。**注意不是拼 shell 字符串**——
// exec.Command 逐个参数传，没有注入面（D-15）。
func NftProbe(ctx context.Context) error {
	const tbl = "haweb_caps_probe"
	// 先尝试删除（清理上次异常退出的残留）
	_ = exec.CommandContext(ctx, "nft", "delete", "table", "inet", tbl).Run()
	if out, err := exec.CommandContext(ctx, "nft", "add", "table", "inet", tbl).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	// 无论后续如何都要删掉
	defer func() {
		_ = exec.CommandContext(context.Background(), "nft", "delete", "table", "inet", tbl).Run()
	}()
	if out, err := exec.CommandContext(ctx, "nft", "list", "table", "inet", tbl).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// TcProbe 检查 tc 命令存在且能列 qdisc。
func TcProbe(ctx context.Context) error {
	if _, err := exec.LookPath("tc"); err != nil {
		return fmt.Errorf("找不到 tc 命令（安装 iproute2）: %w", err)
	}
	if out, err := exec.CommandContext(ctx, "tc", "qdisc", "show").CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// IfbProbe 建临时 ifb 设备再删。
func IfbProbe(ctx context.Context) error {
	const dev = "haweb-caps-ifb"
	_ = exec.CommandContext(ctx, "ip", "link", "del", dev).Run()
	if out, err := exec.CommandContext(ctx, "ip", "link", "add", dev, "type", "ifb").CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.CommandContext(context.Background(), "ip", "link", "del", dev).Run()
	return nil
}
