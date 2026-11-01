# 交接卡 · S6 前置：控制平面与装配现状

**日期**: 2026-11-01
**本轮提交**: `ebd22cb`（control + nftables.StagedApplier + adapter/bridge）

---

## 一个必须说清楚的事实：新代码造完了但没装到车上

本轮开始时我核对了生产装配的实际引用：

```
adapter/nftables   被生产代码引用: 0 处
adapter/tcnetlink  被生产代码引用: 0 处
adapter/ctnl       被生产代码引用: 0 处
adapter/logstore   被生产代码引用: 0 处
transport/httpapi  被生产代码引用: 0 处（7 条路由 vs 旧 api 的 53 条）
```

`platform/app.Run` 里用的仍是**旧的 `proxy.Manager` + 旧的 `api.NewRouter`**。

**后果**：S6 要求的「新旧两套二进制跑 403 条用例做 diff」**现在无法执行**——
编译出的新二进制与改造前功能等价，diff 会得到「两边完全一致」，
那个结果没有意义。

---

## 本轮补的中间层（S6 装配的前提）

### internal/control（95.3% 覆盖率）

把 `compile.Plan` 装配到内核，负责「先装后切」编排与失败回滚（C-10）：

| 阶段失败 | 行为 |
|---|---|
| LoadShadow | DropShadow → 返回「旧规则继续生效」 |
| VerifyShadow | DropShadow → 返回「旧规则继续生效」 |
| CommitShadow | DropShadow → 返回「旧规则继续生效」，**不 GC** |
| GC | 忽略（已无引用） |
| ApplyTc | 返回 `PartialError`，**nft 不回滚** |

`PartialError` 的存在理由：tc 失败时不回滚 nft，因为「限速暂时不生效」
远好于「回滚期间转发面为空」。但这个状态必须能被 `/api/status` 看到。

### nftables.StagedApplier（与一体化路径等价）

原来的 `CommitShadow` 是一体化的，控制平面直接调它就无法在阶段之间判断。
新增 `BeginStage/StageLoad/StageVerify/StageCommit/StageCleanup/StageAbort`。

`TestStagedEquivToCommitShadow` 固化等价性：两条路径跑完后
active 槽与各链规则数完全一致。

### adapter/bridge（75.0%）

唯一同时 import control 与 adapter 的地方。control 保持不依赖 adapter，
所以它的测试不需要 CAP_NET_ADMIN。

---

## 本机限制（决定了接下来怎么做）

```
id -u              → 1000
CapEff             → 0000000000000000
ip netns add       → Permission denied
nft add table      → Operation not permitted
```

**这台机器（WSL2）无法做任何内核面验证**。所有 nft/tc/conntrack 的
真机验证只能在 `192.168.10.170` 上做，而那是生产机。

事故教训（`docs/incident-2026-10-30-orphan-reconcile.md`）明确：
**绝不在生产机上用测试配置启动完整服务**。

---

## 下一步的三个选项（需要决策）

### 路径 A · 在 .170 上建隔离 netns 验证（推荐）

在业务机上开一个独立 netns（`ip netns add haweb-test`），在里面建
veth 对、建独立的 nft 表、跑完整装配链路。**netns 内的表与业务表完全隔离**，
不会互相影响。

前提：需要确认 `.170` 有 `CAP_NET_ADMIN`（有，我们一直在上面跑 nft/tc）。

风险点：netns 里的 nft 表仍在同一个内核，但**表名独立**（用 `haweb_test`
而非 `haweb`），且事故的根因（实例 ID + 默认不拆）已修，双重保险。

### 路径 B · 先补完装配，再统一验证

把 `platform/app.Run` 改成走新链路（`compile` → `control` → `bridge`），
写装配层的单元测试（注入假 adapter），真机只在最后做一次端到端。

工作量最大，但一次性解决「新代码没上生产」的根本问题。

### 路径 C · 缩小 S6 范围

只对已装配的部分（`/api/status`、`/api/capabilities`、三个新增接口）
做双跑，其余 44 条接口标记「未迁移」。

---

## 仍未解决的实际问题（与本次改造无关，但需要知道）

**生产机上上传限速仍然失效**：实测 112 MB/s vs 配置 8 MB/s。
原因是部署的二进制是旧版（md5 `05fa7edd...`），`ifb` 侧 filter 用
`at 16`（目的地址），而上传包进 ifb 后 `daddr` 是公网服务器。

修复在 `docs/poc-result.md` §3.2 已定位（应为 `match ip src`），
S2 的 `tcnetlink` 已按正确方向实现，但**尚未部署**。

要修现场需要单独处理：改旧代码（`snat.go:1848`）或部署新版。

---

## 决策与执行进展（2026-11-01）

用户选定：**先 A 后 B**。

### A 已完成（commit `c89e99d`）

在 `.170` 的独立 netns 里验证，业务表全程未受影响。三组对照：

| 组 | 结构 | 配置 | 实测 | 误差 | direct |
|---|---|---|---|---|---|
| 1 | 无 qdisc | — | 2103.31 MB/s | 链路天花板 | — |
| 2 | `default` → **叶子兜底类** | 2 MB/s | **1.9900 MB/s** | **−0.50%** | **0** |
| 3 | `default` → **内层类**（无 qdisc） | — | 2061.78 MB/s | **绕过 1031 倍** | **+238,841** |

另复验：双表切换 10 次，jump 恒为 1；双向隔离确认（host 看不到 netns 表，
netns 看不到业务表）。

**过程中我自己犯了三次实验设计错误**，都记在报告里：
① htb 建在接收侧网卡（应建在发送侧）② 收发都在 netns 内 → 走 `lo`
从未碰 veth ③ 直到第三版才把接收放 netns、发送放 host。

判据教训：**速率、子类 `Sent`、`direct` 三个数必须一起看**。
只看速率会得到完全相反的结论（v1/v2 都跑出 2200+ MB/s 却以为在测限速）。

### B 的范围重新评估（重要）

原本设想「把新链路接进 `platform/app.Run`」。实际核对后，装配层对
`proxy.Manager` 的依赖是：

```
AdoptListeners / ApplyOptions / SetInstanceID / SetWebListener
StartAll / StartHealthChecks / StartSnatPolling / StopAll
```

这些覆盖了**用户态转发、监听管理、健康检查、SNAT 计数轮询、双进程升级、
优雅排空**。新链路目前只有 nft/tc 的编译与应用能力，**不含上面这些**。

所以「完整替换 Manager」远超一轮能安全完成的范围。调整 B 为**增量接入**：

**B-1（已完成，`bb5ec4b`）· 只读影子比对**
`internal/control/shadowverify`：从 DB 读规则 → 新 compile 编译 → 与内核
现有规则比对 → **不写任何内核对象**。用来在生产机上安全回答
「新编译器与旧实现产出的规则集是否等价」。

**B-2（待做）· 让新链路接管 nft/tc，Manager 保留用户态转发**
改 `StartAll` 里 nft/tc 那一段走 `control.Controller`，监听与转发不动。
风险中等，需要先在 netns 里跑通完整装配。

**B-3（待做）· 替换转发引擎**
重写 TCP/UDP 用户态转发、健康检查、升级、排空。这是最大的一块。

**建议节奏**：B-1 的产出（等价性报告）是 B-2 的放行条件——
不等价就先查清原因，别急着换。

---

## 仍未解决

**生产机上传限速失效**（112 MB/s vs 配置 8）。部署的二进制是旧版
（md5 `05fa7edd...`），`ifb` filter 用 `at 16`。修复在 `tcnetlink` 已实现
但未部署。要修现场需改旧代码 `snat.go:1848` 或部署新版。

**这一条要不要处理、以及 B-2 什么时候做，需要你定。**
