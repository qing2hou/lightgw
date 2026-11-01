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

## 待你确认

1. 走哪条路径（A / B / C）？
2. 生产机的上传限速失效要不要现在处理？

我倾向 **A 先验证、再 B 补装配**：先在 netns 里确认新链路真的能工作
（这样 B 的改造有底），验证通过后再改生产装配。

在得到确认前我不会碰 `.170`。
