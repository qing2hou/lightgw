# 交接卡 · S2 tc 落地（adapter/tcnetlink）

**阶段**: S2 — tc 树落地
**日期**: 2026-10-30
**本轮提交范围**: `68a40d3`（含 S1 两处阻塞项的补齐）

---

## 已完成

| 文件 | 内容 |
|---|---|
| `internal/adapter/tcnetlink/tc.go` | `Apply`（qdisc→class→filter 顺序）、`ensureQdisc`（参数不一致整树重建）、`cleanupClasses`（D-01 保护）、`attachFqCodel`（只挂 IsLeaf）、`applyFilters`/`applyMirred`（D-16 方向）、`ReadClassStats` |
| `internal/adapter/tcnetlink/tc_test.go` | 14 个测试（handle 解析、掩码、方向、mirred 约束、非法计划拦截） |
| `internal/compile/expand.go` | 多网段白名单展开（S1 阻塞项 1） |
| `internal/compile/expand_test.go` | 9 个测试 |
| `internal/adapter/nftables/translate.go` | ICMP 豁免表达式（S1 阻塞项 2） |

## 真机实测结果

| 场景 | 配置 | 实测 | 误差 | direct |
|---|---|---|---|---|
| 单源（.152 → 1:201） | 8 MB/s | **7.894 MB/s** | −1.3% | 0 |
| 双源并发（合计） | 8 MB/s | **8.1187 MB/s** | **+1.48%** | **0** |
| 双源并发（T4 树） | 4 MB/s | 4.07 MB/s | +1.8% | 0 |

双源时两条流各约 4 MB/s（不是各 8），**总额是共享的**——与 P0 阶段 15 组二维扫描的 `max(parent.rate, Σrate)` 语义一致。

---

## 本轮确定的实现事实（下一阶段必须遵守）

### 1. tc 的 `major:minor` 是**十六进制**

`tc class show` 输出 `1:208` 表示 minor = **0x208 = 520**，不是十进制 208。
`parseHandle` 曾按十进制解析，导致所有 class ID 错位。**任何新增的 handle
解析都必须按 hex**。

### 2. `TcPlan.Validate` 是最后一道闸

`Engine.Apply` 在写入前调用它。五条硬约束（default 指叶子、IsLeaf 不能有子类、
filter flowid 存在且非内层、pref != 0、mirred 必须有目标）任一违反即拒绝。
**不要在 adapter 里再判一遍**——两份可能不一致的真相比没有判断更危险。

### 3. 清理历史 class 的三重保护（D-01）

1. 判据是「本次计划里没有它」，不是区间扫描
2. 显式跳过 `1:30` / `1:100` / `1:199`
3. 只删同设备上的（class 归属由 qdisc 反查）

事故背景：曾有循环从 `1:2` 到 `1:249` 把刚建好的限速类删掉，default 指向
不存在的 class，**8MB/s 配置跑出 24MB/s**。

### 4. 多网段展开在 compile 层，不在 translate 层

`TranslatePlan` 拿到的 `Plan` 已经是「每条规则只有单个网段」的形态
（`Compile` 里调 `ExpandAddrMatches`）。**不要在 translate 层再处理多网段**——
那需要预建命名 set + Lookup，会引入 set 生命周期与原子性两个新问题。

### 5. ICMP 的 Payload 基址是 TransportHeader

真机 `nft -j`：`{"payload": {"protocol": "icmp", "field": "type"}}`。
用 `NetworkHeader` 会读 IP 头的第一字节（version/IHL），永远匹配不到。
且必须先匹配 `l4proto`，否则 tcp/udp 包的首字节会被误判为 icmp type。

---

## 未完成 / 降级

| 项 | 状态 | 影响 |
|---|---|---|
| **conntrack 事件订阅**（`internal/adapter/ctnl`） | **未实现** | S2 技术方案的 6.3 节。需要 `ti-mo/conntrack`（**依赖申请**，见下）。当前没有它，会话表无法维护、`KillSession` 无法实现 |
| `ReadClassStats` 的 `Lended`/`Borrowed` | 只有 `Sent`/`Packets` | `netlink.ClassStatistics` 没有暴露 HTB 的 lended/borrowed（只有 Basic/Queue/RateEst）。要读这两个值只能解析 `tc -s` 文本或直接 netlink dump |
| 真机上的 `direct_packets_stat` 断言自动化 | 人工观察 | S6 回归时可做成脚本断言 |
| tcnetlink 测试覆盖率 | 27.9% | 真实 netlink 路径无法在 CI 跑（需 CAP_NET_ADMIN）。已由真机验证覆盖；纯函数部分（handle/掩码/方向）100% |
| `burst` 千兆复验 | 未做 | 只测了 8MB/s 与 4MB/s |

---

## 依赖申请

**`github.com/ti-mo/conntrack`**（S2 的 conntrack 事件订阅）

| 项 | 内容 |
|---|---|
| 用途 | 订阅 conntrack 的 NEW/UPDATE/DESTROY 事件，维护内存会话表 |
| 宪法状态 | **白名单内，标注「需申请，S2 阶段」** |
| 备选 | 原生 nfnetlink dump（`docs/poc-nftables.md` 已验证「conntrack dump 原生 NETLINK_NETFILTER 通道可用，不引第三方库也行」） |
| 建议 | **先用原生实现**，减少一个依赖面；若事件订阅的 netlink 多播细节过于繁琐再引入 |

---

## 下一阶段的入口

**必须先读**：
- `docs/handoff/P0-poc.md`（T23–T29 七个坑）
- `docs/handoff/S0-domain-compile.md`（TcPlan 五条硬约束、常量表、HRW 的 fmix64）
- `docs/handoff/S1-nftables-shadow.md`（四条 nft 硬约束、connAPI 的存在理由）
- 本卡「本轮确定的实现事实」全部 5 条

**S3 的关键待办**：
1. 双库拆分（`config.db` / `traffic.db`），`PRAGMA auto_vacuum=2` **必须在建库时设置**
2. 分表表名白名单 `^traffic_log_\d{8}$`（SQL 注入面）
3. logstore 的 `ch` 满时丢弃并计数，永不阻塞转发路径

**S4 的关键待办**：
1. `Disabled 策略 → 立即断开已建会话`（旧代码只拦 `ct state new`，已建会话最长存活 86400s）
2. `domain/session.ShouldDrop` 已提供判据
3. 45 个接口的契约测试

---

## 待你确认的问题

**conntrack 依赖选择**：用 `ti-mo/conntrack`（白名单内、需申请），还是先用原生
nfnetlink 实现（`docs/poc-nftables.md` 已验证可行、零新增依赖）？我倾向**原生**，
理由是少一个依赖面、且 PoC 已确认通道可用。若你同意，我在下一轮直接实现。
