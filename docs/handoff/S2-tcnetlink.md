# 交接卡 · S2 tc 落地（adapter/tcnetlink）

**阶段**: S2 — tc 树落地
**日期**: 2026-10-30
**本轮提交范围**: `68a40d3`（tc + S1 阻塞项）、`65f28ed`（conntrack）

---

## 已完成

| 文件 | 内容 |
|---|---|
| `internal/adapter/tcnetlink/tc.go` | `Apply`（qdisc→class→filter 顺序）、`ensureQdisc`（参数不一致整树重建）、`cleanupClasses`（D-01 保护）、`attachFqCodel`（只挂 IsLeaf）、`applyFilters`/`applyMirred`（D-16 方向）、`ReadClassStats` |
| `internal/adapter/tcnetlink/tc_test.go` | 14 个测试（handle 解析、掩码、方向、mirred 约束、非法计划拦截） |
| `internal/compile/expand.go` | 多网段白名单展开（S1 阻塞项 1） |
| `internal/compile/expand_test.go` | 9 个测试 |
| `internal/adapter/nftables/translate.go` | ICMP 豁免表达式（S1 阻塞项 2） |
| `internal/adapter/ctnl/codec.go` | nfnetlink 编解码（纯函数）+ KillSession 的 Delete 请求构造 |
| `internal/adapter/ctnl/table.go` | 32 分片会话表、快照、全量替换、汇总统计 |
| `internal/adapter/ctnl/engine.go` | 双连接事件订阅、60s 对账、KillSession |
| `internal/adapter/ctnl/*_test.go` | 47 个测试（含 golden 真机字节） |

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
| `ReadClassStats` 的 `Lended`/`Borrowed` | 只有 `Sent`/`Packets` | `netlink.ClassStatistics` 没有暴露 HTB 的 lended/borrowed（只有 Basic/Queue/RateEst）。要读这两个值只能解析 `tc -s` 文本或直接 netlink dump |
| 真机上的 `direct_packets_stat` 断言自动化 | 人工观察 | S6 回归时可做成脚本断言 |
| tcnetlink 测试覆盖率 | 27.9% | 真实 netlink 路径无法在 CI 跑（需 CAP_NET_ADMIN）。已由真机验证覆盖；纯函数部分（handle/掩码/方向）100% |
| `burst` 千兆复验 | 未做 | 只测了 8MB/s 与 4MB/s |

---

## 依赖申请

**无。** conntrack 用原生 nfnetlink 实现，**未引入 `ti-mo/conntrack`**。
依据：`docs/poc-nftables.md` 已验证原生通道可用；`go.mod` 未变。

---

## conntrack（ctnl）的实现事实 —— 下一阶段必读

### 1. 必须用**两条** netlink 连接

| 连接 | 用途 | 订阅多播 | 读超时 |
|---|---|---|---|
| 请求通道 | dump、delete | **不订阅** | 无 |
| 事件通道 | 只收 NEW/UPDATE/DESTROY | 三个组 | 1 秒 |

**为什么**：同一条 socket 上订阅多播后，异步事件与 dump 响应混在一起，
`Execute` 的序列号校验报 `netlink validate: mismatched sequence in netlink reply`。
真机实测得出，不是推测。

另：`mdlayher/netlink` 的 `Config.Groups` **只在 Dial 时生效**，没有
`JoinGroups` 方法——多播组必须拨号时指定。

### 2. CTA_* 常量必须与内核头逐项对齐（曾整组错位）

按记忆写的那一版：`STATUS=4 / COUNTERS=7 / TIMEOUT=8`。
内核头实际：`STATUS=3 / TIMEOUT=7 / COUNTERS_ORIG=9 / COUNTERS_REPLY=10`。

后果：status 读到 `CTA_PROTOINFO` 的值 → **所有会话显示未建立**；
counters 读到 `CTA_TIMEOUT` → **所有字节数为 0**。

**这个错误自造消息测试永远发现不了**（自造消息用自造常量，往返一致）。
唯一手段是 `golden_test.go`：把真机 dump 的原始 hex 硬编码进测试。

### 3. KillSession 必须带完整属性集

只给 `CTA_TUPLE_ORIG` 会被内核以 EINVAL 拒绝（真机报 `invalid argument`）。
strace `conntrack -D` 得出的权威格式（196 字节）：

```
CTA_TUPLE_ORIG + CTA_TUPLE_REPLY + CTA_STATUS
+ CTA_PROTOINFO + CTA_TIMEOUT + CTA_MARK
```

reply tuple 缺失时用 orig 镜像补齐；PROTOINFO 按协议给最小合法结构
（TCP → state 子属性；ICMP → id/type/code）。

### 4. 读超时错误**不是** EAGAIN

`mdlayher/netlink` 在 `SetReadDeadline` 到期后返回
`netlink receive: i/o timeout`（内部是 `os.ErrDeadlineExceeded`）。
只判 `EAGAIN` 会让超时被当成致命错误 → `Run` 退出 → `KillSession`
报「引擎未启动」。

### 5. 默认 dump **不返回 counters**

真机 dump 的原始字节里没有 `CTA_COUNTERS_*`，所以 `Packets`/`Bytes` 恒为 0。
要拿计数必须：① 在 dump 请求里带 `CTA_FLAGS + CTA_FLAGS_COUNTER`，
或 ② 用事件订阅（NEW/UPDATE 事件带 counters）。
**这是已知限制，不是解析器漏读**（`TestCountersNotRequested` 固化）。

### 6. 真机验证结果

```
BASELINE sessions=14
STATS total=14 established=13
AFTER_CONNECT sessions=15 (delta=1)   ← NEW 事件实时捕获
KillSession → KILL_OK + KILL_LOCAL_REMOVED
DROPPED=0  RUN_EXITED_OK
```

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

**S3/S4 的关键待办**：
1. `Disabled 策略 → 立即断开已建会话`：用 `ctnl.Engine.KillSession`，
   判据用 `domain/session.ShouldDrop`（旧代码只拦 `ct state new`，
   已建会话最长存活 86400s）
2. `ctnl` 的 `Dropped()` 与 `Reconciles()` 要接进 `/metrics` 与 `/healthz`
   （丢弃数持续增长说明会话统计已不可信）
3. 会话表快照接进 `GET /api/sessions`；`Table.Snapshot()` 已是稳定顺序
4. 45 个接口的契约测试

---

## 待你确认的问题

无。S2 的全部交付物（tc + conntrack）已完成，DoD 满足。
