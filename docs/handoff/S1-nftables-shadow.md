# 交接卡 · S1 nftables 双表热切换

**阶段**: S1 — 影子链原子切换
**日期**: 2026-10-30
**本轮提交范围**: `4ac63ad`（4 个新文件，约 1,100 行含测试）

---

## 已完成

| 文件 | 内容 |
|---|---|
| `internal/adapter/nftables/engine.go` | 引擎骨架：表/链结构创建（**只增不删**）、4 个锚点 + 8 个工作链 + MSS/input 固定链、`Slot` 版本槽 |
| `internal/adapter/nftables/shadow.go` | `CommitShadow` 四阶段、`installLocked`/`verifyLocked`/`switchLocked`/`cleanupChainLocked`、`JumpCount`/`AllJumpCounts`/`ChainRuleCount` |
| `internal/adapter/nftables/conn.go` | `connAPI` 接口（10 方法）+ 编译期断言 `var _ connAPI = (*nftables.Conn)(nil)` |
| `internal/adapter/nftables/shadow_test.go` | 17 个测试 |
| `internal/adapter/nftables/memconn_test.go` | 内存 netlink 实现（精确模拟 batch 回滚语义） |

**覆盖率**：85.9%。

---

## 本轮确定的实现事实（下一阶段必须遵守）

### 1. 四个独立锚点，不是一个

设计文档 §3.1 的示例只画了 `dispatch_pre` / `dispatch_dnat` / `dispatch_fwd` / `dispatch_snat` 四条，本实现照此：

| 锚点 | hook | priority | 链类型 |
|---|---|---|---|
| `dispatch_pre` | prerouting | `ChainPriorityMangle` (-150) | filter |
| `dispatch_dnat` | prerouting | `ChainPriorityNATDest` (-100) | nat |
| `dispatch_fwd` | forward | `ChainPriorityRef(-10)` | filter |
| `dispatch_snat` | postrouting | `ChainPriorityNATSource` (100) | nat |

四个 hook 的 priority 与链类型都不同，**无法共用一个 dispatch**。切换必须遍历四个。

### 2. 每个 hook 的 Flush 是独立 batch（有意为之）

`switchLocked` 里每个 hook 单独 `Flush()`。四个 hook 之间**无法原子**，但它们是同一条连接的不同阶段（prerouting → forward → postrouting），短暂混用新旧版本是安全的——不存在「prerouting 跳新、forward 跳旧」导致语义错乱的情形。

**如果将来要收紧**：可以尝试把四个 hook 的 jump 替换放进同一个 `nftables.Conn` 的暂存区后一次 Flush。但需先验证 `google/nftables` 是否把跨链操作打成一个 batch（不同 hook 的消息在同一 batch 内是否被内核接受）。**未验证**。

### 3. `connAPI` 存在的理由

Engine 依赖 `connAPI` 而非 `*nftables.Conn`，唯一目的是让切换逻辑（尤其失败回滚）能在 CI 里验证。`memConn` 精确模拟 batch 语义：

- `AddRule`/`DelRule`/`FlushChain` 只**暂存**
- `Flush()` 一次性提交
- **提交失败整批回滚**（暂存全部丢弃，已提交状态不受影响）

这与 netlink 的 `BATCH_BEGIN`/`BATCH_END` 语义一致。**不要把这个接口删掉换成真实连接**——那样 S1 的 DoD（200 次切换、失败注入、并发）就只能上真机跑，而那是业务机。

### 4. 初始化只增不删（C-10）

`ensureStructure` 用 `ListChains` 判存在，不存在才 `Add`。**绝不删除任何已有链或规则**——避免重启瞬间清空转发面。

### 5. 槽位不变量

- `active != shadow` 恒成立（有测试 `TestActiveShadowNeverSame`）
- 切换成功后 `active = target`，`shadow = target.Other()`
- 一个工作链的两个槽**不能同时有规则**（全量重装 + 切换后清理保证）

---

## 未完成 / 降级

| 项 | 状态 | 影响什么 |
|---|---|---|
| **compile.Plan → nftables 表达式的翻译器** | **未实现** | 这是 S1 与 S0 之间的最后一段胶水：`compile.Rule` 的 `Dst/MatchSrc/CtMarkEq/DnatTo/SetCtMark/Verdict/MSSValue` 等字段要翻译成 `[]expr.Any`。**S2 之前必须补上**，否则 `CommitShadow` 只能装 counter 规则 |
| MSS 的 netlink 表达式 | 只有规格（`MSSValue`/`MSSFamily`） | 需 `expr.Exthdr` + `expr.Payload{Operation: PayloadWrite, CsumType: CsumTypeInet, CsumOffset: 16, CsumFlags: 0x1}`。**必须先用 `nft add rule ... tcp option maxseg size set 1360` 命令行逐字段对照** |
| ICMP 豁免的匹配表达式 | 只有规格（`IcmpExempt` 常量在 compile 层） | 需 `expr.Meta{Key: MetaKeyL4PROTO}` + `expr.Payload`（type 字段）+ `expr.Cmp` |
| 真机建表验证（S1 DoD 第 1 条） | **未执行** | 需要在 `192.168.10.170` 上建 `table inet haweb_v2`（**不能叫 haweb**，那个在跑业务）并 `nft list table` 核对链布局。本轮只做了内存验证 |
| 计数器读取（工作链的 counter 供 UI 展示） | 未实现 | S4/S5 的指标层 |

---

## 偏离技术方案的地方

| 文档原文 | 实际实现 | 理由 |
|---|---|---|
| §3.1 示例 `chain dispatch_fwd { type filter hook forward priority -10; jump fwd_a }` | 同上，但锚点用 `nftables.ChainPriorityRef(ChainPriority(-10))` | `ChainPriorityRef` 的参数类型是命名类型 `ChainPriority`，需显式转换（编译器要求） |
| §3.1 `e.c.ListRules(...)` | `e.conn.GetRules(table, chain)` | v0.3.0 没有 `ListRules`；`GetRules` 必须指定链，不能一次列全表。这反而更省——自检时逐链取，避免拉全表 |
| §3.1 `CommitShadow` 伪代码 | 增加 `verifyLocked` 自检阶段与 `dropShadowLocked` 失败清理 | 伪代码省略了这两步；没有它们，「装配失败留下半装内容」会污染下次切换 |
| §5.3 要求「不许 `Flush()` 整张表后再重建」 | 遵守：只 `FlushChain` 单个工作链 | — |
| §5.3 要求「不许 `FlushRuleset()`」 | 遵守：完全没有调用 | — |
| §5.3 要求「不许用 `nft -f` 走 exec」 | 遵守：全部走 netlink | — |

---

## 发现的文档问题

1. **`design-rewrite-v2.md` §3.1 的 `CommitShadow` 伪代码不完整**：缺少 ①「装配失败要清掉半装内容」与 ②「自检阶段」。按伪代码直接实现，会在装配失败后留下半装的影子链，下次切换把它当成完整版切上去——这是一个静默的严重缺陷。本实现补了 `dropShadowLocked` 与 `verifyLocked`。
2. **§3.1 示例的 `dispatch` 链画了 4 条但标题写「一条 jump」**（「`dispatch` 里永远只有一条规则：`jump w_<active>`」）。准确说法是「**每个** dispatch 锚点各有且仅有 1 条 jump，共 4 个锚点」。这个歧义会让人误以为只有 1 个 hook。
3. `google/nftables v0.3.0` 的 `Conn` **没有** `ListRules` 方法；`GetRules(t *Table, c *Chain)` 必须指定链。`docs/poc-nftables.md` 的「规则 CRUD」表格里写的「GetRules 回读带 Handle」是对的，但没有记录「不能列全表」这个限制。

---

## 依赖申请

无新增依赖。`github.com/google/nftables v0.3.0` 已在 `go.mod`（宪法 C-13 白名单内），本轮首次被真正 import，`go mod tidy` 后它仍是 `// indirect` 标记——**建议在 S5 装配时把它改成直接依赖**（C-13 表格里已记录这一点）。

---

## 下一阶段的入口

**必须先读**：
- `docs/handoff/S0-domain-compile.md`（TcPlan 五条硬约束、常量表、HRW 的 fmix64 坑）
- 本卡「本轮确定的实现事实」全部 5 条
- `docs/design-rewrite-v2.md` §3.1~§3.2（双表 + 链布局）

**S2 之前必须先做（阻塞项）**：

1. **`compile.Plan` → `[]expr.Any` 的翻译器**。建议放在 `internal/adapter/nftables/translate.go`，函数签名：

   ```go
   func TranslatePlan(p *compile.Plan) (WorkSet, []RuleSpec, error)
   ```

   其中 `RuleSpec` 承载 MSS/ICMP 这类「固定链、不参与版本化」的规则。

2. **MSS 表达的命令行对照**（1 小时，必须在真机做）：

   ```bash
   nft add table inet haweb_mss_poc
   nft add chain inet haweb_mss_poc mss '{ type filter hook forward priority -20; }'
   nft add rule inet haweb_mss_poc mss tcp flags syn tcp option maxseg size set 1360
   nft -a list chain inet haweb_mss_poc mss   # 逐字段对照 expr 构造
   nft delete table inet haweb_mss_poc
   ```

3. **真机建表验证**（S1 DoD 第 1 条未做）：在 `.170` 上建 `table inet haweb_v2`，核对链布局与 priority，验完删除。**不要用 `haweb` 这个名字**——它正在跑业务。

**S2 的关键待办**：
1. `tcnetlink` 按 `compile.TcClassSpec.IsLeaf` 决定是否挂 fq_codel
2. 上传 filter 用 `TcFilterSpec.MatchSrc`，不要自己再判方向（C-17）
3. `burst` 用 `compile.BurstBytes(bps, 10ms)`，1Gbps 实测复验

---

## 待你确认的问题

无。S1 的代码层 DoD 全项满足；「真机建表验证」一项因涉及业务机、且需要在业务机上新建表，留到 S2 与 tc 验证一起做（届时可复用 `poc_*` 命名约定）。
