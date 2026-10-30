# 交接卡 · S0 domain + compile 纯函数层

**阶段**: S0 — 纯函数地基
**日期**: 2026-10-30
**本轮提交范围**: `9811dbb`（实现）+ `52afdd7`（DoD 补充单测），20 个新文件，约 5,600 行

---

## 已完成

### `internal/domain/`（零 IO）

| 包 | 内容 | 覆盖率 |
|---|---|---|
| `model` | `Rule` / `Policy` / `Egress` / `BWGroup` / `AclGroup` / `Session` 实体；`PolicyAction` 三态、`DenyScope` 三档、`AclGroupKind` 三类；`CtKey` 五元组（`String`/`Parse` 互逆）；`Pool` 不可变值语义 | 88.2% |
| `rule` | 规则校验、监听端点冲突检测（禁用规则不参与）、后端集合汇总（去重+排序） | 92.5% |
| `policy` | `Order` 排序（同 Order 按 ID 兜底）、三态语义评估、`AllowsForwarding`（accept 需白名单 AND） | 96.5% |
| `snat` | HRW 池分配、`ReshuffleRate`、`Distribution` | 91.7% |
| `bandwidth` | 额度计算、`CheckOversubscription`/`ValidateOversubscription`（ADR-15） | 95.7% |
| `session` | 状态机（closed 终态、同态幂等）、超时判定、`ShouldDrop` | 100.0% |

### `internal/compile/`（编译层）

| 文件 | 内容 | 覆盖率 |
|---|---|---|
| `plan.go` | `ct mark` 布局（`rule_id<<8\|flags`，24 位 = 1677 万条）、`Plan`/`NftPlan`/`TcPlan`/`TcClassSpec`/`TcFilterSpec`、`TcPlan.Validate` 五条硬约束、`SortedPrefixes` | — |
| `mss.go` | MSS clamping（只改 SYN、选项必须存在、重算校验和） | — |
| `nft.go` | DNAT（判定+改写两条）、SNAT（按 ct mark）、策略三态、默认拒绝三档 + ICMP 3/11 豁免、转发白名单、回程放行 | — |
| `tc.go` | 双向 htb 树、`DownloadPref`/`UploadPref`、`BurstBytes`、`KBpsToBytesPerSec` | — |
| `compiler.go` | `State` → `Plan` 编排、能力降级警告 | — |
| **合计** | | **89.1%** |

---

## 本轮确定的实现事实（下一阶段必须遵守）

### 1. tc 树结构（与设计文档原稿有 2 处不同，已按 P0 实测修正）

```go
qdisc htb 1: default 199                      // TcFallbackMinor，必须指向叶子
class 1:100  parent 1:     rate=ceil=<总额>    // 内层类，IsLeaf=false
class 1:199  parent 1:100  rate=<保底> ceil=<总额>  // 叶子兜底，IsLeaf=true
class 1:201+ parent 1:100  rate=<保底> ceil=<总额>  // 每源，IsLeaf=true
filter parent 1: pref <DownloadPref> u32 match ip dst <源> flowid 1:2NN
filter parent 1: pref <UploadPref>   u32 match ip src <源> flowid 1:2NN   // ifb 侧
filter parent ffff: pref <UploadPref> u32 match ip src <源> action mirred → ifb
```

**`TcClassSpec.IsLeaf` 是新增字段**，存在理由：内层类挂 fq_codel 会 `EINVAL`，
叶子类不挂 FQ 则包走 direct 绕过。这个判断必须由编译层显式给出，不能靠 adapter 猜。

**`TcPlan.Validate` 强制五条硬约束**（任一违反即报错，不静默降级）：

1. `default` 指向的类必须 `!hasChildren && IsLeaf`
2. `IsLeaf` 的类不能有子类
3. filter 的 `flowid` 必须存在且非内层类
4. `pref != 0`（tc 保留值）
5. `class ID` 换算（`RateBytes` 用 bytes/sec，`KBpsToBytesPerSec` 是唯一换算点）

### 2. 常量定义位置（下一阶段直接引用，不要重复定义）

| 常量 | 位置 | 值 |
|---|---|---|
| `CtRuleShift` / `CtRuleMask` / `CtFlagMask` | `compile/plan.go` | 8 / 0xFFFFFF00 / 0xFF |
| `CtFlagDnat` / `CtFlagHairpin` / `CtFlagPolicyDrop` | `compile/plan.go` | 0x1 / 0x2 / 0x4 |
| `MarkFwdOK` / `MarkPolicyOK` | `compile/plan.go` | 0x1 / 0x2 |
| `TcTotalClass` / `TcFallbackClass` / `TcBypassClass` | `compile/tc.go` | 1:100 / 1:199 / 1:30 |
| `TcSourceClassBase` / `TcSourceClassMax` | `compile/tc.go` | 201 / 998 |
| `DownloadPrefBase` / `UploadPrefBase` / `PrefSpan` | `compile/tc.go` | 2 / 1002 / 997 |
| `DefaultMSSv4` / `DefaultMSSv6` / `MinMSS` | `compile/mss.go` | 1360 / 1340 / 536 |
| `DefaultMinKBps` | `domain/bandwidth` | 1024 |

### 3. HRW 必须带 fmix64 终混（改动前必读）

`domain/snat/pool.go` 的 `score()`：FNV-1a 之后必须跑 `fmix64`。

**根因**：IPv4 的 `As16()` 是 v4-in-v6 形式（前 10 字节 0、2 字节 0xff），
所以「同一 src 对不同 member」的输入**只有最后 1~4 字节不同**。FNV-1a 是流式
哈希，前面 28 字节的处理结果完全相同，末尾字节只影响低位 → 各成员分数高度
相关，最大值几乎恒定落在同一个成员上。

**实测症状**：5 成员池分布退化成 25%/25%/25%/25%/**0%**（有一个成员永远选不到），
重排率失真为 0.25。加 `fmix64` 后：分布 19.78%~20.14%，重排率 **0.2014**。

**为什么不换 maphash**：maphash 每次进程启动种子不同，池成员选择必须跨重启粘性。

### 4. 零值语义：`ACLMode("")` 必须按 `ACLOff` 处理

旧库所有规则的 `acl_mode` 都是空串。若把零值判为非法，**全部历史规则校验不过**。
`model.validatePrefixes` 里已把 `""` 归一化为 `ACLOff`。

### 5. C-12 的正确检查方式

`go list -deps ./internal/domain/...` 会输出 `os` —— 但这来自标准库 `fmt` 的
**内部**依赖（`fmt` → `internal/fmtsort` → `os`），不是本包的 IO。

**正确的检查方式**：直接扫本包源码的 import 块：

```bash
for f in $(find internal/domain internal/compile -name '*.go'); do
  awk '/^import \(/,/^\)/' "$f" | grep -E '"(os|net|os/exec|github.com/google/nftables|vishvananda/netlink|database/sql|gin-gonic|gorm)"'
done
# 必须为空
```

已在 `docs/agent-playbook.md` 的 DoD 条目上标注这个差异（见「发现的文档问题」）。

---

## 未完成 / 降级

| 项 | 状态 | 影响 |
|---|---|---|
| `ReleasePreview` 之外的接口 | — | S0 范围内无遗漏 |
| adapter 层（netlink/exec 落地） | 未开始 | S1（nftables 双表）与 S2（tc+conntrack） |
| MSS 规则的 netlink 表达式构造 | 只有规格（`MSSValue`/`MSSFamily`），无 expr | S1 负责翻译；**必须在真机用 `nft add rule ... tcp option maxseg size set 1360` 逐字段对照** |
| `burst` 千兆复验 | 未验证 | S2 用 1Gbps 实测 |

---

## 偏离技术方案的地方

| 文档原文 | 实际实现 | 理由 |
|---|---|---|
| §3.5.3 `qdisc fq_codel 100: parent 1:100` | fq_codel 挂叶子类；新增叶子兜底类 1:199 承接 default | 实测 `RTNETLINK answers: Invalid argument`；内层类做 default 会 100% 绕过（2828.79 MB/s） |
| §3.5.3「`1:100` 总额硬上限」 | 不假设硬上限；`bandwidth.ValidateOversubscription` 强制 `Σ保底 ≤ 总额` | 15 组实测：合计 ≈ `max(parent.rate, Σ子类rate)` |
| §4.3 `domain/snat` 只要求 `Pick` | 另加 `PickAddr` / `Distribution` / `ReshuffleRate` | 后两个让「重排率」和「均匀性」成为可执行断言，而不是文档里的一句话 |
| §2.1 `Caps` 在 `platform` | S0 内定义了最小子集（`TcNetlink`/`Ifb`/`PerSrcLimit`） | S0 不能依赖 S5 的 platform 层；S5 装配时做适配 |

---

## 发现的文档问题

1. **`agent-playbook.md` §4.4 的 C-12 检查命令不可用**：`go list -deps ... | grep '^os$'` 必然命中（`fmt` 的标准库内部依赖）。建议改为扫本包 import 块，已在本文档记录正确命令。
2. **`design-rewrite-v2.md` §3.5.9 第 4 条**原文仍是「`default` 必须是 `100`」，与本轮实测冲突，已在本轮同时修正为「必须指向叶子兜底类」。
3. `compile` 包名与旧 `internal/proxy/fw/compile.go` 无冲突（不同包路径），但**语义相近**——迁移时注意不要混用。旧包的 `returnPathCounterRows` 在新方案里被 `CompileEstablished` 取代（ct mark 贯穿双向，不需要回程计数行）。

---

## 依赖申请

无。本轮未新增任何第三方依赖，`go.mod` 未变。

---

## 下一阶段的入口

**必须先读**：
- `docs/handoff/P0-poc.md`（tc 结构的三条硬约束 + 7 个坑 T23–T29）
- `docs/design-rewrite-v2.md` §3.1（双表切换）、§3.2（链布局）、§11（目录）
- 本卡「本轮确定的实现事实」全部 5 条

**S1 的关键待办**：
1. `CompileMSSClamp` 产出的规格 → netlink `expr.Exthdr` + `expr.Payload{CsumType: CsumTypeInet, CsumOffset: 16, CsumFlags: 0x1}`。**先用 `nft add rule` 命令行逐字段对照**
2. `CommitShadow` 的失败回滚（P0 Task C 没覆盖：工作链只有 counter）
3. 用 `TcPlan.Validate` 作为 adapter 写入前的最后一道闸

**S2 的关键待办**：
1. 按 `TcClassSpec.IsLeaf` 决定是否挂 fq_codel
2. 上传 filter 用 `TcFilterSpec.MatchSrc`，**不要自己再判方向**
3. `burst` 用 `BurstBytes(bps, 10ms)`，1Gbps 实测复验

---

## 待你确认的问题

无。S0 按 `design-rewrite-v2.md` §4 的任务卡完成，DoD 全项满足。
