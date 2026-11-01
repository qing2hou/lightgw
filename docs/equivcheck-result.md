# B-1 实战结果 · 规则集等价性比对（只读）

**日期**: 2026-11-01
**执行**: `192.168.10.170`，DB 以 `mode=ro` 只读打开，`nft -a list table` 只读
**现场影响**: 零（全程未调用任何写接口，验证后 `haweb` 规则数仍为 8、服务 PID 不变）

---

## 结论先行

**比对器已能跑通，但还不足以作为 B-2 的放行条件。**

第一次实战暴露了两个我自己的映射缺口（不是现场问题）：

1. **漏了名单组展开** —— 已修
2. **期望侧不含前置条件** —— 未修，这是 B-2 之前必须解决的问题

---

## 缺口 1 · 漏了名单组引用（已修）

规则#30 的 `allow_list` 是空串、`acl_group_id = 1`，源网段在名单组里：

```
forward_rules:  id=30  name=test  acl_mode=whitelist  allow_list=""  acl_group_id=1
acl_groups:     id=1   mode=whitelist  entries=[...2 个网段...]
```

我的第一版只读 `allow_list`，于是期望算成 **0 条**，而现网有 8 条 ——
误报「多余 8 条」。

**这正是 AGENTS.md 记录过的坑**：「规则有两处引用位，新增引用位时必须同步
引擎展开，漏一处就是『改了组不生效』」。我在转换器里重犯了同一个错误。

修法：`ExpectationDigest` 展开 `acl_group_id` 引用的组；组不存在时**跳过比对
并记 note**，而不是当作「没有源」（后者会误报一堆「多余」）。

---

## 缺口 2 · 期望侧不含前置条件（未修）

修完缺口 1 后的输出：

```
期望 2 条:
  srcnat: @nh,96,32 0xc0a80a98 → snat ip to 192.168.10.170
  srcnat: @nh,96,32 0xc0a80a97 → snat ip to 192.168.10.170

现网 8 条（节选 srcnat 的两条）:
  srcnat: iifname "eth0" oifname "eth0" meta mark & 0x00000004 == 0x00000000 \
          @nh,96,32 0xc0a80a98 snat ip to 192.168.10.170
```

**这 2 条语义上是同一条规则**，但比对报了「缺失 2 条 + 多余 8 条」——
因为期望侧只写了「地址匹配 + SNAT 动作」，现网侧还带
`iifname` / `oifname` / `meta mark & 0x4 == 0` 这三个前置条件。

也就是说：**我还没想清楚新编译器应该产出什么完整形态**。
`compile.Plan` 里的 `Rule` 结构能表达这些前置条件（有 `Src`/`Dst`/`MetaMarkNotSet`），
但 `ExpectationDigest` 这个「从 DB 反向推导期望」的函数还没做完整映射。

### 为什么这一条不能草率修掉

如果把 `ExpectationDigest` 改成「只比对地址 + 动作，忽略前置条件」，
比对会立刻显示「等价」—— 但那是**假等价**：
前置条件恰恰是 `meta mark & 0x4` 那个「发布流量豁免 SNAT」的关键语义
（AGENTS.md：默认拒绝与 SNAT 豁免都依赖它）。忽略它会让比对器失去意义。

正确做法是让 `ExpectationDigest` 走**真正的编译路径**：
构造 `compile.State` → `Compiler.Compile` → 从 `Plan.Nft.Snat` 提取期望摘要。
这样「期望」与「将来实际要下发的」是同一条代码路径，比对才有意义。

---

## 缺口 3 · compile 层不支持 SNAT 规则（已修：方案 A 独立类型）

按原计划把 `ExpectationDigest` 改成走真实编译路径，实测失败：

```
编译失败: 校验规则[test#30] 失败: 协议 "" 无效（只支持 tcp/udp）
```

根因是**建模不匹配**：`compile` 层先跑 `rule.Validate`，要求
`Proto ∈ {tcp,udp}`，而 SNAT 规则没有协议概念（作用于所有协议的穿越流量），
现网规则#30 的 `protocol` 字段值是 `"snat"`。

### 修复（方案 A · 独立类型）

新增 `internal/compile/snat_rule.go`：

```go
type SnatRule struct {
    ID, Name       // 身份
    SourceNets     []netip.Prefix  // 白名单源（替代 Proto+ListenAt）
    OutIP          netip.Addr      // SNAT 目标（替代 Backend）
    IfIn, IfOut    string          // 网卡前置条件
    MetaMarkExempt uint32          // 发布流量豁免（MarkDNAT=0x4）
    Enabled, Counter
}
```

**结构上就没有 Proto 字段** —— 协议校验问题从根上消失。

`CompileSnatRules` 每条源网段生成**两条**规则：
① 放行+改写行（`saddr ∈ 源` + `snat ip to OutIP`）
② 回程计数行（`daddr ∈ 源`，无 verdict）

② 是 AGENTS.md 的硬要求：只装上行的计数会让页面速率只反映 ACK 小包
（实测过 3.54MB/s 显示成 68.9KB/s）。

### 修复后 B-1 的实际比对结果

期望摘要（4 条，由真实编译路径产出）：

```
srcnat  iifname eth0 oifname eth0 meta mark & 0x4 == 0x0 @nh,96,32  0xc0a80a98 snat ip to 192.168.10.170 counter
srcnat  iifname eth0 oifname eth0 meta mark & 0x4 == 0x0 @nh,128,32 0xc0a80a98 counter
srcnat  iifname eth0 oifname eth0 meta mark & 0x4 == 0x0 @nh,96,32  0xc0a80a97 snat ip to 192.168.10.170 counter
srcnat  iifname eth0 oifname eth0 meta mark & 0x4 == 0x0 @nh,128,32 0xc0a80a97 counter
```

现网实际（8 条）：

```
pre_mark  ct state established,related meta mark set meta mark | 0x1
fwd       ... @nh,96,32  0xc0a80a98 counter meta mark set meta mark | 0x1
fwd       ... @nh,96,32  0xc0a80a97 counter meta mark set meta mark | 0x1
fwd       ... @nh,128,32 0xc0a80a98 counter
fwd       ... @nh,128,32 0xc0a80a97 counter
fwd       iifname eth0 meta mark & 0x1 == 0x0 counter drop
srcnat    ... @nh,96,32  0xc0a80a98 snat ip to 192.168.10.170        ← 无 counter
srcnat    ... @nh,96,32  0xc0a80a97 snat ip to 192.168.10.170        ← 无 counter
```

### 消除掉的三个假差异（都是我的比对器缺陷，不是现场问题）

| # | 假差异 | 归一化处理 |
|---|---|---|
| 1 | 网卡名带引号 `iifname "eth0"` vs `iifname eth0` | 剥引号 |
| 2 | 掩码宽度 `0x4` vs `0x00000004`、`== 0` vs `== 0x00000000` | 补零到 32 位 + 裸 0 归一 |
| 3 | 动作切分位置不同（一侧在 Match、一侧在 Action） | 两侧统一：整行放 Match |

### 剩下的差异是**真实的**

期望侧有 4 条 `srcnat` 规则，现网只有 2 条（且不带 `counter`）。
差异根源：

| 项 | 现网（旧实现） | 新编译产物 |
|---|---|---|
| srcnat 规则数 | 2（每源一条 SNAT） | 4（每源：放行 + 回程计数） |
| srcnat counter | **无** | **有** |
| 回程计数位置 | 在 `fwd` 链（`@nh,128,32` 那两条） | 在 `srcnat` 链 |

**这不是 bug，是两代设计的真实差异**：

- 旧实现把「回程计数」放在 `fwd` 链，靠 `meta mark & 0x1`（established 打标）放行
- 新设计（AGENTS.md 第 64 条）把回程计数放在 `srcnat` 的 `daddr=源` 行，
  与 SNAT 放行行共用 comment 汇总

也就是说：**新编译器产出的规则集与旧实现不等价，且差异是刻意设计的**。

## B-1 的最终结论

| 问题 | 答案 |
|---|---|
| 比对器能跑通吗 | ✅ 能，且只读、生产安全 |
| 新旧规则集等价吗 | ❌ **不等价**，差异是真实的（回程计数位置 + srcnat counter） |
| 差异是好还是坏 | 需要判断：新设计把回程计数移到 srcnat，是否比旧设计更好？ |
| B-2 能直接开工吗 | **不能**——需要先确认这个设计变更是否要保留 |

## B-2 之前必须决策的一件事

**回程计数应该放 `fwd` 链还是 `srcnat` 链？**

| 方案 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| **保持旧设计** | 回程计数留在 `fwd`（`@nh,128,32` 行） | 与现网行为一致，B-2 风险小 | 计数分散在两个链，汇总要看两处 |
| **采用新设计** | 回程计数移到 `srcnat` 的 `daddr=源` 行 | 与 SNAT 放行行同链同 comment，汇总简单 | 与现网行为不同，切换时计数会断档 |

AGENTS.md 第 64 条写的是「`CompileSNAT` 为每个源追加一条 `daddr=源` 的只计数行
（无 verdict）」——**新代码遵循了 AGENTS.md，但现网跑的是旧实现**。

所以这不是「新代码错了」，而是「AGENTS.md 描述的目标形态与现网当前形态不同」。
这是升级本身的预期差异，不是缺陷。

**需要你确认**：B-2 切换时接受这个计数位置变更（计数断档一次），
还是有别的顾虑？

---

## 本次执行的安全边界（可核查）

- DB 打开方式：`file:<path>?mode=ro` —— SQLite 层面禁止写
- 内核读取：只用 `nft -a list table inet haweb`
  （测试 `TestLegacyReaderOK` 断言命令形态必须是这个字符串）
- 未调用 `apply` / `commit` / `drop` 任何写接口
- 执行前后对比：`haweb` 规则数 8 → 8，服务 PID 不变，`ifb` filter 数不变
