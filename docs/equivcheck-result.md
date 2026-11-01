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

## 下一步（B-1 补完）

把 `ExpectationDigest` 从「手写映射」改成「走 compile 编译」：

1. 新增 `BuildCompileState(Rules) compile.State`：
   DB 实体 → `compile.State`（`model.Rule` 用 `netip.AddrPort`，需解析地址）
2. `ExpectationDigest` 改为：
   `Compiler.Compile(state)` → 遍历 `Plan.Nft.Snat/Dnat/Forward` →
   每个 `compile.Rule` 转成 `RuleDigest`（**包含** Src/Dst/MetaMarkNotSet 等条件）
3. 重新比对；若仍不等价，差异就是真实的「新编译器与旧实现的语义差异」，
   那才是 B-2 之前真正要讨论的

这样做的额外收益：`BuildCompileState` 是 B-2 装配时**必须要有**的代码，
现在写正好复用。

---

## 本次执行的安全边界（可核查）

- DB 打开方式：`file:<path>?mode=ro` —— SQLite 层面禁止写
- 内核读取：只用 `nft -a list table inet haweb`
  （测试 `TestLegacyReaderOK` 断言命令形态必须是这个字符串）
- 未调用 `apply` / `commit` / `drop` 任何写接口
- 执行前后对比：`haweb` 规则数 8 → 8，服务 PID 不变，`ifb` filter 数不变
