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

## 缺口 3 · compile 层不支持 SNAT 规则（新发现，阻塞 B-1 收尾）

按原计划把 `ExpectationDigest` 改成走真实编译路径，实现 `CompileState`
（DB 实体 → `compile.State`），然后调 `Compiler.Compile`。

**实测失败**：

```
digests=0 err=编译失败: 配置校验失败: 校验规则[test#30] 失败:
               校验规则失败: 协议 "" 无效（只支持 tcp/udp）
```

根因不是转换 bug，是**建模不匹配**：

`compile` 层先跑 `rule.Validate`，它要求每条规则的 `Proto ∈ {tcp, udp}`：

```go
if !r.Proto.Valid() {
    return fmt.Errorf("校验规则失败: 协议 %q 无效（只支持 tcp/udp）", ...)
}
```

但 **SNAT 规则没有「协议」概念** —— 它作用于所有协议的穿越流量。
现网规则#30 的 `protocol` 字段值是 `"snat"`，不是 `tcp`/`udp`。

`domain.Rule` 的结构是为 **DNAT**（端口转发：`Proto` + `ListenAt` + `Backend`）
设计的，SNAT 只有「源集合 + 出口 + 目标地址」，套不进那个形状。

### 这条缺口的影响

| 项 | 状态 |
|---|---|
| B-1 的「走真实编译路径」 | ❌ 阻塞 |
| 手写映射（`ExpectationDigest`） | ⚠️ 可用但表达力不足（不含前置条件） |
| B-2 装配 | ❌ 阻塞（SNAT 规则无法编译，就没法下发） |

### 必须先补的设计缺口（S0 遗留）

`compile` 层需要为 SNAT 引入**独立类型**（或放宽 `rule.Validate` 对 SNAT 的协议要求）。
两个方向的取舍：

| 方案 | 做法 | 代价 |
|---|---|---|
| **A · 独立类型** | 新增 `compile.SnatRule`（源集合 + 出口 + 目标 + 前置条件），`CompileSnat` 改用它 | `compile.Compiler` 的 `State.Rules` 要拆成 `DnatRules` / `SnatRules` |
| **B · 放宽校验** | `rule.Validate` 对 `Proto == "snat"` 跳过协议检查 | 语义混乱：`Proto` 字段既存协议又存规则类型 |

**我倾向 A**：SNAT 与 DNAT 本来就是两类规则（一个是「谁能穿出去」，一个
是「谁能进到后端」），共用一个结构只会让两边都别扭。B 方案会让
`Proto` 字段变成「有时是协议、有时是类型」的双关，与 AGENTS.md
记录的「字段语义要单一」原则冲突。

这是 S0 阶段的设计缺口，当时只按 DNAT 建模、SNAT 留了 TODO 没验证。
**B-2 开工前必须先补这一块。**

---

## 下一步

1. **补 compile 的 SNAT 建模**（方案 A）→ 这是 B-2 的前置
2. 补完后 B-1 自动可用：`ExpectationDigest` 改走编译路径，重新比对
3. 拿到真实差异后再决定 B-2 怎么做

---

## 本次执行的安全边界（可核查）

- DB 打开方式：`file:<path>?mode=ro` —— SQLite 层面禁止写
- 内核读取：只用 `nft -a list table inet haweb`
  （测试 `TestLegacyReaderOK` 断言命令形态必须是这个字符串）
- 未调用 `apply` / `commit` / `drop` 任何写接口
- 执行前后对比：`haweb` 规则数 8 → 8，服务 PID 不变，`ifb` filter 数不变
