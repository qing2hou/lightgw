# 交接卡 · P0 技术假设验证

**阶段**: P0 — 技术假设验证（PoC）
**日期**: 2026-10-30
**本轮提交范围**: 仅新增 `docs/poc-result.md`（668+ 行）。**未修改任何 `internal/` 生产代码。**

---

## 已完成

| 交付物 | 路径 | 内容 |
|---|---|---|
| PoC 完整报告 | `docs/poc-result.md` | 任务 A / B / C 全部原始输出、实测/配置/误差三数、冲突清单、现场恢复证据 |
| 交接卡 | `docs/handoff/P0-poc.md`（本文件） | 本阶段结论与下一阶段入口 |
| 检查点提交 | `c3ef724` | 每源 htb 保底子类 + ifb 上传路径 + tc 序列串行化（作业前既有改动，验证全绿后提交） |
| 文档订正 | ADR-15 / §3.5.3 / §3.5.7 / §3.5.8 / §10 / `AGENTS.md` 第 67 条 | 按实测结论修正总额语义与 tc 结构 |

**任务 A · 上传方向限速修复**（`poc-result.md` §3）

- 现场缺陷复现：实测 **112.2485 MB/s** / 配置 8 MB/s / **+1303.1%**（14.03 倍）
- 仅改 `match ip dst → src`：**8.0954 MB/s** / 8 / **+1.19%**
- 完整修复结构：**7.7595 MB/s** / 8 / **−3.01%**，`direct_packets_stat` 增量 **0**

**任务 B · `MinKBps` 保底**（§4）

- 等保底 1+1（总额 4）：合计 **3.8751**，`borrowed` 各 +3,941 / +3,973
- 不等保底 1:2（总额 4）：**1.3162 : 2.5579 = 1 : 1.943** → HTB 真在读 `rate`
- 二维扫描 15 组：总量 ≈ **`max(parent.rate, Σ子类rate)`**，误差 −2.5%~−4.2%

**任务 C · 双表热切换原子性**（§6.3）

- 60 次翻转 / **0 异常** / `jump` 恒为 1 / 客户端 300s **零 reset**（104.79 MB/s 稳定）
- 两工作链各承载 ~11 GB（704,457 / 710,846 包），证明每次切换都真实改变数据面

**§3.5 eBPF 备选**（§8.1）：结论 5 行 + 三个未知点，未写任何 eBPF 代码。

---

## 未完成 / 降级

| 项 | 状态 | 为什么降 | 影响什么 |
|---|---|---|---|
| `CommitShadow` 失败回滚 | **未验证** | Task C 的工作链只有 `counter`，装什么都不会影响转发，无法覆盖「影子链装配失败 → 旧链仍服务」这条异常路径 | S1 DoD 第 3 条（注入 `AddRule` 失败）必须覆盖 |
| `burst` 随速率缩放 | **未验证** | 本轮只测 8 MB/s，未测千兆 | S2 用 1Gbps 复验 |
| ifb 上 policing 与 htb 并存 | **未验证** | ADR-15 已选方案 A，不需要 policing | 仅当将来改选方案 B 时才需补验 |

以上三项均**不阻塞** S0 / S2 开工。

---

## 已决策事项（原「待确认」，现已闭环）

### 决策 1 · 超额订阅的产品语义 → **方案 A（约束式）**，见 ADR-15

`docs/requirements-rewrite-v2.md` §8.16 ADR-15：

- **决策**：`domain/bandwidth` 在保存带宽包时校验 `Σ(成员 MinKBps) ≤ 总额`，超额**拒绝保存**并返回可读错误；查询侧提供「实际可分配保底 = 总额 ÷ 已配源数」供 UI 提示。
- **不做的**：不在 ifb / 出口网卡叠 `police` 做硬丢包（方案 B）；**不接受**「总额可超卖」（方案 C）。
- **理由**：方案 B 的 policing 与 htb 并存**未验证**且丢包会误伤 TCP；方案 C 与「带宽包总额」的产品语义矛盾（客户按总额采购却被超卖）；方案 A 是纯 domain 校验，零内核复杂度、可完整单测。
- **代价**：用户不能配置超额订阅，多源包必须显式配小保底。
- **S0 落地位置**：`internal/domain/bandwidth/`。

### 决策 2 · `internal/` 两处未提交改动 → **验证后提交为检查点 `c3ef724`**

- 内容：每源 htb 保底子类 + ifb 上传路径 + `tcMu` 序列串行化 + `tcOwnedClasses` 所有权差集清理 + `ifbNameFor` 按包隔离。
- 提交前验证：`go build ./...` ✅ / `CGO_ENABLED=0 go build ./...` ✅ / `go vet ./...` ✅ / `go test ./...` ✅（全部包 ok）
- 同时修正了 `manager.go` 的 gofmt（新增字段未对齐；另 3 个 gofmt 不合规文件是 HEAD 既有问题，不属本轮范围）。
- `git status internal/` **现已为空**，DoD 最后一项满足。
- **该提交保留了已知缺陷**：上传方向 ifb 侧分类 filter 仍写 `match ip dst`（`snat.go:1848`），与 §3.2 实测结论不符。提交信息里已明确记录，**修复留待 S2 按正确结构重写**，避免同一处反复改。

### 决策 3 · 文档修订 → **已按实测完成**

| 文件 | 改了什么 |
|---|---|
| `docs/requirements-rewrite-v2.md` | 新增 **§8.16 ADR-15**（总额语义：约束式） |
| `docs/design-rewrite-v2.md` §3.5.3 | 重写结构图：新增叶子兜底类、fq_codel 挂叶子、`default` 指向叶子；补三条硬约束及实测反证 |
| `docs/design-rewrite-v2.md` §3.5.7 | 订正「总额硬上限」为 `max(parent.rate, Σ子类rate)`；补不等保底对照实测 |
| `docs/design-rewrite-v2.md` §3.5.8 | 验证状态表全部更新（4 项已验证 / 2 项未验证） |
| `docs/design-rewrite-v2.md` §10 | 假设 1 改「✅ 通过」，新增假设 5「总额硬上限 ❌ 被证伪」，PoC-1 标记已通过并写入实测结果与踩坑 |
| `AGENTS.md` 第 67 条 | 改为四条硬约束：①上传 src / 下载 dst；②`default` 必须指向叶子类（内层 = 100% 绕过）；③fq_codel 只能挂叶子（内层报 EINVAL）；④`parent.rate` 不是硬上限 |

---

## 本轮确定的实现事实（下一阶段必须遵守）

### 1. tc 树的正确结构（**与设计文档 §3.5.3 有两处不同**）

```
qdisc htb 1: root default <兜底叶子类号，如 199>        ← ★ default 必须指向叶子类
class 1:100  parent 1:      rate=ceil=<带宽包总额>
class 1:199  parent 1:100  rate=<?> ceil=<总额>          ← ★ 新增：承接 default 的叶子兜底类
  qdisc fq_codel 199: parent 1:199                       ← ★ fq_codel 挂叶子，不能挂 1:100
class 1:1NN  parent 1:100  rate=<MinKBps> ceil=<总额>
  qdisc fq_codel 1NN: parent 1:1NN                       ← ★ 每源叶子各挂一个
filter parent 1: pref <srcFilterPref>  u32 match ip dst <客户端>/32 flowid 1:1NN   ← 下载
（上传方向 ifb）
filter parent 1: pref <uploadFilterPref> u32 match ip src <客户端>/32 flowid 1:1NN ← ★ src
```

**三条硬约束（都有实测反证支撑）**：

1. **`default` 不能指向挂了子类的内层类**。指向 `1:100` 时，未命中 filter 的包进不了任何队列 → 走 `direct queue` 绕过整棵树。实验室实测：`default` 指向叶子时 7.81 MB/s（`direct=0`），指向内层后 **2828.79 MB/s**。
2. **`fq_codel` 不能挂内层类**。`tc qdisc add ... parent 1:100 fq_codel` 返回 `RTNETLINK answers: Invalid argument`。
3. **ifb 侧分类 filter 必须 `match ip src`**。现场成因：`at 16`（目的地址）永不命中，因为包进 ifb 后 `daddr` 是公网服务器。

### 2. 总额约束的真实公式

```
实际总量 ≈ max(parent.rate, Σ children.rate)        误差 −2.5% ~ −4.2%（15 组）
```

**`parent.rate` 是「保底总池」，不是上限。** 要让总额成为硬上限，唯一办法是保证 `Σ MinKBps ≤ 带宽包总额`。

### 3. nft 侧事实

- 同一 hook 上不同 priority 的链**全部会被遍历**，前序链的 `policy accept` **不短路**后续链（四条探针链各 72,029 包，完全相等）。
- `netlink batch` 内 `delete rule` + `add rule` 提交 `jump` 替换：60/60 成功，零空窗。

### 4. 现场部署状态

- 在跑的二进制 `/usr/local/bin/haproxyweb`（md5 `05fa7edd…`）**不等于工作区代码**：设备名是 `ifb-haweb`，而 `ifbNameFor()` 生成 `ifb-hw<N>`；filter `pref` 硬编码 10。
- 带宽包配置：`bw_groups.id=1`，`total_kbps=8192`，`min_kbps=1024`。

---

## 偏离技术方案的地方

| 文档原文 | 实际实现/结论 | 理由 |
|---|---|---|
| §3.5.3 `qdisc fq_codel 100: parent 1:100` | 挂到**每个叶子类**，并新增叶子兜底类承接 `default` | 实测 `RTNETLINK answers: Invalid argument`；且内层类做 default 会 100% 绕过 |
| §3.5.3「`1:100` 总额硬上限」 | 实为 `max(parent.rate, Σchildren.rate)` | 15 组实测反证 |
| §3.4 / D-06「`default` 必须是总额类号 `100`」 | `default` 必须是**叶子**类，`100` 是内层类不能当 default | 同 1 |
| `AGENTS.md` 第 67 条「双向 htb（总额父类 + 每源保底子类 + fq_codel）」 | 结构成立，但缺「叶子兜底类」与「fq_codel 挂叶子」两个条件，且总额不硬 | 实测 |

---

## 发现的文档问题

1. `design-rewrite-v2.md` §3.5.3 的上传方向结构图，`ifb-<bwID> filter ... match ip src` 与 `class 1:100` 的组合**缺少 default 归属说明**——这是现网 14 倍超速的第二层原因。
2. `design-rewrite-v2.md` §3.5.7 只说「超额订阅时不保证每源拿到 1024」，**没说会突破总额上限**。
3. `agent-playbook.md` §3.2 Step 2 的判定表「只有 8MB/s 说明现场已被修过」不严谨：`default` 指向内层类时，未分类流量绕过，但**若恰好所有流量都因别的原因被限住**，也可能看到 8MB/s。**必须同时检查子类 `Sent` 与 `direct_packets_stat`。**
4. `design-rewrite-v2.md` §10 假设 1 的状态应从「待验」改为「`jump` 原子性 ✅ / `CommitShadow` 回滚 ❗」。
5. `docs/poc-nftables.md` 是 v1 的 `google/nftables` **库能力**验证（10/10 PASS），与本轮的任务 C（**内核面** `jump` 原子性）不是同一件事，不要混淆。

---

## 依赖申请

无。本轮未新增任何依赖，未改动 `go.mod`。

---

## 下一阶段的入口

**必须先读**：

- `docs/poc-result.md`（本阶段全部结论，尤其 §3.2、§4.2.1、§5.4、§6.3.5）
- `docs/design-rewrite-v2.md` §2（核心类型）、§3.5（限速，**需按本卡纠正**）、§11（目录）
- `docs/agent-playbook.md` §2（宪法 C-01~C-18 / D-01~D-19）
- `AGENTS.md`（第 67 条需按本卡纠正）

**已知的坑**（下一轮会再踩）：

1. **T23 · `default` 指向内层类 = 静默 100% 绕过**。任何 `applyHtb` 实现都要断言 `default` 指向的类 `!hasChildren && hasQdisc`。
2. **T24 · `fq_codel` 挂内层类报 EINVAL**。要么挂叶子，要么不挂。
3. **T25 · 总额不是硬上限**。`CompileTc` 与 `domain/bandwidth` 必须校验 `Σ MinKBps ≤ 总额`（ADR-15 方案 A）。**不存在「配了就一定拿到总额」的语义**。
4. **T26 · 打流端位置决定实验有效性**。在网关本机打流走 OUTPUT 不进 FORWARD；验证 nft forward 规则时必须从客户端发起。**必须用 counter > 0 做前置自检**，否则「切换 0 异常」会被误读为「原子性成立」。
5. **T27 · SSH 远端路径**。客户端上不存在的目录（如网关侧 `/tmp/poc-flip`）会让发送脚本 `open()` 直接抛异常，且 `setsid nohup ... &` 会让 ssh 不返回（需 `> /dev/null 2>&1 < /dev/null & disown`）。
6. **T28 · `pkill -f <script>` 会杀掉自己的 ssh 命令**（命令行含同串）。用 `ps -eo pid,args | grep "[p]attern"` 精确取 PID。
7. **T29 · 同一 hook 上不同 priority 的链全部会被遍历**，前序链的 `policy accept` **不短路**后续链（四探针链各 72,029 包，完全相等）。但 `drop` 会。所以 PoC/观测链只放 `counter`，**绝不放 `accept`**——放了会在业务链之前终结遍历，等于绕过业务的按源放行/拒绝。

---

## 待你确认的问题

**无。** 原三项待确认已于收尾时闭环：

1. ~~超额订阅语义~~ → **ADR-15 方案 A**（约束式），已写入 `docs/requirements-rewrite-v2.md` §8.16
2. ~~`internal/` 两处未提交改动~~ → 验证全绿后提交为检查点 **`c3ef724`**，`git status internal/` 已为空
3. ~~文档是否修订~~ → 已按实测修订 `design-rewrite-v2.md`（§3.5.3 / §3.5.7 / §3.5.8 / §10）、`requirements-rewrite-v2.md`（新增 ADR-15）、`AGENTS.md` 第 67 条

**S0 现在可以开工。** 入口：`domain/` + `compile/` 纯函数层，按 `design-rewrite-v2.md` §11 的目录结构与 §2 的核心类型。带宽包校验按 ADR-15。
