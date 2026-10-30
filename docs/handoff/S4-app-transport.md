# 交接卡 · S4 app + transport

**阶段**: S4 — 用例层 + 传输层
**日期**: 2026-10-30
**本轮提交范围**: `0e93279`（5 个新文件，约 1,900 行含测试）

---

## 已完成

| 文件 | 内容 |
|---|---|
| `internal/app/policyapp/service.go` | 策略用例：启停（禁用踢会话）、删除（踢会话）、保存（按影响面判定踢不踢） |
| `internal/app/sessionapp/service.go` | 会话用例：批量踢（逐条容错 + 去重 + 上限）、名单组踢会话 |
| `internal/transport/httpapi/handler.go` | 五个接口 + `{code,message,data}` 统一格式 |
| `internal/app/*/service_test.go` | 24 个测试 |
| `internal/transport/httpapi/*_test.go` | 15 个测试（含端到端） |

**覆盖率**：policyapp 87.1% / sessionapp 88.9% / transport 80.0%。`go test -race` 通过。

---

## 本轮修掉的旧缺陷（最重要）

### 禁用策略不踢会话 → 验收直接不通过

**旧实现**（`internal/api/fwpolicy.go:206`）：

```go
if kill && pol.Action == "drop" {
    killed = h.Mgr.KillPolicySessions(*pol)
}
```

`disable` 路径**完全不踢会话**，而 `newFlowGuard()` 只拦 `ct state new`，
已建会话最长存活 86400s。这就是验收文档「禁用策略后流量立即断开」
不通过的原因。

**新实现**（`policyapp.Service.SetEnabled`）：

| 操作 | 行为 |
|---|---|
| 启用 | 只重装规则，**不踢会话**（放宽/收紧新连接，没理由打断现有连接） |
| 禁用 | 重装 + **立即踢掉所有匹配会话** |
| 删除 | 重装 + 踢会话（否则会「幽灵放行/幽灵拒绝」） |
| 保存 | 按 `needsKick` 判定：任一版本是 drop、或 accept→收紧 → 踢；纯放宽 → 不踢 |

**顺序固定「先改库 → 再重装 → 再踢会话」**。反了会出现「内核已无规则
但库还标着启用」，重启后策略复活（有单测 `TestDisableOrderStoreThenInstall`
验证重装时库里已是禁用状态）。

`needsKick` 抽成独立纯函数，11 个子用例穷举覆盖。

---

## 本轮确定的实现事实（下一阶段必须遵守）

### 1. app 层用接口注入依赖，不 import gorm/gin

`policyapp.Store` / `SessionKiller` / `Reinstaller` / `Auditor` 全是接口。
收益：app 层的测试不需要建数据库、不需要 root、不需要真机。

**新增用例时保持这个模式**：端口定义在 `app/<domain>/`，实现放 `adapter/`。

### 2. transport 层零业务判断

`grep -c "switch .*\.Action" internal/transport/httpapi/*.go` = **0**。

⚠️ 注释里不要写这个模式本身（会造成 grep 假阳性，本轮踩过）。

transport 不 import gorm / netlink / sqlite，也不直接碰 db（§8.6）。

### 3. 响应格式定死 `{code, message, data}`

保留旧的 `{error: ...}` 会被测试 `TestErrorResponseShape` 拦住。
错误码分段：40000 参数 / 40400 不存在 / 40900 冲突 / 50300 依赖未就绪 /
50000 内部。

`message` 必须中文且不含内部细节——测试断言不含 `SELECT`/`/proc/`/
`goroutine`/`.go:`。

### 4. 批量操作的容错语义

`KillBatch` 的三分类必须分开报告：
- `killed`：成功
- `not_found`：会话已自然结束（**不是错误**，长时间打开的页面上是常态）
- `failed`：真失败，原因是白名单化的粗分类（不泄露内部细节）

单条失败**不影响其它条**（批量接口不能因为一条失败就整体回滚）。
单次上限 1000 条——一次踢 10 万条会同时打爆 conntrack 与审计日志。

### 5. 踢会话失败时的行为

- 禁用策略时踢会话失败：**不回滚启停**（规则已撤，安全性已达成；
  残留会话靠 conntrack 超时自然消亡），但必须上报错误
- 重装规则失败：**中止**，不继续踢会话（规则还没撤，踢了会立刻重连）
- 名单组踢会话时单条失败：继续处理其余（组里通常几十上百条）

---

## 未完成 / 降级

| 项 | 状态 | 影响 |
|---|---|---|
| `app/ruleapp`、`egressapp`、`authapp`、`backupapp`、`settingsapp` | **未实现** | 本轮只做了策略与会话两个最关键的域（对应三个缺失接口） |
| 45 个接口的完整契约测试 | **部分**：本轮 5 个 | 其余接口仍在 `internal/api`（旧实现，51 条路由），迁移到 transport 是后续工作 |
| `docs/openapi.yaml` | **未写** | DoD 第 5 条；建议在接口全部迁完后一次性生成并加测试校验 |
| `internal/api` 与 `internal/transport/httpapi` 的共存 | **并存** | 旧 `api` 包未删除（它服务现有前端且测试全绿）。迁移策略：逐域搬到 app+transport，两边都跑通后再删旧实现 |

---

## 偏离技术方案的地方

| 文档原文 | 实际实现 | 理由 |
|---|---|---|
| §8.2 清单 45 个接口 | 本轮只实现 5 个（3 个新增 + 2 个删除/启停） | 三个缺失接口是验收阻塞项，优先做；其余已在旧实现中可用，迁移不必一次完成 |
| §8.3「改带宽包立即重下发 tc」 | 未在本轮 | 属于 `bwgroupapp`，不在本轮范围（本轮只做策略与会话） |
| §8.5「45 个接口全部有契约测试」 | 5 个有 | 同上 |

**这不是「跳过」，是「按阻塞优先级切片」**：三个缺失接口直接对应验收
不通过的用例，其余接口旧实现已能跑通。

---

## 发现的文档问题

1. **§8.5 的 grep 检查命令需要排除注释**：`grep -c "switch .*\.Action"`
   会把注释里的示例代码也算进去。建议文档加一句「注释里不要写这个模式」
   或改用 `grep -c "switch .*\.Action" --include="*.go" | grep -v "//"`。
2. **§8.3 未说明「踢会话失败时是否回滚启停」**。本实现的判定是
   「不回滚」——规则已撤即安全性达成，残留会话靠超时自然消亡。
   建议文档明确这个取舍。

---

## 依赖申请

无。本轮只用了已有的 `gin-gonic/gin`（C-13 白名单），`go.mod` 未变。

---

## 下一阶段的入口

**必须先读**：
- `docs/handoff/S3-sqlite-logstore.md`（双库结构、logstore 的丢弃计数）
- `docs/handoff/S2-tcnetlink.md`（`ctnl.Engine.KillSession` 的用法）
- 本卡「本轮确定的实现事实」全部 5 条

**S5 的关键待办**：
1. `platform/caps` 能力探测（nftables / conntrack / tc / ifb / CAP_NET_ADMIN
   / sqlite WAL），缺失必须在 UI 可见
2. `backup`：local / sftp / s3 三种目标，每种都要 sha256 + 回滚可用性验证；
   **不许 `sh -c` 拼命令**（D-15）
3. `cmd/haproxyweb/main.go` ≤ 100 行，顺序：读配置 → 建 logger → 探测能力 →
   打开库 → 建 Engine → 启 control loop → 启 HTTP → 启信号处理
4. 把 `app/policyapp` 与 `app/sessionapp` 接到真实的 `proxy.Manager` 与
   `ctnl.Engine`（当前只有测试替身）

**迁移旧接口的顺序建议**：
先 `bwgroupapp`（改带宽包要立即重下发 tc，与 S2 直接相关），
再 `ruleapp`（规则 CRUD + 热更新），最后 `authapp`/`settingsapp`/`backupapp`。

---

## 待你确认的问题

无。
