# HAProxyWeb 项目总览与生产就绪评估

> 面向对象：接手本项目的工程师/运维。第一部分回答"这是什么"，第二部分回答"放上生产前还差什么"。
> 本文所有技术断言基于代码取证（初始评审 commit `735db16`，§4 差距修复状态更新至 `f9b8b7a`）。
> 结论速览：**首轮评审的 4 个 P0 与 7 个 P1 中，除 2FA/监控令牌/CI/LICENSE 等已全部修复（见 §4.5 修复记录）外，剩余项见 §4.2/§4.3**。

---

## 1. 这个项目是做什么的

**HAProxyWeb 是一个纯 Go 实现的 TCP/UDP 四层端口转发平台，自带 Web 管理后台，单二进制交付。**

名字里的 "HAProxy" 只是历史命名——它与 HAProxy 软件零交互（无 exec、无 haproxy.cfg）。它解决的问题：

> 你有一批"把 A 机器的某端口转发到 B 机器的某端口"的需求（如把 `:9000` 映射到内网 `10.0.0.5:3306`），
> 手写 iptables/socat 难以管理、无审计、无观测。HAProxyWeb 让你在浏览器里完成转发规则的
> 创建/启停/限速/黑白名单，每条会话有流量日志，每次操作有审计，后端挂了有健康检查和告警数据。

### 1.1 核心能力（全部已实现并经代码验证）

| 能力 | 说明 | 代码位置 |
| --- | --- | --- |
| TCP 端口映射 | 四层转发，空闲超时可按规则覆盖 | `internal/proxy/tcp.go` |
| UDP 转发 | 按客户端会话表转发，空闲 60s 回收 | `internal/proxy/udp.go` |
| 规则热更新 | 监听地址不变则零中断；`ruleConfig` 经 `atomic.Pointer` 原子替换 | `internal/proxy/manager.go` |
| 限速 | 每规则独立上/下行令牌桶 + 整机带宽上限 | `internal/ratelimit/` |
| 连接上限 | 全局 + 规则双信号量，成对获取/释放 | `internal/proxy/manager.go` |
| IP 黑白名单 | 单 IP 与 CIDR，黑/白名单模式互斥 | `internal/proxy/acl.go` |
| 后端健康检查 | TCP 规则每 60s 连接探测，状态翻转才记日志，历史落库 | `internal/proxy/health.go` |
| 流量日志 | 每会话一条（双向字节/状态/耗时），channel + 批量落库 | `internal/trafficlog/` |
| 操作审计 | 登录/改密/规则增删改启停/导入导出全部留痕 | `internal/audit/` |
| 零中断升级 | SIGUSR2 交接监听 fd，存量长连接不断 | `internal/proxy/upgrade.go`, `main.go:297` |
| 配置热加载 | SIGHUP 重读配置，转发面参数即时生效 | `main.go:154` |
| 可观测性 | `/healthz` 探针（不鉴权）、`/api/metrics`（Prometheus 文本）、pprof、运行监控页 | `internal/api/router.go:109`, `internal/api/metrics.go` |

### 1.2 架构速览

```
┌────────────────────────── 单二进制 haproxyweb ──────────────────────────┐
│                                                                         │
│  internal/api (管理面)              internal/proxy (数据面)              │
│  ┌────────────────────┐             ┌────────────────────────┐          │
│  │ gin REST + 嵌入式   │──Mgr.Apply/Stop──▶ Manager(热更新) ──▶ TCP/UDP  │
│  │ Vue3 前端(go:embed) │             │  与 DB 解耦,规则快照     │  转发引擎 │
│  └─────────┬──────────┘             └───────────┬────────────┘          │
│            │              SQLite (WAL, 纯 Go 驱动无 cgo)                │
│   trafficlog/audit 异步批量写  ◀──────────────┘                          │
└─────────────────────────────────────────────────────────────────────────┘
```

- **两层解耦**：API 层通过 `Mgr.Apply/Stop` 驱动引擎，引擎不依赖 DB 读取热路径配置（启动时加载快照，运行时原子替换）。
- **数据全部落 SQLite**：规则/用户/流量日志/审计/健康历史/登录锁定。内存只留运行瞬态（连接、计数器、健康当前状态）。
- **JWT 密钥刻意不入库**（`data_dir/secret.key`，0600）——全库快照下载不能带走签名密钥（`internal/auth/auth.go:55`）。

### 1.3 技术栈与规模

- 后端：Go 1.25 + gin 1.12 + GORM + glebarez/sqlite（纯 Go，无 cgo，交叉编译即拷贝即用）
- 前端：Vue 3 + Element Plus + Pinia，构建产物嵌入二进制（`main.go:34` go:embed）
- 测试：`go test ./...` 全绿（2026-10-20 实测 `make test` 与绕缓存复跑均 exit=0；9 个包中 7 个含测试 —— api/proxy/auth/ratelimit/store/trafficlog/audit/config，覆盖转发引擎/认证锁定/备份/热升级等集成测试）
- 历史约 44 个 commit，粒度"一个功能一个 commit"

---

## 2. 部署形态（已具备的）

仓库自带生产部署的一整套件（`deploy/`）：

- **systemd 单元**（`deploy/haproxyweb.service`）：Type=notify、沙箱加固（ProtectSystem=strict、仅数据目录可写、NoNewPrivileges、CapabilityBoundingSet 仅 CAP_NET_BIND_SERVICE、LimitNOFILE=65535）、Restart=on-failure
- **每日备份 timer**（`deploy/haproxyweb-backup.{service,timer}`）：03:00 sqlite3 在线备份，保留 30 份
- **备份三件套**：全库快照（VACUUM INTO 在线一致性）/ 规则导出 JSON / `sqlite3 .backup` 命令行
- **Prometheus 告警规则示例**（README §可观测性）：后端不可达 / panic 隔离 / 日志丢弃 / 规则启动失败

---

## 3. 投产前必须理解的设计边界

这些不是缺陷，是**设计取舍**，评估生产适配时要知道：

1. **单管理员模型**：没有多用户/角色系统。首次启动种子用户 `admin`（`internal/store/store.go:65`），强制改密后所有操作都以同一账号审计。团队使用时无法区分操作者。
2. **SQLite 单实例，无 HA**：单写者模型，无主从/多活。宕机 RTO ≈ systemd 拉起（约 3 秒）；数据 RPO 取决于备份间隔（每日备份 = 最坏丢 24h 的**日志与配置变更**；转发本身无状态）。
3. **管理面与数据面同进程，`/healthz` 是唯一不鉴权端点**：所有可观测端点都在管理端口内（无独立监听），且 `/healthz` 无需登录即返回版本、规则数、活跃会话数、后端状态、库体积等运营数据（`internal/api/router.go:109`）——供探针使用是明确取舍，但该端口若对公网可达即暴露运营情报，管理端口的可达性策略直接决定暴露面。
4. **UDP 无健康检查**：无握手语义，探测无意义（与 HAProxy tcp-check 的取舍一致）。
5. **splice 快路径的代价**：开启后未限速规则走内核 splice，实时字节统计不刷新、空闲超时不生效（`config.yaml:33` 有注明）。
6. **转发面错误细节不回传访问者**：后端不可达等信息只进日志/审计，访问者侧看不到——安全上对，排障时要看服务端日志。

---

## 4. 生产就绪差距清单

> 评级口径：
> **P0 阻断**：不解决不应上线（明文凭证/无人守护主干/丢数据风险）
> **P1 应做**：上线后第一个迭代内补齐
> **P2 增强**：按需排期

### 4.1 P0 —— 上线前必须解决（本轮已全部修复，见 §4.5）

| # | 问题 | 证据 | 说明与修复方向 |
| --- | --- | --- | --- |
| P0-1 | **TLS 默认关闭** | `config.yaml:11-12` cert/key 被注释；启动时仅打日志警告（`main.go:147`） | 明文 HTTP 下 JWT 与登录密码裸奔在网络上。启用 `web.cert_file/key_file`（或前置 TLS 反代），策略上建议：未配置 TLS 且监听非回环地址时直接拒绝启动，而不是仅警告 |
| P0-2 | **无 CI 流水线** | 仓库无 `.github/workflows/` | `make test` 全靠本地自觉，250s 的测试套件没有任何机制强制跑在每次提交上。最少建一条 CI：`make vet && make test` + go.mod 依赖审计（govulncheck），防"测试文件编译失败多日无人发现"重演（AGENTS.md 记载有过此事故） |
| P0-3 | **管理面 HTTP Server 超时不完整** | `main.go:133-136` 仅 `ReadHeaderTimeout: 10s`，无 ReadTimeout/WriteTimeout/IdleTimeout | 慢速攻击（slowloris 变体）可无限挂住管理面连接耗尽句柄。数据面有完整空闲超时，管理面没有。补齐三个超时即可（注意 pprof/快照下载等长响应的 WriteTimeout 豁免） |
| P0-4 | **无 LICENSE 文件** | 仓库根目录（README/AGENTS/Makefile/config.yaml/go.mod 等）确无 LICENSE | 对外部署/分发前必须定许可协议，否则法律上默认保留所有权利。若仅内部使用也应有内部版权声明 |

### 4.2 P1 —— 上线后尽快补齐

| # | 问题 | 证据 | 说明 |
| --- | --- | --- | --- |
| P1-1 | 无 HSTS/HTTP→HTTPS 跳转、无 CSP | `internal/api/router.go:44-48` 只有 X-Frame-Options/nosniff | 启用 TLS 后补 `Strict-Transport-Security`；`Content-Security-Policy` 可缓解 JWT 存 localStorage 的 XSS 窃取面 |
| P1-2 | JWT 存 localStorage | `web/src/stores/auth.js:12` | XSS 可窃取 24h 令牌。改 HttpOnly Cookie 需要动 CSRF 防护，短期靠 CSP + 输入转义缓解 |
| P1-3 | `/api/metrics` 令牌 24h 过期，无人值守采集难 | README §可观测性自述 | 抓取方每天要换 token。方向：长效只读监控令牌（单独 scope），或按 README 建议由反代注入鉴权 |
| P1-4 | 备份留在本机数据目录 | `deploy/haproxyweb-backup.service:11` 备到 `/var/lib/haproxyweb/backups/`，无远端推送步骤 | 机器盘坏 = 备份与数据同归于尽。加一步 rsync/rclone 推到异地（含 `secret.key` 的安全存储）。另注意该单元强依赖 `sqlite3` 命令行——未安装时每晚备份静默失败（仅 systemd 单元转 failed 态），上线时确认 `sqlite3` 已装并监控 timer 状态 |
| P1-5 | 无依赖漏洞扫描 | go.mod 一堆传递依赖（sonic/quic-go/protobuf 等） | 接入 `govulncheck ./...`（本地快扫当前无已知漏洞依赖面，但这是时点结论，需要常态化） |
| P1-6 | 无 2FA/TOTP | `internal/auth/auth.go` 仅密码 | 管理端口映射了内网真实服务，凭证被爆破/钓走的爆炸半径大。IP 锁定（5 次锁 10 分钟）+ 全局阈值（60s 内 100 次锁全网 5 分钟）已明显缓解，但密钥因子仍是空白 |
| P1-7 | 无告警通知通道 | 健康检查仅 webhook POST（尽力而为不重试，`internal/proxy/health.go`；`web.health_webhook_url` 在配置 schema 中、样例 config.yaml 未列出） | Prometheus 规则示例已备好，但"谁盯着 Prometheus"要落到值班渠道（PagerDuty/飞书/钉钉 webhook） |

### 4.3 P2 —— 按需增强

| # | 问题 | 说明 |
| --- | --- | --- |
| P2-1 | 多用户/角色（viewer/operator/admin） | 解决 §3-1 的审计归因问题；工程量在配额与权限矩阵设计 |
| P2-2 | 双机热备方案 | 当前 RTO≈3s（systemd 重启）。要求更高可用时：keepalived/VIP + 规则导出 JSON 同步是代价最小的路径 |
| P2-3 | 审计日志防篡改 | 当前审计与业务同库，管理员可（间接）影响。合规场景需 append-only 转发到中心日志 |
| P2-4 | WAL 体积监控 | 高会话量下 SQLite WAL 增长需要观测（`/healthz` 已暴露 db_size_bytes，可加告警线） |
| P2-5 | 规则变更的"上线前校验"工作流 | dry_run 导入已支持;可再加"变更计划审批/两步生效"类流程 |
| P2-6 | i18n / 登录页品牌化 | 界面当前纯中文 |

### 4.4 已具备、无需重复建设的（避免误工）

以下能力容易被认为是生产缺口但其实已有，评估时别重复造轮子：

- 优雅关闭与日志落库顺序（`main.go:257` shutdown 序列是唯一权威）
- systemd 沙箱加固单元、每日备份 timer、Prometheus 告警规则示例
- 登录爆破防护双层（IP 持久化锁定 + 全网滑动窗口限流）
- 改密全局吊销旧令牌（`users.token_version`）、默认密码强制修改的接口级拦截
- XFF 不可伪造（默认不信任任何代理头）
- 转发路径 panic 隔离与计数暴露、日志队列打满丢弃计数暴露
- pprof 专用短时作用域令牌（URL/Cookie 通道只认 pprof scope,防令牌重放）

---

### 4.5 修复记录（首轮评审后，commit `f9b8b7a`）

首轮 P0/P1 清单的修复状态（全部经独立评审 + 独立 QA 双重验证）：

| 原编号 | 问题 | 状态 | 修复内容 |
| --- | --- | --- | --- |
| P0-1 | TLS 默认关闭 | ✅ 已修复 | 非回环监听 + 未配 TLS 启动即拒绝（带指引的硬失败）；默认监听改为 `127.0.0.1:8080`；`web.allow_insecure` / `HAWEB_ALLOW_INSECURE` 逃生口 |
| P0-2 | 无 CI | ✅ 已修复 | `.github/workflows/ci.yml`：vet + test + govulncheck + 前端构建（本地无法跑 runner，CI 实际运行 notCovered，需推送后观察） |
| P0-3 | HTTP 超时不完整 | ✅ 已修复 | Read 60s / Write 10min / Idle 120s（WriteTimeout 留足快照下载余量） |
| P0-4 | 无 LICENSE | ✅ 已加 | MIT（**版权归属请维护者确认**） |
| P1-1 | 无 HSTS/CSP | ✅ 已修复 | TLS 时 HSTS（明文不发，防钉死）；全站 CSP（pprof 路径豁免——标准库页面自带内联样式） |
| P1-3 | metrics 令牌 24h 过期 | ✅ 已修复 | 设置页签发长效监控令牌（一年，仅限 /api/metrics，改密自动失效） |
| P1-4 | 备份留本机 + sqlite3 静默失败 | ✅ 已修复 | backup.sh 前置检查 sqlite3、umask 077、`HAWEB_BACKUP_PUSH_CMD` 异地推送钩子（推送失败单元转 failed） |
| P1-5 | 无漏洞扫描 | ✅ 已修复 | govulncheck 进 CI |
| P1-6 | 无 2FA | ✅ 已修复 | TOTP 两步验证（RFC 6238 官方向量验证、防重放、10 个一次性恢复码；启用后登录两步）；评审返工修复 pending 作用域 fail-closed / 防重放并发 / 第二步爆破锁定三个必修项 |
| P1-7 | 告警无值班渠道 | ✅ 部分 | README 增补 Alertmanager/飞书/钉钉接入指引 + db_size 与备份失败两条新告警规则（通知落地仍需现场配置） |
| P2-4 | WAL 体积监控 | ✅ 部分覆盖 | `haweb_db_size_bytes > 2GB` 告警规则 |

剩余未做（见 §4.2/§4.3）：JWT 仍存 localStorage（P1-2，靠 CSP 缓解，HttpOnly Cookie 改造需连动 CSRF 防护，建议下个迭代）、多用户角色（P2-1）、双机热备（P2-2）、审计日志防篡改（P2-3）、i18n（P2-6）。

## 5. 上线检查清单（可直接勾选）

```markdown
## 上线前
[ ] TLS 已启用（cert_file/key_file 或前置反代），浏览器验证证书有效
[ ] 默认密码已修改（强制改密流程已走完）
[ ] CI 已建立（make vet + make test + govulncheck）并要求主干绿
[ ] 管理面 HTTP 超时已补齐（Read/Write/Idle）
[ ] LICENSE/版权声明已落定
[ ] 防火墙：仅放行管理端口（限源 IP 更佳）+ 转发端口；trusted_proxies 按拓扑配置
[ ] 系统参数按 README「性能调优」核对（somaxconn/NOFILE/conntrack）
[ ] tuning.max_global_conns 已按 NOFILE 80% 设定
[ ] 部署冒烟：haproxyweb -check 通过 → systemctl start → /healthz 200 → 建一条测试规则转发验证 → 删除

## 上线后第一周
[ ] Prometheus 抓取 + 四条告警规则接到值班渠道
[ ] 备份推异地（含 secret.key 的安全归档），并做一次真恢复演练
[ ] 观察运行监控页：日志丢弃/清理失败/规则失败计数保持为 0
[ ] 高峰期看 goroutine/内存/WAL 体积水位

## 流程
[ ] 升级路径演练：SIGUSR2 零中断升级一次 + 回滚演练
```

---

## 附：验证记录（P5 核查口径）

- `go test ./...`：全绿（首轮 2026-10-20 exit=0；修复后全量复跑 exit=0，含新增 2FA 攻击面回归与并发测试）
- 实进程冒烟矩阵（首轮）：TLS 强制拒绝/回环放行、登录/改密/管理接口鉴权边界、2FA 全流程（独立 Python TOTP 实现交叉验证 RFC 6238 跨实现一致）、监控令牌作用域隔离——5/5 通过
- 独立评审（P4）：发现 3 必修项（pending 作用域 fail-open、防重放 map 并发崩溃、第二步爆破锁定失效）——全部返工修复
- 独立 QA（P5）：三项修复逐项 verified（代码+测试+运行三层证据；`-race` 下 20 goroutine 并发同码无竞争），全量回归无失败
- notCovered：CI 工作流实际运行（本地无 runner，需推送 GitHub 后观察首个 Action 结果）；LICENSE 版权归属确认
- 代码取证：README / config.yaml / main.go / internal/{api,auth,store,proxy} / deploy/ 关键断言可溯源到文件；与 AGENTS.md 工程备忘一致
