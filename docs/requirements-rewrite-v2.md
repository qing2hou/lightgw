# 专线网关 · 重构 PRD

| 项目 | 内容 |
|---|---|
| 文档编号 | LDG-PRD-2026-002 |
| 版本 | V1.0 |
| 状态 | 待评审 |
| 代码基线 | `qingzhou@172.22.140.11:/home/qingzhou/haproxyweb`（44 commit，生产代码 20,789 行） |
| 产品定位 | 单机轻量四层专线网关（nftables 转发面 + 单二进制交付） |
| 编制日期 | 2026-10-30 |

---

## 1. 摘要

现有代码是一个**已经跑通的产品**，不是原型：nftables netlink 直连、规则快照原子替换、零中断升级、2FA、三档日志轮转都已落地。重构的目标**不是重写转发逻辑**，而是解决三个阻碍产品继续演进的**架构级耦合**，让后续 20 个功能需求能落下去而不是只能打补丁。

一句话概括方案：**把 DNAT 已经走通的 netlink 路线，推广到 SNAT、限速、会话表；把配置文件与日志数据拆开；在 API 与数据库之间插一层。**

| 维度 | 现在 | 重构后 |
|---|---|---|
| 内核操作 | netlink（DNAT/策略）与 `exec`（SNAT/限速/会话）两套并存，14 处外部命令 | 全部 netlink，`exec` 归零 |
| 数据 | 配置与日志同库 `haproxyweb.db` | `config.db` + `traffic.db`（按天分表） |
| 分层 | API handler 直接 `h.DB` 操作（约 100 处） | `transport → service → domain ← adapter` |
| 最大文件 | `snat.go` 1,890 行 | 单文件 ≤ 400 行 |
| 限速 | 用户态令牌桶 + tc/HTB 两条独立实现 | 统一 `Limiter` 端口，语义明确 |
| 交付 | 41.7 MB 单二进制 | 保持单二进制，≤ 45 MB |

**周期**：13 周（3 个月），两人并行，分 6 期，**每期独立可发布、可回滚**，不需要停机窗口。

---

## 2. 背景：为什么必须重构

不是为了"代码好看"，是三个具体的、已经造成需求无法交付的障碍。

### 2.1 障碍一：数据层耦合，导致日志相关需求无法兑现

**事实**：配置（规则、策略、用户）与日志（流量、审计）存在同一个 `haproxyweb.db` 里。`internal/store/store.go:35` 一次 `AutoMigrate` 迁移全部 10 张表。

**已造成的后果**：

| 需求 | 为什么做不了 |
|---|---|
| "Web 配置日志存储路径" | 日志不是文件，没有"路径"这个概念。改路径 = 改整个数据目录 |
| "日志远程备份" | 备份 `haproxyweb.db` 会连配置和审计一起备份；日志膨胀到几十 GB 后，每次备份都传全量 |
| "日志保留 30 天，配置永久" | 同一文件内无法分离保留策略，只能靠 `DELETE WHERE` 删行——**删完文件不缩小**，需要 `VACUUM` 锁库 |
| "备份保留 30 份" | `deploy/backup.sh` 的 `KEEP=30` 与日志保留耦合，磁盘占用 = 30 × 全库大小 |

**这不是实现问题，是数据模型问题。** 后续任何与日志生命周期、归档、外发相关的需求都会被这一条卡死。

### 2.2 障碍二：两套内核操作路径，导致能力不一致与静默失效

**事实**：`exec.Command` 共 **15 处，其中 14 处在 `snat.go`**：

```
iptables-save                                 # 读规则
iptables -t <t> -L <chain> --line-numbers       # 读链
iptables -L FORWARD -v -x -n                     # 读计数
tc qdisc show dev <if>        ×3                # 读限速配置
tc -s class show dev <if>                       # 读限速统计
ip rule list / ip rule list from <src>          # 读策略路由
conntrack -L                                    # 读会话表
conntrack -D ...                                # 删会话
ip link show <dev>                              # 读网卡
```

而 DNAT、防火墙策略、默认拒绝已经全部走 `google/nftables` netlink（`dnat_nft.go` 370 行 + `fw/compile_dnat.go` 263 行 = 633 行，替代了原先的模板代码生成）。

**已造成的后果**：

1. **静默失效**：`readSnatDropCounters` 在 `iptables` 不存在时 `return &snatCounters{}`——返回零值不报错。生产镜像若未装 iptables，SNAT 的流量统计恒为 0，UI 显示"零流量"，运维会误判限速策略没生效。
2. **能力不一致**：DNAT 的会话踢断走 netlink，SNAT 的走 `conntrack -D` 命令。两套代码、两套失败语义、两套测试。
3. **部署脆弱**：`conntrack`、`iptables`、`tc`、`ip` 任意一个缺失，对应能力就废掉，且**没有启动期探测**。

### 2.3 障碍三：分层缺失，改一个功能动全身

**事实**：

| 症状 | 数据 |
|---|---|
| API handler 直接操作数据库 | `h.DB` 出现约 100 处（`rules.go` 19、`bwgroups.go` 15、`router.go` 12、`aclgroups.go` 11…） |
| 业务逻辑与 HTTP 耦合 | `rules.go` 1,051 行，含校验、编译、装载、审计、响应构造 |
| 巨型文件 | `snat.go` 1,890 行，混合 tc 整形、iptables 兼容、规则应用、conntrack 操作 |
| 无端口抽象 | `proxy.Manager` 同时被 API 层直接调用方法、直接读字段 |

**已造成的后果**：任何跨模块改动都要同时动 handler、model、manager、前端四处；单元测试只能靠启动完整 SQLite + 伪造 Manager 来做，`api` 层测试必须 `AutoMigrate` 全表。

### 2.4 一个重要的有利事实

**DNAT 已经证明了 netlink 路线可行且更省代码。** 这不是"要不要冒险换架构"的问题，而是"**把已经成功的模式复制到剩下 30%**"的问题：

| 模块 | 实现方式 | 代码量 |
|---|---|---|
| DNAT + 防火墙策略 + 默认拒绝 | ✅ netlink | 633 行 |
| SNAT + 限速 + 会话表 | ❌ exec | 1,890 行（snat.go） |

同样的功能，netlink 路线的代码量是 exec 路线的 **1/3**。这是重构方案最有力的论据。

---

## 3. 目标与非目标

### 3.1 目标

| # | 目标 | 可验证的完成标准 |
|---|---|---|
| G1 | 内核操作路径统一 | `exec.Command` 从 15 处降至 ≤1 处（仅保留自我升级的 `self -c config`） |
| G2 | 数据层解耦 | 配置与日志分库；日志按天分表；删除一天数据用 `DROP TABLE` 而非 `DELETE` |
| G3 | 建立分层 | `transport` 层零 `*gorm.DB` 引用；业务逻辑可在无 HTTP 环境下单测 |
| G4 | 能力降级可见 | 启动探测 `conntrack/tc/ip` 能力，缺失时 `/api/healthz-detail` 明确报告，UI 飘红 |
| G5 | 保持交付形态 | 仍为单二进制，`go:embed` 前端，体积 ≤ 45 MB |
| G6 | 保持性能 | 单包转发 p99 时延劣化 ≤ 5%；吞吐劣化 ≤ 3% |
| G7 | 补齐测试 | 核心包（`domain`、`fw`）覆盖率 ≥ 80%，整体 ≥ 60% |

### 3.2 非目标（明确不做）

| 不做 | 原因 |
|---|---|
| 拆成微服务 / 多进程 | 单二进制是核心交付优势；管理面故障隔离用 goroutine + recover 解决即可 |
| 更换转发模型（如 eBPF/XDP） | 当前性能未到瓶颈；eBPF 会破坏"无内核模块依赖"的承诺 |
| 引入 Kubernetes Operator | 客户是裸机，无 K8s |
| 自研 HA / VRRP | 定位为单机轻量网关，HA 由外部基础设施承担（见改造任务清单 DEV-17） |
| 重写前端 UI 视觉 | 只做工程化（TS 化 + 契约生成），不动交互与视觉 |
| 支持多租户 | 单管理员 + 三档 RBAC 是上限 |
| 数据库换 PostgreSQL/ClickHouse | 客户环境无外部 DB；SQLite 单机足够（已有 50 万 conntrack、万兆实测报告） |

---

## 4. 用户与使用场景

| 角色 | 场景 | 重构后的关键改善 |
|---|---|---|
| **网络运维** | 日常查看规则、出口状态、会话表 | 数据分库后页面加载不再被大日志表拖慢；会话表查询走独立库 |
| **安全运维** | 查"某 IP 为什么不通"、加黑名单立即生效 | 拒绝日志可溯源（`dynamic set + counter`）；踢会话统一入口 |
| **审计/合规** | 导出 180 天操作与流量记录 | 日志可按天归档、可远程备份、可独立保留期 |
| **实施工程师** | 现场部署、故障排查 | 能力探测页明确告诉"这台机器缺什么"；不再出现"统计为 0 但没报错" |
| **开发** | 加一条新策略字段 | 改 `domain` + `service` + 前端类型，不动 handler 与 DB |

---

## 5. 重构后的能力矩阵

功能范围**不扩大**，只保证现有能力完整、语义正确、边界清晰。

| 能力域 | 现有 | 重构后补齐 |
|---|---|---|
| TCP/UDP 四层转发 | ✅ | 保持 |
| DNAT（源地址保留） | ✅ | 补 MSS clamping、ICMP 差错改写 |
| SNAT（固定/轮转/粘性 + 池） | ✅ | 迁 netlink，消除 iptables 依赖 |
| 共享/保障带宽（上下行） | ✅ tc + 令牌桶 | 统一 `Shaper` 端口；下行保障缺失时明确降级 |
| 多出口负载（ECMP + 探测） | ✅ | 保持，补 per-出口会话统计 |
| 防火墙策略（accept/drop） | ✅ | accept 语义明确为 AND；补 enable/disable |
| 名单组（白/黑/IP 组） | ✅ | 补"加黑名单立即踢存量" |
| 会话表 | ✅ 只读 + 单条踢 | 补按规则/按源/全量踢；conntrack 水位监控 |
| 带宽包 | ✅ | 保持，明确"跨卡为近似"边界 |
| 日志（流量/审计/拒绝） | 流量+审计；**拒绝无记录** | 补拒绝日志；日志落 sink（sqlite/file/syslog/remote）四选 |
| 日志存储路径可配 | ❌ | ✅ Web 配置 + 11 条路径校验 + 迁移 |
| 日志远程备份 | ❌（仅 shell 环境变量） | ✅ SFTP/S3 纯 Go + sha256 校验 + 先校验后清理 |
| 高可用 | ❌ | 不补功能，改为提供**外部 HA 集成契约**（ARP 抑制、`/readyz`、优雅退出、keepalived 配置生成器） |
| 管理面 | ✅ 单管理员 + 2FA | 补三档 RBAC；pprof 默认关闭 |

---

## 6. 非功能需求

| 类别 | 指标 | 当前 | 目标 |
|---|---|---|---|
| 吞吐 | 万兆线速转发 | 已有实测报告 | 劣化 ≤ 3% |
| 时延 | p99 单包处理 | 待补测 | 劣化 ≤ 5% |
| 新建连接 | CPS | 待补测 | ≥ 现有 |
| 启动时间 | 冷启动到 `/readyz` 200 | 待测 | ≤ 现有 + 200ms |
| 内存 | 稳态 RSS（10 万会话） | 待测 | ≤ 现有 + 50MB |
| 二进制 | 体积 | **41.7 MB** | ≤ 45 MB |
| 可靠性 | 转发面 panic 隔离 | 有 recover | 管理面 panic 不影响转发（独立 goroutine + recover） |
| 可维护 | 单文件最大行数 | **1,890** | ≤ 400 |
| 可维护 | API 层 DB 直连 | **约 100 处** | **0** |
| 可维护 | `exec` 依赖 | **15 处** | **≤ 1** |
| 测试 | 整体覆盖率 | 待测（36 个测试文件） | ≥ 60% |
| 测试 | `domain`/`fw` 覆盖率 | — | ≥ 80% |
| 安全 | 依赖漏洞 | 无扫描 | `govulncheck` 进 CI，0 high |
| 兼容 | 配置向后兼容 | — | 旧 `config.yaml` 直接可用，无需人工迁移 |

---

## 7. 目标架构

### 7.1 分层与依赖方向

```
┌─────────────────────────────────────────────┐
│ transport/httpapi    gin handler，仅 DTO 转换 │
└───────────────────┬─────────────────────────┘
                    │ 调用
┌───────────────────▼─────────────────────────┐
│ app（service）       用例编排、事务边界、审计  │
└───────┬─────────────────────┬───────────────┘
        │ 依赖                 │ 依赖接口
┌───────▼──────────┐  ┌───────▼───────────────┐
│ domain            │  │ port（接口定义）        │
│ 纯模型 + 纯函数编译 │  │ Repository/Filter/... │
└───────────────────┘  └───────▲───────────────┘
                                │ 实现
                    ┌───────────┴───────────────┐
                    │ adapter                    │
                    │ sqlite/nftables/tc/ct/... │
                    └───────────────────────────┘
```

**铁律**：

1. `domain` **不 import 任何外部包**（除标准库）。gorm tag 一律不出现，DB 映射在 `adapter/sqlite` 里做。
2. `transport` **不 import `adapter`**，不持有 `*gorm.DB`。
3. 依赖只能向下，`domain` 不知道数据库、不知道 HTTP、不知道 nftables。
4. 现有 `internal/proxy/fw` 包已经是这个风格（纯函数、离线可测、318 行测试），**保留并扩大**。

### 7.2 目录结构（重构后）

```
cmd/
└─ haproxyweb/main.go            装配，≤ 80 行
internal/
├─ domain/                       ← 新增，零依赖
│  ├─ model/       实体与值对象（无 gorm tag）
│  ├─ rule/        规则聚合、校验、编译输入
│  ├─ policy/      策略聚合、笛卡尔展开、优先级
│  ├─ bandwidth/   保底/共享/借用计算（纯函数）
│  ├─ session/     会话值对象
│  └─ event/       领域事件
├─ port/                         ← 新增，接口定义
│  ├─ repository.go
│  ├─ logstore.go      写入 + 查询 + 归档
│  ├─ packetfilter.go  nftables 抽象
│  ├─ shaper.go        tc 抽象
│  ├─ sessiontable.go  conntrack 抽象
│  ├─ notifier.go
│  └─ backuper.go
├─ app/                          ← 新增，service 层
│  ├─ ruleapp/ policyapp/ egressapp/
│  ├─ sessionapp/ settingsapp/ backupapp/ authapp/
├─ adapter/                      ← 由现有包迁移而来
│  ├─ sqlite/        （原 internal/store）
│  ├─ nftables/      （原 internal/nft）
│  ├─ tcnetlink/     （新，替代 snat.go 的 tc exec）
│  ├─ ctnl/          （新，替代 conntrack exec）
│  ├─ logstore/      sqlite | file | syslog | remote 四实现
│  ├─ backup/        sftp | s3 | local
│  └─ notify/        webhook | smtp
├─ transport/httpapi/            ← 原 internal/api（瘦身）
├─ platform/                     ← 新增
│  ├─ config/        config.yaml + runtime.yaml + env
│  ├─ caps/          能力探测
│  ├─ version/
│  └─ crash/
└─ compile/                      纯编译层（原 proxy/fw，独立出来）
web/                              前端
```

**迁移映射表**（保证可渐进替换）

| 现有 | 目标 | 方式 |
|---|---|---|
| `internal/model` | `domain/model` + `adapter/sqlite/entity` | 拆：纯模型 vs gorm 实体 |
| `internal/store` | `adapter/sqlite` | 移 + 拆双库 |
| `internal/nft` | `adapter/nftables` | 移 |
| `internal/trafficlog` | `adapter/logstore/sqlite` + `app/logapp` | 拆：存储 vs 编排 |
| `internal/audit` | `adapter/logstore/sqlite` + `app/auditapp` | 同上 |
| `internal/ratelimit` | `domain/bandwidth` + `adapter/shaper` | 拆：算法 vs 执行 |
| `internal/proxy/fw` | `internal/compile` | 移（已在正确层次） |
| `internal/proxy`（转发） | `app/forwardapp` + `adapter/sessiontable` | 拆 |
| `internal/api` | `transport/httpapi` + `app/*` | 拆 |
| `internal/auth` | `app/authapp` + `adapter/sqlite` | 拆 |

### 7.3 模块职责（关键三条）

| 模块 | 职责 | 明确不做 |
|---|---|---|
| `domain/rule` | 校验规则合法性、生成编译输入、计算生效语义 | 不碰 DB、不碰 nftables |
| `app/ruleapp` | 编排"校验→存库→编译→装载→审计"、事务边界、失败回滚 | 不拼 HTTP 响应 |
| `adapter/nftables` | 把编译好的规则序列下到内核、读回计数 | 不理解"规则"的业务含义 |

---

## 8. 技术选型与决策记录

### 8.1 选型总表

| 领域 | 现在 | 目标 | 变化 |
|---|---|---|---|
| 语言 | Go 1.25 | **Go 1.25** | 不变 |
| HTTP 框架 | gin 1.12 | **gin 1.12** | 不变 |
| ORM | GORM 1.31 | **GORM 1.31（限 adapter 层）** | 用法收窄 |
| 配置库 | SQLite（`glebarez`，纯 Go） | **同左** | 不变 |
| 日志库 | 同库 | **独立 `traffic.db` + 按天分表** | 拆 |
| 内核规则 | `google/nftables` 0.3.0 | **同左**（升级到最新） | 不变 |
| 流量整形 | `exec tc` | **`vishvananda/netlink` tc 包** | 换 |
| 会话表 | `exec conntrack` | **`ti-mo/conntrack`**（netlink） | 换 |
| 结构化日志 | 自定义 `logf` | **`log/slog`** | 换 |
| 指标 | 手写 `metrics.go` 299 行 | **`prometheus/client_golang`** | 换 |
| 远程备份 | `exec rsync`（shell 环境变量） | **`pkg/sftp` + `minio-go`** | 换 |
| 前端 | Vue 3.5 + JS + Vite 5 | **+ TypeScript + `openapi-typescript`** | 增强 |
| 测试 | `go test` | **+ `-race` + `golangci-lint` + `govulncheck`** | 增强 |
| 打包 | `make build` | **+ `goreleaser`**（deb/rpm/tar） | 增强 |

### 8.2 ADR-01 · 保留单进程单二进制，不拆服务

| 项 | 内容 |
|---|---|
| **问题** | 管理面与数据面同进程，Web 端一个 panic 会不会打死转发？是否拆成两个进程？ |
| **选项** | A. 拆两个进程（`haproxyweb-web` + `haproxyweb-dp`）；B. 单进程 + goroutine 隔离；C. 不改 |
| **决策** | **B** |
| **理由** | ① 单二进制是核心交付优势（现场只需 `scp` 一个文件 + `systemctl start`），拆进程要维护 socket 协议、版本一致、启动顺序，运维复杂度翻倍；② 实测 panic 风险已由 `gin.Recovery()` 与 `Manager` 内的 `recover` 覆盖；③ 真正的进程级隔离（管理面 OOM 不影响转发）只有 cgroup 分离才有意义，而那是 systemd 的事（`MemoryMax` 给整个进程即可） |
| **补强措施** | ① 管理面所有 handler 强制 `recover` 且记录 panic 计数（已有 `EngineCounters.Panics`）；② 转发面 goroutine 池独立，不受 HTTP 连接数影响；③ `deploy/haproxyweb.service` 增加 `MemoryMax=2G`，让 OOM 时由 systemd 重启而非拖垮机器 |
| **风险** | 管理面内存泄漏最终仍会影响转发。缓解：`/api/healthz-detail` 暴露 heap 大小，> 阈值告警 |

### 8.3 ADR-02 · 双库拆分：config.db + traffic.db

| 项 | 内容 |
|---|---|
| **问题** | 配置与日志同库，导致日志生命周期无法独立管理 |
| **选项** | A. 保持单库；B. 拆两个库文件；C. 拆两个进程各管一库 |
| **决策** | **B** |
| **理由** | ① 单库无法解决"删日志不缩小文件"（SQLite `DELETE` 不释放空间）；② 拆库后可对 `traffic.db` 单独设 `auto_vacuum`、单独设保留期、单独备份、单独换路径；③ `config.db` 体积恒定在 MB 级，备份瞬间完成 |
| **分界线** | `config.db` = User / ForwardRule / FwPolicy / Egress / AclGroup / BWGroup / HealthLog / LoginFail / **AuditLog**（量小、重要、随配置走）；`traffic.db` = TrafficLog / DenyStat（量大、可丢、独立生命周期） |
| **风险** | SQLite 跨库无法 join。缓解：统计类查询只查 `traffic.db`；规则名等展示信息由 app 层二次查 `config.db` 拼接（内存 join，数据量小） |

### 8.4 ADR-03 · 日志按天分表，删除用 DROP TABLE

| 项 | 内容 |
|---|---|
| **问题** | 现有轮转用 `DELETE WHERE ts < ?`，200 CPS 下每天 600 万行，DELETE 慢且不释放空间，`VACUUM` 会锁库数十秒 |
| **选项** | A. `DELETE` + 定期 `VACUUM`；B. 按天分表 + `DROP TABLE`；C. 按天分库文件 |
| **决策** | **B** |
| **理由** | ① `DROP TABLE` 是 O(1) 元数据操作，毫秒级；② 同一库内可分表，避免 ATTACH 数量上限（默认 10）；③ 归档时单表 `.dump` + gzip 即可，不用扫全库 |
| **表命名** | `traffic_20261030`、`deny_20261030`，由 `logstore` 按写入时间路由 |
| **空间回收** | 建库时设 `PRAGMA auto_vacuum=2`（incremental）；每天轮转后执行 `PRAGMA incremental_vacuum(1000)`，分批还空间，不锁库 |
| **跨天查询** | 维护 `traffic_meta(table_name, day, rows, bytes)` 登记表；查询 N 天 = 按 meta 拼 `UNION ALL`，只 UNION 存在的表 |
| **风险** | 表数量增长（3 年 ≈ 1100 张）。缓解：SQLite 单库表数量上限远高于此，且 `sqlite_master` 查询仍毫秒级；超过 2 年自动归档为独立文件 |

### 8.5 ADR-04 · 保留 GORM，但禁止跨层

| 项 | 内容 |
|---|---|
| **问题** | GORM 隐式全表扫描、跨库不支持、复杂聚合难写。要不要换 sqlc 或手写 SQL？ |
| **选项** | A. 全换手写 SQL；B. 换 sqlc（代码生成）；C. 保留 GORM 但收窄使用面 |
| **决策** | **C** |
| **理由** | ① 团队已熟悉 GORM，全换的收益不抵风险；② 主要痛点集中在"统计聚合"和"跨库"，这两类只占查询的 10%；③ GORM 的 `AutoMigrate` 对单机 SQLite 场景是刚需（免手工建表） |
| **规则** | ① GORM 只在 `adapter/sqlite` 出现，`transport`/`app` 通过 `port.Repository` 访问；② **统计类查询一律 `db.Raw()` 手写 SQL**，不用 GORM 链式；③ 禁止在循环内调用 GORM（N+1）；④ 所有 list 接口强制 `LIMIT`，默认 200 |
| **风险** | `AutoMigrate` 在 SQLite 上不支持删列/改类型。缓解：结构性变更走显式 migration 脚本（`adapter/sqlite/migrations/`） |

### 8.6 ADR-05 · 保留 gin

| 项 | 内容 |
|---|---|
| **问题** | Go 1.22+ 的 `http.ServeMux` 已支持 method + path param，gin 带来 sonic 等一堆间接依赖，是否换掉？ |
| **决策** | **保留 gin** |
| **理由** | ① 45 个路由 + 15 个前端页面已对接，路由层重写是纯成本无收益；② gin 的 binding/validation 省掉大量样板；③ 换框架不解决任何当前痛点 |
| **补强** | `gin.SetMode(ReleaseMode)`（已有）；关闭 gin 默认 logger，改用 `slog`；`SetTrustedProxies` 已正确配置 |

### 8.7 ADR-06 · tc 操作改 netlink，保留 CLI 兜底

| 项 | 内容 |
|---|---|
| **问题** | 14 处 `exec` 里 6 处是 tc，读 qdisc/class 配置与统计 |
| **选项** | A. 全换 `vishvananda/netlink`；B. 保留 exec；C. netlink 为主 + CLI 兜底 |
| **决策** | **C**（先写 PoC 验证 netlink 覆盖度，能覆盖则纯 A） |
| **理由** | `netlink` 的 `tc` 子包对 HTB qdisc/class 支持完整，但 **u32 过滤器**（`ingress + u32 match ip src + mirred`）在纯 netlink API 下构造复杂，且不同内核版本行为有差异 |
| **必须做的 PoC**（1 天） | 用 `netlink.QdiscAdd/ClassAdd/FilterAdd` 复现现有 ifb 整形链路，与 `tc` CLI 结果 `tc -s -d` 逐字段比对 |
| **兜底策略** | 若 u32 无法稳定构造，保留 `exec tc` 但**必须**：① 启动 `exec.LookPath("tc")` 探测；② 缺失时写 `capabilities.tc = false` 并在 UI 明示"限速不可用"；③ 绝不允许静默通过 |
| **风险** | 内核 4.x 与 5.x 的 tc netlink 属性差异。缓解：目标基线锁 Linux ≥ 5.4（客户现网 5.15） |

### 8.8 ADR-07 · 会话表改 netlink

| 项 | 内容 |
|---|---|
| **问题** | `conntrack -L` 解析文本、`conntrack -D` 删条目，脆弱且慢 |
| **决策** | 引入 **`github.com/ti-mo/conntrack`**（纯 Go，netlink CTNETLINK） |
| **理由** | ① `conntrack -L` 解析依赖输出格式稳定，工具版本变就崩；② netlink dump 有游标，可控批量；③ 删除按 `orig` 五元组精确匹配，与现有 `deleteConntrackEntry` 语义一致 |
| **成本** | 替换 `readConntrackTable` + `deleteConntrackEntry` 两个函数，约 150 行，调用方（5 处）不变 |
| **风险** | 需要 `CAP_NET_ADMIN`（已有）。降级：若 netlink 失败，回退 `exec conntrack` 并标记能力降级 |

### 8.9 ADR-08 · 限速统一为 Limiter 端口

| 项 | 内容 |
|---|---|
| **问题** | 两条独立实现：用户态令牌桶（`x/time/rate`，排队语义）与 tc/HTB（整形语义）。同一个"限速 100Mbps"在两处表现不同 |
| **决策** | 定义 `port.Shaper`，两个实现，**由规则类型决定用哪个**，并在 UI/文档明确语义差异 |
| **接口** | 见下方代码块（4 个方法：Apply / Stats / Remove / Kind） |
| **语义声明** | 用户态令牌桶：超限表现为**延迟上升**（`WaitUpload` 阻塞）；内核 HTB：超限表现为**排队后突发**。验收判定标准必须分开写 |
| **归属** | 用户态代理规则（TCP/UDP 转发）→ 令牌桶；内核转发规则（SNAT/DNAT）→ HTB |
| **风险** | 两条路径的 `Stats` 口径不同（字节数统计点不同）。缓解：统一在 `app` 层做归一化，UI 只显示归一化后的值 |

```go
type Shaper interface {
    Apply(ctx context.Context, spec ShapeSpec) error
    Stats(ctx context.Context, id string) (ShapeStats, error)
    Remove(ctx context.Context, id string) error
    Kind() ShapeKind // "userspace-token-bucket" | "kernel-htb"
}
```

### 8.10 ADR-09 · 日志统一 slog + logstore 端口四实现

| 项 | 内容 |
|---|---|
| **问题** | `logf` 是自定义格式化，无级别、无结构化；流量/审计日志只能落 SQLite |
| **决策** | ① 程序运行日志 → `log/slog`（JSON handler，输出到 stderr + 可选文件）；② 业务日志（traffic/audit/deny）→ `port.LogStore`，四个 adapter：`sqlite`、`file`（JSON Lines）、`syslog`（RFC5424）、`remote`（HTTP 批量推送） |
| **配置** | 见下方 YAML 片段 |
| **关键约束** | 审计与拒绝日志**禁止采样**；流量日志可采样（200 CPS 全量 = 6GB/天，必须可调） |
| **风险** | 多 sink 写入放大延迟。缓解：sink 写入全部异步 + 有界队列 + 满则丢弃计数（现有 `trafficlog` 已是此模型，沿用） |

```yaml
logging:
  runtime: {level: info, format: json, output: [stderr, /var/log/gw/gw.log]}
  traffic: {sinks: [sqlite, file], sample_ratio: 1.0}
  audit:   {sinks: [sqlite, syslog], sample_ratio: 1.0}   # 审计不可采样
  deny:    {sinks: [sqlite], sample_ratio: 1.0}
```

### 8.11 ADR-10 · 指标换 prometheus/client_golang

| 项 | 内容 |
|---|---|
| **问题** | 手写 `metrics.go` 299 行生成 Prometheus 文本格式，易错且无类型检查 |
| **决策** | 引入 `prometheus/client_golang`，用 `promhttp.Handler()` |
| **收益** | ① histogram 类型自动分桶（现在手写）；② 统一 `/metrics` 与 `/api/metrics` 两个端点；③ 支持 `go_*` 运行时指标自动注册 |
| **成本** | 替换 299 行手写代码，约 150 行声明式注册 |
| **风险** | 新增约 2MB 二进制。可接受（预算 45MB 内） |

### 8.12 ADR-11 · 配置三分

| 项 | 内容 |
|---|---|
| **问题** | `config.yaml` 既是运维手写又可能被程序改写（如日志路径），冲突风险 |
| **决策** | 三层，优先级从低到高：`config.yaml`（运维手写，只读） → `runtime.yaml`（程序写，Web 改的可变项） → 环境变量（部署覆盖） |
| **可变项** | 只有这些进 `runtime.yaml`：日志路径、备份目标、告警通道、MSS 值、默认拒绝作用域 |
| **热加载** | `SIGHUP` 重读三层并合并（已有机制，扩展后保留） |
| **风险** | 三层合并的可解释性。缓解：`GET /api/config/effective` 返回合并结果并标注每项来源 |

### 8.13 ADR-12 · 前端引入 TypeScript + 契约生成

| 项 | 内容 |
|---|---|
| **问题** | 前端纯 JS（4,873 行），API 字段靠人工同步，改后端字段前端静默失常 |
| **决策** | ① 后端从 gin 路由 + DTO 生成 OpenAPI 3.1 spec（`swaggo` 或手写 `openapi.yaml`）；② 前端用 `openapi-typescript` 生成类型，`axios` 调用带类型 |
| **范围** | 只做类型化，不改 UI 与交互；渐进式：新页面用 TS，老页面标 `// @ts-nocheck` 逐步迁移 |
| **收益** | 消灭"后端改字段前端白屏"这类最高频联调问题 |
| **风险** | 构建链增加一步。缓解：生成的类型文件提交入库，CI 校验是否过期 |

### 8.14 ADR-13 · 能力探测层（Capabilities）

| 项 | 内容 |
|---|---|
| **问题** | `conntrack`/`tc`/`iptables`/`ip` 缺失时能力静默失效 |
| **决策** | 新增 `platform/caps`：启动时探测内核模块、外部命令、文件系统、权限 |
| **探测项** | `nftables`（netlink 可用）、`conntrack`（netlink + CLI）、`tc`（netlink + CLI）、`ifb`（模块加载）、`ip_rule`、`CAP_NET_ADMIN`、`CAP_NET_RAW`、`syslog` socket、`sqlite` WAL 可用 |
| **暴露** | `GET /api/capabilities`（需鉴权）返回每项 `{available, source, detail}`；`/api/healthz-detail` 含摘要 |
| **UI** | 依赖缺失的功能在页面上置灰并给出"缺失项 + 安装命令" |
| **原则** | **能力缺失必须可见**，宁可首页红条警告，不能静默降级 |

### 8.15 ADR-14 · 分层采用"务实三层 + 端口"，不套完整六边形

| 项 | 内容 |
|---|---|
| **问题** | 洋葱/六边形架构理想但样板多，2 万行项目是否值得？ |
| **决策** | **务实版**：`domain`（纯函数 + 模型）+ `app`（编排）+ `adapter`（实现）+ `transport`（HTTP），共 4 层，`port` 只定义 7 个接口 |
| **不做的** | 不引入 DI 框架（用 `main.go` 手工装配）、不做 CQRS、不做事件总线、不做 domain event 持久化 |
| **理由** | 目标是"业务逻辑能脱离 HTTP 单测"和"DB 不渗透到上层"，两点用 4 层就够；DI 框架与事件总线在 2 万行规模是负资产 |

### 8.16 ADR-15 · 带宽包「总额」语义：约束式保证，不做 policing

| 项 | 内容 |
|---|---|
| **问题** | 真机实测（`docs/poc-result.md` §4.2.1，15 组二维扫描）证明：当前「父类 rate + 每源 rate 子类」结构下，实际总量 ≈ `max(parent.rate, Σ子类rate)`，误差 −2.5%~−4.2%。**`parent.rate` 是「保底总池」，不是硬上限**。`Σ MinKBps > 总额` 时合计会突破总额（实测 N=12 / parent=4MB 跑出 11.50 MB/s，超 **187.6%**）。带宽包总额到底该怎么保证？ |
| **决策** | **约束式（方案 A）**：`domain/bandwidth` 在保存带宽包时校验 `Σ(成员 MinKBps) ≤ 总额`，超额时**拒绝保存**并返回可读错误；查询侧提供「实际可分配保底 = 总额 ÷ 已配源数」供 UI 提示。**不引入 policing**。 |
| **不做的** | 不在 ifb / 出口网卡上叠 `police` 做硬丢包（方案 B）；**不接受**「总额可超卖」（方案 C） |
| **理由** | ①方案 B 需要验证 policing 与 htb 能否在同一 device 并存（**未验证**），且丢包会误伤 TCP 拥塞控制；②方案 C 与「带宽包总额」的产品语义直接矛盾，客户按总额采购却可被超卖；③方案 A 是纯 domain 层校验，零内核复杂度，可完整单测，且与既有「超额订阅按 rate 比例分配」的语义兼容（只是把该情形提前拦在保存阶段）。 |
| **代价 / 已知限制** | 用户不能配置超额订阅（多源包必须显式配小保底）。若将来确实需要超额，再评估方案 B，届时须先补验「ifb 上 policing + htb 并存」。 |
| **验证证据** | `docs/poc-result.md` §4.2.1（15 组扫描）、§5.4（三方案对比）、§4.1（真机三组） |
| **落地位置** | `internal/domain/bandwidth/`（S0）；校验入口在带宽包保存用例（S4） |

---

## 9. 数据模型设计

### 9.1 物理布局

```
/var/lib/haproxyweb/
├── config.db                    # 配置 + 审计（MB 级，随配置备份）
├── config.db-wal
├── traffic/
│   ├── traffic.db               # 主库，含 traffic_YYYYMMDD 与 deny_YYYYMMDD 分表
│   └── traffic.db-wal
├── runtime.yaml                 # Web 可变配置
├── certs/                       # TLS 证书
└── keys/                        # 备份私钥（0600）
```

### 9.2 表分配

| 库 | 表 | 保留 |
|---|---|---|
| `config.db` | User / ForwardRule / FwPolicy / Egress / AclGroup / BWGroup / HealthLog / LoginFail / AuditLog / ConfigSnapshot | 配置永久；AuditLog 90 天；HealthLog 跟随配置；Snapshot 保留 50 条 |
| `traffic.db` | `traffic_YYYYMMDD` / `deny_YYYYMMDD` / `traffic_meta` | 默认 30 天，可配；每表一天 |

### 9.3 分表规范

```sql
-- 每日建表（logstore 启动时预建今天 + 明天）
CREATE TABLE IF NOT EXISTS traffic_20261030 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,              -- unix 毫秒
  rule_id INTEGER NOT NULL,
  proto TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  src_port INTEGER,
  dst_ip TEXT NOT NULL,
  dst_port INTEGER,
  status TEXT NOT NULL,             -- ok / denied / reset / timeout
  upload_bytes INTEGER DEFAULT 0,
  download_bytes INTEGER DEFAULT 0,
  duration_ms INTEGER DEFAULT 0,
  session_id TEXT
);
CREATE INDEX idx_t_ts   ON traffic_20261030(ts);
CREATE INDEX idx_t_rule ON traffic_20261030(rule_id, ts);
```

**关键约束**：分表**不加外键**、**不加 UUID 主键**（自增更快）；`session_id` 用现有 base64 五元组编码，不引入新格式。

### 9.4 迁移（旧库 → 新结构）

```sql
-- 启动时检测：config.db 存在 traffic_logs 且有数据 → 迁到 traffic.db
ATTACH 'traffic/traffic.db' AS t;
-- 按 started_at 的日期分批插入对应分表（Go 侧循环，每批 5000 行）
INSERT INTO t.traffic_20261030 SELECT ... WHERE started_at >= ? AND started_at < ?;
-- 校验行数一致后才删
DROP TABLE traffic_logs;
```

**铁律**：**先校验后删**。行数或字节和不一致，保留旧表并告警，绝不删。

---

## 10. 关键接口设计

```go
// port/repository.go
type RuleRepository interface {
    List(ctx context.Context, f RuleFilter) ([]domain.Rule, int64, error)
    Get(ctx context.Context, id uint) (domain.Rule, error)
    Create(ctx context.Context, r domain.Rule) (uint, error)
    Update(ctx context.Context, r domain.Rule) error
    Delete(ctx context.Context, id uint) error
    SetEnabled(ctx context.Context, id uint, on bool) error
}

// port/logstore.go
type LogStore interface {
    Write(ctx context.Context, entries []domain.LogEntry) error
    Query(ctx context.Context, f LogFilter) ([]domain.LogEntry, error)
    Rotate(ctx context.Context, before time.Time) (dropped int64, err error)
    Archive(ctx context.Context, day time.Time, w io.Writer) error
    Healthy() Health
}

// port/packetfilter.go
type PacketFilter interface {
    Apply(ctx context.Context, plan domain.Plan) error   // 整段重装
    Counters(ctx context.Context) (map[string]Counter, error)
    Capabilities() Caps
}

// port/sessiontable.go
type SessionTable interface {
    Snapshot(ctx context.Context, f SessionFilter) ([]domain.Session, error)
    Delete(ctx context.Context, s domain.Session) (bool, error)
    Usage(ctx context.Context) (used, max int)
}
```

**设计要点**：`port` 只用 `domain` 类型，不出现 `*gorm.DB`、`*nftables.Conn`、`sql.NullString`。这样 `app` 层可以纯内存 mock 测试。

---

## 11. 实施路线（绞杀者模式）

**核心策略**：不新建项目、不长期维护双分支。在现有代码上逐块替换，**每一期结束都能出可发布的版本**，出问题回滚本期即可。

### M0 · 基线加固（1 周）

| 项 | 内容 |
|---|---|
| 交付 | CI 流水线（`go vet` / `golangci-lint` / `go test -race` / `govulncheck`）；覆盖率基线报告；`go mod tidy`（修正 `nftables`/`netlink` 被标 `// indirect` 的错误） |
| 门槛 | CI 全绿；覆盖率数字记录在案 |
| 风险 | 无（不改业务代码） |

### M1 · 数据层拆分（2 周）

| 项 | 内容 |
|---|---|
| 交付 | `config.db` / `traffic.db` 双库；按天分表；`auto_vacuum=2`；旧库迁移脚本；`port.Repository` 与 `adapter/sqlite`；**`transport` 层 `h.DB` 归零** |
| 门槛 | 旧库升级后行数一致；`api` 层 grep `h.DB` = 0；并发读写无 `database is locked` |
| 回滚 | 保留 `--legacy-single-db` 开关，一键回退单库 |
| 风险 | 跨库 join 缺失导致统计接口要改口径——这期最痛，但躲不过 |

### M2 · 内核面收口（3 周）

| 项 | 内容 |
|---|---|
| 交付 | `adapter/tcnetlink`（先做 PoC，再替换）；`adapter/ctnl`（`ti-mo/conntrack`）；`platform/caps` 能力探测；`snat.go` 中 `exec` 归零或全部走能力降级路径 |
| 门槛 | `exec.Command` ≤ 1 处；移除 `iptables`/`conntrack`/`tc` 命令后，UI 正确显示能力缺失而非静默 0 |
| 回滚 | 每个 adapter 保留 CLI 实现，配置项 `force_exec: true` 可切回 |
| 风险 | **最高**。tc u32 过滤器 netlink 构造若不可行，必须坦然保留 CLI + 探测（这仍然是巨大改进） |

### M3 · 业务层抽取（3 周）

| 项 | 内容 |
|---|---|
| 交付 | `domain`（model/rule/policy/bandwidth）+ `app`（ruleapp/policyapp/egressapp/sessionapp）；`snat.go` 拆为 ≤ 5 个文件、各 ≤ 400 行；`rules.go` 从 1,051 行拆到 ≤ 200 行 handler + app 逻辑 |
| 门槛 | `transport` 不 import `adapter`；`domain` 单测覆盖率 ≥ 80%；单文件最大值 ≤ 400 行 |
| 回滚 | 按模块逐个切换，每个模块有 feature flag |
| 风险 | 改动面最大但风险最低（纯结构调整，行为不变），靠"改前改后跑同一套 E2E 结果一致"保证 |

### M4 · 日志与可观测（2 周）

| 项 | 内容 |
|---|---|
| 交付 | `port.LogStore` 四实现（sqlite/file/syslog/remote）；拒绝日志（`dynamic set + counter`）；`slog` 替换 `logf`；`prometheus/client_golang` 替换手写指标；MSS clamping；策略 enable/disable；批量清会话 |
| 门槛 | 拒绝日志可溯源；`/metrics` 由 prometheus 库输出；运行日志全为 JSON |
| 回滚 | `logging.traffic.sinks` 配置可退回单 sqlite |
| 风险 | 多 sink 写入放大——用有界队列 + 丢弃计数兜住 |

### M5 · 前端与契约（2 周）

| 项 | 内容 |
|---|---|
| 交付 | OpenAPI spec；`openapi-typescript` 生成类型；新页面 TS 化；E2E 用 Playwright 覆盖 5 条主流程 |
| 门槛 | CI 校验 OpenAPI 与生成的类型一致；前端 `vue-tsc` 0 error（新页面） |
| 风险 | 低 |

**总周期**：13 周。M1、M2 可部分并行（数据层与内核面互不依赖），实际约 11 周。

```
W1      M0
W2-W3   M1 ────────────┐
W4-W6        M2 ───────┤（M1/M2 可并行，甲 M2、乙 M1）
W7-W9   M3 ────────────┘
W10-W11 M4
W12-W13 M5
```

---

## 12. 风险登记册

| # | 风险 | 概率 | 影响 | 应对 |
|---|---|---|---|---|
| R1 | tc u32 过滤器 netlink 化不可行 | 中 | 中 | 保留 CLI + 能力探测，这本身就是改进；不阻塞 M2 其他项 |
| R2 | 双库迁移丢日志 | 低 | 高 | 先校验后删；旧表保留 7 天；`--legacy-single-db` 开关 |
| R3 | 统计接口因跨库改口径，与前端不一致 | 高 | 中 | M1 期同步改 5 个统计接口 + 前端；契约先行 |
| R4 | 分层重构引入行为差异 | 中 | 高 | 每模块切换前后跑同一套 E2E，结果 diff 必须为空 |
| R5 | 性能劣化 | 低 | 高 | M0 建立性能基线（p99/吞吐/CPS），每期回归 |
| R6 | 二进制超 45MB | 中 | 低 | 加 sftp/s3/prometheus 三库约 +5MB；用 `-ldflags="-s -w"` 与 `upx` 兜底 |
| R7 | 团队对 netlink 不熟 | 中 | 中 | M2 前先做 1 天 PoC；`docs/poc-nftables.md` 已有先例可循 |

---

## 13. 度量指标（如何判定重构成功）

**重构不是"改完了"，是这些数字变了。**

| 指标 | 当前基线 | 目标 | 测量方式 |
|---|---|---|---|
| `exec.Command` 数量 | **15** | ≤ 1 | `grep -rc` |
| `snat.go` 行数 | **1,890** | ≤ 400（拆 5 文件） | `wc -l` |
| 最大单文件行数 | 1,890 | ≤ 400 | `find + sort` |
| `transport` 层 `h.DB` 引用 | **约 100** | **0** | `grep -c 'h.DB' internal/transport/` |
| 整体测试覆盖率 | 待测 | ≥ 60% | `go test -cover` |
| `domain` + `compile` 覆盖率 | — | ≥ 80% | 同上 |
| 二进制体积 | **41.7 MB** | ≤ 45 MB | `ls -l` |
| 冷启动到 `/readyz` | 待测 | ≤ 基线 + 200ms | 脚本计时 |
| 转发 p99 时延 | 待测 | ≤ 基线 × 1.05 | `wrk`/`iperf3` + 抓包 |
| 万兆吞吐 | 有实测报告 | 劣化 ≤ 3% | 同上 |
| 依赖漏洞（high） | 未扫描 | 0 | `govulncheck` |
| 旧配置兼容 | — | 100% | 用现网 `config.yaml` 直接启动 |

---

## 14. 验收标准

重构完成需同时满足：

1. **功能零回归**：现有 403 条验收用例中，重构前通过的项重构后必须全部通过。
2. **指标全达标**：第 13 节表格全部满足。
3. **可回滚**：任一期的回滚开关都在文档中列明并实测有效。
4. **可交付**：单二进制 + `systemd` unit + 升级脚本，现场部署步骤不超过 5 步。
5. **文档同步**：`PROJECT-OVERVIEW.md`、`docs/contracts/api-fwgateway.md`、`docs/design-*` 全部更新到重构后状态；新增 `docs/architecture.md` 记录分层与依赖规则。

---

## 15. 附录

### A. 现阶段明确保留的好设计（重构中不得破坏）

| 设计 | 位置 | 为什么好 |
|---|---|---|
| 规则快照原子替换 | `atomic.Pointer` in `Manager` | 零锁读路径，热更新无抖动 |
| 编译层纯函数化 | `internal/proxy/fw` | 可离线单测，318 行测试已证明 |
| SIGUSR2 零中断升级 | `internal/proxy/upgrade.go` | 现场升级不掉连接 |
| 日志异步有界队列 | `internal/trafficlog` | 转发路径绝不被日志阻塞 |
| 三档轮转（时间/容量/水位） | `internal/trafficlog` | 磁盘打爆的兜底 |
| 单一自有 nft 表 | `nft.Table = "haweb"` | 与其他工具零冲突，卸载即删表 |
| `isLocalSession` 护栏 | `policy_nft.go` | 防止策略/清会话误杀管理面 |
| 内部路径剥离 `X-Forwarded-For` | `router.go` | 防登录锁绕过与审计污染 |
| 默认改密强制 | `requirePasswordChanged` | 开箱不留后门 |
| 双库文件 `0600` | `store.go` | 防同机用户读取凭据 |

### B. 技术债清理清单（随重构顺带处理）

| 项 | 处理 |
|---|---|
| `go.mod` 中 `google/nftables`、`vishvananda/netlink` 被标 `// indirect` | `go mod tidy` 修正 |
| `docs/` 下 19 份文档无索引 | 建 `docs/README.md` 索引 |
| `cmd/poc`（1,042 行）混在主干 | 移到 `tools/poc/` 或单独 module |
| 测试文件命名不统一（`zz_dstgroup_test.go`） | 统一为 `<module>_test.go` |
| `internal/api` 中 `router.go` 承担了 handler 职责 | 拆出 `handlers/auth.go` |
| 无 LICENSE | 补 |
| 无 CHANGELOG | 补，随版本 |

### C. 术语

| 术语 | 含义 |
|---|---|
| 端口（port） | 六边形架构中的接口定义，依赖倒置的边界 |
| 适配器（adapter） | 端口的具体实现，如 sqlite/nftables |
| 绞杀者模式 | 在旧代码外围逐步替换，新旧并存直到旧代码无引用 |
| 分表 | 按天建独立物理表，删除用 `DROP TABLE` |
| 能力探测 | 启动时检查内核/命令/权限，缺失则显式降级 |
| 范围内默认拒绝 | 仅对本产品入口（或本产品后端目标）的未打标流量拒绝，非全局 FORWARD DROP |

---

**评审待决事项**

| # | 事项 | 需谁拍板 |
|---|---|---|
| 1 | M2 中 tc 若无法 netlink 化，是否接受"保留 CLI + 能力探测" | 技术负责人 |
| 2 | 日志默认保留期是否从 30 天调整（影响磁盘预算） | 产品/运维 |
| 3 | 是否本期引入 RBAC（M4 或单独立项） | 产品 |
| 4 | 前端 TS 化范围：全量还是仅新页面 | 前端负责人 |
| 5 | 重构期间是否并行接新需求（建议冻结非紧急需求） | 项目负责人 |
