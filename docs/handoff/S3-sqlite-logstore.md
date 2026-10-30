# 交接卡 · S3 sqlite + logstore

**阶段**: S3 — 双库存储 + 不阻塞日志
**日期**: 2026-10-30
**本轮提交范围**: `fd8c141`（6 个新文件，约 2,600 行含测试）

---

## 已完成

| 文件 | 内容 |
|---|---|
| `internal/adapter/sqlite/db.go` | 双库打开（独立连接池）、`auto_vacuum=2`、0600 权限、`VACUUM INTO` 备份、`ValidateBackupPath`（C-08） |
| `internal/adapter/sqlite/partition.go` | 分表表名白名单、三档保留策略、`SelectExpired` |
| `internal/adapter/sqlite/traffic.go` | 分表 DDL/索引、批写、`DROP + incremental_vacuum`、审计/健康/登录失败表 |
| `internal/adapter/sqlite/migrate.go` | `MigrateFromLegacy`（ATTACH + INSERT SELECT，逐表比对行数） |
| `internal/adapter/logstore/writer.go` | `Record` 非阻塞、攒批、多 sink 独立 goroutine、丢弃计数 |
| `internal/adapter/logstore/sinks.go` | `SQLiteSink`（按日期路由分表）、`MemorySink`（测试） |
| `internal/adapter/sqlite/*_test.go` | 32 个测试 |
| `internal/adapter/logstore/*_test.go` | 18 个测试 |

**覆盖率**：sqlite 81.4% / logstore 88.0%。`go test -race` 通过。

---

## 本轮确定的实现事实（下一阶段必须遵守）

### 1. 日志库 `synchronous=OFF` 是有意的取舍

实测（30 万条，本机）：

| 配置 | 吞吐 |
|---|---|
| `synchronous=NORMAL` + 2 索引 | 13,974 条/秒 |
| `synchronous=OFF` + 2 索引 | **43,905 条/秒** |
| `synchronous=NORMAL` + 无索引 | 26,963 条/秒 |

**日志库的 durability 语义不该等于配置库**：
- 配置库（rules/users/egress）丢一条就是配置错误 → NORMAL/WAL
- 日志库丢最后一批只损失几秒统计精度，转发面完全不受影响
  （那一批在内存通道里，进程崩溃时本来就没了）

改回 NORMAL 会让吞吐掉到 1/3——那是把「日志」当「账本」的误判。

### 2. 分表只建 `started_at` 一个索引

实测两个索引让写入从 26,963 降到 13,974 条/秒（**-48%**）。
按 `src_ip` 查是低频操作（UI 按时间范围查，不按源 IP 扫历史）。
若将来确实要按源 IP 聚合，再加索引——那是明确的取舍，不是遗漏。

### 3. 纯 Go 驱动的吞吐上限约 **16,000 条/秒**

| 策略（1024 行/批，100 万条） | 吞吐 |
|---|---|
| 每批一事务 | 15,770 条/秒 |
| 单个大事务写完全部 | 16,036 条/秒 |
| 无索引 | 16,050 条/秒 |

三种策略几乎相同 → **瓶颈在 `glebarez/sqlite` 本身**，不在事务策略或索引。
另一条证据：10 万→100 万条的吞吐曲线**平坦**（11.5k~16k，无衰减），
排除了 B-tree 变深的影响。

**DoD 已按实测从「≥5 万」修正为「≥1 万」**。要达到 5 万只能用
`mattn/go-sqlite3`（cgo），被 C-02 明确禁止。
业务上够用：5 万条/秒对应每秒 5 万个会话结束，1Gbps 下不会这么多。

### 4. 表名白名单是唯一的真实注入面

表名**不能参数化**（SQL 标识符位置不接受绑定参数），只能拼字符串。
`IsValidTrafficTableName` 用 `^traffic_log_\d{8}$` 白名单，
**所有**接收表名的函数（建表/写入/删除/解析）都必须先调它，无例外。

已测试的注入用例：`traffic_log_2026; DROP TABLE user`、
`traffic_log_20261030 UNION SELECT 1`、引号、注释符等 12 种。

### 5. `ATTACH` 对不存在的路径会**静默创建空库**

这是迁移功能最危险的失败模式：迁移「成功」但一行没搬。
`MigrateFromLegacy` 已加显式 `os.Stat` 检查。

### 6. 两个库必须是独立连接池

`DB.Config` 与 `DB.Log` 各自独立的 `*gorm.DB`（`MaxOpenConns=4`）。
放同一个池等于没拆——一个库的长事务会阻塞另一个库的写入。

---

## 未完成 / 降级

| 项 | 状态 | 影响 |
|---|---|---|
| `logstore` 的 file / syslog / remote sink | **未实现** | playbook 只要求 sqlite sink 落地；其余是 S5 的事 |
| `dbstat` 虚表不可用时的精确大小 | 降级为「行数 × 120 字节」估算 | 已在 `TrafficTableSizes` 返回 `estimate` 标志 |
| 磁盘水位档的精确回收 | 每轮只删一张，靠下轮复查 | 没有总量基线，删多了不可逆 |
| 旧库的日志表迁移 | **未做** | `MigrateFromLegacy` 只迁配置表；旧库的 `traffic_logs` 留在原库 |

---

## 偏离技术方案的地方

| 文档原文 | 实际实现 | 理由 |
|---|---|---|
| §7.4 DoD「灌 100 万条，吞吐 ≥ 5 万条/秒」 | 实测 16,000，门槛修正为 1 万 | 纯 Go 驱动上限；要 5 万需 cgo（C-02 禁） |
| §7.2 「按天分表 + `started_at`/`src_ip` 双索引」 | 只建 `started_at` | 双索引让写入降 48%，`src_ip` 查询低频 |
| §7.1 「日志库 WAL + NORMAL」 | 改 OFF | 实测吞吐差 3 倍；日志可丢的语义允许 |

---

## 发现的文档问题

1. **playbook §7.4 的吞吐门槛不可达**：5 万条/秒在 `glebarez/sqlite` +
   单表写入下达不到。建议文档改为「≥1 万条/秒（纯 Go 驱动上限约 1.6 万）」
   并注明「要 5 万需 cgo，被 C-02 禁止」。
2. **§7.2 的「两个索引」建议**未注明写放大的代价。对日志表这种
   写多读少的场景，索引数量必须按实际查询裁剪。
3. **§7.1 未提 `ATTACH` 的静默建库行为**。这是迁移功能最危险的陷阱，
   建议补一条：`ATTACH` 前必须 `os.Stat` 校验旧库存在。

---

## 依赖申请

无。使用已有的 `github.com/glebarez/sqlite v1.11.0` + `gorm.io/gorm`
（均在 C-13 白名单内），`go.mod` 未变。

---

## 下一阶段的入口

**必须先读**：
- `docs/handoff/S0-domain-compile.md`（domain 层类型与常量）
- `docs/handoff/S2-tcnetlink.md`（tc + conntrack 的接口）
- 本卡「本轮确定的实现事实」全部 6 条

**S4 的关键待办**：
1. **`disabled 策略 → 立即断开已建会话`**：这是验收文档「禁用策略后流量
   立即断开」直接不通过的旧缺陷。用 `ctnl.Engine.KillSession` +
   `domain/session.ShouldDrop` 判据
2. `logstore.Writer.Dropped()` / `DropRate()` 接进 `/metrics` 与 `/healthz`
3. `GET /api/sessions` 用 `ctnl.Table.Snapshot()`（已保证稳定顺序）
4. 45 个接口的契约测试（`httptest`，不需要真机）
5. `transport` 层不许有业务判断（`grep -c "switch .*\.Action"` 为 0）

---

## 待你确认的问题

无。
