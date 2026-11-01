# API 参考（HTTP + Prometheus）

本文档对应 `internal/api` 的实际实现。所有接口都在**主端口**内（默认 `:8443`），
没有独立监听端口。

- 传输：HTTP/HTTPS（配置了 `web.cert_file`/`key_file` 时为 HTTPS，本项目部署默认开启）
- 编码：请求与响应均为 JSON（`/api/metrics` 与 `/healthz` 除外）
- 错误格式：统一 `{"error": "中文错误消息"}`；5xx 为脱敏消息，详情记服务端日志

---

## 1. 鉴权

### 1.1 登录拿 JWT

```http
POST /api/login
Content-Type: application/json

{"username": "admin", "password": "******"}
```

成功（200）：

```json
{
  "token": "eyJhbGciOi...",
  "username": "admin",
  "must_change_password": false
}
```

令牌默认 **24 小时**有效。带 `Authorization: Bearer <token>` 访问后续接口。

若账号启用了两步验证，返回 **401** 且带 `pending_token`：

```json
{"error": "需要两步验证码", "code": "totp_required", "pending_token": "..."}
```

此时用 `POST /api/login/2fa` 携带 `pending_token` + 验证码完成登录（`pending_token` 2 分钟有效）。

### 1.2 改密与令牌失效

```http
PUT /api/password
Authorization: Bearer <token>

{"old_password": "旧", "new_password": "新"}
```

**改密会递增 `users.token_version`，所有旧 JWT 立即失效**（包括监控令牌）。

### 1.3 未改初始密码时的限制

`must_change_password=true` 的账号只能访问 `/api/logout`、`/api/me`、`/api/password`，
其余接口一律拒绝。这是刻意的首登强制改密。

### 1.4 客户端 IP 与可信代理

所有涉及来源 IP 的判定（登录失败锁定、审计记录）走 `c.ClientIP()`。
**必须显式配置 `web.trusted_proxies`**，否则默认不信任任何 `X-Forwarded-For`
——否则任何人都能伪造 XFF 绕过登录锁定。

---

## 2. 转发规则（端口映射）

规则表 `forward_rules` 承载三种协议，行为完全不同（见 §9）。

### 2.1 列表

```http
GET /api/rules?page=1&page_size=50&protocol=tcp,udp
```

响应：

```json
{
  "items": [ { ...规则对象... } ],
  "total": 3,
  "page": 1,
  "page_size": 50
}
```

查询参数：

| 参数 | 说明 |
|---|---|
| `page` / `page_size` | 分页，`page_size` 上限见 API 校验 |
| `protocol` | 逗号分隔过滤，如 `tcp,udp` |

### 2.2 规则对象关键字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | int | 主键 |
| `name` | string | 规则名 |
| `protocol` | string | `tcp` / `udp` / `snat` |
| `listen_addr` | string | tcp/udp 为 `IP:端口`；snat 为入口网卡名 |
| `target_addr` | string | tcp/udp 为后端 `IP:端口`；snat 为出口网卡名 |
| `acl_mode` | string | `off` / `whitelist` / `blacklist`（空串为旧数据兼容值） |
| `allow_list` / `deny_list` | string | **JSON 数组字符串**，如 `["192.168.1.0/24"]` |
| `acl_group_id` | int | 引用名单组（0=不引用） |
| `dst_acl_mode` / `dst_allow_list` / `dst_deny_list` / `dst_acl_group_id` | | SNAT 目标限制 |
| `bw_group_id` | int | 绑定的带宽包（0=不绑定，不限速）|
| `min_kbps` | int | 包内每源保底 |
| `upload_limit_kbps` / `download_limit_kbps` | int | 规则自身限速（绑包后失效）|
| `max_conns` | int | 并发上限（0=不限）|
| `idle_timeout_sec` | int | 空闲超时（0=用全局默认）|
| `health_check` | bool/null | 后端健康检查开关（null=旧数据按开启）|
| `source_ip` | string | 连后端时绑定的本机源 IP（空=路由自动）|
| `enabled` | bool | 是否启用 |
| `last_error` | string | 启动失败原因（空=正常）|

### 2.3 新建 / 更新 / 删除

```http
POST   /api/rules
PUT    /api/rules/:id
DELETE /api/rules/:id
```

- **删除会先 `Mgr.Stop()` 主动拆内核规则，再删库**，不是只删记录
- 保存后引擎**热应用**：监听地址不变则原子替换配置（零中断）；变化则先绑新端口再关旧端口
- 失败原因写入 `last_error`，在列表里可见

### 2.4 启停

```http
POST /api/rules/:id/enable
POST /api/rules/:id/disable
```

**停用会断开存量连接**（TCP 走排空、超时强制关闭），不是"只挡新连接"。

### 2.5 实时统计

```http
GET /api/rules/:id/live
```

```json
{
  "rule_id": 33, "rule_name": "151", "enabled": true,
  "active_conns": 1,
  "upload_bytes": 2221379246, "download_bytes": 656199,
  "rate_up_bps": 3997696, "rate_down_bps": 1130,
  "window_seconds": 10
}
```

速率是**最近 10 秒滑动窗口平均**。

### 2.6 后端健康历史

```http
GET /api/rules/:id/health?start=<unix秒>&end=<unix秒>
```

- 缺省近 24 小时，最长 31 天
- 超过 1440 个点时**均匀降采样**，末点必留
- 仅 TCP 规则有健康检测（UDP 不探测）

### 2.7 导入导出

```http
GET  /api/rules/export
POST /api/rules/import        （原样导入）
POST /api/rules/import?mode=replace   （替换）
```

`replace` 会删除现有规则，**删除后必须调 `RecomputeDefaultDeny()` 重算 SNAT 默认拒绝辖区**，
否则可能留下指向不存在规则的拒绝行（该网卡全部转发被永久拒绝）。

---

## 3. 会话表

### 3.1 列表

```http
GET /api/sessions?proto=tcp&q=<关键词>&limit=500
```

**只返回 `ESTABLISHED` 状态的会话。** 原因：conntrack 里绝大多数是 `TIME_WAIT`
（生产实测 9 条里 7 条），已无数据流，混进来会淹没真实连接、让"共 N 条"失真。

响应：

```json
{
  "total": 3,
  "items": [
    {
      "id": "dGNwfDE3Mi4xNi4zMC4zfDYzODI4fDE3Mi4xNi40MC4xMHwyMjIy",
      "proto": "tcp",
      "src": "172.16.30.3:63858",
      "dst": "172.16.40.10:2222",
      "src_after": "172.16.40.10:63858",
      "backend": "172.16.30.20:22",
      "router": "other",
      "state": "ESTABLISHED"
    }
  ]
}
```

字段说明：

| 字段 | 说明 |
|---|---|
| `src` / `dst` | 客户端与服务端（NAT 前） |
| `src_after` | NAT 改写后的源（SNAT 出口 IP） |
| `backend` | **实际后端 `ip:port`**。端口映射是用户态重新 dial，conntrack 里没有这个信息，靠四元组关联进程内会话取得。为空表示：内核转发会话（SNAT）或 dial 未完成 |
| `router` | 归属：`snat:<出口IP>` / `dnat:<发布IP>` / `other` |

**两段合并**：一条端口映射连接在 conntrack 里是两条记录（客户端→网关、网关→后端），
列表会把它们**合并成一行**（用 dial 本地端口关联），不会出现同一连接两行。
合并判据同时要求「源端口命中 dial 端口」**且**「目的地址等于该会话后端」，
防止 dial 端口被内核复用导致误合并。

### 3.2 掐断

```http
POST /api/sessions/kill
Content-Type: application/json

{"id": "<会话列表返回的 id>"}
```

```json
{"killed": 1}
```

对**端口映射（用户态转发）**：真正关闭进程内的两个 socket，传输立即中断。
对 **SNAT 会话**：删 conntrack 表项。

> 只删 conntrack 断不了端口映射——进程里的 copy 协程会继续搬数据，内核立刻重建表项。

---

## 4. 监控与可观测性

### 4.1 Prometheus 指标（重点）

```http
GET /api/metrics
Authorization: Bearer <监控令牌 或 普通 JWT>
```

**这是标准 Prometheus 文本格式**（`# HELP` / `# TYPE` / `name{labels} value`），
可直接被 Prometheus 抓取。

#### 获取长效监控令牌

普通 JWT 只有 24 小时，不适合无人值守抓取。用这个接口签发**有效期 365 天**的专用令牌：

```http
POST /api/metrics-token
Authorization: Bearer <普通 JWT>
```

```json
{
  "token": "eyJhbGciOi...",
  "usage": "curl -H 'Authorization: Bearer <token>' https://<host>/api/metrics",
  "expires_in": 31536000
}
```

该令牌 **scope 限定为 `metrics`，只能访问 `/api/metrics`**，访问其它接口一律 401。
改密码后全部失效（`token_version` 递增）。

#### 完整指标清单

| 指标名 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `haweb_build_info` | gauge | `version` | 构建版本，恒为 1 |
| `haweb_uptime_seconds` | gauge | | 进程运行秒数 |
| `haweb_db_size_bytes` | gauge | | 数据库文件大小（含 WAL）|
| `haweb_rules_total` | gauge | | 规则总数 |
| `haweb_rules_enabled` | gauge | | 已启用规则数 |
| `haweb_rules_failed` | gauge | | 启动失败规则数（`last_error` 非空）|
| `haweb_sessions_active` | gauge | | 当前活跃会话数 |
| `haweb_backends_down` | gauge | | 后端异常规则数 |
| `haweb_engine_rejected_total` | counter | `reason=global\|rule` | 因并发上限被拒的连接数 |
| `haweb_engine_accept_errors_total` | counter | | accept 临时错误次数 |
| `haweb_engine_panics_total` | counter | | 转发路径被隔离的 panic 次数 |
| `haweb_rule_connections_current` | gauge | `rule_id,rule,protocol` | 规则当前连接数 |
| `haweb_rule_connections_total` | counter | `rule_id,rule,protocol` | 规则累计接受连接数 |
| `haweb_rule_bytes_total` | counter | `rule_id,rule,protocol,direction=up\|down` | 规则累计转发字节 |
| `haweb_rule_rate_bytes_per_second` | gauge | 同上 | 规则实时速率（10s 窗口，B/s）|
| `haweb_rule_errors_total` | counter | `rule_id,rule,protocol` | 出错会话数 |
| `haweb_rule_denied_total` | counter | `rule_id,rule,protocol` | 被 ACL 拒绝的连接数 |
| `haweb_rule_backend_up` | gauge | `rule_id,rule,protocol` | 后端健康，1=正常 0=异常（仅 TCP 规则）|
| `haweb_log_dropped_total` | counter | `kind=traffic\|audit` | 日志队列打满丢弃条数 |
| `haweb_log_cleanup_failures_total` | counter | `kind=traffic\|audit` | 保留期清理失败次数 |
| `haweb_log_queue_depth` | gauge | `kind=traffic\|audit` | 日志队列待落库条数 |
| `haweb_go_goroutines` | gauge | | goroutine 数 |
| `haweb_go_mem_alloc_bytes` | gauge | | 堆已分配字节 |
| `haweb_fd_count` | gauge | | 打开的文件描述符数 |

#### 口径注意（容易踩坑）

- `haweb_rule_bytes_total` 是**进程内实时累计**，与落库的流量日志口径不同，**不要混用**
- `/api/stats` 的今日/累计只含**已落库**数据，活跃会话字节单独在 `live_*` 字段，**不要叠加**（会双重计数）
- 限速开启（`tuning.splice=false` 或有规则/整机限速）时速率准确；
  splice 快路径下速率恒 0、字节数在会话结束时一次性入账

### 4.2 运行监控摘要（JSON）

```http
GET /api/observability
```

给「运行监控」页面用的 JSON 摘要：

```json
{
  "version": "dev",
  "uptime_seconds": 10625,
  "db_size_bytes": 4751008,
  "backends_down": 0,
  "rules": {"total": 3, "enabled": 3, "failed": 0},
  "engine": { ... },
  "runtime": {"goroutines": 42, "mem_alloc_bytes": 12345678, "fd_count": 31},
  "logs": {
    "traffic_queued": 0, "traffic_dropped": 0, "traffic_cleanup_failed": 0,
    "audit_queued": 0, "audit_dropped": 0, "audit_cleanup_failed": 0
  },
  "rule_metrics": [ ... ]
}
```

### 4.3 存活/就绪探测

```http
GET /healthz
```

**无需鉴权**，返回 JSON 摘要。适合作为 Kubernetes liveness/readiness 或 Prometheus blackbox 探测目标。

实测输出（生产机，字段已核对源码 `internal/api/router.go:200-223`）：

```json
{
  "status": "ok",
  "version": "dev",
  "tls": true,
  "uptime_seconds": 10625,
  "db_size_bytes": 4751008,
  "egresses_up": 2,
  "egresses_down": 0,
  "backends_down": 0,
  "rules_total": 3,
  "rules_enabled": 3,
  "rules_failed": 0,
  "active_sessions": 0,
  "rejected_global": 0,
  "rejected_rule": 0,
  "accept_errors": 0,
  "panics": 0,
  "traffic_log_dropped": 0,
  "audit_log_dropped": 0,
  "traffic_cleanup_failed": 0,
  "audit_cleanup_failed": 0,
  "traffic_log_rotated": 0
}
```

`traffic_log_rotated` 非零表示容量/水位自动轮转已发生过（删过行）。

### 4.4 性能分析

```http
GET /api/pprof-token
```

```json
{"url": "/api/debug/pprof/?pprof_token=..."}
```

浏览器新标签页无法带 `Authorization` 头，所以用查询参数令牌（10 分钟、仅限
`/api/debug/pprof` 路径）。首次带令牌访问时服务端落一个 HttpOnly Cookie，
让索引页里的相对子链接（`/goroutine`、`/heap` 等）也能通过鉴权。

> 带 `pt=pprof` 作用域的令牌访问其它接口一律 401——不要放宽这条，
> 否则 URL 里的令牌会被重放到全部 API。

---

## 5. 防火墙策略（全局）

作用于**全部转发流量**，与规则内的源白名单（只管一条规则）是两个层级。

### 5.1 列表

```http
GET /api/fw-policies
```

```json
{
  "total": 1,
  "items": [
    {
      "id": 17, "name": "禁止访问外部 25", "order": 1, "action": "drop",
      "src_list": ["192.168.1.0/24"], "dst_list": null,
      "proto": "tcp", "port_range": "25", "enabled": true,
      "stats": {"pkts": 128, "bytes": 7680}
    }
  ]
}
```

注意 `src_list` / `dst_list` 在**响应里是数组**（`null` = 未配置 = 任意），
但在**请求里必须是 JSON 字符串**（见下）。

### 5.2 新建 / 更新

```http
POST /api/fw-policies
PUT  /api/fw-policies/:id
Content-Type: application/json

{
  "name": "禁止访问外部 25",
  "action": "drop",
  "proto": "tcp",
  "port_range": "25",
  "src_list": "[\"192.168.1.0/24\"]",
  "dst_list": "",
  "enabled": true,
  "kill_established": false
}
```

| 字段 | 约束 |
|---|---|
| `action` | `accept` / `drop` |
| `proto` | `tcp` / `udp` / `icmp` / `any`（空= tcp）|
| `port_range` | `80` / `80,443,1000-2000`；**`icmp`/`any` 时必须为空** |
| `src_list` / `dst_list` | JSON 字符串数组；空串 = 任意。**直接写裸 IP 会 400** |
| `kill_established` | 仅 `drop` 有意义：保存时立即掐断匹配的存量会话 |

响应：

```json
{"id": 17, "killed_sessions": 0}
```

### 5.3 动作语义

| 动作 | 编译结果 | 含义 |
|---|---|---|
| `accept` | `meta mark \|= POLICY_OK`，**不终结** | 打标，后续仍要过规则白名单 |
| `drop` | `verdict drop`（终结）+ counter | 直接丢弃，计入拒绝统计 |

按 `order` **升序**评估，先命中先生效。

### 5.4 删除 / 重排

```http
DELETE /api/fw-policies/:id
PUT    /api/fw-policies/reorder

{"ordered_ids": [3, 1, 2]}
```

`order` 有唯一索引，重排走两阶段更新（先置负数占位再写目序号）避免唯一冲突。

---

## 6. 其他资源

| 资源 | 端点 | 说明 |
|---|---|---|
| **SNAT 带宽包** | `GET/POST/PUT/DELETE /api/bandwidth-groups` | 多条规则共享的额度。绑了包才限速，不绑不限 |
| **名单组** | `GET/POST/PUT/DELETE /api/acl-groups` | 三类：`whitelist` / `blacklist` / `ip`（中性，两种模式都能引用）|
| **出口管理** | `GET/POST/PUT/DELETE /api/egresses`、`POST /api/egresses/:id/probe` | SNAT 出口实体与连通性探测 |
| **网卡列表** | `GET /api/interfaces` | 供前端下拉选择 |
| **流量日志** | `GET /api/traffic-logs` | 分页查询，支持时间/状态/规则过滤 |
| **操作审计** | `GET /api/audit-logs` | 所有写操作都有记录 |
| **统计** | `GET /api/stats` | 今日/累计（**仅落库数据**）+ `live_*`（活跃会话，**勿叠加**）|
| **能力探测** | `GET /api/capabilities` | nft/conntrack/tc/ifb 等内核能力 |
| **状态** | `GET /api/status` | 运行状态摘要 |
| **数据库备份** | `GET /api/backup/db` | `VACUUM INTO` 生成一致性快照后下载并立即删除临时文件 |
| **两步验证** | `GET /api/2fa/status`、`POST /api/2fa/begin\|confirm\|disable` | TOTP |

---

## 7. Prometheus + Grafana 对接（能否？）

### 7.1 结论：**可以，当前版本已具备完整能力**

| 条件 | 状态 |
|---|---|
| 暴露标准 Prometheus 文本格式 | ✅ `GET /api/metrics` |
| 长效采集凭据（无需每天换 token）| ✅ `POST /api/metrics-token`，**365 天** |
| 凭据权限最小化 | ✅ scope 限定 `metrics`，只能读这一个端点 |
| 指标覆盖 | ✅ 实测 **24 个指标族 / 47 个样本**：进程、规则、会话、引擎、日志队列、Go 运行时 |
| Grafana 数据源 | ✅ Prometheus 数据源即可，无需插件 |
| 存活探测 | ✅ `GET /healthz`（无需鉴权）|

**没有 Prometheus 专属 exporter 进程**，但不需要——`/api/metrics` 就是标准格式。

### 7.2 Prometheus 配置

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'lightgw'
    scheme: https
    metrics_path: /api/metrics
    scrape_interval: 15s
    # 自签证书时二选一：
    tls_config:
      insecure_skip_verify: true     # 简单但不安全
      # ca_file: /etc/prometheus/lightgw-ca.pem   # 推荐
    authorization:
      type: Bearer
      credentials: '<从 POST /api/metrics-token 拿到的令牌>'
    static_configs:
      - targets: ['192.168.10.170:8443']
```

拿到令牌的方式：

```bash
TOKEN=$(curl -sk -X POST https://192.168.10.170:8443/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"***"}' | jq -r .token)

MT=$(curl -sk -X POST https://192.168.10.170:8443/api/metrics-token \
  -H "Authorization: Bearer $TOKEN" | jq -r .token)

# 验证
curl -sk https://192.168.10.170:8443/api/metrics -H "Authorization: Bearer $MT" | head
```

### 7.3 实测验证记录（2026-11-01，生产机 192.168.10.170）

本节所有步骤都在真机跑过，非纸面推演：

| 检查项 | 结果 |
|---|---|
| 登录拿 JWT | ✅ 156 字符 |
| 签发监控令牌 | ✅ 176 字符，`expires_in=31536000`（365 天）|
| 监控令牌抓 metrics | ✅ **HTTP 200**，24 个指标族 / 47 个样本行 |
| 监控令牌访问 `/api/rules` | ✅ **HTTP 401 正确拒绝**（scope 隔离生效）|
| 无令牌访问 `/api/metrics` | ✅ **HTTP 401 正确拒绝** |
| `/healthz` 免鉴权 | ✅ HTTP 200 |
| `haweb_rule_bytes_total` 存在 | ✅ counter |
| `haweb_rule_backend_up` 存在 | ✅ gauge |

### 7.4 推荐的 Grafana 查询

**带宽（按规则）**

```promql
sum by (rule) (rate(haweb_rule_bytes_total[5m])) * 8
```

**活跃连接**

```promql
sum by (rule) (haweb_rule_connections_current)
```

**后端异常告警**

```promql
haweb_rule_backend_up == 0
```

**ACL 拒绝速率（异常扫描/攻击信号）**

```promql
sum by (rule) (rate(haweb_rule_denied_total[5m])) > 1
```

**日志丢弃（说明日志系统跟不上转发）**

```promql
rate(haweb_log_dropped_total[5m]) > 0
```

**并发上限逼近（reason=rule 持续增长说明该规则名额不够）**

```promql
rate(haweb_engine_rejected_total{reason="rule"}[5m]) > 0
```

**服务存活**

```promql
time() - haweb_uptime_seconds    # 期望稳定不出现"重置"
```

### 7.5 已知限制（务必知悉）

| 限制 | 说明 |
|---|---|
| **splice 路径速率恒 0** | `tuning.splice=true` 且规则与整机都不限速时走零拷贝，速率与字节数滞后到会话结束。需要实时速率就关掉 splice |
| 指标口径与落库不同 | `haweb_rule_bytes_total` 是进程内累计，`/api/stats` 是已落库数据，**不要相加** |
| 无 metric 级鉴权粒度 | 一个令牌可读全部指标，无法按规则隔离 |
| 令牌 365 天 | 不会自动轮换，建议记在日历里定期重签 |
| 改密即失效 | 改 `admin` 密码会让监控令牌一起失效，Prometheus 需重新配置 |
| 无原生 Grafana Dashboard | 仓库不附带 JSON dashboard，需按 §7.3 自行搭 |

---

## 8. 错误码速查

多数业务错误用 **400** + 中文 `error`，鉴权失败 **401**，不存在 **404**，
服务端内部错误 **500**（消息已脱敏，详情看 `journalctl -u haproxyweb`）。

常见 400 消息：

| 消息 | 原因 |
|---|---|
| `src_list 必须是 JSON 字符串数组: ...` | 名单字段直接写了裸 IP，没写成 `["1.2.3.4"]` |
| `proto 为 icmp/any 时 port_range 必须为空` | 协议选了 any/icmp 却填了端口 |
| `action 只能是 accept 或 drop` | 动作值非法 |
| `白名单模式需选择名单组或至少添加一条白名单` | 选了白名单模式但名单为空 |
| `端口发布（dnat）功能已下线，请改用端口映射（tcp/udp）` | `protocol=dnat` 已被产品下线 |
| `监听端口无效` / `端口 %q 无效` | 端口超出 1-65535 |

---

## 9. 三种协议的行为差异（选型必读）

| | 端口映射 `tcp`/`udp` | SNAT 穿越 `snat` |
|---|---|---|
| 实现层 | **用户态**（Go 进程 accept 后重新 dial）| **内核**（nftables + tc）|
| 是否占端口 | 是，`net.Listen` 真占 | 否，不监听 |
| `listen_addr` | `IP:端口` | 入口网卡名 |
| `target_addr` | 后端 `IP:端口` | 出口网卡名 |
| 后端看到的源 IP | **网关 IP**（重新 dial 的必然结果）| 保持客户端源或 SNAT 后地址 |
| 会话可查 | ✅ 进程内会话，可看实时速率、可掐断 | 只有 nft counter，掐断靠删 conntrack |
| 性能 | 每连接一次用户态拷贝 | 内核转发，更高 |

> **端口发布（`dnat`）已在当前版本下线**，仅保留引擎代码。理由：hairpin SNAT
> 会把后端看到的源地址改写成网关 IP，与"纯内网模拟公网访问、需要真实源 IP"
> 的诉求冲突（实测见 `docs/poc-result.md` §3.7）。

---

## 10. 变更记录

| 日期 | 变更 |
|---|---|
| 2026-11-01 | 会话表只返回 ESTABLISHED；新增 `backend` 字段；两段 conntrack 合并成一行 |
| 2026-11-01 | 端口发布（dnat）下线 |
| 2026-11-01 | 掐断对端口映射生效（关闭用户态 socket）；ACL 收紧会断开存量连接 |
