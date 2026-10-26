# 轻量专线网关（HAProxyWeb）

纯 Go 实现的**专线防火墙网关**：**TCP/UDP 端口映射 + SNAT 穿越与端口发布（内核 nftables 线速转发，netlink 直连零 iptables 依赖）+ 多出口主备/权重分担 + 状态防火墙策略 + 会话可视化 + IPv6 双栈**，自带 Web 管理后台（登录制），前端构建产物嵌入二进制，**单文件部署**。

## 功能特性

- **两种协议转发**
  - TCP 四层端口映射（`:9000 -> 10.0.0.5:3306`）
  - UDP 转发（按客户端会话表转发，空闲 60s 回收）
- **实时速率**：每条规则的上传/下载实时速率（最近 10 秒滑动窗口平均，B/s），规则列表与总览页直接显示；`GET /api/rules/:id/live` 供外部系统按规则轮询（活跃连接/累计字节/实时速率）；`/api/metrics` 提供 `haweb_rule_rate_bytes_per_second` 指标族（splice 快路径规则速率恒 0，与实时字节统计同口径的已知滞后）
- **名单组**：可自定义白名单/黑名单组（`/api/acl-groups`，「名单组」页管理），多条规则直接引用同一组；组条目变更即时热生效（联动重应用全部引用中的规则，存量连接不断）；规则引用组时无需直配名单，导出规则 JSON 时组条目自动内联展开（跨实例导入自包含）
- **规则热生效**：新建/修改/启停规则无需重启进程；监听地址不变时零中断
- **限速**：每条规则独立配置上传/下载限速（KB/s，令牌桶，规则内所有连接共享配额），0 表示不限
- **连接上限**：每条规则可配置并发连接/请求数上限（0 = 不限），超出直接断开，防止资源耗尽
- **IP 黑白名单**：每条规则独立配置，支持单 IP 与 CIDR 网段；黑名单优先，白名单非空时仅放行名单内 IP；被拒绝的访问记入流量日志
- **端口发布（DNAT）**：公网 IP:端口 → 内网后端（状态 DNAT 内核线速转发）；源白名单、后端健康联动（不可达自动卸载/恢复自动重装）、停用即断（conntrack 精确掐断）、不可达行为可配（即时拒绝/静默丢弃）
- **多出口**：出口实体（网卡+网关+优先级分层+层内权重）四种探测（ICMP 网关/ICMP 目标/TCP 端口/常开）自动切换回切（去抖阈值可配）；主备与同层权重分担统一模型；切层时受影响存量会话按出口地址集精确掐断
- **状态防火墙策略**：有序 accept/drop（源/目的/协议/端口组），已建会话免重评（含回程包）；drop 策略可选立即掐断存量；命中计数展示；全链热更新
- **SNAT 源池**：出口网卡多地址池，源确定性映射（同源恒同出口 IP），“一卡多址对外呈现多出口 IP"
- **会话表**：内核转发会话实时可视化（穿越/发布归属判定、过滤、单条掐断）
- **IPv6 双栈**：NAT66 穿越 / v6 发布 / v6 策略全链支持
- **宿主和平共存**：docker / firewalld / iptables-nft 环境零冲突（单锚点规则）；iptables-legacy 宿主启动即报错指路（防黑洞）
- **后端健康检查**：运行中的 TCP 规则每 60 秒对目标做一次连接探测（新建/修改规则后立即探测一次），状态翻转才记日志；可在规则表单按需开关（默认开启）。检测结果落库（`health_logs` 表，保留期跟随流量日志保留天数，重启不丢）。规则列表「后端」列绿=正常/红=异常，点击打开检测历史抽屉：支持时间段筛选（快捷选项/自定义范围）与折线图；`/healthz` 的 `backends_down` 与 `/metrics` 的 `haweb_rule_backend_up` 可供告警
- **流量日志**：每条 TCP/UDP 会话一条记录（来源、双向字节、状态、耗时），异步批量落库，自动按保留天数清理；队列打满时丢弃计数暴露在 `/healthz`
- **操作审计**：登录/登出/改密/规则增删改启停全部留痕
- **安全**：JWT 会话（24h，改密即吊销全部旧令牌）、bcrypt 密码、内置 TLS 支持（**非回环监听且未配置 TLS 时启动即拒绝**，回环/localhost 仅本机访问不受限）、**TOTP 两步验证**（RFC 6238，验证器 App 扫码 + 10 个一次性恢复码，防重放）、登录失败 5 次锁定来源 IP 10 分钟（锁定状态落库，重启不失效；不信任伪造的 X-Forwarded-For）+ 全网滑动窗口限流、首次登录强制修改默认密码、HSTS/CSP 等安全响应头
- **监控采集令牌**：设置页可签发仅限 `/api/metrics` 的长效令牌（一年），Prometheus 无人值守抓取不必每天换 24h 会话令牌；改密自动失效
- **单二进制**：SQLite（纯 Go 驱动，无 cgo）+ go:embed 前端，交叉编译即拷贝即用
- **生产可运维**：优雅关闭（SIGTERM 落库残余日志）、`/healthz` 健康检查、版本号注入、systemd 部署单元

## 快速开始

```bash
# 构建前端 + 后端（需要 Node.js 18+ 与 Go 1.25+）
make build

# 启动（首次自动创建 data/ 目录、SQLite 与默认管理员）
./bin/haproxyweb
```

浏览器打开 `http://<服务器IP>:8080`，默认账号 `admin / admin123`（首次登录必须修改密码，未改密前其余管理接口全部拒绝访问）。

## 配置

`config.yaml`（同目录，可缺省，支持环境变量覆盖；`-c` 可指定配置文件路径）：

```yaml
web:
  listen: ":8080"            # 管理后台监听地址（HAWEB_LISTEN）
  data_dir: "./data"         # 数据目录：SQLite 与 JWT 密钥（HAWEB_DATA_DIR）
  log_retention_days: 30     # 流量日志保留天数（HAWEB_LOG_RETENTION_DAYS）
  cert_file: ""              # TLS 证书（HAWEB_CERT_FILE），与 key_file 同时配置时启用 HTTPS
  key_file: ""               # TLS 私钥（HAWEB_KEY_FILE）
  trusted_proxies: []        # 可信代理网段（HAWEB_TRUSTED_PROXIES，逗号分隔），空 = 不信任任何代理头
```

> 注意：转发规则不能占用管理后台端口，创建规则时会自动校验。数据目录权限为 0700，数据库文件 0600。

## 规则字段说明

| 字段 | 说明 |
| --- | --- |
| 协议 | tcp / udp |
| 监听地址 | `:9000`（所有网卡）或 `192.168.1.5:9000`（指定网卡） |
| 目标地址 | `host:port`（如 `10.0.0.5:3306`） |
| 白名单 | 与黑名单二选一（「控制模式」选择）；JSON 数组，元素支持 `1.2.3.4`、`192.168.1.0/24`；仅名单内 IP 可访问；也可引用「名单组」代替直配 |
| 黑名单 | 与白名单二选一；命中直接拒绝，其余放行；也可引用「名单组」代替直配 |
| 名单组 | 在「名单组」页预定义白名单/黑名单组，规则直接引用（与控制模式同类型）；组条目变更即时热生效到全部引用中的规则，无需逐条改规则 |
| 上传/下载限速 | KB/s，规则内连接共享令牌桶；0 = 不限 |
| 连接上限 | 并发连接数上限，超出直接断开；0 = 不限 |
| 空闲超时 | TCP 连接持续无数据超过该秒数后断开（防止僵死连接耗尽句柄）；0 = 跟随全局 `tuning.tcp_idle_timeout_sec` |
| 健康检测 | 仅 TCP：每分钟探测后端端口并落库，绿/红状态与可筛选时间段的折线图（默认查询近 24h，最长 31 天）；默认开启 |

## REST API（Bearer Token 认证）

```
GET  /healthz                    健康检查（不鉴权：版本/uptime/规则失败数/拒绝与丢弃计数/库体积）
POST /api/login                  登录 {username, password} -> {token}（开启两步验证时返回 totp_required + pending_token）
POST /api/login/2fa              两步验证第二步 {pending_token, code} -> {token}
GET  /api/2fa/status             两步验证状态
POST /api/2fa/begin              生成两步验证密钥（二维码+恢复码，待确认）
POST /api/2fa/confirm            确认开启两步验证 {code}
POST /api/2fa/disable            关闭两步验证 {password, code}
POST /api/metrics-token          签发监控采集令牌（仅 /api/metrics，一年）
POST /api/logout                 退出
GET  /api/me                     当前用户
PUT  /api/password               修改密码 {old_password, new_password} -> {token}
GET/POST /api/rules              规则列表 / 新建
PUT/DELETE /api/rules/:id        更新 / 删除
GET  /api/rules/:id/live         单规则实时统计（活跃连接/累计字节/实时速率 B/s）
POST /api/rules/:id/enable|disable
GET/POST /api/acl-groups         名单组列表 / 新建（whitelist/blacklist 组）
PUT/DELETE /api/acl-groups/:id   名单组更新（联动重应用引用规则）/ 删除（被引用时拒绝）
GET  /api/rules/export           导出全部规则 JSON（附件下载）
POST /api/rules/import?mode=merge|replace&dry_run=   导入规则（逐条校验，逐条报告结果）
GET  /api/stats                  总览统计
GET  /api/streams                实时活跃会话
GET  /api/traffic-logs           流量日志（分页+筛选：rule_id/protocol/source_ip/status/start/end）
GET  /api/audit-logs             操作审计（分页+筛选）
GET  /api/observability          运行监控数据（进程/引擎/日志水位/逐规则指标，JSON）
GET  /api/metrics                Prometheus 文本格式指标（同上数据，供采集）
GET  /api/debug/pprof/*          性能分析（pprof）
GET  /api/backup/db              全库一致性快照下载（VACUUM INTO，含用户/规则/日志）
```

## 生产部署（systemd）

1. **构建与安装**

   ```bash
   make build                                        # 产出 bin/haproxyweb（前端已嵌入）
   sudo useradd --system --home /var/lib/haproxyweb --shell /usr/sbin/nologin haproxyweb
   sudo mkdir -p /var/lib/haproxyweb /etc/haproxyweb
   sudo install -m 0755 bin/haproxyweb /usr/local/bin/
   sudo install -m 0640 deploy/haproxyweb.service /etc/systemd/system/
   ```

2. **配置**：写入 `/etc/haproxyweb/config.yaml`，必须启用 TLS：

   ```yaml
   web:
     listen: ":8443"
     data_dir: "/var/lib/haproxyweb"
     cert_file: "/etc/haproxyweb/tls.crt"
     key_file: "/etc/haproxyweb/tls.key"
   ```

   证书可用 Let's Encrypt（`certbot certonly`）或内部 CA 签发；文件属主设为 `haproxyweb` 或让服务以 `root` 读取后降权。绑定位端口无需 root，unit 已授予 `CAP_NET_BIND_SERVICE`。

   > **安全底线**：`listen` 为非回环地址（`:8443`、`0.0.0.0:8443`、外网 IP）且未配置 cert/key 时，进程启动即失败并给出指引——防止登录密码明文暴露在网络上。仅隔离内网/临时调试可显式设 `web.allow_insecure: true`（或环境变量 `HAWEB_ALLOW_INSECURE=1`）放行。默认 `127.0.0.1:8080` 仅本机访问不受限。

3. **启动与开机自启**

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now haproxyweb
   curl -fsS http://127.0.0.1:8443/healthz   # 健康检查
   ```

4. **防火墙**：只放行管理后台与需要暴露的转发端口；`trusted_proxies` 保持为空（直连部署）。可观测数据（运行监控页、`/api/metrics`）都在管理端口内，无需额外放行。

5. **日志**：经 stdout/journal 采集：`journalctl -u haproxyweb`。访问日志含来源 IP 与 UA。流量日志与审计日志按保留天数自动清理（默认 30/90 天），删除后自动收缩 WAL。

### 配置热加载

`kill -SIGHUP <pid>`（或 `systemctl reload`，unit 已配置 `ExecReload=kill -TERM $MAINPID` 之外的方案时可自行调整）重新读取配置文件：

- **即时生效**：`tuning` 全部转发面参数（全局连接上限、空闲/拨号超时、UDP 参数、整机带宽上限、splice、健康检查周期与保留期、webhook 地址）、`web.log_retention_days`、`web.audit_retention_days`、`web.trusted_proxies`
- **需重启生效**：`web.listen`、`web.data_dir`、`web.cert_file/key_file`（重载时日志会明确列出需重启的参数，未列出的都已生效）
- 重载失败（配置文件非法）时保留当前配置并记日志，不影响运行中的转发

### 零中断升级（SIGUSR2）

升级二进制后**无需停服、不断连接**：

```bash
# 替换二进制文件后：
kill -USR2 $(systemctl show -p MainPID --value haproxyweb)
```

流程：新进程继承全部监听（fd 传递，同一 socket 无重绑定）并接管新连接；旧进程继续服务存量连接——**SSH 隧道等长连接完全不断**——直到所有连接自然结束，旧进程落库日志后自动退出。日志以 `[upgrade]` 前缀记录交接全过程。说明：

- systemd 会通过 sd_notify 重新绑定主进程 PID，后续 `systemctl restart/stop` 正常作用于新进程
- UDP 会话随旧进程结束重建（数据报语义，客户端无感知）
- 新进程启动失败（如配置错误）时旧进程不受影响继续服务
- 与 `systemctl restart` 的区别：restart 会排空并断开存量连接（见下节）

### 升级行为与维护窗口

- **SIGTERM 行为**：停止接收新连接 → 等待存量连接自然结束（`tuning.drain_timeout_sec`，默认 10s，超时强制关闭）→ 落库残余日志 → 退出。进行中的传输会被正常关闭（非 RST），长连接隧道会中断——升级请安排在低峰期。
- **升级步骤**：备份（见下节）→ `systemctl stop haproxyweb` → 替换二进制 → `haproxyweb -check` 校验配置 → `systemctl start haproxyweb` → `/healthz` 与运行监控页验证。
- **注意**：新进程必须等旧进程完全退出（管理端口释放）后再启动，否则新进程会因端口占用绑定失败退出；systemd 部署下 `Restart=on-failure` 会自动重试，无需人工干预。
- **回滚**：换回旧版本二进制重启即可（schema 迁移为增量式，旧版本读新库兼容；若不放心可连同恢复升级前的数据库快照）。
- **WSL / 无 root 环境**：可用 systemd 用户级服务代替系统级安装（`~/.config/systemd/user/haproxyweb.service`，`systemctl --user enable --now haproxyweb`，`loginctl enable-linger $USER` 实现开机自启），日常用 `systemctl --user status/restart haproxyweb` 管理，日志看 `journalctl --user -u haproxyweb`。

## 备份与恢复

三种手段，按需组合：

| 手段 | 内容 | 适用 |
| --- | --- | --- |
| 规则导出 JSON | 仅转发规则配置 | 跨实例迁移、人工审阅编辑、版本化管理 |
| 全库快照 `.db` | 用户+规则+流量+审计 | 例行备份、整机恢复 |
| `sqlite3 .backup` | 全库（命令行） | 不便登录 Web 时的替代 |

- **导出/导入**：管理后台「备份恢复」页，或 `GET /api/rules/export` / `POST /api/rules/import?mode=merge&dry_run=true`。导入支持 `dry_run` 预览（零副作用），`merge` 冲突跳过并逐条报告，`replace` 清空后导入（前端二次确认）。导出/导入均有审计记录。
- **快照下载**：管理后台「备份恢复」页，或 `GET /api/backup/db`。
- **定时备份**：仓库提供现成单元 `deploy/haproxyweb-backup.{service,timer}`（每日 03:00 在线备份到 `/var/lib/haproxyweb/backups/`，保留 30 份）。脚本含 sqlite3 前置检查（缺依赖时单元转 failed 而非静默失败），并支持可选异地推送：

  ```bash
  sudo apt install -y sqlite3   # 备份依赖 sqlite3 命令行
  sudo install -m 0755 deploy/backup.sh /usr/local/share/haproxyweb/backup.sh
  sudo install -m 0640 deploy/haproxyweb-backup.service deploy/haproxyweb-backup.timer /etc/systemd/system/
  # 可选异地推送（防止机器盘坏丢备份）：编辑 unit 的 [Service] 加一行，
  #   Environment=HAWEB_BACKUP_PUSH_CMD=rclone copy /var/lib/haproxyweb/backups remote:haproxyweb
  sudo systemctl daemon-reload && sudo systemctl enable --now haproxyweb-backup.timer
  ```

  手工替代：`sqlite3 /var/lib/haproxyweb/haproxyweb.db ".backup '/backup/haproxyweb-$(date +%F).db'"`

- **恢复流程**：`systemctl stop haproxyweb` → 用快照替换 `/var/lib/haproxyweb/haproxyweb.db`（连同 `.wal/.shm` 一并清理）→ **同时还原 `secret.key`**（否则所有登录会话失效）→ `systemctl start haproxyweb`。
- **RTO/RPO 预期**：进程崩溃由 systemd 自动拉起（约 3 秒，转发中断窗口即 RTO）；数据恢复点取决于备份间隔（RPO）。SQLite 单实例无 HA，如需多活需外部方案。

## 可观测性

可观测数据全部在管理后台内查看，**不需要额外监听端口**：

- **「运行监控」页**（登录后侧边栏）：进程状态（版本/运行时长/goroutine/堆内存/文件描述符/数据库体积）、引擎防护计数（连接拒绝、accept 错误、已隔离 panic）、日志写入器水位（队列深度/丢弃/清理失败）、逐规则指标（活跃与累计连接、双向字节、错误、ACL 拒绝），每 5 秒自动刷新。数据来自 `GET /api/observability`。
- **`GET /api/metrics`**：同一份指标的 Prometheus 文本格式（0.0.4），挂在主端口、需 Bearer Token 鉴权，供程序化采集。两种令牌：普通会话 JWT（24h，适合临时验证）与**监控采集令牌**（一年，仅限 /api/metrics，设置页「监控采集令牌」签发，改密自动失效）——无人值守抓取请用后者：

  ```yaml
  # Prometheus 抓取配置（scheme 按部署改 http/https）
  scrape_configs:
    - job_name: haproxyweb
      authorization:
        credentials: <设置页签发的监控令牌>
      static_configs:
        - targets: ["your-host:8443"]
  ```
- **性能分析**：`/api/debug/pprof/`（登录后可在「运行监控」页右上角直达，前端会签发 10 分钟有效的专用令牌拼入链接），提供 goroutine/heap/profile 等标准 pprof 视图。
- **`/healthz`**（不鉴权）：版本、uptime、TLS、规则总数/启用/失败数、活跃会话、拒绝计数、panic 计数、日志丢弃与清理失败计数、数据库体积。适合 systemd/负载均衡探针。
- **日志**：服务运行日志（含访问日志 IP/UA、清理与 panic 记录）走 stdout/journal：`journalctl -u haproxyweb`。`rules_failed`、`rejected_*`、`panics` 非零时需要关注。

Prometheus 告警规则示例（按需调整 for 时长与通知渠道）：

```yaml
groups:
  - name: haproxyweb
    rules:
      - alert: HaproxywebBackendsDown
        expr: haweb_backends_down > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "{{ $value }} 条转发规则的后端不可达"
      - alert: HaproxywebPanics
        expr: increase(haweb_engine_panics_total[10m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "转发路径发生被隔离的 panic，请查日志定位"
      - alert: HaproxywebLogDropped
        expr: increase(haweb_log_dropped_total[10m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "日志队列打满出现丢弃，落库速度跟不上产生速度"
      - alert: HaproxywebRulesFailed
        expr: haweb_rules_failed > 0
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "{{ $value }} 条规则启动失败（端口被占用或地址非法）"
      - alert: HaproxywebDBSizeGrowing
        expr: haweb_db_size_bytes > 2 * 1024 * 1024 * 1024
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "数据库（含 WAL）超过 2GB，检查清理任务与保留期配置"
      - alert: HaproxywebBackupFailed
        expr: time() - node_systemd_unit_state{name=~"haproxyweb-backup.*",state="failed"} > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "每日备份单元转为 failed（sqlite3 缺失或推送失败），查看 systemctl status haproxyweb-backup"
  ```

  告警通知接到值班渠道的两种常见做法（任选其一，与上面告警规则叠加）：

  - **Alertmanager 飞书/钉钉 webhook**：Alertmanager 配 `webhook_configs` 指向飞书群机器人（或经 [apprise/prometheus-webhook-wechat](https://github.com/timonwong/prometheus-webhook-wechat) 等适配器转钉钉/企业微信）。
  - **免 Alertmanager 轻量路径**：后端健康翻转已内置 `web.health_webhook_url`（config.yaml，POST JSON，尽力而为）直接指向群机器人；其余指标告警仍需 Prometheus 侧落地。

## 性能调优

- **数据面**：TCP 拷贝使用池化缓冲（`tuning.buffer_size`，默认 32KB，全进程共享），稳态零分配；读写均带空闲超时续期（`tuning.tcp_idle_timeout_sec` 默认 900s，可按规则覆盖）。UDP 限速超时丢包（`udp_limiter_max_wait_ms`）。
- **零拷贝快路径**：`tuning.splice: true` 后，未配置限速的 TCP 规则走 Linux splice，消除用户态拷贝。代价：传输期间实时字节统计不刷新（落库仍精确）、该路径无空闲超时（仅靠内核 keepalive）。默认关闭，吞吐瓶颈在网卡线速以下时不建议开启。
- **系统参数**（`/etc/sysctl.d/99-haproxyweb.conf`，万级并发建议）：

  ```bash
  net.core.somaxconn = 4096
  net.ipv4.tcp_max_syn_backlog = 4096
  net.ipv4.ip_local_port_range = 1024 65535
  net.core.rmem_max = 16777216
  net.core.wmem_max = 16777216
  net.ipv4.tcp_rmem = 4096 87380 16777216
  net.ipv4.tcp_wmem = 4096 65536 16777216
  fs.file-max = 2097152
  net.netfilter.nf_conntrack_max = 1048576   # 启用 conntrack 时
  ```

  同时确认 systemd unit 的 `LimitNOFILE=65535`（可按需调大），并为 `tuning.max_global_conns` 设置上限（建议为 NOFILE 的 80%）。

## 开发

```bash
make dev        # vite dev(5173, 代理 /api -> 8080) + go run .
make test       # 单元 + 集成测试（配置校验/拷贝循环/连接上限/导出导入/日志清理等）
make web        # 仅构建前端
make build-go   # 仅构建后端（复用已有 web/dist）
```

## 目录结构

```
main.go                     入口 + go:embed 前端 + 优雅关闭
config.yaml                 配置
deploy/                     systemd 部署单元
internal/
  config/                   配置加载（yaml + 环境变量 + -c）
  model/                    数据模型
  store/                    SQLite 初始化与种子数据
  auth/                     JWT / 登录锁定 / 会话吊销 / 中间件
  api/                      REST API（gin）/ 健康检查
  proxy/                    转发引擎：manager 热更新 / tcp / udp / acl
  ratelimit/                令牌桶限速器
  audit/                    操作审计异步写入
  trafficlog/               流量日志异步批量写入与清理
web/                        Vue3 + Element Plus 前端
```

## 已知边界

- UDP 限速采用"短等待+丢包"策略：100ms 内拿不到令牌的包直接丢弃，符合 UDP 语义；连接上限超限时同样丢弃新客户端的包
- 后端健康检查仅覆盖 TCP 规则（UDP 无握手语义，连接探测无意义）；探测为纯 TCP 连接，对 SSH 类后端会在目标机的认证日志留下连接记录（与 HAProxy tcp-check 行为一致）
- TCP 连接上限超限时直接断开（不排队），避免半开连接堆积；进程级总量由 `tuning.max_global_conns` 兜底
- TCP 空闲超时（默认 900s）会断开持续无数据的连接；长连接隧道请按需调大或按规则覆盖
- splice 快路径下实时字节统计不刷新且无空闲超时（见「性能调优」）
- 被拒绝（denied）的访问日志按"规则+来源 IP"每分钟最多一条去重，防止端口扫描刷爆日志
- 优雅关闭：停止接收新连接后等待存量 TCP 连接结束（`tuning.drain_timeout_sec` 默认 10s，超时强制关闭），随后落库残余日志；与日志排空并发写入的最后几条可能丢失（进程退出场景，可接受）
- 统计口径：总览中"今日/累计流量"只含已落库数据，活跃会话进行中的字节数单独显示
