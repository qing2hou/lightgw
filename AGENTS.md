# AGENTS.md — 给 AI 与新成员的项目地图

## 项目是什么

纯 Go 实现的 **TCP/UDP 端口转发平台** + Web 管理后台。名字里的 "HAProxy" 只是历史命名，**与 HAProxy 软件零交互**（无 exec、无 haproxy.cfg），不要朝 HAProxy 集成方向找代码。HTTP 转发已移除，仅保留 TCP/UDP。

- 单二进制：前端 `web/dist` 经 `go:embed` 嵌入，SQLite 纯 Go 驱动（无 cgo）
- 两层结构：`internal/api`（gin REST + 嵌入式前端）+ `internal/proxy`（转发运行时引擎，与 DB 解耦，API 通过 `Mgr.Apply/Stop` 驱动）
- 数据：SQLite（WAL）在 `data_dir`，JWT 密钥在 `data_dir/secret.key`（0600，**刻意不入库**——全库快照下载不能带走签名密钥）
- 数据落库口径：规则/用户/流量日志/审计/健康检测历史（health_logs）/登录失败锁定（login_fails）全部在 SQLite；内存里只留运行时瞬态（连接、计数器、健康当前状态——重启后由 DB 历史与立即探测恢复）
- 可观测性：全部在主端口内（无独立监听）——「运行监控」页吃 `GET /api/observability`（JSON 摘要），`GET /api/metrics` 输出 Prometheus 文本（鉴权），`/api/debug/pprof/*` 转交标准 pprof（handler 里要剥 `/api` 前缀再调用）；指标数据源在 `internal/proxy/stats.go`（进程内 atomic）与 `internal/api/metrics.go`（渲染）

## 常用命令

```bash
make build      # 前端 + 后端，版本号经 -ldflags 注入 main.version
make test       # go test ./...
make vet        # go vet ./...
make dev        # vite(5173 代理 /api) + go run .
./bin/haproxyweb -c /path/config.yaml   # 指定配置文件
```

## 约定

- 语言/技术栈：Go 1.25 + gin + GORM；前端 Vue3 + Element Plus + Pinia，axios 实例统一在 `web/src/api/index.js`
- 错误处理：内部错误一律 `serverError()`/`logf` 记详情、给客户端返回脱敏消息；转发面的后端错误细节绝不能回传给访问者
- 错误消息风格：中文，格式 `监听 %s 失败: %w` 这类"发生了什么+在哪"
- 配置：config.yaml → 环境变量（`HAWEB_*`）优先；新增配置项两处都要加，且 `Load()` 里做格式校验（启动即失败，不静默回退）
- 客户端 IP：一律走 `c.ClientIP()`，但可信代理必须显式配置 `web.trusted_proxies`，默认不信任任何 XFF——改这里会影响登录锁定与审计
- 提交纪律：git 检查点，一个功能一个 commit；`bin/`、`data/`、`*.db`、`secret.key` 已 gitignore，绝不入库

## 转发引擎要点（改代码前必读）

- **热更新**：规则运行时配置封装为 `ruleConfig`，`atomic.Pointer` 原子替换；监听地址不变则零中断，变化则先绑新端口再关旧端口
- **拷贝路径二选一**：`copyTCP`（池化缓冲 + 循环内计数 + idle deadline 续期）是默认路径；`tuning.splice` 开启且规则双向不限速时走 `copyFast`（`TCPConn.ReadFrom` 委托触发 splice，无 idle 超时、live 统计滞后到会话结束）。两条路径的字节都经 `sess.addBytes` 同步进会话与规则级指标，别绕开它另加计数
- **双进程零中断升级**（upgrade.go）：SIGUSR2 → 监听 fd 经 exec ExtraFiles 传给磁盘新二进制（JSON 映射 env `HAWEB_UPGRADE_FDS` + 子进程标记 `HAWEB_UPGRADE_CHILD`），子进程 `AdoptListeners` 后 StartAll 不再 net.Listen；父进程收到管道 ready 信号后 `StopAccepting`（关监听+刷 UDP，存量 TCP 继续服务）、sd_notify MAINPID 交给 systemd、等会话归零后落库退出。子进程就绪前崩溃对父进程零影响。新增监听类型时必须同步 MarshalListeners/unmarshalListeners
- **配置热加载**：SIGHUP → 重读配置 → `mgr.ApplyOptions`（Manager.optsStore 原子替换，热路径每次 `m.opts()` 取快照）+ writers 的 `SetRetention`（atomic）；连接级参数（listen/data_dir/cert）只提示需重启。新增运行参数时记得同时接进 buildProxyOptions 与热加载 diff
- **锁纪律**：`Manager.mu` 是全局管理锁。任何会阻塞的操作（`server.Shutdown`、`listener.Close`、排空等待）必须在锁外执行——收集到切片、解锁后再逐个关闭。曾经有 `server.Close()` 在锁内被长连接卡死整个管理面的 bug
- **全局+规则双信号量**：`globalConns` 与 `cfg.conns`（TCP/UDP 均是）必须成对获取/释放，顺序统一"先全局后规则"，所有失败分支（含 UDP 重复首包、entry 已关闭）都要补释放，否则名额泄漏等于慢性拒绝服务
- **优雅关闭排空**：`tcpEntry` 用 conns 注册表 + WaitGroup 跟踪存量连接；`StopAll` 关 listener → `drainTCP` 等待（超时强制关闭）→ 之后才允许 `tlog.Close()`。顺序反了会丢最后一批流量日志；`main.go` 的 shutdown 序列是唯一权威
- **UDP 会话**：`udpGetOrCreateSession` 是 check-then-act，重新加锁后必须二次检查 `e.sessions[key]` 是否已存在，否则并发首包会创建重复会话泄漏。关闭入口统一走 `m.udpCloseEntry`（会落库+释放信号量），不要直接关 backend
- **连接上限**：见双信号量条目，释放统一在会话结束路径（`udpFinishSession`、TCP `defer`）
- **日志写入器**（trafficlog/audit）：channel + 批量落库，队列满丢弃并计数（`/healthz` 暴露）。`Close()` 只能调一次，关闭靠 done channel 而非 close(ch)——close(ch) 后再 Record 会 panic。保留期清理失败也计数（`CleanupFailures`），不要静默吞清理错误
- **后端健康检查**（health.go）：每 60s 对运行中的 TCP 规则做一次 TCP 连接探测（UDP 不检测），新建/热更新规则后立即异步探测一次；状态翻转才 logf，稳态不刷屏。规则级开关 `ForwardRule.HealthCheck *bool`（nil/true=开启，旧数据 nil 兼容为开启）。检测结果双写：内存原子量（当前状态，供列表/healthz/metrics）+ `health_logs` 表（历史，保留期跟随 log_retention_days，healthLoop 每小时清理）。历史查询走 `BackendHealthRange`（超 1440 点均匀降采样、末点必留），`GET /api/rules/:id/health?start=&end=`（unix 秒，缺省近 24h，最长 31 天）。锁序固定 statsMu → healthMu，别反向。`CheckBackendsNow()` 供测试与手动触发；`ForgetRule` 与每轮清理都会删内存 health 条目（DB 历史靠保留期清理）

## 踩过的坑

- GORM 的 `db.Model(x)` 只接受一个参数，按 ID 更新要 `Model(&T{}).Where("id = ?", id)`，不能 `Model(&T{}, id)`
- `Select(...)` 更新白名单要显式含新字段（如 `MaxConns`），否则永远不更新
- ACL 模式（`acl_mode`）二选一：whitelist/blacklist 模式下后端校验黑白名单互斥；空模式是旧数据兼容语义（黑白并用量纲），前端编辑旧规则时按名单推断模式，黑白同时配置的按白名单处理并提示
- gin 默认信任所有代理：不调 `SetTrustedProxies(nil)` 时任何人可伪造 XFF 绕过登录锁定
- 改密码必须同步递增 `users.token_version`（JWT 里的 `tv`），否则旧 token 继续有效 24h；JWT 数字 claim 解出来是 float64
- 语义重构（如 ParseACL 加 mode 参数）后要立刻跑 `make test`——曾有测试文件与 api 包双双编译失败多日无人发现
- `recover()` 必须由 defer 的函数体**直接**调用：包一层闭包（`defer func(){ if m.helper() {...} }()`，helper 里 recover）捕获不到，panic 照样崩进程；`logPanic` 只负责记录，recover 在各挂载点内联
- `VACUUM INTO` 目标文件必须放数据目录内（systemd 沙箱 `ReadWritePaths` 只放行该目录）且不能已存在；`/api/backup/db` 用临时名下载后立即删除
- 前端 axios 下载（`responseType: 'blob'`）出错时错误体也是 Blob，拦截器需先 `text()` 解析成 JSON 才能取到 `error` 字段
- 浏览器新标签页不带 Authorization 头：pprof 页面走 `pprof_token` 查询参数（auth.IssuePprofToken 签发 10 分钟作用域令牌）。查询参数令牌**只在 pprof 路径被中间件读取**，且带 `pt` 作用域的令牌访问其他接口一律 401——别放宽这两条，否则 URL 里的令牌会被重放到全部 API
- pprof 索引页内的子链接（goroutine/heap 等）是**相对链接，不携带查询参数**：首次带令牌访问时 handler 落一个仅限 `/api/debug/pprof` 路径的 HttpOnly Cookie（10 分钟），子页面靠它过鉴权；URL/Cookie 通道只认 `pt=pprof` 作用域令牌，普通 JWT 借道 URL/Cookie 一律 401
- 测试/CI 判断退出码别用管道（`go test ./... | grep` 会吃掉失败状态），用显式 `; echo exit=$?` 或分步执行
- `make clean` 只许删构建产物。数据目录曾放在 `bin/data` 下，一条 `rm -rf bin` 就是删库事故
- **路由表号 253-255 是内核保留表**（253 default / 254 main / 255 local），32766/32767 亦然。策略路由分配与拆除只能落在 `nft.RouteTableBase(201)..RouteTableEnd(252)`；`TearEgressRoute` 对段外/保留表号直接拒做。曾经一段启动对账按 201..300 扫描孤儿，把系统自带的 `32766: from all lookup main` 判成孤儿，连 main 的默认路由一起删掉——**目标主机整机失联**（见 docs/test-report-prod-170.md DEFECT-10）。删除类操作按"最坏输入"评估爆炸半径
- Vue SFC 里 `<script setup>`/`<style>` 之外的代码会被编译器**静默丢弃**（不报错），而 `onMounted` 仍会调用它 → ReferenceError 中断整个挂载钩子，页面数据全空。改 `.vue` 后可用 `@vue/compiler-sfc` 的 `parse+compileScript` 自检"函数是否真的进了产物"
- 前端字段类型要对齐后端序列化形态：`egress_ids`/`snat_pool`/`allow_list` 等在库里是 **JSON 字符串**，取值必须先 `parseListJSON` 再 `.map()`，直接对字符串 `.map` 抛 TypeError
- **SNAT 的 counter 必须覆盖双向**：放行行以 `saddr=白名单源` 为条件只命中上行；下载回程包（源=服务器、目的=客户端）靠 pre_mark 的 established 打标放行，不经过任何 counter——只装上行的计数会让页面速率只反映 ACK 小包（曾实测 3.54MB/s 显示 68.9KB/s）。`CompileSNAT` 为每个源追加一条 `daddr=源` 的只计数行（无 verdict），与其共用 comment 汇总
- **SNAT 的实时速率不能复用 `rateMeter`**：`rateMeter` 是"每次写入落一个秒槽 + 按 10 秒窗口平均"，适配逐次计数的会话路径；SNAT 的字节数只能按 5s 轮询从内核 nft counter 取差分，塞进去会让 10 槽只填 2 个、显示值被除以 5（曾实测 46.7MB/s 显示 66KB/s）。SNAT 走独立的 `SnatRateBps`（差分 ÷ 实际采样间隔）
- **默认拒绝行的辖区覆盖"存在的全部 SNAT 规则（含停用）"+"启用出口实体的网卡（无规则时兜底）"**，不是"启用中的规则"。停用最后一条规则必须仍然保留拒绝行——否则 `ip_forward=1` 会让整机静默变成全放行路由器（生产事故）。相应地在**删除规则/导入 replace/创建回滚**这些"DB 行真的消失"的路径后要调 `Mgr.RecomputeDefaultDeny()`：Stop() 时规则还在库里，重算出的辖区包含它，必须等 DB 删除后再算一次
- **带宽包限速 = 双向 htb（总额父类 + 每源保底子类 + **叶子兜底类** + fq_codel 挂叶子）**。**订正（真机实测，2026-10-30，见 `docs/poc-result.md`）**：本条原写「本环境无可用分类器」，**已证伪**。`u32` 在 `192.168.10.170`（KVM+virtio+Linux 6.8.0-147）实测可用：下载 `u32 match ip dst` 跑 8.006507MB/s（配置 8MB/s，误差 0.08%）。当年「u32 不参与分类」的观感，真因是上传方向的 filter 写成了 `match ip dst`。**四条硬约束（每条都有实测反证）**：
  1. **上传 filter 必须 `match ip src`，下载必须 `match ip dst`**，两个方向严禁照抄。包经 mirred 进 ifb 后 daddr 是公网服务器、saddr 才是客户端，写成 `dst` → 永不命中 → 静态超速 14.8 倍（实测现网 112.2485MB/s vs 配置 8）。
  2. **`default` 的目标类自身不能有子类**（等价表述：必须是叶子类）。实测：`default` → 叶子类 7.81MB/s（`direct` 增量 0）；`default` → 内层 `1:100` 变 **2828.79MB/s**，`direct_packets_stat` 增量与总包数完全相等（942MB 一个包都没进 HTB）。**归因订正（2026-11-01 netns 三组对照）**：触发条件不是"内层/外层"，而是**`default` 指向的类自身挂着子类**——同一个 `1:100` 无子类时 `default` 指它照样正常限速（7.6567MB/s, direct=0），挂上子类后才变成 2575.3739MB/s 全绕过（direct=270363=总包数）。所以结构里必须有**叶子兜底类**承接 `default`；本实现用 `1:250`（`leafClassID`，须避开 `srcClassID` 产出的 `1:1..1:249`）。
  3. **`fq_codel` 只能挂叶子类**。挂内层 `1:100` 直接 `RTNETLINK answers: Invalid argument`（内层类不能挂叶子 qdisc）。同一条内核规则的另一个侧面：1:100 无子类时能挂上，有子类时被拒。**别用 `_ = runQuiet(...)` 吞这个错误**——曾有版本吞掉后表现为"日志正常但 fq_codel 从未存在"（生产两个设备上 `grep -c fq_codel` 都是 0）。
  4. **`parent.rate` 不是总额硬上限**，实测 15 组：实际合计 ≈ `max(parent.rate, Σ子类rate)`，误差 −2.5%~−4.2%。`Σ保底 > 总额` 时突破总额（N=12/总额4 → 11.50MB/s，超 187.6%）。**要总额硬限必须保证 `Σ MinKBps ≤ 总额`**（产品语义见 ADR-15「约束式」）。
  `pref` 不许写死 `10`，按 `srcFilterPref`(2..998)/`uploadFilterPref`(1002..1998) 派生。`direct_packets_stat` 增长是 filter **未命中**的兜底，不是「挂了子类」的副作用。每源硬保底（`MinKBps`）成立（`fw`/`flower` 的局限仍成立，只是不再需要它们）；不等保底对照实测 1:1.943（配置 1:2），证明 HTB 真在读 `rate`。**清理历史子类时务必跳过 `1:100` / `1:30` / `1:250`**——曾有循环从 1:2 到 1:249 把刚建好的限速类删掉，default 指向不存在的 class 导致限速彻底失效（8MB/s 配置跑出 24MB/s）。`srcClassID` 的产出区间也必须避开这三个保留号：老实现 `1+h%248` 会产出 **1:100**，源哈希到它时 `tc class replace classid 1:100` 把带宽包总额父类替换成该源保底子类，整包总额静默消失（现改为跳过 30/100/250 的 247 槽映射，`TestSrcClassIDAvoidsReservedIDs` 穷举锁死）
  5. **`tc qdisc show` 把 htb `default` 打印成 `0x<完整 minor hex>`**：`default 250` 显示 `default 0x250`（不是 `0xfa`）。幂等判定若写 `fmt.Sprintf("default 0x%x", 250)` 会永远匹配不上 → 每个 apply 周期都 `qdisc del`+`add` 重建，重建瞬间无 qdisc（流量无限速）。生产实测两种写法（`default 250` / `default 0x250`）输出完全一致；现由 `htbDefaultToken()` 固定返回 `"default 0x250"` 并由 `TestHTBDefaultTokenMatchesKernel` 锁死
- **SNAT 允许入口==出口（单臂网关）**，但有两个内核行为必须处理：①同卡且目标同网段时内核回 ICMP redirect 不转发（包不进 FORWARD），规则启用时要写 `send_redirects=0`；②tc 限速的下载 filter（daddr=源）与上传 filter（saddr=SNAT源）同卡时共用一个 qdisc，pref 必须分段（下载 2..998 / 上传 1002..1998），否则 `tc filter replace` 互相覆盖导致某方向限速静默失效
- 名单组有三类（`whitelist`/`blacklist`/`ip`），兼容判据统一走 `model.AclGroupMatchesMode(组类型, 使用模式)`：同类型组或中性 `ip` 组可用。规则有**两处**引用位——源名单 `AclGroupID`、SNAT 目标限制 `DstAclGroupID`；新增引用位时必须同步：校验、引擎展开（`buildRuleConfig`/`buildSnatSpec`）、联动 `ApplyAclGroup`、删除保护 `ReferencedByAclGroup`、导出内联，漏一处就是"改了组不生效"或"删组把规则打挂"
- 列表类控件未选成员时提交 `"[]"` 而非空串：后端"未配置"判据要用 `isEmptyJSONList`（空串/`[]`/`null` 等价），否则界面必填项都填好仍被 400 拒
- 统计口径：`/api/stats` 的今日/累计只含落库数据，活跃会话字节单独 `live_*` 字段，不要叠加（会双重计数）；`/metrics` 的规则级字节数是进程内实时累计，与落库口径不同，不要混用
- **绝不在生产机上用测试配置启动完整服务**。曾用空数据目录在生产机跑新版二进制验证 `/api/status`，启动对账把生产的 SNAT/DNAT 规则全判成「孤儿」拆掉，`inet haweb` 三个链清空、转发中断约 2 分钟（见 `docs/incident-2026-10-30-orphan-reconcile.md`）。真机验证要么用 `netns` 隔离，要么只跑单功能探针，绝不跑完整服务
- **对账/清理类判据必须能证明归属，不能靠「我以为」**。旧判据「内核里有标记 + 我的库里没有 = 孤儿」在「第二个进程用不同数据目录碰同一张表」时全线崩溃。现方案：数据目录下 `instance_id`（16 位 hex）参与 nft 规则 comment（`haweb-nft:<instance>:<kind>:<id>`），对账只认本实例；旧格式标记一律视为非本实例、不拆。这与 DEFECT-10（`ip rule` 扫 201..300 删掉内核 32766 导致整机失联）是同一错误模式。**删除类操作按「最坏输入」评估爆炸半径**
- **孤儿清理默认只告警不删**（`tuning.nft_reconcile_purge` 默认 false）。孤儿残留只多几条内核规则；误拆会清空转发面。代价不对称，默认选安全那边
- **`fwd` 是 nft 保留字**：`chain fwd { }` 与 `add rule inet haweb fwd ...` 都会被解析成关键字（加引号也不行），所以 `nft -f` 无法用于本项目的表（链名里有 `fwd`）。这是全部走 native netlink 的实际原因。手工恢复规则时改用 `systemctl restart haproxyweb` 让服务自建
