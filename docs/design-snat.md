# SNAT 规则 技术设计

> 前置：docs/requirements-snat.md（P1 已确认：方案A iptables+tc / ip_forward 允许自动开启 / 限速仅入向总闸）

## 技术上下文

- 实现：Go 1.25（复用 haproxyweb 单二进制），iptables/tc 经 `os/exec` 调用系统命令（仅规则变更时，数据面零 exec）
- 存储：SQLite `forward_rules` 表新 `protocol=snat` 行为（新字段 if_in/if_out，见数据模型），无新表
- 部署：能力随二进制；运行需 root（systemd 单元本就以 root 运行，iptables/tc 天然可用）
- 性能：转发线速（内核 fast path）；规则变更 <1s 生效
- 目标机：192.168.10.161（ens19 入 / eth0 出，实测 ip_forward=1）

## 架构：snat 规则的一生

```
API 创建（protocol=snat, if_in=ens19, if_out=eth0, 源网段白名单, 限速）
  │ 保存 DB（forward_rules 行, protocol='snat'）
  ▼
Manager.Apply(rule) ──► snatEntry（新规则类型，挂进 Manager.snatRules）
  │ buildIptables：
  │   ① ip_forward=0 且规则启用 → sysctl 写 1（审计+日志）
  │   ② nat POSTROUTING -I: -o eth0 -s <白名单或全放> -j SNAT --to-source <eth0主IP>
  │      以 -m comment --comment haweb-sn:<ruleID> 标记
  │   ③ filter FORWARD -I: -i ens19 -o eth0 -s <白名单> -j ACCEPT（同标记）
  │   ④ 白名单外的 -i ens19 -o eth0 转发流量 -j DROP（同标记，仅当配置了白名单）
  │   ⑤ 入向限速>0 时：tc（ingress 总闸）—— ifb 设备挂 eth0? — 见 ADR-2
  ▼
运行中：计数轮询器（每 5s iptables -L -v -x 读包/字节计数）
  │ → ruleStats（复用 RateUp/RateDown 速率窗口? — 见 ADR-3）
  ▼
停用/删除/改配置 → 逐条精确 -D（按 comment 标记），tc 拆除
升级/重启 → 启动对账：iptables 里 haweb-sn: 孤儿规则（DB 无对应启用规则）全删后重建
```

## 数据模型

`forward_rules` 表（复用，不建新表）：

| 字段 | 用法（snat 行） | 约束 |
| --- | --- | --- |
| protocol | `'snat'` | 与 tcp/udp 并列；旧版本读到 snat 行：`未知协议` 走 last_error 标记，不影响其他规则（AC-5.3） |
| listen_addr | 存**入口网卡名**（`ens19`） | 非空；创建时校验存在于 `net.Interfaces()` |
| target_addr | 存**出口网卡名**（`eth0`） | 非空；同上；且 ≠ if_in |
| allow_list | 源网段白名单 JSON（如 `["172.16.40.0/24"]`），空=放行全部 | 元素为 CIDR/IP；互斥规则与 acl_mode 一致 |
| acl_mode | `off`=全放行（宽松）/ `whitelist`=仅 allow_list 内放行 | blacklist 对 snat 无意义，拒绝创建 |
| upload_limit_kbps | **入向总闸** KB/s（0=不限） | 下载限速字段对 snat 忽略（前端禁用） |
| health_check | 忽略（恒关） | 前端不显示 |
| max_conns / idle_timeout_sec | 忽略 | 前端不显示 |

ACL 组复用：`acl_group_id` 引用白名单组（同 TCP/UDP 的组语义，组变更联动重建规则 + tc）。

## API 契约（变更部分）

```markdown
## API-R1 规则创建/更新（复用 POST/PUT /api/rules）
- protocol 新增枚举值 "snat"
- snat 时：listen_addr=入口网卡名、target_addr=出口网卡名（校验存在且互异）
- 响应错误示例：
  - 400 {"error": "入口网卡 ens19 不存在（可用：eth0, ens19, lo…）"}
  - 400 {"error": "入口与出口网卡不能相同"}
  - 400 {"error": "snat 规则的名单模式必须是 off 或 whitelist"}

## API-R2 规则列表（复用 GET /api/rules）
- snat 行 live 结构：
  { "active_conns": 0, "upload_bytes": <累计入向字节>, "download_bytes": <累计出向字节>,
    "rate_up_bps": <入向速率>, "rate_down_bps": <出向速率> }
- 附加 "snat" 摘要对象（仅 snat 行）：
  { "if_in": "ens19", "if_out": "eth0", "snat_ip": "192.168.10.161",
    "packets": N, "denied_packets": N }

## API-R3 单规则实时（复用 GET /api/rules/:id/live）
- 同上 live 结构（active_conns 恒 0）

## API-R4 网卡列表（新）GET /api/interfaces
- 响应 200：{ "items": [ { "name": "ens19", "ip": "172.16.40.10", "status": "up" }, … ] }
- 用途：前端表单下拉（替代手输网卡名）；过滤 veth/docker 类接口但仍全量返回+标记
```

`/api/metrics`：snat 规则进入现有 `haweb_rule_*` 族（bytes/packets 以 iptables 计数差分入账；denied_packets 进 denied）。

## 任务表（tasks.md 摘录）

- T001 [US1] snatEntry + iptables 构建器（build/teardown，comment 标记）+ 单测（命令拼装）
- T002 [US1] Manager 集成：Apply/Stop/StopAccepting/对账孤儿清理 + ip_forward 自动开启
- T003 [US3] tc 入向限速（ingress qdisc total 闸）+ 拆除
- T004 [US4] 计数轮询 → ruleStats → /metrics 与 live API
- T005 [US1/2] API 层：协议校验分支 + interfaces 端点 + 组联动分支
- T006 [前端] 表单 snat 分支（网卡下拉/字段显隐）+ 列表 live 展示
- T007 [US2] 白名单组联动（引用组时 iptables 规则含组网段）
- T008 [P5] 161 真机验收（AC-1.2 源 IP 验证 / AC-3.1 限速实测 / AC-5.2 无残留）+ 全量回归

## ADR

### ADR-1 复用 forward_rules 表与规则生命周期（而非独立 snat_rules 表）
- 状态：已采纳
- 背景：SNAT 规则的启停/删除/审计/列表/UI 语义与 TCP/UDP 规则完全同构
- 决策：一行两用——protocol=snat 时字段语义切换（listen_addr=入口网卡等）；Manager 多挂一张 snatRules 表
- 后果：上下文聚合好（好）；字段语义复用需文档与前端显隐配合（坏，容易误读——用注释与表单分支锁死）

### ADR-2 入向限速用 tc ingress qdisc total 闸（不引 ifb per-rule class）
- 状态：已采纳
- 背景：入向（ens19 收包）限速在内核里要么 ifb+htb 多 class、要么 ingress qdisc 单 total 闸。
  P1 已确认"仅入向总闸"语义；同一入网卡多条 snat 规则场景当前不存在（一台机器 snat 规则数量预期个位数）
- 决策：`tc qdisc add dev <in> handle ffff: ingress` + `tc filter add ... police rate N burst M drop`，
  带注释标记；规则级限速即入口网卡总闸（多规则同网卡时取各规则限速之和为总闸并文档声明）
- 后果：实现极简、零 ifb 依赖（好）；多规则共享总闸且无法按规则细分（坏——首版语义已确认，留 ADR 复议空间）

### ADR-3 速率统计用 iptables 计数差分（不复用 rateMeter 直注入）
- 状态：已采纳
- 背景：穿越流量不经代理进程，`addBytes` 拿不到逐包事件；唯一可信源是 iptables 计数器
- 决策：每 5s `iptables -L FORWARD -v -x` 解析指定 comment 行的 pkts/bytes，差分进现有 rateMeter
  （复用滑动窗口与 /metrics 管道）；首帧建基线
- 后果：复用全部速率展示（好）；采样粒度 5s、进程重启计数器累计值重新基线（连续性坏——docs 注明）
- 注：SNAT 规则的 BytesUp/BytesDown 语义 = 自规则启用以来穿越字节累计（iptables 累计值，非差分累计）

### ADR-4 iptables 规则全部带 comment 标记，绝不全链 flush
- 状态：已采纳
- 背景：161 上有 docker 的 FORWARD/PREROUTING 规则；误 flush=生产事故
- 决策：所有写入规则 `-m comment --comment haweb-sn:<ruleID>`；删除按 comment 精确匹配（先 -L 找行号/-D 全规范形式）；启动对账仅清扫 haweb-sn: 前缀
- 后果：与任何外来链和平共处（好）；删除逻辑复杂于全删（坏，用集成测试锁）

## 安全清单

- [x] 鉴权：全部新端点挂现有 admin 组（requirePasswordChanged 之下）
- [x] 输入面：网卡名经 `net.Interfaces()` 白名单校验（不进 shell 拼接的路径：网卡名/网段/IP 全部先校验再拼 iptables 参数；iptables 用数组参数 exec.Command，无 shell 解释）
- [x] 注入面：无 SQL 拼接（GORM 参数化）；命令注入面=网卡名/CIDR（均正则+解析库双重校验）
- [x] 越权：单用户系统，无归属校验需求（不适用）
- [x] 内核面：ip_forward 仅 0→1 单向写（绝不关回去——其他规则可能依赖）；iptables 仅操作自有标记
- [x] 升级面：新库旧行兼容性（snat 行在旧版本=未知协议不入引擎）；旧规则在新增字段上取零值默认

## 简化门禁

- 顶层新增模块 1 个（internal/proxy/snat.go + snat_test.go），未超预算
- 不做：连接级会话表、NAT66、DNAT、逐规则 ifb class（ADR-2 已裁）
- tc 仅在配置限速时触碰；无 ifb 依赖

## PRD 对照

- US1 → ADR-1 复用 + T001/T002（AC-1.1/1.3/1.4 by 对账与重建）
- US2 → allow_list/acl_group_id 分支 + T007（AC-2.1/2.2/2.3）
- US3 → ADR-2 + T003（AC-3.1/3.2/3.3）
- US4 → ADR-3 + T004（AC-4.1/4.2/4.3）
- US5 → ADR-4 + T008 真机验收（AC-5.1 显式跳过健康检查 / AC-5.2 comment 标记 / AC-5.3 未知协议兼容）

---

# 增量设计：菜单拆分与 SNAT 源/出口增强（需求见 requirements-snat-split.md）

## ADR-5 SNAT 仍复用 forward_rules 行（不拆表），菜单拆分只在前端与 API 过滤层
- 状态：已采纳
- 背景：拆独立表需要迁移数据、双套 CRUD/审计/启停代码路径；而规则生命周期（启停/删除/审计/导出）两类完全同构
- 决策：存储继续一行两用（protocol=snat）；API 加 `protocol` 过滤参数；前端两页面各自带 filter 调同一接口
- 后果：改动小、零迁移（好）；api 层要防"snat 行漏过 snat 校验"（复用既有 validate(h) 分支，坏处可控）

## ADR-6 出口 SNAT IP 用显式列名 snat_ip 存储（空 = 自动跟随网卡首地址）
- 状态：已采纳
- 背景：一卡多址须可固化"用哪个 IP"；同时"自动"语义要保留（网卡换址不改配置）
- 决策：ForwardRule 加 `snat_ip` 字符串列（点分 IPv4，空 = 自动取出口网卡第一个 IPv4——现行为）；
  显式 IP 时不校验其仍绑定在网卡上（安装时校验过；网卡后续地址变更属运维事件，liber 拆装语义见 ADR-4 标记拆除）
  ——但安装时若显式 IP 不在网卡地址列表内则拒绝（防误配）
- 后果：配置直白（好）；网卡换址后"自动"档跟随、"手动"档保持（需要文档说明两档差异）

## 契约变更（增量）

### API-R5 GET /api/interfaces（扩展）
- 响应 200：{ "items": [ { "name": "ens19", "ips": ["172.16.40.10","172.16.40.11"], "status": "up" }, … ] }
- 变更点：单 ip 字段改 ips 数组（含全部 IPv4）；前端 SNAT 出口下拉数据源

### API-R6 GET /api/rules?protocol=snat|tcp|udp（扩展）
- 列表接口新增 protocol 过滤；不改既有分页/搜索语义

### API-R7 规则创建/更新（snat 分支扩展）
- 新字段 snat_ip（可空字符串；空=自动）。校验：非空时必须是合法 IPv4 且属于出口网卡地址列表
- 源网段 = 既有 allow_list/acl_mode/acl_group_id 语义（零变更，AC-2.3）

## 任务表（增量）

- T101 [US1] API：rules 列表 protocol 过滤 + interfaces ips 数组 + 单测
- T102 [US3] 模型 snat_ip 列 + validateSnat 校验（IP 合法且属出口网卡）+ buildSnatSpec/teardown（显式 IP 固化）+ 单测
- T103 [US1/3] 前端：SnatRulesView 独立页（侧边栏第二菜单）+ SnatRulesForm（源网段/出口 IP 下拉）
- T104 [US4] 兼容：旧库 snat 行 snat_ip 空 → 自动档；/rules 路由 redirect
- T105 [P5] 全量回归 + 161 热升级 + 真机（源拒绝/出口二址选择）

---

# 增量设计：共享带宽包（需求见 requirements-bwgroup.md）

## PoC 结论（161 实测）

htb 同一 class（rate=32mbit）被两条独立 u32 filter（两个不同 dst IP）导入时，
两路流量**共享 class 额度**：12 秒并发窗口合计 40.9MB（≈3.4MB/s ≈ 闸 4MB/s，overlimits 18599）。
共享带宽包 = 包额度建一个 class + 每个成员规则的流量 filter 导入该 class。

## ADR-7 带宽包用独立实体 + tc 层 per-包 class（成员 filter 汇聚）
- 状态：已采纳
- 背景：用户语义"包引用规则、规则自身限速取消"；tc 侧共享 class 即共享额度（PoC 实证）
- 决策：新表 bandwidth_groups（id/name/total_kbps）；成员关系**存在规则行**（ForwardRule 加 bw_group_id
  列——而非 join 表：成员增删=规则更新，联动点单一；包侧"引用规则"的 API 形态由 bw_group_id
  反向实现——包编辑时批量改成员规则的 bw_group_id）
- 后果：成员查询一次扫表（好，简单）；规则行缺失时包编辑冲突面小（包编辑序列化在 Manager 锁内）
- 执行结构：入包期间规则的自身限速（ingress policer/htb）**完全卸载**，
  替换为包的共享 class 挂载（每个成员网卡的 root htb 建包 class 1:2x，成员 filter 导入）；
  成员规则自身的 htb root 若被包占用则扩展 class 编号空间（root 保持 htb、规则私有 class 1:10、包 class 1:2x 并存）

## 执行形态（每成员网卡）

```
tc qdisc:  root htb default 30（1:30 全速 default）
class:     1:30 全速 | 1:lo 规则私有限速（若有且未入包）| 1:2x 包共享限速（x=包内序号）
filter:    规则流量 → 私有 class（未入包时）；入包后 → 包 class 1:2x
upload 方向: ingress qdisc + policer 同理按包聚合——policer 无法共享令牌（per-filter 独立桶）！
```

## ADR-8 上传（入向）共享限速用 per-包 ifb 汇聚（policer 不能共享）——首版降级：上传方向不提供包级共享
- 状态：已采纳（带明确降级声明）
- 背景：tc ingress policer 是 per-filter 独立令牌桶，无法共享；真共享需 ifb 转发到 egress htb
  （架构重、每包 overhead、且 ifb 模块可能缺失）
- 决策：首版带宽包的共享限速**只对下载（出向）方向生效**（htb class 天然共享）；
  上传方向成员各自保留自身 ingress 限速（若有）；文档与前端明确标注
- 后果：实现可靠落地（好）；上传共享缺失（坏——ADR-9 复议做 ifb 方案）

## API 契约（增量）

### API-B1 GET /api/bandwidth-groups → { items: [{id,name,total_kbps,members:[{id,name,protocol,list_status}],member_count}] }
### API-B2 POST /api/bandwidth-groups {name,total_kbps,member_rule_ids[]} → 201 包（成员批量入包：改规则 bw_group_id+tc 重建）
- 409 重名；400 额度≤0；400 成员不存在/非启用规则；成员可混合 tcp/udp/snat
### API-B3 PUT /api/bandwidth-groups/:id {name,total_kbps,member_rule_ids[]} → 全量成员替换（diff 增删）
### API-B4 DELETE /api/bandwidth-groups/:id → 成员清空后可删；有成员 400（提示）
### API-B5 规则入包后 GET /api/rules 每规则附 bandwidth_group: {id,name,total_kbps}|null；
  入包规则保存时限速字段变更被忽略（响应 200 附提示字段 limit_ignored:true）

## 任务表

- T201 [US1] 模型 BWGroup + ForwardRule.bw_group_id + AutoMigrate
- T202 [US1/2] Manager：包→tc 重建域（成员网卡 htb root 统一管理：规则私有 class 与包 class 并存/互斥装拆）
- T203 [US1] API bwgroups CRUD + 规则 limit_ignored 语义 + 单测
- T204 [US2] 引擎装拆：入包卸私有限速挂包 class；解除反操作（1s 内生效）
- T205 [US3] 前端「带宽包」页（列表/新建/编辑含成员多选）+ 两规则列表联动显示
- T206 [P5] 回归 + 161 部署 + 双规则并发合计压测（PoC 复刻为真机验收）

## ADR-9 tcp/udp（代理转发路径）入包共享：共享 Limiter 实例注入 ruleConfig
- 状态：已采纳
- 背景：tcp/udp 是用户态代理（每连接 goroutine 走 ratelimit.Limiter 令牌桶），tc 网卡层 filter 拦不到
  GO socket 出向流量；但其限速本来就是多连接共享同一 Limiter 实例的语义
- 决策：Manager 维护包→共享 Limiter 池（map[bwGroupID]*ratelimit.Limiter，按包额度构建）；
  buildRuleConfig 时规则入包则 limiter 指向包共享实例（替代自身限速实例）。tcp/udp 由此天然
  与 snat 的 tc 侧各自独立共享（snat 用户态 limiter 在代理路径同样注入——注意 snat 无代理路径，
  tc 侧见 ADR-7）。上传/下载两方向同一实例（包额度合计语义在用户态可精确双向同桶——比 tc 更准）
- 后果：代理路径（tcp/udp）与内核路径（snat tc）**各享独立额度**（同一包混挂两类规则时各限
  total_kbps——合计语义近似为"两类路径各 total"）——跨路径真共享需要 snat 也走用户态（放弃内核
  线速，不可取）；混挂场景文档声明，用户单类型挂包（当前现网形态）无差异

---

# 增量设计：带宽包全协议统一（tcp/udp 入包 + SNAT 自身限速移除）

> 需求（用户确认）：①tcp/udp 规则也入包共享 ②SNAT 表单移除自身限速字段——限速只在包。
> 决策推翻 ADR-7 的"tc per-包共享 class"执行方案。

## ADR-9 带宽包执行改引擎共享令牌桶（替代 tc 共享 class）
- 状态：已采纳（取代 ADR-7 的执行层——数据模型/包管理 API 不变）
- 背景：tcp/udp 是代理路径（用户态 socket 发出），tc 挂不住；且 tc 方案跨网卡不共享（ADR-7 声明缺陷）、
  上传方向不共享（ADR-8）、同卡多规则互拆（必修2 修复为不拆但留残留）。引擎已有 ratelimit.Limiter
  令牌桶（tcp/udp 每规则限速在用）——同一包的成员规则引用**同一个 Limiter 实例**即天然共享：
  跨网卡、双向、全协议统一。
- 决策：Manager 维护 bwLimiters map[包ID]*ratelimit.Limiter；成员规则的 ruleConfig.limiter
  指向包实例（入包规则不再建私有 Limiter）。SNAT 引擎虽不走限速器（内核转发），但 snat 的
  tc 限速整体移除（含 htb/ingress 方案）——SNAT 规则要限速必须入包，但 SNAT 是内核转发
  （不经用户态 Limiter）→ **SNAT 成员的包限速经 tc 实现：包的每个成员网卡挂 per-包 htb class**
  （保留 ADR-7 结构但只用于 snat 成员）；tcp/udp 成员走用户态共享 Limiter。
  混合包：tcp/udp 成员共享用户态令牌桶 + snat 成员共享 tc class——两桶各自 total_kbps
  （用户已选"合计单额度"，跨执行域精确共享不可行——声明：总计≤2×额度）。
- 后果：tcp/udp 全双向真共享（好）；SNAT/tc 路径沿用已验证结构（好）；混合包双域各限（声明缺陷）；
  tc 残留管理问题（必修2 方案）继续存在（坏，重启对账兜底已覆盖）。

## 变更清单

- 模型/语义：SNAT 的 upload/download_limit_kbps 语义废弃（保存强制 0，旧值迁移忽略）
- 引擎：buildSnatSpec 保留 BWGroupKBps（tc 挂包 class）；私有 DownloadKbps/上传 ingress 路径删除
- Manager：bwLimiters 包实例池；buildRuleConfig 对入包的 tcp/udp 规则注入包 Limiter；
  包额度/成员变更时重建受影响规则（现有 applyBWMembers 已逐个 Apply——对齐）
- API：validateSnat 删除自身限速校验分支（强制 0）；带宽包 validate 放开 snat-only 限制
- 前端：SnatRulesView 表单删"限速"区块（入包显示包徽标已存在）；BWGroupsView 下拉放开全协议

---

# 增量设计：tcp/udp 规则的出向源 IP 选择

> 需求：转发规则连后端时可指定本机源 IP（172.16.40.10 或 192.168.10.161——后端看到的来源）。
> 监听指定 IP（172.16.40.10:8080）现状已支持（监听地址字段），不在本期范围。
> 用户已确认：per-规则选源 IP（默认=路由自动）。

## ADR-10 出向源 IP 用 Dialer.LocalAddr 绑定（每规则一个可选字段）
- 状态：已采纳
- 背景：后端看到的来源=连接的本机源地址；Linux 下 bind 本机任意本地 IP 即可源地址选择
  （内核按目的路由选网卡、源用 bind 值——两网卡都可达后端时均可）
- 决策：ForwardRule 加 source_ip 字符串列（空=路由自动首选）；tcp/udp 的拨号点
  Dialer.LocalAddr 绑定该 IP；UDP 会话的 backend WriteToUDP 同用拨号时绑定的
  socket（Go UDP 网络地址处理：backend 连接创建时 bind，其后复用）
- 后果：后端路由回所选 IP 的网段是前提（172.16.4x 网段的后端需能回 40.10）；
  绑定非本机 IP 时出错（引擎侧校验+拨号失败回落路由自动选择并 last_error 留痕）

## 任务表

- T301 模型 `source_ip` 列 + validate（tcp/udp：空或本机有效 IP）+ update Select 列
- T302 引擎：buildRuleConfig 加 dialSourceIP；tcp.go/udp.go 拨号 Dialer/ListenPipe 绑定
- T303 前端：转发规则表单"后端连接源 IP"下拉（来自 /api/interfaces 的全部本机 IP，含自动）
- T304 回归 + 161 实测（指定 40.10 时后端看到来源=40.10）+ 评审
