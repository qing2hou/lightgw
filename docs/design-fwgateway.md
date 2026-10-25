# 专线防火墙网关（fwgateway）技术设计

> 版本：v1 · 依赖需求：docs/requirements-fwgateway.md · 前序设计：docs/design-snat.md（SNAT v1，iptables 形态）
> 状态：P2 待用户确认

## 技术上下文

- 语言/运行时：Go 1.25，零 cgo（不可协商，现有部署形态）
- 内核面依赖：**google/nftables v0.3.0**（netlink 直连 nf_tables，零 exec）、**vishvananda/netlink**（路由/ip rule）、**ti-mo/conntrack-go**（会话表读删）——均为纯 Go netlink 族，符合章程
- 保留 exec 的既有路径：tc（限速）、ipv4 ip_forward sysctl——本期不动（ADR-9）
- 内核要求：≥ 5.x（inet NAT 需 4.18+；resilient/nexthop 多路径按内核实际能力，PoC 验证）；root 或 CAP_NET_ADMIN
- 存储：SQLite（WAL）+ GORM，新实体纯迁移，不动既有表
- 测试：规则编译层全离线单测（无内核权限可跑）；内核集成测试 root 门控（`HAWEB_NFT_POC=1` + sudo）；真机回归每里程碑一次
- 性能目标：万兆（US8）——转发全在内核，程序面零热路径

## 总体架构

```
内网客户端 ──→ [入口网卡 in-if] ──→ 内核 netfilter ──→ [出口网卡 out-if] ──→ 公网
                                        │
   ┌────────────────────────────────────┤（全部在内核线速路径，程序只做控制面）
   │ 表 haweb（inet，双栈）：
   │   pre_mark   prerouting -150  识别+打标记：发布命中 / 白名单源 / established
   │   dstnat     prerouting -100  DNAT（端口发布表）
   │   fwd        forward     -10  ACL 有序策略 + 范围默认拒绝
   │   srcnat     postrouting 100  SNAT（按出口/池改写源地址）
   │
   │ 表 filter（既有宿主表，仅在存在时介入一条）：
   │   FORWARD 头部插入唯一锚点规则：标记命中 → ACCEPT
   │   （docker / firewalld / iptables-nft 的 policy DROP 由锚点穿越）
   └────────────────────────────────────┘
   程序控制面：Web/API → 编译层(纯函数) → netlink 下发 / 路由改写 / conntrack 掐断
```

设计支柱：

1. **自有表隔离一切变更**：所有自有规则只存在于 `haweb` 表；对宿主表的侵入收敛为**每张既有 filter FORWARD 链一条锚点规则**（带标记，可对账可拆除）。绝不 flush 宿主链/表（沿承 iptables 时代的共存纪律，ADR-4 思想不变）。
2. **标记（fwmark）跨表传导 ACCEPT**：nftables 的 ACCEPT 只终止本表链遍历，压不住宿主 FORWARD 的 policy DROP；DROP 则全局终结。因此"我们要放行的流量"在早期链打标记，宿主链里的唯一锚点规则见标记即放行（ADR-2）。
3. **策略/发布/白名单全部规则化**：ACL 有序规则、DNAT 发布、SNAT 白名单统一编译为 haweb 表内规则 + nft set，先命中先适用。

## nftables 表/链设计（核心）

### 链序与 verdict 语义

| 链 | hook | priority | type | 职责 |
|---|---|---|---|---|
| `pre_mark` | prerouting | -150 | filter | `ct state established,related → set mark K_FWD_OK`；发布端口命中（dst ∈ 发布 set）→ K_FWD_OK；出口网关路由标记 |
| `dstnat` | prerouting | -100 | nat | DNAT：`dst <公网IP> port <端口> → <后端IP:端口>`（每发布规则一行 + counter + comment 标记） |
| `fwd` | forward | -10 | filter | ① `ct state established,related → 无verdict直通`（放行由标记/宿主完成）② ACL 有序规则（accept→K_FWD_OK 标记 / drop→终终权限+counter）③ 范围内默认拒绝：`iif ∈ 本产品入口网卡 set & 未标记 → DROP + counter` |
| `srcnat` | postrouting | 100 | nat | SNAT 两种形态：固定单 IP（`iif in + src ∈ 规则源set → snat <ip>`）；按出口（`oifname <egress网卡> + src ∈ 规则源set → snat <该出口池IP>`，见池设计） |

标记分配（32bit fwmark 位段）：bit0 `K_FWD_OK`（放行）；bit1..6 粘滞哈希槽；bit7..12 轮换哈希槽。锚点规则 `meta mark & 0x1 == 0x1 → ACCEPT`（宿主 filter FORWARD 头部，ip/ip6 各存在则各一条）。

关键推导（ADR-2 详述）：宿主 FORWARD 链在 priority 0，我们的 `fwd` 在 -10（先于宿主执行）→ 我们的标记/终终权限先生效，宿主锚点后看到标记。DNAT 在 -100 早于 fwd/-10，`fwd` 看到的是改写后目的（内网后端）——发布流量靠 `pre_mark`(-150，看原始目的) 的发布 set 命中打标，不依赖改写后字段。

### 规则标记与对账（沿承现状纪律）

- 所有自有规则 `comment` = `haweb-nft:<kind>:<id>`（kind: dnat/snat/pol/anchor/egress-sn/…），comment 即 rule userdata
- 幂等：安装前按 comment 盲拆（netlink GetRules 读全表按标记精确删除）
- 启动对账：枚举标记规则 ID vs DB 实体，孤儿全拆（PurgeOrphanSnatRules 的 netlink 版）
- 宿主锚点：`haweb-nft:anchor:<iface表名>`，启动时探测缺失补装、退出/停用清理

### 宿主共存与探测

启动时探测宿主形态（纯 netlink + /proc，零 exec）：

| 宿主形态 | 探测途径 | 共存策略 |
|---|---|---|
| iptables-nft（docker 等） | nf_tables 里存在 `filter` 表 ip/ip6 家族 + DOCKER* 链名 | 锚点规则插入其 FORWARD 头部；自有规则全部在自己表 |
| firewalld | FWD-* 链名特征 | 同上 |
| iptables-legacy | `/proc/net/ip_tables_names` 非空 | legacy 的 policy DROP**无法被 nft ACCEPT 覆盖**（两套 hook 并行、ACCEPT 不跨框架）→ 检出 legacy+FORWARD policy DROP 时启动 fail-fast 报错并指引迁移（AC-1.2 边界） |
| vanilla（无表） | nf_tables 无 filter 表 | 不装锚点（默认 ACCEPT 无阻挡）；默认拒绝由自有 `fwd` 链范围内 DROP 承担 |
| 旧版本（本项目 iptables 形态） | iptables-nft filter 表内 `haweb-sn:` comment 规则 | netlink 读取并按标记拆除（T006，零 exec） |

gateway-firewall.sh 机器级基线脚本**废弃**：默认拒绝不再依赖机器级 FORWARD policy DROP，改由 `fwd` 链范围内 DROP 实现（语义更精确：只管本产品入口网卡进的穿越流量，不再越权整机）。升级文档声明。

## 多出口路由模型（ADR-3）

```
出口实体（DB）:  id, iface, gw, priority, weight, probe…
分组推导:        同 priority 值 = 同层；层间主备（小 priority 优先），层内按 weight 加权分担
路由形态:        每规则专属路由表 2xx（沿用现有 snatAllocTable 段位）：
                  default nexthop via gwA dev ifA weight wA, via gwB dev ifB weight wB ...
                （仅含该规则可用出口集中健康成员的最高优先层）
ip rule:         from <规则源set 各成员> lookup <表>（netlink，pref 1）
每流出路决定:    内核 multipath 按流哈希（五元组）→ 同流同出口（会话亲和天然成立）
SNAT 跟随出口:   srcnat 链 `oifname` 匹配 → 该出口的 SNAT IP
```

- **主备切换**（US4）：探测判 down → 路由表 replace（剔除坏出口；层内全 down 落下一层）→ 按策略掐断受影响存量会话（conntrack reply-src ∈ 坏出口 SNAT IP 集）→ 审计 + 状态翻转。恢复对称处理（可配不回切）。
- **负载分担**（US5）：weight 进 nexthop；新建会话由内核哈希分配，15 分钟偏差验证（SC-3）。每出口新建数/字节统计经 conntrack 轮询桶计数（按 reply-src 归属出口）+ srcnat 规则 counter。
- **规则绑定出口集**：`ForwardRule.EgressIDs`（空 = 全部出口）。显式 SnatIP 固定单 IP 时自动钉死到持有该 IP 的出口（单成员表）。
- PoC 风险点：内核 multipath 哈希稳定性 / weight 粒度；不达标降级为按源哈希 mark 分路（ADR-3 备选记录）。

### SNAT 池（USR6 → US6，ADR-4）

| 模式 | 实现 |
|---|---|
| 固定单 IP | `snat to <ip>` 单规则（现状语义，SnatIP 列保留兼容） |
| 按会话轮换 | `pre_mark`：`mark set jhash(ip saddr . ip daddr . th sport . th dport) mod 64`（轮换槽位）；srcnat 规则按槽位扇出 `mark 槽位 == k → snat to pool[k mod N]` |
| 源粘滞 | 同上，jhash 仅 `ip saddr`（粘滞槽位）——同源客户端固定同出口 IP |

池成员保存时校验归属出口网卡；运行时复验（失配告警不静默黑洞，沿承 AC-6.2）；成员下线：改规则扇出（新会话不再分配），存量按老化/掐断可配（AC-6.3）。池上限 32（PRD 规则面预算内，静态扇出规模可控，ADR-4 不选 nft map 的理由）。

## DNAT 端口发布（US2）

- 规则形态：`protocol=dnat`，`listen_addr=公网IP:端口`（IP 必须归属本机网卡，含一卡多址），`target_addr=内网后端:端口`；源名单复用 `AclMode/AllowList/AclGroupID`；`dnat_reject_mode`（reject/timeout，默认 reject）。
- 编译为 `pre_mark` 发布 set + `dstnat` DNAT 规则 + counter；后续包 conntrack 自动还原（状态 DNAT）。
- 停用/删除掐断：conntrack 按 `reply-src == 后端IP` 或 orig-dst 四元组精确删（杀 conntrack 会话的 netlink 版）。
- 健康检查联动：复用 health.go（TCP 探测后端）→ down 时禁用 `dstnat` 规则（卸载端口发布）+ 状态展示；恢复自动重装。
- v6 发布同理（inet 表，set/daddr 为 v6）。

## 状态防火墙策略（US3）

- 独立实体 `FwPolicy`（ADR-6）：有序列表，字段见数据模型；编译为 `fwd` 链 ② 段有序规则（每条带 counter + comment）。
- 顺序变更 = 重排整段规则（delete+insert，同一 netlink batch，无窗口——fwd 链瞬时缺规则只影响新包判定，established 由 pre_mark 短路，风险可控；P5 用例覆盖变更期间新流不中断断言（established 维持））。
- "新增拒绝立即掐断存量"选项：conntrack 匹配该策略五元组范围精确删。
- 会话可视化：conntrack netlink dump（ti-mo/conntrack-go），按规则/出口归属（reply-src 反查 srcnat 池）聚合展示。

## 数据模型（GORM 迁移）

新增表/列（全部增量，不动既有列语义）：

```go
// Egress 出口：网卡+网关+优先级/权重+探测配置
type Egress struct {
    ID          uint
    Name        string  // 唯一
    Iface       string  // 出口网卡名
    GatewayV4   string  // v4 网关（可空 = 该出口仅 v6）
    GatewayV6   string  // v6 网关（可空）
    Priority    int     // 层：小者主（主备）
    Weight      int     // 层内权重 1..100（默认 1）
    ProbeMode   string  // icmp-gw / icmp-target / tcp-target / none
    ProbeTarget string  // 探测目标（非 icmp-gw 时必填；tcp-target 为 host:port）
    IntervalSec int     // 默认 3
    FailCount   int     // 判 down 阈值，默认 2
    UpCount     int     // 判回 up 阈值，默认 2
    Enabled     bool
    // 运行时状态不入库（内存原子量 + healthz）：Up/Down、探测时延、最近切换时间
}

// FwPolicy 状态防火墙策略（有序）
type FwPolicy struct {
    ID       uint
    Name     string
    Order    int  // 唯一索引，升序即评估序
    Action   string // accept / drop
    SrcList  string // JSON 数组（IP/CIDR；空 = 任意）
    DstList  string // JSON 数组（IP/CIDR；空 = 任意）
    Proto    string // tcp / udp / icmp / any
    PortRange string // "80" / "1000-2000"（any 不适用）
    Enabled  bool
    Comment  string
    // 命中计数运行时读 nft counter（列表接口注入），不落库
}

// ForwardRule 新增列（dnat + snat 增强）
SnatMode    string `gorm:"size:16;default:fixed"` // fixed / rotate / sticky（snat 协议）
SnatPool    string `gorm:"type:text"`             // JSON IP 数组（rotate/sticky 模式；fixed 用 SnatIP）
EgressIDs   string `gorm:"type:text"`             // JSON 出口 ID 数组（空 = 全部出口；snat 协议）
DnatRejectMode string `gorm:"size:16;default:reject"` // dnat 拒绝模式 reject/timeout
```

迁移与兼容：既有 snat 规则无新列值 = 现状语义（fixed 单 IP、全部出口）；`EgressGw` 列不再读（历史保留，不删列）；导出/导入格式版本递增兼容。

## 模块结构

```
internal/nft/        # nftables 引擎层（I/O 隔离）
  conn.go            #   netlink 连接管理、batch flush、错误语义（半装回滚）
  table.go           #   haweb 表/链生命周期、锚点装卸、宿主探测
  sets.go            #   nft set 构建与同步
  rules.go           #   规则 CRUD（comment 标记、盲拆、GetRules/counter 读）
  route.go           #   multipath 路由表/ip rule（vishvananda/netlink）
  ct.go              #   conntrack dump/delete（ti-mo/conntrack-go）
internal/proxy/fw/   # 编译层（纯函数、全离线单测）
  compile.go         #   Egress/FwPolicy/DNAT/SNAT 规则 → nftables.* 结构
  portsrc.go         #   池槽位/哈希、集合派生
internal/proxy/      # Manager 集成
  snat.go            #   改造为经 fw 编译层 + nft 引擎（接口语义不变）
  dnat.go            #   dnat 规则生命周期 + 健康联动
  egress.go          #   出口探测循环、切换执行、状态机
  policy.go          #   策略应用/重排、conntrack 掐断
internal/api/        # egress.go fwpolicy.go sessions.go + rules/interfaces 扩展
web/src/views/       # 出口管理页 / 策略页 / 会话页 / 规则表单扩展
```

编译层/引擎层严格分层：`fw/compile.go` 不 import netlink——所有单测离线可跑（P5 主力）；`nft/` 集成测试 root 门控。

## 统计与观测

- 规则级：沿承计数差分模式（pollSnatCounters 泛化）——netlink 读规则内 counter，5s 差分进 ruleStats（速率/累计/拒绝）；DNAT 同一套。
- 策略命中：nft counter per 规则（列表接口注入包/字节/时间戳换算）。
- 出口：探测状态/时延/切换次数/当前活跃流数（conntrack 桶计）→ healthz + observability + `haweb_egress_*` Prometheus 指标。
- `/metrics` 新增：`haweb_fw_policy_pkts/bytes_total`、`haweb_egress_up`、`haweb_egress_flows`、`haweb_nft_anchor_present`。

## ADR

### ADR-10 自有 inet 表 + google/nftables 直接 netlink（废弃 iptables exec）
- 状态：已采纳（取代 ADR-4 的 iptables+comment 形态，纪律沿承）
- 背景：去外部二进制（AC-1.1）；双栈需 ip/ip6 两套遍历；iptables-nft 转译层不可控。
- 决策：全部自有规则进 `haweb`（inet 家族，v4/v6 统一）；google/nftables v0.3.0 netlink 下发；锁版本不用 main。
- 后果：最小系统可跑、双栈单表（好）；库自称 early-stage、API 或有 breaking（坏——锁 tag 缓解，PoC T001 验全清单）；netlink 缓冲区需分批 flush（坏——引擎层限批）。

### ADR-11 宿主共存：标记 + 单条锚点规则（非寄生逐条规则）
- 状态：已采纳
- 背景：nft 的 ACCEPT 不跨表终结，宿主（docker/firewalld/iptables-nft）FORWARD policy DROP 会丢弃我们要放行的流量。方案 A：把每条放行规则塞进宿主链（等价现状，宿主表内规则面膨胀、对账复杂）；方案 B：早期链打 fwmark + 宿主链头部**仅一条** `mark → ACCEPT` 锚点。
- 决策：方案 B。我们的链（-150/-10）先执行打标，锚点在宿主链（priority 0）见标放行。
- 后果：宿主侵入面收敛为每链一条（好）；锚点规则本身在宿主表（坏——需启动对账补装/清理，iptables-legacy 宿主无解→fail-fast 拒装）；mark bit0 被占用（坏——位段规划留档，冲突概率低）。

### ADR-12 多出口=内核 multipath + 每规则路由表（非用户态逐流 mark）
- 状态：已采纳（PoC T001 失败则触发备选）
- 背景：加权分担+会话亲和+故障切换。方案 A：用户态在 prerouting mark 决定出口（全控制力，但每新建流都要用户态介入，与"内核线速、程序零热路径"冲突）；方案 B：内核 fib nexthop multipath 按流哈希（亲和天然、线速、netlink 只在拓扑变化时重写路由表）。
- 决策：方案 B。层= priority，层内 weight=nexthop weight；切换/回切=路由表 replace + 受影响会话按策略掐断。
- 后果：实现小、亲和稳（好）；流哈希分布精度依赖内核（坏——SC-3 允差 20%、PoC 验证）；出口切换时存量会话换路必须掐断（坏——语义已入 PRD AC-4.3，是内核 NAT 语义决定的，非实现缺陷）。

### ADR-13 SNAT 池=预生成槽位规则扇出（非 nft map/vmap）
- 状态：已采纳
- 背景：轮换/粘滞需要 per-flow 哈希→池成员映射。方案 A：nft `snat to mark map {...}`（map 对象）；方案 B：哈希 mark 固定 64 槽 + 每池成员一条静态 snat 规则（`mark 槽位段 == k → snat pool[k mod N]`）。
- 决策：方案 B（google/nftables 的 map/concat 支持面在 PoC 前不可证，静态扇出确定可表达；N≤32 扇出规模可控）。
- 后果：规则数随池膨胀（坏——上限 32 且预算内）；池成员增减引起部分源重映射（坏——粘滞语义近似，文档声明）；实现与调试直观（好）。

### ADR-14 DNAT 复用 ForwardRule + 独立 dnat_reject_mode（非新表）
- 状态：已采纳（沿承 ADR-1 复用思想）
- 决策：dnat 为 ForwardRule 第四协议形态；发布地址=listen_addr、后端=target_addr；健康检查复用 health.go。
- 后果：规则 API/前端/导出/审计全链复用（好）；listen_addr 在 dnat 语义下必须是完整 IP:port（坏——校验器分支）；后端健康 down 的动作=卸载发布（新增语义，文档化）。

### ADR-15 策略独立实体 FwPolicy（不塞进 ForwardRule）
- 状态：已采纳
- 背景：策略是横向有序列表，作用对象是全部穿越+发布流量，与规则（纵向、each 独立生命周期）正交。
- 决策：独立表 + order 唯一索引 + reorder 接口。
- 后果：语义清晰（好）；策略与规则的 verdict 交互需文档（策略先评估，PRD 3.7"拒绝优先"）；又一张表一个页面（坏——可接受，防火墙主体功能）。

### ADR-16 计数沿承"规则内嵌 counter + 5s 轮询差分"（不引入 eBPF/flowtable 采集）
- 状态：已采纳
- 后果：与现有 stats/速率窗口/live API 无缝（好）；5s 粒度（坏——沿用现状口径，PRD 未要求更细）。

### ADR-17 旧 iptables 形态迁移：netlink 读标记拆除（不 exec iptables）
- 状态：已采纳
- 决策：升级首次启动按 `haweb-sn:` comment 在 nf_tables 里定位并拆除旧规则；gateway-firewall.sh 基线废弃（默认拒绝改由 fwd 链承担）。
- 后果：升级零外部命令（好）；宿主如曾手动设 FORWARD policy DROP 则保留原状告知（坏——文档化）；旧基线 unit 文件需部署脚本卸载（T007）。

### ADR-18 tc 限速保留 exec（本期不 netlink 化）
- 状态：已采纳
- 背景：tc htb 语义（借用/保底）复杂，重写无新功能价值；章程允许保留。
- 后果：范围收缩（好）；依赖 tc 二进制仍在（坏——v1.1 评估 florianl/go-tc）。

## 安全清单

- [x] 鉴权：新接口全部挂 admin 组（JWT + token_version），与现有一致；无匿名接口新增（healthz 既有）
- [x] 输入面：egress/policy/规则新字段在 API 层逐字段校验（IP/CIDR/端口段/JSON 结构），错误消息中文可读；Engine 编译层二次校验兜底（直改库降级路径，沿承 parseIPListOrEmpty 模式）
- [x] 注入面：全程无 shell（netlink 取代 exec）；SQL 全 GORM 参数化
- [x] 越权：实体 ID 校验存在性+归属（会话/出口引用），无跨资源暴露
- [x] 敏感数据：无新增（探测目标等非敏感）；审计全量记录策略/出口/规则变更
- [x] 转发面错误细节不回传访问者（拒绝模式 reject/timeout 可控呈现）；管理面内部错误 serverError 脱敏
- [x] fail-fast：netlink 半装回滚；legacy 宿主拒装；探测自失败不误判（去抖计数）

## 简化门禁

- 顶层新模块 2 个（internal/nft、internal/proxy/fw）≤ 3 ✅；api/web 各为新资源扩展文件，非新层
- 不自包装：netlink 直用库 API，不造抽象层；fw 编译层只是纯函数集
- 集成优先：内核面测试 root 门控真跑（PoC/集成），mock 仅用于探测时钟与轮询窗口

## PRD 对照（AC 覆盖检查）

| AC | 承接 |
|---|---|
| AC-1.1 无 iptables 环境 | ADR-10/11（锚点在自表+宿主表，均 netlink） |
| AC-1.2 宿主共存 | 共存探测矩阵 + ADR-11 锚点（legacy fail-fast 为边界，T007 矩阵验证） |
| AC-1.3 升级迁移 | ADR-17（T006） |
| AC-1.4 策略路由去 exec | nft/route.go（vishvananda/netlink） |
| AC-2.x DNAT | dstnat 链 + pre_mark 发布 set + conntrack 掐断 + health 联动（T101-104） |
| AC-3.x 策略/会话 | fwd 链 ② 段 + nft counter + conntrack dump（T105-109） |
| AC-4/5.x 多出口 | ADR-12 模型 + egress.go 状态机（T201-206） |
| AC-6.x SNAT 池 | ADR-13（T207-209） |
| AC-7.x 双栈 | inet 表 + 编译层家族分支（T210-211） |
| AC-8.x 万兆 | 调优包 + 真机基准（T301-302，US8 P2） |

## 出口门禁自检

- [x] 每个故事的接口契约三态齐全（docs/contracts/api-fwgateway.md）
- [x] 错误响应格式全局统一（沿用现有 `{code,message,field}`）
- [x] 数据模型齐（Egress/FwPolicy/ForwardRule 增列 + 迁移兼容）
- [x] 关键取舍 9 条 ADR（含负面后果；ADR-10 编号接续既有 ADR-1..9）
- [x] 安全清单逐项勾过
- [x] 简化门禁通过
- [x] PRD 逐条对照完成
