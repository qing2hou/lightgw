# 更新日志

## 未发布——名单组扩展（2026-10-27）

### 新增
- **名单组第三种类型「IP 组」**：中性 IP 集合，不带方向语义，可被白名单、
  黑名单或 SNAT 目标限制任意引用，条目按引用方的模式生效。原「名单组」
  菜单拆为三个独立子菜单（白名单组 / 黑名单组 / IP 组），各自只显示本类型。
- **SNAT 目标限制支持引用名单组**：目标限制（仅允许访问 / 禁止访问）此前
  只能手填 IP/网段，现可引用同类型组或 IP 组，组条目变更即时热生效。
  列表接口的「被引用」计数同时覆盖源名单与目标限制两侧。

### 变更
- 名单组与规则模式的兼容判据统一为 `model.AclGroupMatchesMode`：同类型组
  或 IP 组可用；类型变更保护从"有引用即拒绝"改为"仅在与引用方冲突时拒绝"
  （白/黑组改成 IP 组总是安全）。
- 规则导出（备份）同时内联展开目标限制引用的组条目，导出文件保持自包含。

## 未发布——生产缺陷修复（2026-10-27）

### 修复
- **SNAT 规则保存必定失败（P1）**：fixed 模式下前端提交 `snat_pool:"[]"`，
  后端把空 JSON 数组当作"已配置源池"而 400。现统一把空串/`[]`/`null`
  视为未配置（`isEmptyJSONList`），并在落库前按模式归一转空。
- **SNAT 页面规则列表与出口下拉全空（P1）**：`loadEgresses()` 被写在
  `<style>` 块之后，Vue 编译器静默丢弃该定义但 `onMounted` 仍调用，
  ReferenceError 中断整个挂载钩子（`load`/`loadIfaces` 一并未执行）。
- **编辑已绑定出口的规则时前端异常（P2）**：`egress_ids` 是 JSON 字符串，
  前端直接 `.map(Number)`；改为先 `parseListJSON` 再映射。

### 安全加固
- **路由表号护栏**：新增 `RouteTableEnd = 252` 与 `IsReservedRouteTable()`；
  `TearEgressRoute` 对段外/内核保留表号（253 default、254 main、255 local、
  32766+）直接拒做。此前分配/拆除区间按 201..300 取，把 main 表包在扫描
  范围内，一次误判即可删除 main 的默认路由导致整机失联（详见
  `docs/test-report-prod-170.md` 的 DEFECT-10）。

## v1.0 fwgateway——专线防火墙网关（2026-10-26）

纯 Go 的多 IP 多出口双栈防火墙网关：全部转发经内核 nftables 数据面线速执行
（netlink 直连，零 iptables/nft 二进制依赖），Web 管理面跨双进程零中断升级。

### 新增（相对 lightgw 0.x / 74a2f85）
- **SNAT 穿越** 迁移到 nftables 后端（自有 inet 表 + 标记锚点与宿主
  docker/firewalld/iptables-nft 和平共存；iptables-legacy 宿主 fail-fast
  拒装指路；从旧 iptables 形态升级自动迁移零中断）
- **端口发布（DNAT）**：公网 IP:端口 → 内网后端，状态 DNAT 线速转发；
  源白名单、后端健康联动（不可达卸载/恢复重装）、停用即断
  （conntrack 精确掐断）、不可达行为可配（拒绝/静默丢弃）
- **状态防火墙策略**：有序 accept/drop 规则（源/目的/协议/端口组），
  established 会话免重评（含回程）、drop 策略可选立即掐断存量、
  命中计数（nft counter）、全链热更新
- **多出口**：出口实体（网卡+双栈网关+优先级分层+层内权重）＋四模式探测
  （ICMP 网关/ICMP 目标/TCP 端口/不探测）＋去抖翻转＋自动切层/回切
  ＋切层时掐断受影响存量会话；多层主备与同层权重分担统一模型
- **SNAT 源池**：出口网卡多地址池按源确定性映射（同源恒同出口 IP；v1 的
  轮换/粘滞同为源映射语义）；成员归属运行时复验
- **IPv6 双栈**：穿越（NAT66）/发布/策略/计数全链路 v6 支持
- **会话表**：conntrack 可视化（归属判定/过滤/单条掐断）；兼容
  新内核 /proc 行格式（ipv4 前缀）
- **万兆调优包**：deploy/tuning-10g.sh + docs/tuning-10g.md
- API：/api/fw-policies、/api/egresses、/api/sessions；
  前端新增 端口发布/防火墙策略/会话表/出口管理 四页

### 修复与加固（相对 0.x）
- fwmark 打标 XOR→幂等 OR（重传二次命中翻转已修复）
- fw 源网段匹配 v4-in-v6 映射坑（Cmp Data 全零回归，单测锁定）
- 策略段与默认拒绝尾行同 batch 装载（fwd 链序保证）
- purge 暂存删除提交丢失（半装残留根因修复）
- reorder 撞 order uniqueIndex（两阶段写）
- conntrack 新内核行格式（ipv4 前缀）兼容

### 已知边界（v1）
- v6 出口网关的策略路由（v6 multipath 表）排期 v1.1
- tc 限速、conntrack 掐断仍依赖二进制（tc/conntrack，netlink 化排期 v1.1）
- 网关模式全流量（默认网关接入）排期 v1.1
- SNAT 池按源轮换的扩缩容重排面较大（连续源段），改跳一致哈希排期 v1.1
