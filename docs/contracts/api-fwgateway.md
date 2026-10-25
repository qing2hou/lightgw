# API 契约 — fwgateway v1

> 全局约定沿承现有 `/api`（JWT admin 组）：成功 `{ "code": 0, "data": {...} }`；失败 `{ "code": <业务码>, "message": "中文错误", "field": "<可选>" }`；列表 `page/pageSize → { items, total }`；时间 ISO 8601。新路由不加版本段（与现行 /api 无版本风格一致，记 ADR-15 附注）。

## 一、出口管理（US4/US5）

### API-E1 出口列表
- GET /api/egresses
- 响应 200：`{ code:0, data:{ items:[{ id:1, name:"电信出口", iface:"ens19", gateway_v4:"172.16.40.1", gateway_v6:"", priority:10, weight:1, probe_mode:"icmp-gw", probe_target:"", interval_sec:3, fail_count:2, up_count:2, enabled:true, status:"up", status_detail:{ probe_latency_ms:1.2, last_switch:"2026-10-25T10:00:00Z", down_reason:"" } }], total:1 } }`
- 错误：500 内部错误（脱敏）

### API-E2 创建出口
- POST /api/egresses
- 请求：`{ name:"电信出口", iface:"ens19", gateway_v4:"172.16.40.1", gateway_v6:"", priority:10, weight:1, probe_mode:"icmp-gw", probe_target:"", interval_sec:3, fail_count:2, up_count:2, enabled:true }`
- 响应 201：`{ code:0, data:{ id:1 } }`
- 错误 422：`{ code:40001, message:"出口名称已存在", field:"name" }`；`{ code:40002, message:"网卡 ens19 不存在", field:"iface" }`；`{ code:40003, message:"gateway_v4 不是合法 IPv4 网关地址", field:"gateway_v4" }`；`{ code:40004, message:"probe_mode 为 icmp-target/tcp-target 时 probe_target 必填", field:"probe_target" }`；`{ code:40005, message:"priority 必须为 0-1000 的整数", field:"priority" }`

### API-E3 更新出口
- PUT /api/egresses/:id（请求同 E2；enabled 原值时热重载探测/路由，状态保持）
- 400 行不存在：`{ code:40401, message:"出口不存在" }`
- 网卡变更时报错（见 E5 落地约束）：`{ code:40006, message:"已启用的出口不允许变更网卡（请新建出口）", field:"iface" }`

### API-E4 删除出口
- DELETE /api/egresses/:id
- 响应 200：`{ code:0, data:{ affected_rules: 3 } }`（列引用该出口的 snat 规则数，规则自动退回全部出口选择）
- 错误 422：`{ code:40007, message:"出口仍被 3 条规则引用（egress_ids），请先解绑", field:"egress_ids" }`

### API-E5 出口手动探测
- POST /api/egresses/:id/probe
- 响应 200：`{ code:0, data:{ up:true, latency_ms:1.2 } }`；不可达 `data:{ up:false, latency_ms:0, reason:"icmp timeout" }`
- 说明：手动探测不影响状态机（去抖计数仅自动探测路径）;网卡不可达立即 up:false

## 二、防火墙策略（US3）

### API-P1 策略列表
- GET /api/fw-policies
- 响应 200：`{ code:0, data:{ items:[{ id:1, name:"放行办公网到业务段", order:1, action:"accept", src_list:["192.168.1.0/24"], dst_list:["10.0.1.0/24"], proto:"tcp", port_range:"80,443", enabled:true, comment:"", stats:{ pkts:1024, bytes:1073741824, last_hit:"2026-10-25T10:00:00Z" } }], total:1 } }`
- 说明：stats 来自 nft counter 差分（5s 内），last_hit 为计数变化时间戳（非精确每包时间）

### API-P2 创建策略
- POST /api/fw-policies
- 请求：`{ name, action:"accept|drop", src_list:[], dst_list:[], proto:"tcp|udp|icmp|any", port_range:"", enabled:true, comment:"" }`
- 新建默认插到列表末尾（order=当前最大+1）
- 错误 422：`{ code:40010, message:"src_list 含非法 IP/CIDR: 192.168.1", field:"src_list" }`；`{ code:40011, message:"port_range 必须是端口或逗号分隔端口/范围（如 80,443,1000-2000）", field:"port_range" }`；`{ code:40012, message:"proto 为 icmp/any 时 port_range 必须为空", field:"port_range" }`；`{ code:40013, message:"action 只能是 accept 或 drop", field:"action" }`

### API-P3 更新策略
- PUT /api/fw-policies/:id（order 不可经此接口改，走 reorder）
- 错误同 P2 + 40401

### API-P4 删除策略
- DELETE /api/fw-policies/:id → 200 `{ code:0 }`

### API-P5 策略重排
- PUT /api/fw-policies/reorder
- 请求：`{ ordered_ids:[3,1,2] }`（全量 ID 集；缺一/多一为 422）
- 错误 422：`{ code:40014, message:"ordered_ids 必须是全部策略 ID 的一个排列", field:"ordered_ids" }`
- 语义：同一 netlink batch 重排，established 会话不受影响

### API-P6 "新增拒绝立即掐断存量"开关（策略 action=drop 创建/更新时）
- 请求体附加字段：`{ ..., kill_established:true }`
- 语义：true=创建后 conntrack 精确删该策略五元组范围的存量会话；false/缺省=仅拦新建

## 三、DNAT 端口发布（US2，经现有 /api/rules）

### API-D1 创建发布规则
- POST /api/rules
- 请求：`{ name, protocol:"dnat", listen_addr:"203.0.113.10:443", target_addr:"10.0.1.5:8443", acl_mode:"whitelist", allow_list:'["58.66.1.0/24"]', dnat_reject_mode:"reject", enabled:true }`
- 响应 201：`{ code:0, data:{ id:5 } }`
- 错误 422：`{ code:40020, message:"listen_addr 必须是完整 IP:port 形式", field:"listen_addr" }`；`{ code:40021, message:"发布 IP 203.0.113.10 不归属任何本机网卡", field:"listen_addr" }`；`{ code:40022, message:"同 IP:端口 已有启用中的发布规则（#7）", field:"listen_addr" }`；`{ code:40023, message:"target_addr 必须是完整 IP:port 形式", field:"target_addr" }`；`{ code:40024, message:"发布地址族 v4 与后端地址族 v6 不一致，v1 不做 NAT64", field:"target_addr" }`

### API-D2 规则列表（扩展，GET /api/rules）
- dnat 行含：`protocol:"dnat", listen_addr:"203.0.113.10:443", target_addr:"10.0.1.5:8443", dnat_reject_mode:"reject", backend_up:true, live:{ pkts_in, bytes_in, pkts_out, bytes_out, active_sessions }`

### API-D3 规则实时接口（扩展，GET /api/rules/:id/live）
- dnat 行含 `active_sessions`（conntrack 归属该规则的会话数）、`backend_up`、上下行计数（counter 差分）

## 四、SNAT 增强（US6，经现有 /api/rules snat 分支）

### API-S1 snat 规则创建/更新新字段
- 请求体扩展：`{ ..., snat_mode:"fixed|rotate|sticky", snat_pool:['["203.0.113.10","203.0.113.11"]'], egress_ids:[1,2] }`
- 错误 422：`{ code:40030, message:"snat_mode 为 rotate/sticky 时 snat_pool 必填且非空", field:"snat_pool" }`；`{ code:40031, message:"snat_pool 成员必须归属 egress_ids 指定出口网卡（203.0.113.99 不在 ens19/ens20 上）", field:"snat_pool" }`；`{ code:40032, message:"snat_pool 最多 32 个 IP", field:"snat_pool" }`；`{ code:40033, egress_ids 引用了不存在的出口: [9] }`

- 现状兼容：旧规则无新字段 = fixed + 全部出口，语义不变

### API-S2 SNAT 池使用分布（GET /api/rules/:id/snat-usage）
- 响应 200：`{ code:0, data:{ items:[{ ip:"203.0.113.10", active_sessions:12, bytes_in:..., bytes_out:... }], total:2 } }`
- 说明：会使 conntrack dump 反查（5s 内数值），rotate/sticky 模式可用；fixed 模式返回单 IP

## 五、会话可视化（US3 AC-3.5）

### API-C1 会话列表
- GET /api/sessions?rule_id=&egress_id=&state=&page=&pageSize=
- 响应 200：`{ code:0, data:{ items:[{ id:"<四元组编码>", proto:"tcp", src:"192.168.1.10:52344", dst:"8.8.8.8:443", src_after:"203.0.113.10:52344", state:"established", egress_id:1, rule_id:2, started_at:"...", bytes_in, bytes_out }], total:187 } }`
- 说明：conntrack netlink dump 聚合；id 为 orig 四元组的稳定编码（base64(tuple)），供掐断接口引用；started_at 为 conntrack 表项的近似创建时间（内核 rtt/timeout 反推，粒度较粗——文档声明）

### API-C2 会话掐断（管理动作）
- POST /api/sessions/kill（单一接口，避免路径参数编码问题）
- 请求：`{ id:"<API-C1 返回的四元组编码>" }`（或显式四元组 `{ proto, src_ip, src_port, dst_ip, dst_port }`）
- 响应 200：`{ code:0, data:{ killed:1 } }`
- 错误 422：`{ code:40040, message:"会话不存在（可能已结束）" }`；`{ code:40041, message:"id 与四元组至少提供一项" }`

## 六、接口/系统（扩展）

### API-I1 接口列表扩展（GET /api/interfaces）
- 每行新增：`{ ..., family:["v4","v6"], ips_v6:["2001:db8::1"] }`

### API-X1 healthz / observability / metrics 扩展
- healthz：`fw_anchor_present:bool`（宿主锚点在位，缺失时提示），`nft_backend:bool`（netlink 可用），`egresses_up/down`
- metrics：`haweb_fw_policy_pkts_total{policy_id,action}`、`haweb_fw_policy_bytes_total{...}`、`haweb_egress_up{egress_id}`、`haweb_egress_probe_latency_ms{...}`、`haweb_egress_active_flows{...}`、`haweb_nft_anchor{hook_family}`
- observability：策略命中 Top、出口状态汇总、会话总数

## 七、权限与审计

- 全部新接口挂 admin 组（现有 JWT 中间件）；POST/PUT/DELETE 全量审计（沿用 audit.go，action=egress.create 等）
- 导出/导入（/api/rules/export、import）包含新字段（格式版本 +1，向后解析：旧包无新字段按默认语义)
