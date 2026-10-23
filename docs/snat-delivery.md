# SNAT 穿越规则 交付报告

> 功能版本链：`51b03a0`（初版）→ `9cc7263`（回程行/盲拆）→ `834bc4d`（链序）→ `56705fc`（live 口径）→ `74967e2`（burst）→ **`fcf2857`（幂等安装，最终版，已部署 161）**

## 功能概述

规则协议第三形态 `snat`：**其他机器的流量从指定入口网卡进入本机、经指定出口网卡 SNAT 出去**（源地址替换为出口网卡 IP），完全由内核 netfilter 转发（线速，不经代理进程）。网卡名随环境自选——规则参数化设计：

- **入口网卡**（listen_addr 字段复用）：流量从哪块网卡进（如上游机器网关指向的本机网卡）
- **出口网卡**（target_addr 字段复用）：流量从哪块网卡出，源地址替换为该网卡当前 IP
- 复用现有治理：**源网段白名单/名单组引用**（组变更热联动）、**入向限速总闸**（tc ingress police）、**流量统计**（iptables 计数差分 → 速率窗口/累计/`haweb_rule_*` 指标/`/api/rules/:id/live`）
- 前端：规则表单"SNAT 穿越"分支（网卡下拉来自 `GET /api/interfaces`）、列表显示 SNAT 源 IP 与穿越包数

## 实现要点（internal/proxy/snat.go）

| 机制 | 说明 |
| --- | --- |
| iptables 三/四行 | 白名单 ACCEPT(-s) → conntrack 回程放行 → 兜底 DROP（仅白名单模式）→ nat SNAT；全部带 `haweb-sn:<ID>` comment 标记，与 docker 等外来规则和平共处，**绝不 flush 整链** |
| 链序契约 | 数组序与 `-I 1` 逐条执行的最终链序相反——白名单 ACCEPT 必须最终在链首（曾在倒序 bug 下 DROP 挡住白名单内流量） |
| 幂等安装 | 安装前 comment 盲拆兜底（曾因只按旧形态 -D 漏拆导致停用/复启循环后 iptables 双份叠加） |
| 停用/删除 | 精确 -D + 盲拆兜底，iptables/tc 拆除彻底（实测零残留） |
| 启动对账 | `PurgeOrphanSnatRules`：进程崩溃残留的孤儿规则（DB 无对应启用规则）开机自动清零 |
| ip_forward | 规则启用且值为 0 时自动写 1（单向：绝不关回），审计日志留痕 |
| 限速 | `tc ingress + police`（rate=配置值，burst=0.5s 配额）；限速失败降级为不限速不阻塞主功能 |
| 统计 | 5s 轮询 iptables 计数差分 → rateMeter 速率窗口 + BytesUp/Down 累计 + Denied；live API 的 snat 行字节取 RuleMetrics 累计（无活跃会话概念，active_conns 恒 0） |

## 真机验收结果（192.168.10.161，真实上游客户端 192.168.10.162）

| 验收项 | 结果 |
| --- | --- |
| 真实穿越：162 →eth0 入→ SNAT(源→172.16.40.10) →ens19 出→ 172.16.40.1:22 | ✅ 连通（tcpdump+iptables 计数双重证据） |
| 源 IP 替换：NAT 表命中 + snat 摘要 snat_ip=172.16.40.10、packets 递增 | ✅ |
| 白名单：名单外（192.168.10.x ∉ 名单）DROP 拒绝 + DROP 计数；名单内放行；**热更新生效** | ✅ |
| 停用即断流 + iptables/tc 零残留（含 docker 链不误伤） | ✅ |
| 复启穿越恢复；启动对账消除历史叠加（残留恰好=当前形态行数） | ✅ |
| 引擎/引擎级回归 `go test ./...` | ✅ 全绿 |
| **限速精度** | ⚠️ **notCovered**：tc police 规则落位/拆除已验证，但吞吐精度实测受阻——可用目标 172.16.40.1:22 是 sshd（灌数据被对端窗口收缩，无闸基线也只有 14KB/s，无法给出有意义的 ±20% 数字）。**待有干净大容量接收器（iperf3 服务端等）后补测** |
| 单机内 veth 同构矩阵（9 项：安装形态/白名单拒放/停用/拆除/docker） | ✅ 全绿 |

## 部署前提（重要）

1. **服务必须以 root 运行**（iptables/tc 需要）：161 已验证的单元已去掉 `User=haproxyweb`；**且不能设置 `CapabilityBoundingSet` 白名单**——bounding set 会剥掉 root 的 DAC_OVERRIDE，SQLite 打开都会失败（踩坑实录：`unable to open database file: out of memory (14)`）
2. 入口流量真正到达指定网卡是**网络层前提**（本机 NAT/网关路由要配合把流量送到那块网卡）；规则按 `-i <网卡>` 匹配，流量物理上进哪块卡就匹配哪条规则
3. SNAT 会话的回程依赖规则自带的 conntrack 放行行；跨网关部署时确认网关有到出口网卡网段的路由

## 已知边界

- 限速是入口网卡维度的**总闸**（同网卡多条 snat 规则共享；ADR-2 设计决策）
- 速率/计数的采样粒度 5 秒；iptables 64bit 计数回绕未处理
- IPv6/NAT66、DNAT 不在本版范围
