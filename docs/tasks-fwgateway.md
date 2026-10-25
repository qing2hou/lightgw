# 任务表 fwgateway v1

编号与 PRD 用户故事对应（docs/requirements-fwgateway.md）。里程碑划分：M1 基座迁移 → M2 DNAT+ACL → M3 多出口+池+双栈 → M4 性能+交付。[P] = 可并行。

## M1 基座迁移（US1）

- [ ] T001 [US1] PoC：google/nftables v0.3.0 能力验证（连内核、NAT/counter/探测宿主兼容；产出 PoC 结论文档）（depends: 无）
- [ ] T002 [US1] nftables 引擎骨架：表/链/规则生命周期、netlink 客户端封装、错误处理、可测的规则构造层（离线单测）（depends: T001）
- [ ] T003 [US1] 规则标记与对账：haweb-nft: 前缀标记、按标记盲拆、孤儿对账 nft 版（depends: T002）
- [ ] T004 [US1] snat 规则迁移到 nftables 后端（白名单/目标名单/计数/零中断快速路径语义不变）（depends: T003）
- [ ] T005 [US1] 出口策略路由 netlink 化（vishvananda/netlink，ip rule/route 语义等价）（depends: T002）[P]
- [ ] T006 [US1] 旧 iptables 形态迁移：启动检测旧标记规则、拆除、无缝接管（depends: T004）
- [ ] T007 [US1] 宿主共存测试矩阵（iptables-legacy / iptables-nft / firewalld / docker）+ gateway-firewall.sh 基线演进（depends: T004, T006）

## M2 DNAT + 状态策略（US2、US3）

- [ ] T101 [US2] DNAT 规则形态：规则模型、API 契约、前端表单（协议 dnat）（depends: M1 全部）
- [ ] T102 [US2] DNAT 内核规则编译：PREROUTING preroute 链 DNAT/FORWARD 放行/回程 conntrack，含源名单与计数（depends: T101, T003）
- [ ] T103 [US2] DNAT 会话掐断（停用/删除即断存量）与拒绝模式（拒绝/超时可配）（depends: T102）
- [ ] T104 [US2] DNAT 与后端健康检查联动（复用 health；不可达时拒绝新建）（depends: T102）
- [ ] T105 [US3] 策略（ACL）实体：有序规则模型、字段校验、审计联动（depends: M1 全部）[P]
- [ ] T106 [US3] 策略内核编译：有序链、默认拒绝、established/related 放行、命中计数（depends: T105, T003）
- [ ] T107 [US3] 策略变更热更新（不中断既有转发）与"新增拒绝立即掐断"选项（depends: T106）
- [ ] T108 [US3] 策略命中计数与趋势（Web 可视化：每规则包/字节计数、最近命中）（depends: T107）
- [ ] T109 [US3] 会话可视化：conntrack 表 netlink 读取 → live 会话列表 API + 前端页（depends: T002）[P]

## M3 多出口 + SNAT 池 + 双栈（US4–US7）

- [ ] T201 [US4] 出口（egress）实体：网卡+网关+优先级+权重+探测配置、API、前端管理页（depends: M1 全部）
- [ ] T202 [US4] 出口探测循环：ICMP/TCP 探测、状态翻转去抖、事件审计（depends: T201）
- [ ] T203 [US4] 出口选择：优先级层+层内权重；每流确定性分配（PoC 不通过则按源哈希，ADR 记录）（depends: T202）
- [ ] T204 [US4] 主备切换：路由改写、存量会话掐断/老化可配、回切策略（depends: T203）
- [ ] T205 [US4] IPv6 出口独立探测与切换（depends: T204）
- [ ] T206 [US5] 会话—出口分配记录与应用（整合 T203，作为正式能力交付：权重分担+亲和）+ 每出口统计（depends: T203）
- [ ] T207 [US6] SNAT 源池：规则级池配置、轮换/粘滞分配、池成员运行时校验（depends: T201）
- [ ] T208 [US6] 同源粘滞哈希：池成员增减时的重分配范围控制（depends: T207）
- [ ] T209 [US6] SNAT 池成员下线的会话处理（默认老化/可配掐断）（depends: T207）
- [ ] T210 [US7] IPv6 贯穿：snat/dnat/acl/名单/限速/统计的 v6 分支与表单校验（depends: T101, T105, T204）
- [ ] T211 [US7] v4/v6 双栈混合部署不互相干扰验证（depends: T210）

## M4 性能 + 交付（US8）

- [ ] T301 [US8] 万兆调优包：conntrack buckets/hashsize/sysctl/多队列脚本 + 调优文档（depends: M3 全部）
- [ ] T302 [US] 真机万兆基准（iperf3 双打 + 小包 pps）与记录（depends: T301）
- [ ] T303 交付物：README/部署文档/CHANGELOG/版本发布（depends: M4 全部）
- [ ] P4 评审（fresh-eyes 子代理）+ P5 QA（独立子代理）作为每里程碑收尾门禁（depends: 各 M）
- [ ] P6 交付复盘（depends: T303）

## DoD（每张卡）

1. 自测实际跑过（命令与结果留存，内核无关层离线单测）
2. 对应验收标准可勾（AC 编号可追溯到测试结果）
→3. 编码规范：遵循项目 AGENTS.md 与 vibecoding-best-practices
4. 已提交 git（Conventional Commits，一卡一 commit）
5. 文档/契约同步（API 文档、ADR、使用手册增量更新）
