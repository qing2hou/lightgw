# fwgateway v1 交付报告（P6）

## 交付范围（PRD docs/requirements-fwgateway.md 的 US1-US8 + 里程碑 M1-M4）

| 里程碑 | 内容 | 验证 | commits |
|---|---|---|---|
| M1 | nftables 基座迁移（SNAT netlink 化+宿主共存+旧形态迁移） | P4 三轮+P5 两轮闭环；五场景容器内核验证 | 11 |
| M2 | DNAT 端口发布+状态防火墙策略+会话可视化 | P4 两轮+P5 两轮闭环；conntrack 新内核格式修复 | 11 |
| M3 | 多出口+SNAT 源池+IPv6 双栈 | P4 三轮+P5 一轮；多分担/亲和/切换容器实测 | 7 |
| M4 | P2 收敛+万兆调优包+交付三件套 | 本报告 | 4 |

## 质量门禁汇总
- P4 fresh-eyes 评审：M1×3、M2×2、M3×3 轮（每次独立子代理；抓出 15+8 必修与两次"替换静默失败"实装事故）
- P5 独立 QA：M1×2、M2×2、M3×1 轮（决定性升级叙事复验、conntrack 新格式 forensic、多出口 30/30 分担实测）
- 回归基线：go test 全绿 + 5 组容器 e2e（穿越/发布/策略/策略链序/多出口/v6）
- 真机项 notCovered 清单：万兆基准（AC-8.2，需真机对打——方法在 docs/tuning-10g.md）、
  混合 backend 宿主矩阵真机复跑、AC-4.2 切换时长的真机计时

## 部署冒烟（容器级，交付前实跑）
- `make build` 全链（前端 npm+后端 go+版本注入）exit 0
- `go vet ./...`、`go test ./...` exit 0
- 5 组 e2e（串行）：dnat 5 PASS / 策略 4 PASS / 策略链序 4 PASS / 多出口
  t1=t2=200×2 + 切备 200 / v6 发布 code=200
- 共存矩阵（docker/legacy/vanilla/firewalld 四形态）FAIL_COUNT=0（M1 复验）

## 已知边界（v1，README/CHANGELOG 已同步）
1. v6 出口网关的策略路由表（v6 multipath）→ v1.1（T205）
2. tc 限速与 conntrack 掐断的 exec 依赖 → v1.1 netlink 化
3. 网关模式全流量（默认网关接入/三区）→ v1.1
4. SNAT 池扩缩容对连续源段的重排面（~74%）→ v1.1 跳一致哈希
5. per-出口会话统计/自然老化可配 → v1.1
6. 契约响应格式（422+code）统一 → 全项目批次重构

## 复盘
### 有效实践（回写团队流程）
1. **独立子代理门禁**：本轮两次"commit 声称修复但代码未变"（reorder 两阶段写、S1 worker）
   均由复审子代理实证抓出——P4 第二轮必须独立复核 diff，不能只看 commit message
2. **e2e 场景脚本固化进 deploy/**：脚本拓扑缺陷（m3 孤岛 netns）由 QA 独立定位修复——
   开发者自测通过的脚本不代表拓扑正确
3. **字节级单测锁内核 ABI**：CIDR Cmp Data（v4-in-v6 映射坑）、verdict 三值、
   40 字节头——内核面行为的回归防护必须在单测层锁死
4. **容器内核验证标准流程**（静态构建+debian:bookworm --privileged）覆盖了
   宿主无权限环境 90% 的验证需求

### 遗留行动项
- [ ] v1.1 任务表：T205（v6 multipath）/netlink 化/网关模式/跳一致哈希
- [ ] 真机万兆基准回填（首次部署时）
- [ ] PoolMemberOf 注释与实测定量不符项（P2-4）随跳一致哈希一并消解
