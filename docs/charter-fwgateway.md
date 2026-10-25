# 团队章程 / Definition of Done — fwgateway v1

> 建立：P1 · 适用：fwgateway v1 全周期（基线沿用既有项目 AGENTS.md，本章程只增补本版本新增约束）

## 技术栈约束

- 后端：Go 1.25（零 cgo 不变）；内核规则下发 **google/nftables v0.3.0**（netlink 直连，锁版本，main 分支 API 不引入）；策略路由 **vishvananda/netlink**
- 新依赖引入仅限：netlink/nftables 族（google/nftables、vishvananda/netlink、ti-mo/conntrack-go、florianl/go-tc 视需要）——任何 cgo 依赖一律拒绝
- 前端：Vue3 + Element Plus + Pinia，axios 走 `web/src/api/index.js` 统一实例
- 数据：SQLite（WAL）；fwgateway 新实体（策略、出口、SNAT 池）纯 GORM 迁移，不动既有表结构

## 不可协商条款

- 内核转发面错误细节不回传给访问者；管理面内部错误一律 `serverError()`/`logf` 记详情、脱敏返回
- 与宿主防火墙共存绝不 flush 整链/整表；全部规则带 `haweb-nft:` 标记，删除只按标记精确匹配
- netlink 半装失败必须回滚到装前形态（不允许"装一半"留在内核里）
- 现网兼容：从 iptables 形态升级必须无缝（US1 AC-1.3），存量数据无损
- QA 验证结论二值化：verified / notCovered，禁止"应该没问题"
- 每里程碑（M1–M4）收尾必须过 P4 fresh-eyes 评审 + P5 独立 QA 才能进下一段；真机回归项在无真机窗口时显式挂 notCovered 台账

## 命名与结构约定

- 跟随项目 AGENTS.md + vibecoding-best-practices
- 新增包内文件命名：`internal/proxy/nft/`（nftables 引擎层）、`internal/proxy/fw/`（防火墙语义层：策略/出口/池）、API 层文件按资源名（fwpolicy.go / egress.go / …）
- 规则构造（纯函数、离线可测）与 netlink 副作用（I/O 层）严格分文件——构造层单测不需要内核权限

## DoD（一张任务卡"完成"的最低标准）

1. 自测实际跑过：内核无关层 `go test ./...` 全绿；内核相关层在本机可跑的跑、跑不了的在 PR 说明并列真机验证项
2. 对应验收标准可勾：AC 编号写进 commit message 或 PR 描述，可追溯到验证方式
3. 符合编码规范（AGENTS.md + vibecoding-best-practices）
4. 已提交 git，Conventional Commits，一卡一 commit
5. 文档/契约同步：API 文档、ADR、使用手册如有变化已更新

## 返工门槛

- P4 必须修复项清零才进 QA；P5 P0/P1 缺陷清零才进下一里程碑
- 同一缺陷最多修 5 轮，超限停下呈报修复尝试记录与根因怀疑
