# T001 PoC 结论 — google/nftables v0.3.0 能力验证

> 日期：2026-10-25 · 环境：debian:bookworm 特权容器（内核 6.18 WSL2）· 产物：`cmd/poc/main.go`
> 结果：**10/10 PASS**（首轮 7/10，3 项失败均为参数错误而非库能力缺失，已修正）

## 能力矩阵结论（design-fwgateway.md 全部内核面依赖已验证）

| # | 能力 | 结论 | 备注 |
|---|---|---|---|
| 1 | netlink 连接 / 表枚举 | ✅ | 空宿主返回空表 |
| 2 | inet 表 + 4 hook 链 | ✅ | pre_mark(-150)/dstnat(-100)/fwd(-10)/srcnat(+100)，ChainType 混排 OK |
| 3 | 规则 CRUD + counter + UserData | ✅ | GetRules 回读带 Handle，DelRule 按 Handle 精确删 |
| 4 | nft set（interval）+ Lookup 引用 | ✅ | interval 段元素用 Key + IntervalEnd 成对表达 |
| 5 | DNAT（目的+端口改写） | ✅ | 注意见坑 1 |
| 6 | SNAT（源改写） | ✅ | 池形态=同结构多规则扇出成立 |
| 7 | fwmark set + 位测试 | ✅ | Meta{SourceRegister:true} 写、load+Bitwise AND+Cmp 测 |
| 8 | multipath 路由 + ip rule | ✅ | vishvananda/netlink，注意见坑 2/3 |
| 9 | conntrack dump（nfnetlink） | ✅ | 原生 NETLINK_NETFILTER dump 通道可用（不引第三方库也行） |
| 10 | 批次语义 | ✅ | **实测 google/nftables Flush 失败后无残留**（batch 中途失败内核回滚已生效消息——与库的 batch 发送/ACK 逐条收回实现一致；引擎层仍按"失败即整体重装"防御性设计，不依赖该行为） |

## 关键实现坑（引擎层 T002 编码约束，已在 PoC 换取）

1. **expr.NAT 的 Family 字段是地址族**（`unix.AF_INET`/`AF_INET6`），不是 TableFamily——传 `TableFamilyINet`(1) 内核报 `address family not supported by protocol`。inet 表里 NAT 表达式必须显式 AF_INET/AF_INET6，v4/v6 双栈各一套 SNAT 规则。
2. **vishvananda Rule 必须用 NewRule() 构造**：裸 struct 字面量零值会把 `Goto=0` 编码成 FR_ACT_GOTO 0（内核 EINVAL）、`SuppressPrefixlen=0` 编码成 suppress 前缀 0——都源自"零值 vs -1 未设置"的语义冲突。引擎层封装 `newIPRule()` 统一走 NewRule()。
3. **NexthopInfo 权重字段是 `Hops`**（内核 RTA_Hops，存储值=配置 weight-1），v1.3.1 无 Weight 字段。路由必须带 Dst（default 用 0.0.0.0/0 显式表达）。
4. mdlayher/netlink Config 无 Timeout 字段（与旧版本不同）；Receive() 返回 ([]Message, error)，无回调式签名。
5. Conn 关闭用 `CloseLasting()`（无 Close）。
6. **ChainPriority/ChainHook 常量全是指针**（`*ChainPriority = ChainPriorityRef(-10)` 自定义 priority 的唯一方式）。

## 对设计的修订

- ADR-13（SNAT 池静态扇出）：验证成立——池形态就是多条同结构 SNAT 规则，无 map 依赖。
- ADR-12（multipath）：`ip route replace ... nexthop via A weight 1 nexthop via B weight 2` 的 netlink 等价可用；Hops 语义（weight-1 存储值）引擎层封装时换算。
- conntrack：原生 nfnetlink 即可 dump（ti-mo/conntrack-go 变为可选依赖——v1 先用原生实现，减少一个依赖面；ADR 修订记入 T109 编码时）。
- 批次原子性：实测无残留，但设计仍保留"失败即重装整段"的幂等策略（不依赖未文档化的内核行为）。

## 环境备注

- 宿主 WSL2 无 CAP_NET_ADMIN（uid 1000 无 sudo 免密）——全部内核面验证走 `docker run --privileged debian:bookworm` + 宿主静态编译挂载执行（`CGO_ENABLED=0 go build` 后二进制进容器）。
- 该方法固化为 P3/P5 的内核面验证标准流程（M1-M4 各里程碑收尾真机回归前，先容器过一遍内核面冒烟）。
