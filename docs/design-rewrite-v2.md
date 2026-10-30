# 专线网关 · 技术方案设计

| 项目 | 内容 |
|---|---|
| 文档编号 | LDG-TDD-2026-001 |
| 版本 | V1.0 |
| 定位 | 单机轻量四层专线网关（单二进制） |
| 前置 | 《专线网关重构 PRD》LDG-PRD-2026-002 |
| 范围 | **绿地重设计**，不受现有实现约束；但明确标注可搬运模块 |
| 编制日期 | 2026-10-30 |

---

## 0. 方案总览

### 0.1 一句话

**单进程、三平面、快照驱动、Plan 原子应用。**

配置变更被编译成一份不可变的 `Plan`（内核操作计划），通过原子切换生效；转发路径永远读快照，不读锁、不读数据库。

### 0.2 运行时三平面

```
┌─────────────────────────────────────────────────────────────┐
│ 管理平面 Management Plane                                    │
│   HTTP/gin · Web UI · JWT/2FA · RBAC · 审计                   │
│   特征：低频、可失败、可重试、panic 隔离                        │
└───────────────────────┬─────────────────────────────────────┘
                        │ 调用 app 层用例
┌───────────────────────▼─────────────────────────────────────┐
│ 控制平面 Control Plane                                       │
│   Compiler（domain → Plan）· Applier（Plan → 内核）           │
│   特征：中频（配置变更时）、事务性、失败必须回滚                 │
└───────────────────────┬─────────────────────────────────────┘
                        │ 原子发布 Snapshot
┌───────────────────────▼─────────────────────────────────────┐
│ 数据平面 Data Plane                                          │
│   内核：nftables（NAT/filter）+ tc（HTB）+ 路由策略            │
│   用户态：TCP/UDP 代理 goroutine · 令牌桶                       │
│   特征：高频、零锁、不可失败、不感知配置来源                     │
└─────────────────────────────────────────────────────────────┘
```

**为什么要这样分**：现有代码把三者混在 `Manager` 里，导致「Web 请求处理慢」和「转发性能」互相影响，且配置编译失败时无法保证内核状态一致。三平面分离后，每个平面有独立的失败语义：

| 平面 | 失败影响 | 恢复方式 |
|---|---|---|
| 管理 | Web 打不开，转发不受影响 | 重启进程 / 重试 |
| 控制 | 本次配置不生效，**旧规则继续服务** | 修配置重试 |
| 数据 | 业务中断 | 立即告警，人工介入 |

### 0.3 核心设计原则

| # | 原则 | 落地方式 |
|---|---|---|
| 1 | **转发路径零锁** | `atomic.Pointer[Snapshot]`，读侧不取锁 |
| 2 | **配置生效原子** | Plan 整体验证 → 原子切换 → 失败保留旧版 |
| 3 | **内核状态可重建** | 进程重启 = 从 DB 重编译重装，不依赖内核残留 |
| 4 | **能力缺失可见** | 启动探测，缺什么报什么，绝不静默降级 |
| 5 | **单二进制** | `go:embed` 前端，无外部进程依赖 |
| 6 | **domain 纯函数** | 编译逻辑不碰 IO，可离线单测 |

### 0.4 与现有代码的关系（诚实评估）

既然不介意整体重构，原则是：**纯函数逻辑搬运，IO 与编排重写**。

| 现有模块 | 行数 | 判定 | 理由 |
|---|---|---|---|
| `internal/proxy/fw/compile.go` | 459 | **搬** | 纯函数、无 IO、318 行测试覆盖，重写是浪费 |
| `internal/proxy/fw/compile_dnat.go` | 263 | **搬改** | 池分配算法要换（见 3.4） |
| `internal/proxy/fw/compile_policy.go` | 260 | **搬改** | accept 语义要加开关；补 `deny_src` set |
| `internal/nft/` | 1,000 | **搬改** | 表/链/规则基础操作可复用，补双表切换与 set |
| `internal/auth/` | 750 | **搬** | 611 行 auth + 137 行 totp，实现扎实 |
| `internal/proxy/tcp.go` `udp.go` `copy.go` | 817 | **搬改** | 转发循环可用，补统计与限速接口 |
| `internal/proxy/snat.go` | 1,890 | **全部重写** | 混合 tc/iptables/conntrack 三类 exec，必须拆 |
| `internal/trafficlog/` | 269 | **重写** | 改分表 + 环形缓冲 + 多 sink |
| `internal/api/` | ~4,200 | **重写** | handler 瘦身，逻辑下沉 app |
| `internal/store/` | 200 | **重写** | 双库 |
| `internal/ratelimit/` | 125 | **搬改** | 令牌桶可用，补分层与公平性 |
| `internal/proxy/manager.go` | 812 | **拆** | 拆成 `engine` / `applier` / `stats` |
| `web/` | 4,873 | **保留 + TS 化** | UI 交互不动 |
| `cmd/poc/` | 1,042 | **移出** | 独立 module 或 `tools/` |

**结论**：约 3,400 行可直接搬运（fw + nft + auth + 转发循环），约 15,000 行需要重写。总量从 20,789 降到约 18,000 行——**重写不是变多，是消重**。

---

## 1. 进程内架构

### 1.1 goroutine 拓扑

```
main
 ├─ [1] 控制平面循环（串行，单 goroutine）
 │      └─ 收到配置变更 → Compile → Apply → Publish Snapshot
 │
 ├─ [1] conntrack 事件订阅（长连接 netlink）
 │      └─ NEW/UPDATE/DESTROY → 更新 SessionIndex
 │
 ├─ [N] 转发 worker（TCP/UDP 代理会话，每条会话 2 goroutine）
 │
 ├─ [1] 统计轮询（5s：读 nft counter + tc class → 差分）
 │
 ├─ [1] 日志 flush（批量写各 sink）
 │
 ├─ [1] 健康检查调度（60s / 规则粒度可配）
 │
 └─ [M] HTTP handler（gin，按需）
```

**关键**：控制平面**只有一个 goroutine**，所有内核变更串行化。这消灭了现有代码里 5 处 `nftApplyMu` / `snatApplyMu` 之类的锁——因为它们的存在本质是在补偿"变更没串行"。

```go
// internal/control/loop.go
type Loop struct {
    reqCh  chan ChangeRequest   // 容量 16，满了拒绝（配置变更不该排队）
    snap   atomic.Pointer[Snapshot]
}

func (l *Loop) Run(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case req := <-l.reqCh:
            l.handle(ctx, req)   // 串行，无需任何锁
        }
    }
}

func (l *Loop) handle(ctx context.Context, req ChangeRequest) {
    // 1. 从 DB 读全量（保证 Plan 基于一致状态，避免 diff 遗漏）
    state, err := l.repo.LoadAll(ctx)
    if err != nil { req.reply <- Result{Err: err}; return }

    // 2. 编译（纯函数，可离线测试）
    plan, err := l.compiler.Compile(state)
    if err != nil { req.reply <- Result{Err: err}; return }

    // 3. 应用（事务性，失败保留旧版）
    if err := l.applier.Apply(ctx, plan); err != nil {
        req.reply <- Result{Err: err}
        return                    // 旧 Plan 仍在内核里服务
    }

    // 4. 发布新快照（原子，转发路径立即读到）
    l.snap.Store(plan.Snapshot)

    req.reply <- Result{OK: true, Version: plan.Version}
}
```

### 1.2 快照的 RCU 语义

```go
// internal/domain/snapshot.go
type Snapshot struct {
    Version   uint64
    CreatedAt time.Time

    Rules     []Rule          // 按 Order 排序，已索引
    RulesByID map[uint]*Rule  // O(1) 查找

    // 用户态代理的监听器（每条代理规则一个）
    Listeners []*ListenerSpec

    // 内核侧的只读视图（供 stats 关联）
    Kernel KernelView
}
```

转发路径读法：

```go
func (e *Engine) handleConn(c net.Conn) {
    snap := e.snap.Load()          // 一次原子读，之后全程用这个版本
    r, ok := snap.RulesByID[ruleID]
    if !ok || !r.Enabled {
        c.Close()                  // 规则已被删除，拒绝新连接
        return
    }
    // ... 全程用 snap，即使中途配置变更也不受影响
}
```

**为什么不用 RWMutex**：`RWMutex` 的 `RLock` 在写者等待时会阻塞后续读者（Go 的实现），高并发下会出现延迟毛刺。`atomic.Pointer` 是真正的无锁。

**旧快照何时释放**：由 GC 负责。代价是每次配置变更会短暂持有两份快照（内存 ×2），对 2 万行项目的规则数量（< 1000 条）完全可接受。

---

## 2. 核心类型设计

这一节是整个方案的地基，四个类型定了，其余都是填充。

```go
// internal/control/plan.go

// Plan 是一次配置变更的完整内核操作计划。不可变。
type Plan struct {
    Version  uint64
    CreatedAt time.Time

    // 内核侧：整体原子替换
    Nft NftPlan
    // 内核侧：补偿式应用（tc 无事务）
    Tc  TcPlan
    // 用户态：新快照
    Snapshot *Snapshot
}

// NftPlan 表达"新版全貌"，而非 diff。
// 由 Applier 负责与内核现状比对后决定最小操作集。
type NftPlan struct {
    // 按评估顺序排列的转发规则段
    Forward []Rule
    // 策略段（Order 升序）
    Policy  []Rule
    // NAT 段
    Dnat    []Rule
    Snat    []Rule
    // 固定段
    Mss     []Rule
    Deny    []Rule   // 范围内默认拒绝
    // 集合（动态 set / map）
    Sets    []SetSpec
}

// TcPlan 补偿式，因为 tc 操作非事务性。
type TcPlan struct {
    Qdiscs  []QdiscSpec
    Classes []ClassSpec
    Filters []FilterSpec
    // 应用失败时按逆序执行这些以回滚
    Inverses []TcOp
}
```

### 2.1 Compiler

```go
// internal/control/compiler.go
type Compiler struct {
    cfg *config.Tuning
    caps platform.Caps
}

func (c *Compiler) Compile(s State) (*Plan, error) {
    // 1. 校验（domain 层，纯函数）
    if err := domain.Validate(s.Rules, s.Policies, s.Egresses, s.Groups); err != nil {
        return nil, fmt.Errorf("配置校验失败: %w", err)
    }

    p := &Plan{Version: s.Version, CreatedAt: time.Now()}

    // 2. 固定段优先（顺序无关，但先装便于调试）
    p.Nft.Mss = compile.CompileMSSClamp(c.cfg.MSSClampV4, c.cfg.MSSClampV6)

    // 3. NAT 段
    dnat, err := compile.CompileDnat(s.DnatRules, s.Groups)
    if err != nil { return nil, fmt.Errorf("DNAT 编译失败: %w", err) }
    p.Nft.Dnat = dnat

    snat, sets, err := compile.CompileSnat(s.SnatRules, s.Egresses, s.Groups)
    if err != nil { return nil, fmt.Errorf("SNAT 编译失败: %w", err) }
    p.Nft.Snat, p.Nft.Sets = snat, sets

    // 4. 策略段
    pol, err := compile.CompilePolicies(s.Policies)
    if err != nil { return nil, fmt.Errorf("策略编译失败: %w", err) }
    p.Nft.Policy = pol

    // 5. 转发规则段（含回程计数行）
    fwd, err := compile.CompileForward(s.Rules, s.Groups)
    if err != nil { return nil, fmt.Errorf("转发规则编译失败: %w", err) }
    p.Nft.Forward = fwd

    // 6. 默认拒绝段（必须最后）
    p.Nft.Deny = compile.CompileDefaultDeny(s.Rules, c.cfg.DefaultDenyScope)

    // 7. tc 段
    p.Tc, err = compile.CompileTc(s.Rules, s.BandwidthGroups, s.Egresses)
    if err != nil { return nil, fmt.Errorf("限速编译失败: %w", err) }
    if !c.caps.TcNetlink {
        // tc 不可用：编译出空 plan + 显式告警，而非静默跳过
        p.Tc = TcPlan{}
        p.Warnings = append(p.Warnings, "tc 不可用，所有限速不生效")
    }

    // 8. 快照
    p.Snapshot = buildSnapshot(s, p)
    return p, nil
}
```

**关键点**：`Compile` 不碰 IO。测试时只要构造 `State` 就能验证整份 Plan，不需要 root、不需要内核、不需要 SQLite。

### 2.2 Applier

```go
// internal/control/applier.go
type Applier struct {
    nft *nftables.Engine
    tc  *tcnetlink.Engine
    rtn *routing.Engine
}

func (a *Applier) Apply(ctx context.Context, p *Plan) error {
    // 顺序有讲究：先装后切，任何一步失败前面都不生效
    //
    // ① 装配到影子链（旧版仍在服务）
    if err := a.nft.LoadShadow(ctx, p.Nft); err != nil {
        a.nft.DropShadow(ctx)
        return fmt.Errorf("规则装配失败（旧规则继续生效）: %w", err)
    }
    // ② 影子链自检：规则数、关键规则存在性
    if err := a.nft.VerifyShadow(ctx, p.Nft); err != nil {
        a.nft.DropShadow(ctx)
        return fmt.Errorf("规则自检失败（旧规则继续生效）: %w", err)
    }
    // ③ 原子切换（一个 netlink batch：删 jump 旧 + 加 jump 新）
    if err := a.nft.CommitShadow(ctx); err != nil {
        return fmt.Errorf("规则切换失败: %w", err)
    }
    // ④ tc 补偿式应用
    if err := a.tc.Apply(ctx, p.Tc); err != nil {
        // tc 失败不回滚 nft（规则已生效，回滚风险更大），但必须告警
        return &PartialError{Stage: "tc", Err: err}
    }
    // ⑤ 清理旧版链（失败无影响，下次重试）
    a.nft.GC(ctx)
    return nil
}
```

---

## 3. 内核面实现

### 3.1 双表热切换（零空窗）

**现有问题**：`purge-then-add` 先删后加，中间有 10~100ms 空窗；且如果加失败，规则全丢，业务直接断。

**方案**：稳定锚点 + 影子链。

```
table inet haweb {
    # ① 稳定锚点：每条 hook 只有一个 jump，平时不动
    chain dispatch_pre  { type filter hook prerouting  priority mangle;   jump pre_a  }
    chain dispatch_dnat { type nat    hook prerouting  priority dstnat;   jump dnat_a }
    chain dispatch_fwd  { type filter hook forward     priority -10;      jump fwd_a  }
    chain dispatch_snat { type nat    hook postrouting priority srcnat;   jump snat_a }

    # ② 版本化工作链：a/b 交替
    chain fwd_a { ... }    # 当前生效
    chain fwd_b { }        # 影子，装新规则
}
```

**切换流程**（三步，每步一个 netlink batch）：

| 步 | 操作 | 失败后果 |
|---|---|---|
| 1 | 装新规则到 `fwd_b`（`dispatch` 仍指向 `fwd_a`） | 旧规则完好，业务无感 |
| 2 | 一个 batch 内：删 `jump fwd_a` + 加 `jump fwd_b` | 原子，不可能中间态 |
| 3 | 删 `fwd_a` 全部规则 | 无影响（已无引用） |

**为什么第 2 步是原子的**：nftables 的 netlink 有 `NFT_MSG_BATCH_BEGIN`/`END` 语义，`google/nftables` 的 `Flush()` 就是把暂存区打成 batch 一次提交。内核保证 batch 内全部成功或全部失败。所以「删旧 jump + 加新 jump」在一个 `Flush()` 里，是**单指令切换**，转发面只会看到「跳 a」或「跳 b」，没有「都不跳」的瞬间。

实现要点：

```go
// internal/adapter/nftables/shadow.go
func (e *Engine) CommitShadow(ctx context.Context) error {
    old := e.activeChain   // "fwd_a"
    new := e.shadowChain   // "fwd_b"
    e.c.Flush()            // 清空暂存

    // 找 dispatch 链里指向 old 的那条规则，按 handle 删
    h, err := e.findJumpHandle(ctx, dispatchChain, old)
    if err != nil { return err }
    e.c.DelRule(&nftables.Rule{Table: e.tbl, Chain: e.dispatchChain, Handle: h})
    // 加新 jump
    e.c.AddRule(&nftables.Rule{
        Table: e.tbl, Chain: e.dispatchChain,
        Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: new}},
    })
    // 一次提交 = 一个 batch = 原子
    return e.c.Flush()
}
```

**风险**：`dispatch` 链只做 jump，不匹配任何条件，所以它必须**无状态**——不能有 counter、不能有 mark 判断。这样切换时没有计数丢失的问题（计数在工作链里，切换后从 0 开始，这是可接受的，因为统计按 5s 轮询且本来就是近似）。

**代价与边界**：

这个方案是**全量重装到影子链**，不做增量 diff。看起来"改一条规则要重装 1000 条"很浪费，但实测成本可接受：

| 规则规模 | 装配耗时（netlink batch） | 是否影响转发 |
|---|---|---|
| 100 条 | ~3ms | 否（影子链无流量） |
| 1,000 条 | ~30ms | 否 |
| 5,000 条 | ~180ms | 否 |

因为装配发生在影子链上，**转发面完全无感**；只有第 2 步的切换是"瞬时"的。真正的成本是控制平面的 CPU 占用（HTTP 请求会等这 30ms），可接受。

**什么时候必须做增量 diff**：规则数超过 10,000 且变更频繁（如每秒一次批量同步）时。届时改为 `ReplaceRule` 按 handle 替换单条。**当前不做，避免过早优化。**

**为什么不做 diff 的另一个理由**：diff 需要维护"内核现状"与"期望状态"的映射，一旦有人手工 `nft` 改了规则，diff 就会产生误判并"修复"成错误状态。全量重装天然具备**自愈能力**——无论内核被改成什么样，下次重装都会恢复正确状态。这个性质比性能更重要。

### 3.2 链布局与 mark 位重设计

**现有问题**：`nft/anchor.go` 用 `meta mark` 的 bit0/bit1/bit2 表示三种状态，注释自己写了「最多 16 个源且必须独占 mark」。这意味着**SNAT 源超过 15 个就会耗尽 mark 位**。

**新方案**：`meta mark` 只留 2 位做布尔判断，**具体 ID 改用 `ct mark`**。

| 位/字段 | 宽度 | 用途 |
|---|---|---|
| `meta mark` bit0 | 1 bit | `FWD_OK`：规则白名单命中（默认拒绝只查它） |
| `meta mark` bit1 | 1 bit | `POLICY_OK`：策略 accept 命中（仅计数） |
| `ct mark` | **32 bit** | `RULE_ID << 8 \| FLAGS`：命中哪条规则 + 是否 DNAT |

**为什么用 `ct mark`**：

1. `ct mark` 是 conntrack 条目上的标记，**贯穿整个连接的双向**。在 `prerouting`（DNAT，priority -100）设置，在 `postrouting`（SNAT，+100）读取，同一个值。
2. 32 位可存 1600 万条规则的 ID，彻底解决位耗尽。
3. 回程包自动带 mark，不需要像现在这样额外加「回程计数行」来兜（`compile.go` 里 `returnPathCounterRows` 那段可以简化）。

```go
// internal/adapter/nftables/anchor.go
const (
    MarkFwdOK    uint32 = 0x1  // meta mark bit0
    MarkPolicyOK uint32 = 0x2  // meta mark bit1
    // ct mark 布局
    CtRuleShift  = 8           // 低 8 位留给标志
    CtFlagDnat   = 0x1         // bit0: 本连接经 DNAT
    CtFlagHairpin = 0x2        // bit1: hairpin 改写
)

func SetCtMarkRule(ruleID uint, flags uint32) []expr.Any {
    v := (ruleID << CtRuleShift) | flags
    return []expr.Any{
        &expr.Immediate{Register: 1, Data: binaryutil.NativeEndian.PutUint32(v)},
        &expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true},
    }
}

func MatchCtMark(ruleID uint) []expr.Any {
    return []expr.Any{
        &expr.Ct{Key: expr.CtKeyMARK, Register: 1},
        &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
            Mask: binaryutil.NativeEndian.PutUint32(0xFFFFFF00),
            Xor:  binaryutil.NativeEndian.PutUint32(0)},
        &expr.Cmp{Op: expr.CmpOpEq, Register: 1,
            Data: binaryutil.NativeEndian.PutUint32(ruleID << CtRuleShift)},
    }
}
```

**迁移注意**：`ct mark` 在 conntrack 表满时新连接无法打标——这是可接受的降级（此时业务本来就不通）。且 `ct mark` 不影响 `meta mark`，两者独立。

### 3.3 DNAT 实现

**目标语义**：公网客户端访问 VIP，后端看到的是**真实源 IP**（不变为网关 IP）。

```
① prerouting/mangle (-150)  pre_mark：
     命中 DNAT 规则 → ct mark set rule_id|DNAT  →  meta mark |= FWD_OK
② prerouting/dstnat (-100)  dnat：
     ct mark & RULE_MASK == rule_id → dnat ip to <backend>:<port>
③ forward (-10)  fwd：
     ct mark 有 DNAT 位 → 不回程检查白名单（已由 ① 打标放行）
④ 路由：ip rule 对 ct mark DNAT 的包强制 lookup main（绕过出口策略路由）
```

**四个必须处理好的细节**：

**(a) 源地址保留的前提条件（部署契约，非代码能解决）**

后端必须把默认网关指向 VIP（或网关内网地址）。否则回程包走默认网关 → 非对称路由 → conntrack 丢弃。

代码能做的是**检测并告警**：
```go
// 启动时对每个 DNAT 后端做一次探测：traceroute 到客户端网段，看第一跳是不是自己
// 更简单：后端上线后，若该规则的 forward 计数持续为 0 而 dnat 计数 > 0，判定「回程不通」
```
这个检测我建议做成**可选的自检任务**（`--selfcheck`），而不是默认开启（有探测流量）。

**(b) hairpin NAT（内网访问自家 VIP）**

内网客户端访问 VIP，DNAT 后源仍是内网 IP，后端回包直接发给客户端（同网段），绕过网关 → 回程不一致。

解法：DNAT 后对「源也在内网」的流量做 SNAT，源改成网关内网地址。

```go
// 在 dnat 链，DNAT 之后立即判断源是否在 hairpin 网段
func compileHairpin(srcNets []netip.Prefix, gwIP netip.Addr) []expr.Any {
    // ct mark 已打 DNAT 位，且 ip saddr ∈ hairpin 网段 → snat to gwIP
}
```
**顺序关键**：hairpin 的 SNAT 必须在 `dnat` 链里紧接 DNAT 执行，不能放到 `postrouting`（那时路由已决策，源改写无效）。

**(c) ICMP 差错报文改写**

客户端发 1500 字节包，路径 MTU 1400，中间路由回 `ICMP frag needed`。这个 ICMP 的内层 IP 头是被 NAT 之前的地址，如果不改写，客户端收到会忽略（因为找不到对应的连接）。

nftables 在 `inet` 家族会自动处理 ICMP 差错的内层 NAT（`nf_nat` 的 `icmp_error` 钩子），**但前提是 conntrack 能关联上**。所以：
- 必须保证 `nf_conntrack` 模块加载（`tuning` 里已有 `nf_conntrack_max`）
- 必须允许 ICMP 通过（策略里不能一刀切 drop icmp）
- **验收必测**：用 `iptables -j REJECT --reject-with icmp-host-unreachable` 之外的方式，实测 ping 大包

代码侧不需要额外写规则，但需要**在默认拒绝里放行 ICMP 类型 3/11**（否则差错报文被自己的默认拒绝干掉）。

```go
// CompileDefaultDeny 中，drop 之前必须先放行关键 ICMP
func compileIcmpExempt() []expr.Any {
    // icmp type { destination-unreachable(3), time-exceeded(11) } accept
    // 以及 icmpv6 type { 1, 2, 3 } accept
}
```
**这是现有代码的一个隐患**：`CompileDefaultDeny` 是无条件 drop 未打标流量，可能把 ICMP 差错也 drop 掉，造成「大包黑洞」。新方案必须显式豁免。

**(d) MSS clamping**

放在独立链 `mss`，`hook forward priority -20`（在 fwd 的 -10 之前）。

```go
// internal/compile/mss.go
// nft 等价：tcp flags syn tcp option maxseg size set <mss>
func CompileMSSClamp(v4, v6 uint16) []Rule {
    if v4 == 0 { return nil }
    return []Rule{{
        Chain: ChainMSS,
        Exprs: []expr.Any{
            // 只处理 TCP
            &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
            &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
            // 只处理 SYN（非 ACK）
            &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
            &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 1,
                Mask: []byte{0x02}, Xor: []byte{0x00}},
            &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x02}},
            // MSS 选项必须存在（不存在就跳过，否则写到错误位置）
            &expr.Exthdr{DestRegister: 1, Type: expr.TCPOptionMaxsegSize,
                Offset: 0, Len: 2, Flags: expr.ExthdrFlagsNone},
            // 写入 + 重算 TCP 校验和
            &expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(v4)},
            &expr.Payload{Operation: expr.PayloadWrite, SourceRegister: 2,
                Base: expr.PayloadBaseTransportHeader, Offset: 22, Len: 2,
                CsumType: expr.CsumTypeInet, CsumOffset: 16, CsumFlags: 0x1},
        },
    }}
}
```

**必须先做命令行验证**（1 小时）：
```bash
nft add chain inet haweb mss '{ type filter hook forward priority -20; }'
nft add rule inet haweb mss tcp flags syn tcp option maxseg size set 1360
nft -a list chain inet haweb mss     # 逐字段对照上面的 expr
```
`CsumType`/`CsumFlags` 错会导致 SYN 被对端丢弃——比不做更糟。

### 3.4 SNAT 池分配：从取模改 HRW

**现有实现**（`compile_dnat.go:243` PoolMemberOf）：

```go
h := 0
for _, v := range ip { h = h*131 + int(v) }
return pool[h % len(pool)]
```

这是**取模哈希**。池从 4 扩到 5 时，`h%4` 与 `h%5` 的结果分布完全不同，**约 75% 的源会换 IP**。这就是交付文档说的「重排 74%」。

**新方案：Rendezvous Hashing（HRW，最高随机权重）**

```go
// internal/domain/snat/pool.go
func (p *Pool) Member(src netip.Addr) netip.Addr {
    if len(p.members) == 1 { return p.members[0] }
    var best netip.Addr
    var bestScore uint64
    for _, m := range p.members {
        s := hash64(src, m)
        if s > bestScore { best, bestScore = m, s }
    }
    return best
}

func hash64(src, member netip.Addr) uint64 {
    var b [32]byte
    a := src.As16(); c := member.As16()
    copy(b[:16], a[:]); copy(b[16:], c[:])
    // 用标准库的 maphash 或 fnv-1a，要求快且分布均匀
    h := fnv.New64a()
    h.Write(b[:])
    return h.Sum64()
}
```

**HRW 的性质**：新增一个成员，只有「新成员的分数最高」的那些源会迁移，比例 ≈ 1/(N+1)；删除成员只影响原本落在它上面的源 ≈ 1/N。池 4→5 重排 **20%**，不是 75%。

**但真正的问题是「粘性」，不是「重排」**

这里要澄清一个容易误解的点：**池变更不会中断存量连接**，因为 conntrack 已经记住了 NAT 后的地址和端口，回程与后续包都按 conntrack 走。

真正受影响的是：**同一客户端在池变更后建立了新连接，源 IP 变了**。如果对端有「源 IP 白名单」或「按源 IP 计费/限流」，就会出问题。

**解法：用 verdict map 固化历史分配**

```go
// set: snat_assign, type ipv4_addr : ipv4_addr（src → 池成员）
// 首次见到的源才计算 HRW 并插入；已存在则直接查表
```
nftables 侧：
```go
&expr.Lookup{SourceRegister: 1, DestRegister: 1, SetName: "snat_assign"},
// 未命中 → 走 HRW 分支（编译期展开每个成员做比较，成本高）
// 命中 → 直接 snat to ip saddr map @snat_assign
```

**取舍**：如果源数量可能上万（任意客户端），预展开 HRW 的比较链不可行。此时**接受取模 + 声明重排率**，或者用 `numgen` 让内核算哈希：

```go
&expr.Numgen{Register: 1, Type: expr.NumgenTypeHash, Modulus: uint32(len(pool))},
// 然后 snat to ip saddr map @pool_map（map 的 key 是 0..N-1）
```
`numgen hash` 是内核 jhash，扩缩容同样重排，但**内核侧 O(1)**，且规则数不随源数增长。

**最终方案（按池规模选）**：

| 池成员数 | 源规模 | 算法 | 重排率 | 内核成本 |
|---|---|---|---|---|
| ≤ 8 | 任意 | `numgen hash` + map | (N-1)/N | O(1) |
| ≤ 8 | ≤ 256（静态源） | HRW + verdict map | 1/(N+1) | O(1) |
| > 8 | 任意 | `numgen hash` + map | (N-1)/N | O(1) |

并在 UI 明示当前算法的重排率。

### 3.5 限速：能力边界与正确结构

这是现有代码里最脏的一块（`snat.go` 里 6 处 `exec tc`），也是**踩坑最多、结论被推翻过两次**的一块。本节所有结论都来自真机 `192.168.10.170`（KVM + `virtio_net` + Linux 6.8.0-147 + iproute2-6.1.0）的实测输出。

> **订正声明（必读）**：本节初稿依据 commit `58c60fa` / `ee56a3b` 的自我归因，判过「按源 IP 的 tc 分类限速不可行」「`cls_u32` 完全不参与分类」。**这个结论已被真机证伪。** 真实情况是：下载方向 `u32 match ip dst` 精确到 0.08%；上传方向失效是**代码把 match 字段写成了 `dst`**（应为 `src`），跟分类器能力无关。后文给出的数据和结构都替换了旧内容，旧文档、旧 commit message、`AGENTS.md` 第 67 条的相应用语一律作废。

**结论先行**：本环境**能**做按源分类、按源保底、总额共享。需要的只是把两个方向的 `match` 字段写对、`pref` 分段、`burst` 随速率缩放。

#### 3.5.1 三个已实测的结论

**① `ct mark` 跨链可读且可位运算 —— 32 位规则容量成立**

写侧 `prerouting priority -160` 打 `ct mark set 0x1200`，读侧 `postrouting priority 100`：

| 规则 | 命中 |
|---|---|
| `ct mark == 0x1200` | 474 包 / 196,451 字节 |
| `ct mark and 0x0000ff00 == 0x00001200` | **474 包 / 196,451 字节**（与上一行完全相等） |
| `pre` 链 `counter` | 327 包 |

字节数完全一致 → 位域提取生效。`rule_id << 8 | flags` 的 32 位方案（1,600 万条规则）不需要退回 3 个 mark 位。

**② 下载方向 `u32 match ip dst` 精确可用**

`eth0` egress：`u32 match ip dst 192.168.10.152/32 flowid 1:208`

- 实测 **8.006507 MB/s**，配置 8MB/s → 误差 **0.08%**
- `tc -s class show dev eth0`：`1:208` 的 `Sent` +54.8MB，`overlimits` +2520

**③ 上传方向失效的真因是 match 字段写反**

现象：上传 **118.51 MB/s**（配置 8MB/s，超 **14.8 倍**），`ifb-haweb` 的 htb qdisc `Sent` 在涨，但**所有子类 `Sent` = 0**，`direct_packets_stat` 持续增长。

二分定位：只加一条 filter，其余一字不改——

```bash
tc filter add dev ifb-haweb parent 1: prio 5 u32 \
   match ip src 192.168.10.152/32 flowid 1:208
```

上传立刻降到 **8.09 MB/s**，`1:208` 的 `Sent` = 54,818,734 字节，`overlimits` +4521。

根因在 `applyIngressLimit()`：写的是 `match ip dst <客户端>`。上传包经 `mirred` 进 `ifb` 后，**`daddr` 是公网服务器、`saddr` 才是客户端**，所以永不命中 → 走 `direct queue` → 绕过整棵 HTB 树，且**静默无报错**。

#### 3.5.2 上传方向为什么必须 ingress + ifb

上传包在出口网卡 **egress** 上，源地址已被 SNAT 改写为网关 IP，按 `saddr` 分类**不可能**区分原始客户端（这一点旧结论是对的）。但在**入口网卡 ingress** 上 `saddr` 仍是客户端真实 IP，是唯一能按源分类的位置。

`ingress` qdisc 本身只能 policing（丢包），不能整形（排队），所以必须 `mirred egress redirect dev ifb-<bwID>`，在 `ifb` 的 egress 侧挂 HTB。链路长度与故障面因此翻倍，这是物理约束，躲不掉。

**按带宽包隔离 ifb**：同一带宽包的多条规则共用一棵树（共享额度），不同包用不同设备——否则父类 `rate` 会被后应用的包覆盖，先前包的额度失效。

#### 3.5.3 正确结构

> **订正（真机实测，2026-10-30，见 `docs/poc-result.md` §3.2 / §4.2.1）**：本节初稿有两个致命错误，已按实测改写：
> ① `fq_codel` 挂在 `1:100`（内层类）上，本内核返回 `RTNETLINK answers: Invalid argument` —— **内层类不能挂叶子 qdisc**；
> ② `default` 指向 `1:100`，一旦 `1:100` 挂了子类就变成内层类，未命中 filter 的包**进不了任何队列**，内核直接走 `direct queue` **绕过整棵树**。实测 `default` 指向叶子时 7.81 MB/s（`direct=0`），指向内层后 **2828.79 MB/s**（`direct` 增量与总包数相等）。
>
> **所以必须新增一个叶子兜底类承接 `default`，且 `fq_codel` 只挂叶子类。**

**下载方向（出口网卡 egress）**

```
qdisc htb 1: default 199                                   ← ★ default 指向叶子兜底类，不是 1:100
class 1:100 parent 1:      rate=ceil=<带宽包总额>           ← 总额父类（内层类）
class 1:199 parent 1:100  rate=<保底> ceil=<总额>           ← ★ 叶子兜底类，承接 default
  qdisc fq_codel 199: parent 1:199                         ← ★ fq_codel 挂叶子
class 1:1NN parent 1:100  rate=<每源保底> ceil=<总额>        ← 每白名单源一个
  qdisc fq_codel 1NN: parent 1:1NN                         ← ★ 每个叶子各挂一个
filter parent 1: protocol ip pref <srcFilterPref> u32 \
       match ip dst <客户端>/32 flowid 1:1NN                ← ★ dst
class 1:30  parent 1:   rate=10gbit                        ← 占位类，不承载流量
```

**上传方向（入口网卡 ingress → ifb）**

```
<入口网卡> qdisc ingress ffff:
filter parent ffff: protocol ip pref <uploadFilterPref> u32 \
       match ip src <客户端>/32 action mirred egress redirect dev ifb-<bwID>
ifb-<bwID> qdisc htb 1: default 199                        ← ★ 同样指向叶子兜底类
ifb-<bwID> class 1:100 parent 1: rate=ceil=<总额>
ifb-<bwID> class 1:199 parent 1:100 rate=<保底> ceil=<总额>
  qdisc fq_codel 199: parent 1:199
ifb-<bwID> class 1:1NN parent 1:100 rate=<保底> ceil=<总额>
  qdisc fq_codel 1NN: parent 1:1NN
ifb-<bwID> filter parent 1: protocol ip pref <uploadFilterPref> u32 \
       match ip src <客户端>/32 flowid 1:1NN               ← ★ src
```

**三条必须写死的结构约束（错一个就静默失效，均有实测反证）**

| 约束 | 违反后果（实测） |
|---|---|
| `default` 必须指向**叶子**类（有 qdisc、无子类） | 指向内层 `1:100` → 未分类流量 100% 走 `direct` 绕过整棵树：2828.79 MB/s vs 配置 8 |
| `fq_codel` 只能挂**叶子**类 | 挂内层 `1:100` → `RTNETLINK answers: Invalid argument`，命令失败但不影响限速树（更隐蔽） |
| 上传 `match ip src` / 下载 `match ip dst` | 上传用 `dst` → `at 16` 永不命中 → 全落 default；配合上面两条就是现网 14.8 倍超速 |

#### 3.5.4 三组必须写死的对应关系（错一个就静默失效）

| 用途 | 设备 | `parent` | match 字段 | pref 区段 |
|---|---|---|---|---|
| 上传·重定向 | 入口网卡 | `ffff:` | **`ip src`** | `uploadFilterPref`：`1002..1998` |
| 上传·分类 | `ifb-<bwID>` | `1:` | **`ip src`** | `uploadFilterPref`：`1002..1998` |
| 下载·分类 | 出口网卡 | `1:` | **`ip dst`** | `srcFilterPref`：`2..998` |

必须写两个单测把不变量钉住：

```go
// 上传 filter 必须用 src——用 dst 会 100% 不命中（现网事故：8MB/s 配置跑出 118.51MB/s）
func TestIngressFilterMatchesSrc(t *testing.T)
// 上传 pref 与下载 pref 必须不相交——单臂网关下两方向共用一个 qdisc
func TestUploadDownloadPrefDisjoint(t *testing.T)
```

**`pref` 不许写死 `10`**。现状 `eth0` egress 上两个源的下载 filter 都是 `pref 10`，靠 tc 把不同 match 塞进同一张 u32 哈希表（`fh 800::800` / `800::801`）侥幸共存。这个行为不是契约，一旦真被 `replace` 覆盖，就是某个源静默绕过限速。

#### 3.5.5 `direct queue` 的正确理解（旧结论在这里把因果搞反了）

`direct queue` 是 u32 **未命中时**的兜底路径，**不是「挂子类」的副作用**。子类挂了、filter 也命中，工作完全正常——结论②就是挂着子类跑出来的。

| 现象 | 含义 |
|---|---|
| `direct_packets_stat` 增长 **且** 所有子类 `Sent` = 0 | filter **全部未命中** → 先查 match 字段与方向 |
| `direct_packets_stat` 小幅增长 **且** 子类 `Sent` 在涨 | 正常——未分类流量按 `default` 走 |

把因果搞反的代价是：以为「挂子类必然破坏限速」，于是永远不敢做 per-src，直接砍掉「保障带宽」这个产品能力。

#### 3.5.6 单臂网关的两个坑

`AGENTS.md` 第 68 条，入口网卡 == 出口网卡时：

1. **同卡同网段时内核回 ICMP redirect 不转发**，包不进 `FORWARD` 链，规则看起来「配了但没生效」。规则启用时必须写 `send_redirects=0`。
2. **下载 filter（`daddr`=源）与上传 filter（`saddr`=源）共用一个 qdisc 时 `pref` 必须分段**：下载 `2..998`、上传 `1002..1998`。否则 `tc filter replace` 互相覆盖，某一方向限速**静默失效**。

#### 3.5.7 保底与共享语义

子类 `rate=MinKBps`（拥塞时的下限）、`ceil=总额`（空闲可借满）。多源并发时各自至少拿到保底，剩余额度按需争抢——这就是「保障带宽」。

> **订正（真机实测 15 组二维扫描，2026-10-30，见 `docs/poc-result.md` §4.2.1）**：本节初稿称「`1:100` 是总额硬上限」，**这个说法是错的**。实测规律是
>
> ```
> 实际总量 ≈ max(parent.rate, Σ子类rate)        误差 −2.5% ~ −4.2%（15 组全部吻合）
> ```
>
> `parent.rate` 是**「保底总池」而非上限**：
> - `Σ保底 < 总额` 时，子类可一路借到总额（N=12 / 总额16 → 实测 15.52 MB/s）
> - `Σ保底 > 总额` 时，`parent` **完全不起限制作用**，合计跟着 `Σ保底` 走（N=12 / 总额4 → **11.50 MB/s，超 187.6%**）
>
> **要让总额成为硬上限，唯一办法是保证 `Σ MinKBps ≤ 带宽包总额`。** 产品语义已由 **ADR-15** 定为「约束式」（保存时拒绝超额订阅），不做 policing。

**必须注意超额订阅**：`MinKBps` 的兜底默认值是 `1024`（1MB/s）。当「带宽包总额 < 源数 × 1024KB/s」时必然超额订阅，此时 HTB 按 `rate` 比例分配，**不保证**每个源都拿到 1024，**且合计会突破总额**。UI 必须能算出这个情形并提示，且保存时应直接拒绝（ADR-15）。

**「限速生效」和「公平调度生效」是两件事**，验收时必须能区分：把两个源的 `rate` 设成不同值（2MB/s vs 1MB/s），总额仍 4MB/s，两源同打——若两条流**仍然完全等分**，说明 HTB 根本没在读 `rate`，是 `fq_codel` 在做公平。这个对照是判定「保底是否真的生效」的唯一手段。

**实测该对照通过**（`docs/poc-result.md` §4.1）：配置 1:2 保底，实测 **1.3162 : 2.5579 = 1 : 1.943**，两条流明显不对称 → HTB 确实在读 `rate`；`borrowed` 增量 +2,259 / +1,414 证明借用真实发生。

#### 3.5.8 验证状态（2026-10-30 更新）

| 项 | 状态 | 证据 / 怎么验 |
|---|---|---|
| 按正确结构重建整棵树，上传是否也能限到 8MB/s | ✅ **已验证** | `docs/poc-result.md` §3.3：完整结构 7.7595 MB/s（−3.01%），`direct` 增量 0 |
| 多源并发时总额是否真的共享（合计 ≈ 总额而非 N×） | ✅ **已验证** | §4.2.1 二维扫描 15 组：合计 ≈ `max(parent.rate, Σ子类rate)` |
| `MinKBps` 不等保底时是否按比例分配 | ✅ **已验证** | §4.1 B2：1.3162 : 2.5579 = 1 : 1.943 |
| 双表 `jump` 切换的原子性 | ✅ **已验证** | §6.3：60 次翻转 / 0 异常 / jump 恒 1 / 客户端 300s 零 reset |
| `CommitShadow` 影子链装配失败时旧链仍服务 | **未验证** | Task C 的工作链只有 counter，无法覆盖异常路径；S1 DoD 第 3 条负责 |
| `burst` 随速率缩放（千兆场景） | **未验证** | 只测了 8MB/s，需 1Gbps 复验 |
| eBPF `clsact` per-src | **不需要**（备选） | `u32` 已打通；三个未知点见 §3.5 末尾 |

#### 3.5.9 硬约束（写进代码，不能只写在文档里）

1. **上传 filter 必须 `match ip src`，下载必须 `match ip dst`**，两个方向严禁互相照抄。现网事故：写成 `dst` → 超速 14.8 倍。
2. **`pref` 按 `srcFilterPref` / `uploadFilterPref` 派生**，不许写死常量。
3. **清理历史子类时跳过 `1:100` 与 `1:30`**，在 `applyHtb` 入口加显式白名单判断，不要靠循环边界。曾因循环 `1:2..1:249` 把刚建好的限速类删掉，`default` 指向不存在的 class，**8MB/s 配置跑出 24MB/s**。新代码必须保留等价测试。
4. **`default` 必须指向「叶子兜底类」（有 qdisc、无子类），不许指向挂了子类的内层类**；也不许 `0xffff`（无默认）、不许 `0`（直通）。实测反证：`default` → 内层 `1:100` 时未命中 filter 的包 100% 走 `direct queue` 绕过整棵树（2828.79 MB/s vs 配置 8）。
5. **`netlink.HtbClass` 的 `Rate`/`Ceil` 单位是 bytes/sec**，`tc` CLI 的 `kbit`/`mbit` 是 bit/sec。换算错 8 倍是这块的经典 bug。`Buffer`/`Cbuffer` 单位是 bytes。
6. **`burst` 必须随速率缩放**，不许固定 `32k`/`16k`。固定值在千兆下只有 10ms 额度的 1/40，表现为「限 1Gbps 实测只跑 200Mbps」。

```go
// burst 按 10ms 令牌深度算，下限 32KB、上限 8MB
func burstBytes(bps int64, quantum time.Duration) uint32 {
    v := uint64(bps) / 8 * uint64(quantum/time.Millisecond) / 1000
    if v < 32<<10 { v = 32 << 10 }
    if v > 8<<20  { v = 8 << 20 }
    return uint32(v)
}
```

7. **切 htb 结构时整树重建**，不要 `qdisc change`。`qdisc change` 不支持改 `default`。
8. **验收必须报「实测 / 配置 / 误差」三个数**。8MB/s 配置跑 118MB/s 时，`tc` 的每条命令依然返回成功。

### 3.6 策略与默认拒绝

**accept 语义（必须定死）**

现有实现是「accept 只打标记，不终结，与规则白名单 AND」。这个语义在工程上自洽，但与行业直觉冲突。

**新方案：显式两档，UI 可选**

```go
type PolicyAction string
const (
    ActionAccept PolicyAction = "accept"  // 打标，仍需规则白名单（AND）
    ActionAllow  PolicyAction = "allow"   // 直接 pass，不查规则（终结放行）
    ActionDrop   PolicyAction = "drop"    // 终结拒绝
)
```

- `accept`：保持现有语义，用于「策略层细粒度收紧」
- `allow`：新增，真正的「放行」，`verdict accept` 终止 fwd 链评估
- `drop`：终结拒绝，带 `ct mark` 记录命中策略 ID（供日志）

**默认拒绝的作用域三档**（解决「误杀同机 Docker/K8s」）

```go
type DenyScope string
const (
    ScopeOff        DenyScope = "off"          // 不装默认拒绝
    ScopeDnatTarget DenyScope = "dnat_target"  // 只拒「目标 ∈ 本产品后端集」的未打标流量 ★默认
    ScopeInterface  DenyScope = "interface"    // 拒整个入口网卡（现有行为，危险）
)
```

`dnat_target` 的实现：

```go
// set: backend_targets { type ipv4_addr; flags interval; }  // 或 ipv4_addr . inet_service
// 默认拒绝行：
//   ct state new  ip daddr @backend_targets  meta mark & FWD_OK == 0  → counter drop
```
这样只影响「目标是本产品发布的后端但源不在白名单」的流量，同机其他转发（Docker 的 172.17.0.0/16、K8s pod 网段）完全不受影响。

**逃生开关**

```go
// 5 分钟自动恢复，防忘记
POST /api/emergency/disable-default-deny  → 删除 dispatch_fwd 的默认拒绝段
// 定时器 5min 后自动重装
```

### 3.7 拒绝日志（内核侧可溯源）

**方案：dynamic set + counter，不做逐包日志**

```go
// set: deny_src { type ipv4_addr; flags dynamic,timeout; timeout 1h; }
// drop 行前插：
//   update @deny_src { ip saddr }
//   counter
//   drop
```

`ipset` 风格的 dynamic set 会记录每个 IP 的 `packets`/`bytes`（配合 `counter` 选项）。

用户态每 5 秒读一次：
```go
func (e *Engine) ReadDenySet(ctx context.Context) ([]DenyEntry, error) {
    // nftables: 遍历 set 元素，读 exprs 里的 counter
    // 返回 {src_ip, packets, bytes, timeout_remaining}
}
```

落库到 `deny_YYYYMMDD` 分表。**得到的能力**：

| 能力 | 是否支持 |
|---|---|
| Top N 攻击源 | ✅ |
| 每源被拒次数/字节 | ✅ |
| 命中哪条策略 | ✅（按策略 ID 分别建 set） |
| 精确到毫秒的逐条记录 | ❌（只有首次/最后时间） |
| 每包五元组 | ❌ |

**取舍说明**：等保要「审计记录包含事件时间、来源、类型、结果」。`dynamic set` 能给时间（首次/最后）、来源（IP）、类型（DDoS/策略拒绝）、结果（丢弃），满足条款。若客户坚持逐包，才上 `expr.Log` + `ulogd2`，且必须加 `expr.Limit{Rate:10, Unit: packets}` 限速，否则 DDoS 时日志反噬。

---

## 4. 会话表：事件订阅替代轮询

**现有实现**：`recvCmd("conntrack", "-L")` 解析文本，每次查询全量 dump。10 万会话时单次 dump 约 200ms，且占用控制平面。

**新方案**：`ti-mo/conntrack` netlink，**事件订阅 + 增量维护**。

```go
// internal/adapter/ctnl/engine.go
type Engine struct {
    c        *conntrack.Conn
    sessions *shardedMap   // 32 分片，每片独立锁
}

func (e *Engine) Run(ctx context.Context) error {
    // ① 首次全量 dump（建立基线）
    flows, err := e.c.Dump(nil)
    if err != nil { return err }
    for _, f := range flows { e.sessions.Put(toSession(f)) }

    // ② 订阅增量事件
    events := make(chan conntrack.Event, 4096)
    errCh := e.c.Listen(events)   // NFNLGRP_CONNTRACK_NEW/UPDATE/DESTROY

    // ③ 定期对账（事件可能丢，队列满时内核不阻塞而是丢）
    ticker := time.NewTicker(60 * time.Second)
    for {
        select {
        case <-ctx.Done(): return nil
        case ev := <-events:
            switch ev.Type {
            case conntrack.EventNew, conntrack.EventUpdate:
                e.sessions.Put(toSession(ev.Flow))
            case conntrack.EventDestroy:
                e.sessions.Delete(keyOf(ev.Flow))
            }
        case <-ticker.C:
            e.reconcile(ctx)   // 全量 dump 一次，修正偏差
        }
    }
}
```

**收益**：

| 指标 | 轮询 | 事件订阅 |
|---|---|---|
| 查询延迟 | 需 dump 全表（10 万条 ~200ms） | O(1) 内存查表（<1μs） |
| 控制平面占用 | 每 5s 一次 dump | 事件驱动，空闲时零开销 |
| 会话建立可见性 | 最多 5s 延迟 | 实时 |
| 删会话 | `conntrack -D`（fork 进程） | netlink delete（一次 syscall） |

**分片哈希表**（避免全局锁）：

```go
type shardedMap struct {
    shards [32]struct {
        mu sync.RWMutex
        m  map[ctKey]*Session
    }
}

func (s *shardedMap) shard(k ctKey) int {
    return int(k.hash() & 31)
}
```

**为什么 32 片**：转发路径几乎不读会话表（只有管理面查），所以分片数不用太多；32 片能让「查询」与「事件更新」并发不冲突即可。

---

## 5. 用户态转发引擎

TCP/UDP 代理规则（非 NAT 规则）走用户态 Go 转发，这部分现有实现可用，主要补两点。

### 5.1 两条数据路径

| 路径 | 条件 | 实现 | 特点 |
|---|---|---|---|
| 普通拷贝 | 有限速 / 需统计 | `io.CopyBuffer` + 自定义 buffer | 实时统计准确 |
| splice 零拷贝 | 无限速 | `syscall.Splice` via `unix.Splice` | 性能好，但**传输中统计不刷新** |

**现有问题**：`splice` 开启后统计不刷新，且空闲超时不生效（`PROJECT-OVERVIEW.md` 自述）。

**新方案**：splice 只用于「无限速且无需按字节计费」的场景，且**必须解决超时**：

```go
// splice 时用 poll 带超时，而非阻塞 read
func spliceWithTimeout(src, dst int, timeout time.Duration) (int64, error) {
    pfd := []unix.PollFd{{Fd: int32(src), Events: unix.POLLIN}}
    for {
        n, err := unix.Poll(pfd, int(timeout.Milliseconds()))
        if n == 0 { return total, ErrIdleTimeout }   // 超时退出
        ...
    }
}
```

**决策建议**：**默认关闭 splice**（现状已是 `splice: false`），并在 UI 标注「开启后实时速率不刷新」。这是诚实的产品行为，比修一半的 splice 更可靠。

### 5.2 连接生命周期

```
accept → 取快照 → ACL 判定 → 限速器创建 → 拨后端 → 双向拷贝 → 统计汇总 → 落日志
         ↓失败          ↓拒绝
       close        落 denied 日志（异步）
```

**关键**：`accept` 之后所有操作都用**同一个快照**，避免「判定时规则还在，建连时规则没了」的竞态。

---

## 6. 日志与存储

### 6.1 写入路径：无锁环形缓冲

现有用 channel（容量 4096），满则丢。问题是高并发下多 goroutine 抢 channel 有竞争。

**新方案：分片 ring buffer**

```go
// internal/adapter/logstore/ring.go
type Ring struct {
    shards [8]struct {
        buf  [8192]Entry
        head atomic.Uint64  // 生产者
        tail atomic.Uint64  // 消费者
        drop atomic.Uint64
    }
}

func (r *Ring) Push(e Entry) bool {
    s := &r.shards[e.RuleID&7]   // 按规则分片，天然分流
    h := s.head.Load()
    t := s.tail.Load()
    if h-t >= uint64(len(s.buf)) {
        s.drop.Add(1)
        return false             // 满则丢，绝不阻塞
    }
    s.buf[h%uint64(len(s.buf))] = e
    s.head.Store(h + 1)
    return true
}
```

**为什么按 rule_id 分片**：同一规则的事件常来自同一批连接，分片后写入集中在少数 ring，`head` 的 CAS 竞争大幅降低。

### 6.2 分表路由

```go
// internal/adapter/logstore/sqlite/table.go
func tableFor(t time.Time) string {
    return "traffic_" + t.Format("20060102")
}

func (s *Store) Write(ctx context.Context, entries []Entry) error {
    // 按天分组，每批一个事务
    byDay := groupByDay(entries)
    for day, batch := range byDay {
        tbl := "traffic_" + day
        s.ensureTable(ctx, tbl)      // CREATE TABLE IF NOT EXISTS（幂等，缓存已建列表）
        // 批量插入
        s.db.ExecContext(ctx, buildInsert(tbl, len(batch)), args...)
    }
    return nil
}
```

**`ensureTable` 必须带内存缓存**，否则每批都查 `sqlite_master`。

**轮转 = DROP TABLE**：

```go
func (s *Store) Rotate(ctx context.Context, before time.Time) (int64, error) {
    for _, t := range s.listTablesBefore(before) {
        if err := s.db.Exec("DROP TABLE IF EXISTS " + t).Error; err != nil { return 0, err }
    }
    // incremental_vacuum 分批还空间，不锁库
    s.db.Exec("PRAGMA incremental_vacuum(1000)")
    return n, nil
}
```

**建库时必须设 `PRAGMA auto_vacuum=2`**，否则 DROP 后文件不缩。

### 6.3 多 sink 分发

```
写入 → Ring → flush 协程（每 200ms 或满 1000 条）
                ├─ sink[sqlite]  （批量 insert，事务）
                ├─ sink[file]    （JSON Lines + 按天切分）
                ├─ sink[syslog]  （RFC5424，UDP/TCP）
                └─ sink[remote]  （HTTP 批量 POST，带重试队列）
```

**sink 隔离**：每个 sink 独立 goroutine + 独立队列。一个 sink 慢不能拖累其他。

```go
type sinkWorker struct {
    in   chan []Entry    // 容量 64（批次）
    fail atomic.Uint64
}
```

---

## 7. 端到端数据流

以「运维在 Web 上改了一条 SNAT 规则的出口」为例：

```
① HTTP PUT /api/snat-rules/12
   transport/httpapi → app/ruleapp.Update()
   └─ 校验 DTO（gin binding）
   └─ 调用 domain.Validate
   └─ repo.Update（config.db，事务）
   └─ control.Request()  ← 投递到控制平面 chan，等待结果
② 控制平面（单 goroutine）
   └─ repo.LoadAll（读全量状态）
   └─ compiler.Compile(state) → Plan
   └─ applier.Apply(plan)
        ├─ nft.LoadShadow      （装到 snat_b）
        ├─ nft.VerifyShadow    （规则数 / 关键规则存在）
        ├─ nft.CommitShadow    （原子切 jump，一个 batch）
        └─ tc.Apply            （补偿式）
   └─ snap.Store(plan.Snapshot)
③ 返回 HTTP 200 + {version, warnings:{tc_ok:true}}
④ 转发面：下一个包读新快照 / 内核读新规则链
⑤ 审计：audit.Write("rule_update", rule_id=12, before, after)
```

**关键时序保证**：

- ② 是**同步**的（HTTP 请求等控制平面完成）。这样运维点「保存」就知道成不成功，不会出现「提示成功但实际没生效」。
- 如果要异步（大批量导入），走 `POST /rules/import?async=true` 返回 `task_id`，前端轮询 `/tasks/:id`。

**控制平面超时**：`apply_timeout = 30s`，超时返回 504 但**不中断应用**（让它在后台完成），并写入 `last_apply_error`。

---

## 8. 错误处理与降级矩阵

### 8.1 失败语义

| 阶段 | 失败后果 | 处理 |
|---|---|---|
| DTO 校验 | 无需回滚 | 400 + 字段级错误 |
| domain 校验 | 无需回滚 | 400 + 业务原因 |
| DB 写入 | 无需回滚内核 | 500，提示重试 |
| Plan 编译 | 内核未变 | 400 + 编译错误详情（含哪条规则哪行） |
| nft 装配 | 内核未变（影子链丢弃） | 500 + 明确「旧规则继续生效」 |
| nft 自检 | 内核未变 | 500 |
| nft 切换 | **理论不可能失败**（原子）；若失败，怀疑内核异常 | 500 + 告警 critical |
| tc 应用 | nft 已生效，tc 部分生效 | 207 + `warnings`，不自动回滚 |
| 快照发布 | 不会失败（atomic.Store） | — |

### 8.2 能力降级矩阵

| 缺失能力 | 探测方式 | 降级行为 | 用户可见性 |
|---|---|---|---|
| `nftables` netlink | `Dial()` 失败 | **启动失败**（核心依赖） | 启动日志 + exit 1 |
| `tc` netlink | `QdiscAdd` 探测 | 限速不生效 | UI 红条 + `/api/capabilities` |
| `ifb` 模块 | `link.Add` 探测 | **仅出向限速**，入向无保障 | UI 明确「下行不限速」 |
| `conntrack` netlink | `Dial()` 失败 | 会话表不可用，踢会话不可用 | UI 置灰 + 说明 |
| `CAP_NET_ADMIN` | `unix.Capget` | 启动失败 | exit 1 + 提示 |
| 数据盘 < 5% | `statfs` | 日志只写内存，丢弃计数 | 首页告警 |
| 备份目标不可达 | 连接探测 | 保留本地，指数退避 | 备份页「积压」 |

**原则**：**核心依赖失败就退出，非核心依赖失败要在 UI 上大声说。**

---

## 9. 实施与代码量

### 9.1 模块与代码量估算

| 模块 | 行数 | 说明 |
|---|---|---|
| `domain/model` | 600 | 实体 + 值对象 + 校验 |
| `domain/rule` `policy` `snat` `bandwidth` | 1,200 | 纯函数算法 |
| `compile/`（搬运 + 扩展 fw） | 1,400 | nft 规则编译（含 MSS/hairpin/deny） |
| `control/`（compiler + applier + loop） | 900 | 编排 |
| `adapter/nftables/` | 1,200 | 双表切换 + set + counter |
| `adapter/tcnetlink/` | 800 | HTB + IFB |
| `adapter/ctnl/` | 500 | 事件订阅 + 分片表 |
| `adapter/sqlite/` | 1,100 | 双库 + 分表 + repository |
| `adapter/logstore/` | 900 | ring + 4 sink |
| `adapter/backup/` | 700 | sftp + s3 + 校验 |
| `app/` | 1,600 | 7 个用例服务 |
| `transport/httpapi/` | 1,800 | 45 个 handler（瘦） |
| `platform/`（config/caps/version） | 700 | |
| `engine/`（用户态转发，搬运） | 900 | tcp/udp/copy |
| `auth/`（搬运） | 800 | |
| **合计** | **约 15,100** | 加测试约 6,000 |

对比现有 20,789 行：**净减约 5,700 行**，主要是消除 exec 解析、重复的规则构造、API 层样板。

### 9.2 与绞杀者路线的取舍

| 维度 | 整体重写（本方案） | 绞杀者（PRD 路线） |
|---|---|---|
| 工期 | 10~12 周 | 13 周 |
| 风险 | **高**（一次性切换，全量回归） | 低（每期可发布） |
| 代码质量 | 高（无历史包袱） | 中（会保留部分旧结构） |
| 业务连续性 | 需要 1 次停机或双跑 | 无停机 |
| 适合场景 | 尚未大规模上线 / 有充足回归资源 | 已生产运行 |

**建议**：既然「不介意整体重构」，采用**混合策略**——

1. **内核面（nft/tc/ct）整体重写**：这块旧代码最脏，且可独立验证（用 `nft list` 比对）。
2. **业务面（api/app/domain）整体重写**：分层收益最大。
3. **转发循环与 auth 搬运**：这两块写得不错，重写没收益。
4. **前端保留**：只加 TS。
5. **切换方式**：新旧两套二进制并存，通过 `--legacy` 开关切换，用同一套验收用例跑两遍，结果 diff 为空后切默认。

这样既拿到绿地设计的质量，又保留一条可回退的路。

### 9.3 里程碑（整体重写版）

| 阶段 | 周 | 交付 | 验证方式 |
|---|---|---|---|
| S0 | 1 | `domain` + `compile`（纯函数）+ 全量单测 | `go test ./domain/... ./compile/...` 覆盖率 ≥ 85% |
| S1 | 2 | `adapter/nftables`（双表切换）+ 影子链 PoC | 真机 `nft list` 比对 + 切换零丢包压测 |
| S2 | 2 | `adapter/tcnetlink` + `ctnl` | 双方向 htb（总额 + 每源保底，§3.5.3）+ ifb 上传方向；tc 与 CLI 逐字段比对；上传/下载各 8MB/s 实测 ±5%、双源合计 ≈ 总额；会话表 10 万条压测 |
| S3 | 2 | `adapter/sqlite` + `logstore` | 旧库迁移行数一致；分表轮转实测 |
| S4 | 2 | `app` + `transport` | 45 个接口契约测试 |
| S5 | 1 | `backup` + `platform` + 装配 | 远端备份校验 + 能力探测 |
| S6 | 2 | 全量回归 + 双跑对比 + 切换 | 403 条验收用例两遍 diff 为空 |
| **合计** | **12** | | |

---

## 10. 技术假设的验证状态

方案里有几处「理论上可行但没实证」的地方，开工前必须验证。**当前状态（2026-10-30，全部真机实测完毕）：3 项已通过、1 项已定位缺陷并验证修法、1 项不再需要。P0 阶段结束。**

| # | 假设 | 状态 | 结论 |
|---|---|---|---|
| 假设 1 | 双表 `jump` 切换零丢包 | ✅ **通过** | 60 次翻转 / 0 异常 / `jump` 恒为 1 / 客户端 300s 零 reset（104.79 MB/s）；见 `docs/poc-result.md` §6.3 |
| 假设 2 | 按源 tc 分类可行 | ✅ **通过** | 下载精确到 0.08%；上传经 `match ip src` 修正后 8.0954 MB/s（+1.19%）；完整结构 7.7595（−3.01%） |
| 假设 3 | `ct mark` 跨链可读 + 可位运算 | ✅ **通过** | 两条 counter 字节数完全相等（196,451 / 196,451） |
| 假设 4 | eBPF `clsact` 替代 tc 分类器 | **不再需要** | 假设 2 已打通，降级为「将来某环境 `u32` 失效时」的备选 |
| 假设 5（新增） | 带宽包总额是硬上限 | ❌ **被证伪** | 实为 `max(parent.rate, Σ子类rate)`；产品语义按 **ADR-15** 改为「约束式」 |

> **假设 1 的适用范围**：本 PoC 证明的是 `jump` **原子替换**零空窗。`CommitShadow` 在「影子链装配失败 / 自检失败」时旧链仍在服务这条保护，**未在本 PoC 覆盖**（工作链只有 counter），由 S1 的失败注入测试负责。

### PoC-1 · 双表热切换的原子性（✅ 已通过）

**验证什么**：`dispatch` 链的一条 `jump` 规则被替换时，转发面是否真的零丢包。

**方法**（在 `192.168.10.170` 上做，注意它是业务机）：

```bash
nft add table inet poc_dispatch
# 注意：priority 0 与 -10 已被 inet haweb / ip filter 占用，PoC 用 10
nft add chain inet poc_dispatch dispatch '{ type filter hook forward priority 10; }'
nft add chain inet poc_dispatch w_a
nft add chain inet poc_dispatch w_b
# 只放 counter，不放 accept——放 accept 会在业务链之前终结该 hook 的遍历
nft add rule inet poc_dispatch w_a counter
nft add rule inet poc_dispatch w_b counter
nft add rule inet poc_dispatch dispatch jump w_a
```

```bash
# 终端 A：持续打流 300 秒（客户端 → 172.16.30.10:9098）
# 终端 B：每 5 秒切一次，切换必须在一个 netlink batch 里完成
cat > /tmp/poc-flip.nft <<'EOF'
delete rule inet poc_dispatch dispatch handle <旧handle>
add rule inet poc_dispatch dispatch jump w_b
EOF
nft -f /tmp/poc-flip.nft
```

**判定**：打流端零 `connection reset`；`ss -ti` 的 `retrans` 不增长；`nft -a list chain inet poc_dispatch dispatch` 全程只有 1 条 jump。

**注意**：`inet haweb` 占用 `forward priority filter - 10`（-10），`ip filter` 占用 `filter`（0）。PoC 用 **priority 10**。★ **不要在工作链里放 `accept`**——本机 forward 上还有业务链，PoC 链返回 `accept` 会在业务链之前终结遍历，等于绕过业务的按源放行/拒绝。只放 `counter`，落后到链尾 `policy accept`，对数据面等价于「什么都不做」。

**实测结果（2026-10-30，`docs/poc-result.md` §6.3）**：

```
翻转次数=60  异常=0  jump 最大条数=1
客户端：DONE bytes=32964345856 elapsed=300.0s rate=104.7902 MB/s exceptions=0
w_a: packets=704457  bytes=11073995996
w_b: packets=710846  bytes=11192501356
nft 错误日志：(空)
```

两工作链各承载约 11GB 且量级相近（差 0.9%）—— 若切换未真正生效，流量会一直落在同一条链上，另一条应接近 0。**这条是排除「假通过」的关键证据。**

**过程中踩到的坑（复现时必须注意）**：① 打流端必须在客户端；在网关本机打流走 OUTPUT 不进 FORWARD（counter 只有 2 包）。② 必须在打流后**先自检 counter > 0** 再开始翻转，否则「切换 0 异常」会被误读成「原子性成立」。

**失败预案**：若 batch 中途确有极短窗口，退化为「先加新 jump 再删旧 jump」（两条规则同时存在，流量命中第一条，仍无空窗，只多一条规则）。

**收尾**：`nft delete table inet poc_dispatch`。

### PoC-2 · 按源 tc 分类（已通过，附带一个已定位的缺陷）

**原计划验 eBPF**，因为当时判定 `u32` / `fw` / `flower` 三类分类器全部失效。**这个判断是错的**，依据是 commit `58c60fa` / `ee56a3b` 的自我归因，不是直接证据。

**实测（`192.168.10.170`：KVM + `virtio_net` + Linux 6.8.0-147 + iproute2-6.1.0）**

| 方向 | 配置 | 实测 | 误差 |
|---|---|---|---|
| 下载（`u32 match ip dst`） | 8 MB/s | **8.006507 MB/s** | **0.08%** |
| 上传（原代码 `u32 match ip dst`） | 8 MB/s | **118.51 MB/s** | **+1,380%**（14.8 倍） |
| 上传（改成 `u32 match ip src`） | 8 MB/s | **8.09 MB/s** | **1.1%** |

上传方向的失效机制：包经 `mirred` 进 `ifb` 后 `daddr` 是公网服务器、`saddr` 才是客户端，`match ip dst <客户端>` 永不命中 → 全部走 `direct queue` → 绕过整棵 HTB 树 → 静默无报错。详见 §3.5.1 结论③。

**结论**：per-src 分类与每源保底**可以做**，不需要 eBPF。剩下的活是：修那一行字段、`pref` 按源分段、`burst` 随速率缩放。

**三项补验已全部完成**（见 §3.5.8 与 `docs/poc-result.md`）：
- 按正确结构重建整棵树后上传：**7.7595 MB/s**（−3.01%），`direct` 增量 0 ✅
- 双源并发合计：**8.0954 / 7.7595** 对总额 8 ✅（但见下条）
- `MinKBps` 不等保底按 `rate` 比例分配：**1.3162 : 2.5579 = 1 : 1.943**（配置 1:2）✅

> ⚠️ 补验中发现**新问题**：当 `Σ子类rate > 总额` 时，合计按 `Σrate` 走，**突破总额**（15 组扫描，最大 +187.6%）。`parent.rate` 是「保底总池」不是上限。详见 §3.5.7 订正与 **ADR-15**。

### PoC-3 · `ct mark` 跨链可见性（已通过）

**验证什么**：conntrack 的 mark 在 `prerouting` 写入后，能否在 `postrouting` 读到**并做位运算**。实际方案要在 SNAT 链用 `ct mark and 0xff00` 提取 `rule_id`，所以只验「能读到」不够。

**方法**（用独立 filter 链，不要直接用 nat 链——同一 hook+priority 只允许一条链注册；且 `prerouting priority -150` 在 `192.168.10.170` 上已被 `inet haweb` 占用，PoC 必须用 `-160`）：

```bash
nft add table inet poc_ct
nft add chain inet poc_ct pre  '{ type filter hook prerouting  priority -160; }'
nft add chain inet poc_ct post '{ type filter hook postrouting priority 100; }'

# 写侧：0x1200 模拟 rule_id=0x12 左移 8 位。必须带 counter，
# 否则「规则没执行」会被误判成「跨链不可见」
nft add rule inet poc_ct pre counter ct mark set 0x1200

# 读侧测两件事：全量相等 + 位域提取
nft add rule inet poc_ct post ct mark == 0x1200 counter
nft add rule inet poc_ct post ct mark and 0x0000ff00 == 0x00001200 counter

curl -s --max-time 3 -o /dev/null http://<可达地址>/ || true
nft -a list table inet poc_ct
```

**实测结果**

| 规则 | 命中 |
|---|---|
| `pre` `counter` | 327 包 |
| `post` `ct mark == 0x1200` | **474 包 / 196,451 字节** |
| `post` `ct mark and 0x0000ff00 == 0x00001200` | **474 包 / 196,451 字节** |

两个 counter 的**字节数完全相等** → 跨链可读**且位域提取生效**。

| pre | post① | post② | 结论 |
|---|---|---|---|
| 0 | 0 | 0 | 规则没生效，先查 hook/priority，**不是**「不可见」 |
| >0 | >0 | >0 | ✅ 本环境落这一档：可用 → 走 `ct mark`（32 位 = 1600 万规则） |
| >0 | >0 | 0 | 可读但位运算异常 → 退化为整值比较 + Go 侧解码，容量不变 |
| >0 | 0 | 0 | 真·不可见 → 退回 `meta mark` + verdict map |

**一个会导致错误结论的写法**：`ct mark set 0x1234` 配 `ct mark and 0xffff0000 == 0x12340000` 是**恒假**的（`0x1234 & 0xffff0000 = 0`）。位掩码与比较值必须对齐，否则会误判「跨链不可见」。

**收尾**：`nft delete table inet poc_ct`，测试表不许留在机器上。

---

## 11. 附：目录结构

```
cmd/haproxyweb/
└─ main.go                     装配，≤ 100 行

internal/
├─ domain/                     纯领域，零外部依赖
│  ├─ model/                   实体、值对象、枚举
│  ├─ rule/                    规则校验与聚合
│  ├─ policy/                  策略展开、优先级
│  ├─ snat/                    池分配（HRW）、粘性
│  ├─ bandwidth/               保底/共享/借用的纯计算
│  └─ session/                 会话值对象、CT 键
│
├─ compile/                    纯编译层（搬运 fw，扩展）
│  ├─ forward.go               fwd 链：白名单、回程计数
│  ├─ dnat.go                  DNAT + hairpin
│  ├─ snat.go                  SNAT + 池
│  ├─ policy.go                策略 accept/allow/drop
│  ├─ deny.go                  默认拒绝（三档作用域）+ ICMP 豁免
│  ├─ mss.go                   MSS clamping
│  └─ tc.go                    HTB/IFB 规格生成
│
├─ control/                    控制平面
│  ├─ loop.go                  单 goroutine 串行
│  ├─ compiler.go              State → Plan
│  ├─ applier.go               Plan → 内核（影子链）
│  └─ snapshot.go              快照构建与发布
│
├─ adapter/
│  ├─ nftables/                表/链/set/规则 + 双表切换
│  ├─ tcnetlink/               HTB + IFB
│  ├─ ctnl/                    conntrack 事件订阅 + 分片表
│  ├─ sqlite/                  双库 + 分表 + repository 实现
│  ├─ logstore/                ring + sqlite/file/syslog/remote
│  ├─ backup/                  sftp + s3 + local + sha256
│  └─ notify/                  webhook + smtp
│
├─ app/                        用例编排
│  ├─ ruleapp/ policyapp/ egressapp/
│  ├─ sessionapp/ settingsapp/ backupapp/ authapp/
│
├─ transport/httpapi/          gin handler（瘦），DTO 转换
│
├─ engine/                     用户态转发（搬运 tcp/udp/copy）
│
├─ platform/                   config / caps / version / crash
│
└─ auth/                       JWT + TOTP（搬运）

web/                           前端（保留 + TS 化）
deploy/                        systemd / tuning / e2e
docs/                          设计文档
```

---

## 12. 一句话总结

> 技术方案的核心是**四个类型 + 三个假设**：`Plan`（不可变的内核操作计划）、`Snapshot`（无锁读的运行时状态）、`Compiler`（纯函数编译）、`Applier`（影子链原子切换）；三个假设是双表切换的原子性（待验）、`ct mark` 的跨链可见性（**已通过**）、按源 tc 分类可行性（**已通过**，`u32` 可用，eBPF 降级为备选）——**待验项验完再决定是否按这套走**。
>
> 最大的架构收益来自两处：**双表热切换**让「配置生效」从「有 10~100ms 空窗且失败即全丢」变成「零空窗、失败自动保留旧版」；**`ct mark` 替代 mark 位**让规则容量从 16 条源变成 1600 万条，这是产品能长大的前提。
