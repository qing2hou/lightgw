# 隔离环境（netns）验证报告

**日期**: 2026-11-01
**环境**: `192.168.10.170` 上的独立 netns（`haweb-test`）
**目的**: 在**不碰业务表**的前提下验证限速结构的两个核心结论

---

## 为什么要用 netns

本机（WSL2）的 `CapEff = 0`，无法做任何内核面验证：

```
id -u        → 1000
CapEff       → 0000000000000000
ip netns add → Permission denied
nft add table → Operation not permitted
```

而 `.170` 是生产机。事故教训（`docs/incident-2026-10-30-orphan-reconcile.md`）
明确：**绝不在生产机上用测试配置启动完整服务**。

netns 是唯一安全的中间路径：同一个内核，但**网络栈完全隔离**——
netns 内的 `inet haweb_test` 与业务的 `inet haweb` 互不可见。

### 隔离性实测

```
✓ host 看不到 netns 内的 haweb_test
✓ netns 看不到业务表 haweb
```

双向验证通过，不是「我觉得隔离了」。

---

## 验证 1 · 双表切换原子性（netns 内复验 P0）

在 netns 内建 `dispatch` 锚点 + `w_a`/`w_b` 工作链，连续翻转 10 次：

```
翻转 10 次完成；最终 jump 数=1
```

每次翻转都是单 batch（`nft -f` 一次提交「删旧 jump + 加新 jump」），
jump 条数全程恒为 1。

**与 P0 结论一致**：`dispatch` 的 jump 替换是原子的。

---

## 验证 2 · 限速结构（这是本轮最重要的数据）

### 实验设计（前三版都错了，这里记录为什么）

| 版本 | 错误 | 症状 |
|---|---|---|
| v1 | 在 netns 内核侧 `$V1` 建 htb | 流量方向是 host→netns，`$V1` 的 root 管的是反方向 |
| v2 | 改到 host 侧 `$V0` | 但收发两端都在 `ip netns exec` 里 → 走 `lo`，从未碰 veth（2280 MB/s = loopback 速度） |
| v3 | **接收在 netns、发送在 host** | ✅ 正确：流量必然穿过 `$V0` 的 egress |

判据：如果 qdisc 计数为 0 而速率又很高，说明流量根本没走这棵树。
v1/v2 都是这个症状 —— **三个互相矛盾的数（速率、子类 Sent、direct）必须一起看**，
只看速率会得出完全错误的结论。

### 三组对照（配置 2 MB/s）

| 组 | 结构 | 实测 | 误差 | `1:199` Sent | `direct` 增量 |
|---|---|---|---|---|---|
| 1 | 无 qdisc（链路天花板） | **2103.3087 MB/s** | — | — | — |
| 2 | `default` → **叶子兜底类 `1:199`** | **1.9900 MB/s** | **−0.50%** | 10,964,008 B | **0** |
| 3 | `default` → **内层 `1:100`**（下面挂子类，无 qdisc） | **2061.7754 MB/s** | **+1031 倍** | 0 | **+238,841** |

### 结论

**① 正确结构精确生效**

组 2：配置 2 MB/s，实测 1.9900 MB/s（−0.50%）。
`1:199`（叶子兜底类）承载全部 10.96 MB，`1:100`（父类）同步计数，
`direct_packets_stat` 增量 **0**。

**② 错误结构静默绕过**

组 3：`default` 指向内层 `1:100`（它下面挂了子类 → 无 qdisc），
实测 **2061.78 MB/s**，是配置的 **1031 倍**。
证据链完整：
- 子类 `1:100` 与 `1:201` 的 `Sent` 都是 **0**
- `direct_packets_stat` 增加 **238,841**（与总包数同量级）
- 速率完全不受限

**这独立复现了 P0 结论 2/3**（`docs/poc-result.md` §3.2 的实验室结果），
而且是在隔离环境里 —— 与业务表无关。

---

## 现场恢复

```
--- netns ---      0
--- veth ---       0
--- nft 表 ---     table inet haweb / table ip nat / table ip filter
--- haweb 规则数 --- 8（与基线一致）
--- ifb ---        ifb-haweb
--- 服务 ---       active
--- /tmp 残留 ---  0
```

所有 netns/veth/临时脚本已删除，业务表未受影响。

---

## 一个观察（与本次验证无关，但值得记录）

`ifb-haweb` 的 MAC 从 `6a:c5:dc:1d:e0:20` 变成了 `4e:54:a7:63:a2:24`，
`eth0` 的 `direct_packets_stat` 从 7244 降到 1742 —— 说明这期间服务重启过，
ifb 设备被重建。

这印证了**上传限速仍然失效**的现状：设备重建后 `applyIngressLimit` 会重新
装上 `match ip dst`（`at 16`）的 filter，而上传包进 ifb 后 `daddr` 是公网
服务器 —— filter 永不命中，全部走 `direct`。

修复已在 `internal/adapter/tcnetlink` 实现（上传用 `MatchSrc: true`），
但**尚未部署**。
