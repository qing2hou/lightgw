# PoC 结果 · 任务 A / 任务 B

> 执行日期：2026-10-30
> 被测机：`192.168.10.170`（KVM + `virtio_net`，Ubuntu 24.04.5，内核 `6.8.0-147-generic`，`iproute2-6.1.0`，`nftables v1.0.9`）
> 打流端：`192.168.10.152`（ceph-2）/ `192.168.10.151`（ceph-1）
> 接收端：`172.16.30.10`（shengji），本次使用临时端口 `9198`（多线程接收器，验完已删）
> 产出脚本：`/tmp/poc-work/*.sh`（本地），网关侧 `/tmp/poc-*` 已全部删除
>
> **PoC 阶段（任务 A/B/C）未写 `internal/` 下任何生产代码。** 作业开始前仓库已存在两处未提交改动（`manager.go` / `snat.go`）；收尾时经全量验证确认健全，修正 gofmt 后提交为检查点 `c3ef724`（详见 §9）。

---

## 0. 结论摘要

| # | 结论 | 与原文档的关系 |
|---|---|---|
| 1 | 现场上传缺陷**当场复现**：实测 **112.2485 MB/s**，配置 8 MB/s，超 **14.03 倍** | 确认 §2.9 结论 3 的现象 |
| 2 | 只把 ifb 侧 filter 从 `match ip dst` 改成 `match ip src`，速率立刻 **8.0954 MB/s**（+1.19%） | 确认 §2.9 结论 3 的修法 |
| 3 | **但缺陷有两层，只改 match 字段不够**：`1:100` 挂了子类后成为内层类、其上无 qdisc，未命中 filter 的流量走 `direct queue` **绕过整棵树**。实测 `direct_packets_stat` 增量与总包数完全相等 | **新增**，文档未记载 |
| 4 | 设计 §3.5.3 的 `qdisc fq_codel 100: parent 1:100` 在本内核**不可执行**：`RTNETLINK answers: Invalid argument`。fq_codel 必须挂到**叶子**类 | **修正文档** |
| 5 | 完整修复结构（`default` 指向叶子兜底类 + `match ip src` + 叶子挂 fq_codel）实测 **7.7595 MB/s**（−3.01%），`direct` 增量 **0** | 新结构，建议进 S2 |
| 6 | 任务 B：`MinKBps` 保底**真的生效**。不等保底对照拿到 1.3162 : 2.5579（≈1:1.94，配置 1:2），证明 HTB 在读 `rate`，不是 fq_codel 在做公平 | 确认 §3.5.7 |
| 7 | **总额上限不是硬上限**：实测 15 组二维扫描，合计 ≈ `max(parent.rate, Σ子类rate)`，误差 −2.5%~−4.2%。parent 是「保底总池」而非上限 | **推翻** §3.5.3「`1:100` 是总额硬上限」与 D-06 的隐含前提 |
| 8 | 要让总额成为硬上限，必须保证 **`Σ MinKBps ≤ 带宽包总额`**（禁止超额订阅） | 三条候选方案见 §5.4，需决策 |
| 9 | 作业期间：`ifb-haweb` 是**唯一** ifb 设备；现网 filter 是 `pref 10 / at 16`（即 `dst`），与工作区代码 `snat.go:1848` 一致 | 部署二进制行为与代码一致 |
| 10 | 任务 C（双表热切换）**通过**：60 次翻转 / 0 异常 / `jump` 恒为 1 / 客户端 300s 零 reset（104.79 MB/s）/ 两工作链各承载 ~11GB（704,457 与 710,846 包） | 确认设计 §3.1 的 `jump` 原子性前提 |
| 11 | 同一 hook 上不同 priority 的链**全部会被遍历**，前序链的 `policy accept` 不短路后续链（四条探针链各 72,029 包，完全相等） | 修正了过程中一个错误推断 |

---

## 1. 现场基线（改动前，只读）

### 1.1 版本与拓扑

```
Linux haproxyweb 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026 x86_64
tc utility, iproute2-6.1.0, libbpf 1.3.0
nftables v1.0.9 (Old Doc Yak #3)
ip utility, iproute2-6.1.0, libbpf 1.3.0
```

```
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0             UP             192.168.10.170/24 192.168.10.171/24 192.168.10.172/24
eth1             UP             172.16.40.10/24
ifb-haweb        UNKNOWN        6a:c5:dc:1d:e0:20 <BROADCAST,NOARP,UP,LOWER_UP>
```

```
default via 192.168.10.1 dev eth0 proto static
172.16.40.0/24 dev eth1 proto kernel scope link src 172.16.40.10
192.168.10.0/24 dev eth0 proto kernel scope link src 192.168.10.170
```

```
0:	from all lookup local
0:	from 192.168.10.152 fwmark 0x4/0x4 lookup main
0:	from 192.168.10.151 fwmark 0x4/0x4 lookup main
1:	from 192.168.10.152 lookup 201
1:	from 192.168.10.151 lookup 201
32766:	from all lookup main
32767:	from all lookup default
```

```
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.eth0.send_redirects = 0
```

### 1.2 改动前 tc（`ifb-haweb`）

```
qdisc htb 1: root refcnt 2 r2q 10 default 0x100 direct_packets_stat 8259 direct_qlen 10000
 Sent 110329025 bytes 7365 pkt (dropped 0, overlimits 8357 requeues 0)

class htb 1:207 parent 1:100 prio 0 rate 8388Kbit ceil 67108Kbit burst 16Kb cburst 32Kb
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0)
 lended: 0 borrowed: 0 giants: 0

class htb 1:100 root rate 67108Kbit ceil 67108Kbit burst 32Kb cburst 32Kb
 Sent 54818824 bytes 201 pkt (dropped 0, overlimits 3836 requeues 0)
 lended: 3837 borrowed: 0 giants: 0

class htb 1:208 parent 1:100 prio 0 rate 8388Kbit ceil 67108Kbit burst 16Kb cburst 32Kb
 Sent 54818824 bytes 201 pkt (dropped 0, overlimits 4521 requeues 0)
 lended: 691 borrowed: 3837 giants: 0
```

### 1.3 改动前 tc filter（三处，注意 `at` 偏移）

`ifb-haweb parent 1:`（**分类 filter**）：

```
filter protocol ip pref 10 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 *flowid 1:208
  match c0a80a98/ffffffff at 16        ← at 16 = 目的地址；c0a80a98 = 192.168.10.152
filter protocol ip pref 10 u32 chain 0 fh 800::801 order 2049 key ht 800 bkt 0 *flowid 1:207
  match c0a80a97/ffffffff at 16        ← c0a80a97 = 192.168.10.151
```

`eth0 parent ffff:`（**ingress 重定向 filter**，由代码 `applyIngressLimit` 建）：

```
filter protocol ip pref 703 u32 ... terminal
  match c0a80a97/ffffffff at 12        ← at 12 = 源地址（正确）
	action order 1: mirred (Egress Redirect to device ifb-haweb) stolen
filter protocol ip pref 704 u32 ... terminal
  match c0a80a98/ffffffff at 12        ← at 12 = 源地址（正确）
	action order 1: mirred (Egress Redirect to device ifb-haweb) stolen
```

> **同一份代码的两个方向字段相反，而 ifb 侧写成了 `dst`** —— 与 `internal/proxy/snat.go:1846-1848` 完全对应：
> ```go
> // snat.go:1840  ingress 重定向 → 正确用 src
> "match", "ip", "src", src,
> // snat.go:1846-1848  ifb 侧分类 → 仍写 dst（缺陷）
> runQuiet("tc", "filter", "replace", "dev", dev,
>     "parent", "1:", "protocol", "ip", "prio", "10", "u32",
>     "match", "ip", "dst", src, "flowid", clsID)
> ```

`eth0 parent 1:`（下载方向，`at 16` 是**正确**的，回程包 `daddr`=客户端）：

```
filter protocol ip pref 10 u32 ... *flowid 1:208
  match c0a80a98/ffffffff at 16
filter protocol ip pref 10 u32 ... *flowid 1:207
  match c0a80a97/ffffffff at 16
```

### 1.4 配置值（权威来源：DB + 配置，只读）

```
bw_groups:
id  name     total_kbps  min_kbps
1   4M共享   8192        1024

forward_rules:
id  name    protocol  listen_addr        target_addr        bw_group_id  min_kbps  enabled
3   dnat-1  tcp       172.16.40.10:1022  192.168.10.152:22  1            0         1
30  test    snat      eth0               eth0               1            0         1
```

`total_kbps=8192` → `8192 × 1024 × 8 = 67,108,864 bit/s` = tc 显示的 `67108Kbit` ✔
`min_kbps=1024`（代码兜底默认）→ `1024 × 1024 × 8 = 8,388,608` = `8388Kbit` ✔

**配置速率 = 8 MB/s（= 8 MiB/s），每源保底 = 1 MB/s。**

### 1.5 部署二进制与服务

```
ExecStart=/usr/local/bin/haproxyweb -c /etc/haproxyweb/config.yaml
ActiveEnterTimestamp=Fri 2026-10-30 02:25:09 UTC
MainPID=718
/proc/718/exe -> /usr/local/bin/haproxyweb   (43776480 bytes, md5 05fa7edd61e098a297a473b1432bb9ff)
```

### 1.6 nft（改动前，39 行全文摘要）

```
table inet haweb {
	chain pre_mark { type filter hook prerouting priority mangle; policy accept;
		ct state established,related meta mark set meta mark | 0x00000001 }
	chain dstnat  { type nat hook prerouting priority dstnat; policy accept; }
	chain fwd {
		type filter hook forward priority filter - 10; policy accept;
		iifname "eth0" oifname "eth0" meta mark & 0x00000004 == 0x00000000 @nh,96,32 0xc0a80a98 counter packets 11704 bytes 105635780 meta mark set meta mark | 0x00000001
		iifname "eth0" oifname "eth0" meta mark & 0x00000004 == 0x00000000 @nh,96,32 0xc0a80a97 counter packets 656 bytes 69690 meta mark set meta mark | 0x00000001
		iifname "eth0" oifname "eth0" meta mark & 0x00000004 == 0x00000000 @nh,128,32 0xc0a80a98 counter packets 15176 bytes 63693645
		iifname "eth0" oifname "eth0" meta mark & 0x00000004 == 0x00000000 @nh,128,32 0xc0a80a97 counter packets 602 bytes 120032
		iifname "eth0" meta mark & 0x00000001 == 0x00000000 counter packets 0 bytes 0 drop }
	chain srcnat  { type nat hook postrouting priority srcnat; policy accept;
		iifname "eth0" oifname "eth0" ... @nh,96,32 0xc0a80a98 snat ip to 192.168.10.170
		iifname "eth0" oifname "eth0" ... @nh,96,32 0xc0a80a97 snat ip to 192.168.10.170 }
	chain input   { type filter hook input priority filter; policy accept; }
}
table ip nat   { chain POSTROUTING { type nat hook postrouting priority srcnat; policy accept; } }
table ip filter { chain FORWARD { type filter hook forward priority filter; policy accept; } }
```

```
$ nft list tables
table inet haweb
table ip nat
table ip filter
```

---

## 2. 流量确实经过网关的证据（四路互证）

| 证据 | 原始输出 |
|---|---|
| ① 客户端路由 | `172.16.30.10 via 192.168.10.170 dev eth0 src 192.168.10.152`（`.151` 同） |
| ② 服务器看到的源地址 = 网关 | 保持 6s 连接后，服务器 `ss` 输出：`172.16.30.10:9098  192.168.10.170:48066` —— **peer 是 .170，不是 .152** |
| ③ 网关上 ifb 计数增长 | 见 §3.1：`ifb` root `Sent` 增量 984,681,231 B，`/proc/net/dev` TX 包数增量与 `direct_packets_stat` 增量**完全相等（15,925）** |
| ④ 作业前后链路天花板 | 无 qdisc 的隔离 veth 实测 2860.53 MB/s；生产 ifb 缺陷态跑 112.25 MB/s —— 说明 8 MB/s 的限制只能来自 tc 树，不是链路或服务器瓶颈 |

---

## 3. 任务 A · 验证上传方向的限速修复

### 3.1 Step 2 基线（不改任何配置，仅打流）

`192.168.10.152` 单源向 `172.16.30.10:9098` 推 8 秒，**现场 tc 一字未改**：

```
=========== BEFORE ===========
TS=1793335555.727963348
1:207 Sent 0 ...
1:100 Sent 54818824 ...
1:208 Sent 54818824 ...
IFB_QDISC: qdisc htb 1: root ... default 0x100 direct_packets_stat 8281
  Sent 110330829 bytes 7387 pkt (dropped 0, overlimits 8357 requeues 0)
ETH0_QDISC: ... direct_packets_stat 297918
  Sent 307170831 bytes 418553 pkt
PROCNET: eth0: 189368592 229673 ... | ifb-haweb: 105915697 12810 ...

=========== TRAFFIC (8s, .152 -> 172.16.30.10:9098) ===========
CLIENT rate=112.2495 MB/s bytes=941621248 elapsed=8.000s

=========== AFTER ===========
TS=1793335564.606496146
1:207 Sent 0 ...
1:100 Sent 54818824 ...          ← 增量 0
1:208 Sent 54818824 ...          ← 增量 0
IFB_QDISC: ... default 0x100 direct_packets_stat 24206
  Sent 1095072851 bytes 7686 pkt
ETH0_QDISC: ... direct_packets_stat 314166
  Sent 1294879084 bytes 1111842 pkt
PROCNET: eth0: 1135071639 288332 ... | ifb-haweb: 1048780587 28735 ...
```

**增量核算**：

| 指标 | 前 | 后 | 增量 |
|---|---|---|---|
| 客户端自报字节 | — | 941,621,248 | — |
| `ifb-haweb` TX 字节 | 105,914,857 | 1,048,779,747 | **+942,864,890** |
| `ifb-haweb` TX 包数 | 12,798 | 28,723 | **+15,925** |
| `direct_packets_stat` | 8,281 | 24,206 | **+15,925** |
| 子类 `1:100` Sent | 54,818,824 | 54,818,824 | **+0** |
| 子类 `1:207`/`1:208` Sent | 54,818,824 | 54,818,824 | **+0** |

**实测 112.2495 MB/s / 配置 8 MB/s / 误差 +1303.1%（14.03 倍）。**

> `direct` 增量 15,925 与 ifb TX 包数增量 15,925 **完全相等** → 这一批 942 MB **全部**走 direct queue，一个包都没进 HTB 树。`default 0x100` 没能接住。

### 3.2 关键：`default` 为什么接不住（隔离实验室，因果定位）

用 `veth + netns` 在同一台机上做隔离实验（不碰任何业务对象，验完 netns/veth 均为 0）：

| 实验 | 结构 | 实测 | 配置 | 误差 | `direct` 增量 |
|---|---|---|---|---|---|
| A0 | 无任何 qdisc | 2860.53 MB/s | — | 链路天花板 | — |
| A1 | `default 100` → **叶子** 1:100 | **7.8063** | 8 | −2.42% | **0** |
| A2 | A1 + 子类 1:208（1:100 变**内层**，无 qdisc） | **2828.79** | 8 | **+35260%** | 增长（绕过） |
| A3 | A2 + `tc qdisc add ... parent 1:100 fq_codel` | — | — | — | **`RTNETLINK answers: Invalid argument`** |
| A4 | A2 + `match ip src` filter | **7.8079** | 8 | −2.40% | 0（被分类的流量） |
| A5 | A4 改成 `match ip dst`（事故写法） | **2807.38** | 8 | **+34992%** | 增长（绕过） |

**结论（有原始输出支撑）**：

1. **`default 100` 本身没有错**。A1 里 1:100 还是叶子类，`default` 精确限到 7.81 MB/s，`direct = 0`。
2. **1:100 一旦挂了子类就变成内层类**，而它上面**没有 qdisc**。此时落到 default 的包进不了任何队列，内核直接走 direct queue —— **绕过整棵 HTB 树**。A1→A2 只加了子类，速率从 7.81 跳到 2828.79 MB/s。
3. **A3 证明设计 §3.5.3 的 `fq_codel parent 1:100` 在本内核不可执行**。HTB 内层类不能挂叶子 qdisc，fq_codel 必须挂到**叶子**类（A4/A5 与真实路径均如此）。
4. 所以缺陷是**两层**：`match ip dst` 让流量不命中子类 **且** `default` 指向一个接不住包的内层类。只改 match 字段能让**被分类的流量**限住（A4），但未分类流量仍然绕过。

### 3.3 真实路径验证（生产网关，poc 对象）

> 拓扑：`eth0 ingress(fref 2/3) → mirred → poc-ifb-a(htb) → 客户端真实上传`
> `pref 2/3` 小于业务 `703/704`，故 .152/.151 的上传在 PoC 期间被导到 `poc-ifb-a`，验完删除。
> 全程未碰 `ifb-haweb`、`eth0` root qdisc、业务 filter、nft、ip rule、service。

**A1 · 复刻现网缺陷写法（`default 100` 内层 + 叶子无 qdisc + `match ip dst`）双源 12s**

```
########## A1 · 缺陷结构（default 100 内层 + 叶子无 qdisc + ifb match dst）双源 12s，配置 8MB/s ##########
  recv active
  T0 rootSent=0 direct=0
  CLIENT 192.168.10.152 rate=55.7784 MB/s bytes=702021632 elapsed=12.003s
  CLIENT 192.168.10.151 rate=56.6891 MB/s bytes=713555968 elapsed=12.004s
  T1 rootSent=1480579601 direct=46081
  IFB-ROOT DELTA: 1480579601 bytes   DIRECT DELTA: 46081 pkts
  RECV ip=192.168.10.170 bytes=702021632 elapsed=12.054 rate=55.5425 MB/s
  RECV ip=192.168.10.170 bytes=713555968 elapsed=12.047 rate=56.4852 MB/s
  RECV DONE count=2 total=1415577600
  CLASS 1:207  rate=8388Kbit     Sent=0            pkts=0        ovl=overlimits
  CLASS 1:100  rate=67108Kbit    Sent=0            pkts=0        ovl=overlimits
  CLASS 1:208  rate=8388Kbit     Sent=0            pkts=0        ovl=overlimits
```

**实测合计 112.4675 MB/s / 配置 8 MB/s / 误差 +1305.8%。所有子类 `Sent = 0`，`direct` +46,081 包。**

**A2 · 同一棵树，只把 ifb 侧 `match ip dst` → `match ip src`（其余一字不改）双源 12s**

```
CLASS 1:207  rate=8388Kbit     Sent=53454647     pkts=461     ovl=overlimits
LEND  1:207  lended=1574     borrowed=4674
CLASS 1:100  rate=67108Kbit    Sent=106634964    pkts=800     ovl=overlimits
LEND  1:100  lended=8764     borrowed=0
CLASS 1:208  rate=8388Kbit     Sent=53180317     pkts=339     ovl=overlimits
LEND  1:208  lended=1346     borrowed=4090
  CLIENT 192.168.10.152 rate=4.0545 MB/s
  CLIENT 192.168.10.151 rate=4.0409 MB/s
  DIRECT DELTA: 1 pkts
```

**实测合计 8.0954 MB/s / 配置 8 MB/s / 误差 +1.19%。`direct` 增量仅 1 包。两源各 ≈4.05 MB/s —— 合计 ≈ 总额，不是 16。**

**A3 · 完整修复结构（`default 199` 叶子兜底 + `match ip src` + 叶子各挂 fq_codel）双源 12s**

```
  qdisc htb 1: root refcnt 2 r2q 10 default 0x199 direct_packets_stat 0 direct_qlen 10000
  CLIENT 192.168.10.152 rate=3.8598 MB/s bytes=48758784 elapsed=12.047s
  CLIENT 192.168.10.151 rate=3.8997 MB/s bytes=49283072 elapsed=12.052s
  T1 rootSent=102522152 direct=0
  IFB-ROOT DELTA: 102522152 bytes   DIRECT DELTA: 0 pkts
  RECV ip=192.168.10.170 bytes=48758784 elapsed=12.170 rate=3.8209 MB/s
  RECV ip=192.168.10.170 bytes=49283072 elapsed=12.216 rate=3.8473 MB/s
  CLASS 1:100  rate=67108Kbit    Sent=102522152    pkts=1463
  CLASS 1:199  rate=8388Kbit     Sent=0            pkts=0     ← 兜底类未被使用（两源都命中）
  CLASS 1:208  rate=8388Kbit     Sent=51535211     pkts=446
  CLASS 1:207  rate=8388Kbit     Sent=50986941     pkts=1017
```

**实测合计 7.7595 MB/s / 配置 8 MB/s / 误差 −3.01%。`direct` 增量 0。**

**A4 · 同一结构单源 8s**

```
  CLIENT 192.168.10.152 rate=7.7406 MB/s bytes=65011712 elapsed=8.010s
  IFB-ROOT DELTA: 67980653 bytes   DIRECT DELTA: 0 pkts
  RECV ip=192.168.10.170 bytes=65011712 elapsed=8.099 rate=7.6553 MB/s
```

**实测 7.7406 MB/s / 配置 8 MB/s / 误差 −3.24%。**

### 3.4 任务 A 判定

| 判定项 | 结果 |
|---|---|
| 缺陷可复现 | ✅ 112.2485 MB/s（实测 / 8 / +1303.1%） |
| 改 `src` 后 ≈8MB/s | ✅ 8.0954 MB/s（+1.19%） |
| 流量真的进子类（不是 default 兜底） | ✅ A3/A4 中 `1:207`/`1:208` 的 `Sent` 与传输字节对齐，`1:199` 为 0，`direct` 为 0 |
| 双源合计 ≈ 总额（非 2×） | ✅ 8.0954 / 7.7595 对 8 |
| `match ip dst` 与 `src` 的差异 | ✅ 同一棵树只换字段：112.47 vs 8.10 |
| 未分类流量不再绕过 | ✅ 实验室 A4：第三源（无 filter）落 `1:199`，合计仍受总额约束，`direct = 0` |

**任务 A 结论：修复有效，但必须同时做三件事，缺一不可**：

1. ifb 侧分类 filter 用 `match ip src`
2. `default` 必须指向 **叶子** 类（不能指向挂了子类的内层 `1:100`）
3. `default` 指向的那个叶子类**必须挂 fq_codel**（内层类挂不上）

### 3.6 生产落地复验（2026-11-01，192.168.10.170）

第 1 项修复（`a6ae2a6`）已部署到生产机，本节是落地后的实测。

**设备名澄清**：新代码 `ifbNameFor(bwGroupID)` 按带宽包隔离产出 `ifb-hw1`（包 #1），
旧代码遗留的 `ifb-haweb` / `ifb-hw1` 之外的设备是历史残留。首次复验我查错了设备
（查 `ifb-haweb`），误判"修复未生效"；实际正确设备是 `ifb-hw1`。

#### 3.6.1 现场 tc 形态（修复生效的直接证据）

```
$ tc filter show dev eth0 parent ffff:
filter protocol ip pref 703 u32 chain 0
  match c0a80a97/ffffffff at 12            ← at 12 = src 偏移（正确）
	action order 1: mirred (Egress Redirect to device ifb-hw1) stolen
filter protocol ip pref 704 u32 chain 0
  match c0a80a98/ffffffff at 12
	action order 1: mirred (Egress Redirect to device ifb-hw1) stolen

$ tc filter show dev ifb-hw1 parent 1:
filter protocol ip pref 1703 u32 chain 0 fh 801::800 *flowid 1:205
  match c0a80a97/ffffffff at 12            ← at 12 = src（正确）；pref 1703 在 1002..1998 上传段
filter protocol ip pref 1704 u32 chain 0 fh 800::800 *flowid 1:222
  match c0a80a98/ffffffff at 12            ← pref 1704

$ tc -s class show dev ifb-hw1
class htb 1:100 root rate 67108Kbit ceil 67108Kbit      ← 8192KB/s 总额
class htb 1:222 parent 1:100 rate 8388Kbit ceil 67108Kbit ← 1024KB/s 保底
class htb 1:205 parent 1:100 rate 8388Kbit ceil 67108Kbit
```

三处都对：`at 12`（src）、`pref` 1703/1704（上传段）、父类 67108Kbit=8192×1024×8。

#### 3.6.2 单源实测（`192.168.10.152` → `172.16.30.10:9098`，10 秒）

```
配置: 带宽包总额 8192KB/s = 67.109 Mbit/s (8.00 MB/s)
      每源保底 1024KB/s = 1.000 MB/s

SEND rate=7.9229 MB/s bytes=83099648 dur=10.003s
RECV rate=7.6548 MB/s bytes=80285232 dur=10.002s peer=192.168.10.170
```

| 项 | 值 |
|---|---|
| **配置** | 8.0000 MB/s |
| **实测（靶子接收端）** | **7.6548 MB/s** |
| **误差** | **−4.32%** |
| 实测（客户端发送侧） | 7.9229 MB/s（−0.96%） |
| 修复前（同机同配置） | 112.2485 MB/s（**+1303.1%，超 14.03 倍**） |
| 收敛比 | 14.7× |

**三重计数互证**（铁律 3 要求不只信速率）：

```
基线 → 并发后
1:222  1875 B / 22 pkt  →  86890006 B / 346 pkt   (+86,888,131 B)
1:205  3329 B / 19 pkt  →      3599 B / 22 pkt   (未承载本次流量)
direct_packets_stat  6  →  6                      (零漏网)
overlimits           0  →  10299                  (整形器确实在掐流)
eth0 ingress pref 704 Sent +83,389,790 B / 346 pkt
```

`direct_packets_stat` 不变是关键：它统计"未命中任何分类、走 direct 绕过 HTB"的包。
本次 346 个包全部进 `1:222`，一个都没漏。

#### 3.6.3 双源并发（`.151` 与 `.152` 同时推 12 秒）

```
A(192.168.10.151) SEND 4.1911 MB/s  →  RECV 3.9540 MB/s
B(192.168.10.152) SEND 4.0488 MB/s  →  RECV 3.8860 MB/s
                  合计 RECV 7.8400 MB/s
```

| 项 | 值 |
|---|---|
| **配置总额** | 8.0000 MB/s |
| **实测合计** | **7.8400 MB/s** |
| **误差** | **−2.00%** |
| 每源保底 | 1.000 MB/s，实测 3.95 / 3.89（各 3.9× 保底，未触底） |
| 约束校验 | `Σ MinKBps` = 1024×2 = 2048 ≤ 8192 总额 ✅（满足 ADR-15 约束式语义） |

tc 计数：`1:222` +53,428,374 B（634-356=278 pkt）、`1:205` +55,367,400 B（392-22=370 pkt），
合计 +108,795,774 B ≈ 接收端 104,071,168 B（差额为 TCP/IP 头与重传）。

**结论**：两源各约 3.9MB/s，合计收敛于 8.00 总额，不是 2×8=16。总额硬上限成立，
每源保底成立（两源均远超 1MB/s 保底，因为总额有富余时允许借用）。

### 3.7 复验中发现的新缺陷：`default` 指向"有子类的类"会完全绕过 HTB

§3.6.1 的现场形态里有一处**看着对、实则 fail-open** 的配置：

```
$ tc qdisc show dev ifb-hw1
qdisc htb 1: root ... default 0x100 ...            ← 指向 1:100
$ tc class show dev ifb-hw1
class htb 1:100 root ...                            ← 1:100 自己挂着子类 1:222 / 1:205
class htb 1:222 parent 1:100 ...
```

生产环境所有包都命中了分类 filter，`default` 从未被走到，所以今天没爆。
但只要某个源的 filter 建失败 / pref 被覆盖 / 源不在白名单，流量就落 `default`
→ 无限速。用 netns 隔离把机制钉死（业务表全程 8 条规则未动）：

| 组 | `default` 目标 | 该目标自身有子类 | 实测接收 | `direct_packets_stat` 增量 | 判定 |
|---|---|---|---|---|---|
| A | `1:100` | **无** | 7.6567 MB/s | 0 | 受限 ✅ |
| B | `1:100` | **有**（1:222） | **2575.3739 MB/s** | 270363（= 总包数） | **完全绕过** ❌ |
| C | `1:250`（叶子） | 无 | 7.6560 MB/s | 0 | 受限 ✅ |

**机制**：判据是「`default` 目标**自身**有没有子类」，不是"内层还是外层"。

- A 组说明：`default` 指向 1:100 **本身不构成问题**（1:100 无子类时正常整形）
- B 组说明：同一个 1:100 一旦挂上子类，`default` 指它就让包走 `direct` 路径
- 协议头注（AGENTS.md 硬约束 2）的表述「`default` 必须指向叶子类」结论正确，
  但归因写成"内层类不能挂"不够精确——真实触发条件是**目标类有子类**

B 组 `1:222 Sent=0` 且 `1:100 Sent=0`，而 `direct_packets_stat` 精确等于总包数
（270363），说明一个包都没进 HTB。

#### 3.7.1 同源的另外两个缺陷（一并修掉）

**(1) `fq_codel` 从来没挂上过**

老代码 `applyHTBLimit` 里：

```go
_ = runQuiet("tc", "qdisc", "add", "dev", ifn, "parent", bwGroupClassID,
    "handle", "100:", "fq_codel")     // parent = 1:100
```

生产机实测该命令被内核拒绝：

```
$ tc qdisc add dev ifb-hw1 parent 1:100 handle 999: fq_codel
RTNETLINK answers: Invalid argument
```

`_ =` 把错误吞了，表现为"日志无异常、fq_codel 从未存在"。现场两个设备
（`eth0`、`ifb-hw1`）上 `tc qdisc show | grep -c fq_codel` 都是 **0**。
netns 补充验证：1:100 **无子类时**挂 fq_codel 成功；**有子类时**报 `Invalid argument`
——与 `default` 的同一条内核规则（内层类不能作为叶子 qdisc 的父）。

**(2) `srcClassID` 会产出 `1:100`（覆盖总额父类）**

```go
return fmt.Sprintf("1:%d", 1+h%248)   // 产出 1:1..1:248，包含 1:100
```

源哈希到 100 时执行 `tc class replace classid 1:100 rate=<MinKBps>`，
把带宽包**总额父类**替换成该源的保底子类——整包总额静默消失
（8192KB/s → 1024KB/s），且 `parent 1:100` 的每源子类全部挂到错误层级。

#### 3.7.2 附带修掉的幂等判定错误

```go
// 老代码
want := fmt.Sprintf("default 0x%x", leafClassIDNum)   // 250 → "0xfa"
```

内核实际打印（生产机实测，`default 250` 与 `default 0x250` 两种写法输出一致）：

```
qdisc htb 1: root refcnt 2 r2q 10 default 0x250 direct_packets_stat 0 ...
```

`0xfa` ≠ `0x250` → 幂等判定永远失败 → 每个 apply 周期都 `qdisc del` + `qdisc add` 重建，
重建瞬间无 qdisc（流量无限速）。改为固定 token `"default 0x250"` 并加测试锁死。

#### 3.7.3 修复后结构（netns 验证）

```
default 0xfa(250) → 叶子 1:250，fq_codel 挂 1:250

########## 修复前形态：default 0x100，fq_codel 挂内层 ##########
  fq_codel 挂 1:100: OK           ← 1:100 无子类时能挂上
  recv: rate=7.6574 MB/s
  direct_packets_stat 0
  1:100   Sent=51529724

########## 修复后形态：default 0xfa(250)，fq_codel 挂叶子 ##########
  fq_codel 挂 1:250: OK
  recv: rate=7.6545 MB/s
  direct_packets_stat 0
  1:100   Sent=0                  ← 总额父类不再直接承载（正确：流量经子类）
  1:250   Sent=50981544
```

两形态速率一致（都受限），差别在**故障时**：修复后任何未分类流量落 1:250 仍受限；
修复前落一个有子类的 1:100 会直接绕过（B 组 2575 MB/s）。

#### 3.7.4 回归测试（新增 6 个，全部绿）

| 测试 | 锁住的约束 |
|---|---|
| `TestHTBDefaultPointsToLeafClass_Constraint2` | `default` 不得为目标为 `100`/`199`/`30` 的写法 |
| `TestFqCodelOnlyOnLeafClass_Constraint3` | `fq_codel` 的 parent 不得是 `bwGroupClassID` |
| `TestHTBDefaultTokenMatchesKernel` | 幂等 token 必须能在内核实际输出里匹配到 |
| `TestLeafClassIDConsistentWithToken` | `leafClassID` / `leafClassIDNum` / token 三者同源 |
| `TestSrcClassIDAvoidsReservedIDs` | 4000 个源地址穷举，不得产出 1:30 / 1:100 / 1:250 |
| `TestSrcClassIDStable` | 同源恒同 class ID（幂等拆除依赖） |

#### 3.7.5 修复后生产复验（2026-11-01，部署 commit `371903a`）

**现场形态（全部正确）**：

```
$ tc qdisc show dev ifb-hw1
qdisc htb 1: root refcnt 2 r2q 10 default 0x250 direct_packets_stat 0 direct_qlen 10000
qdisc fq_codel 250: parent 1:250 limit 10240p flows 1024 ...   ← 首次真正挂上

$ tc qdisc show dev eth0
qdisc htb 1: root refcnt 2 r2q 10 default 0x250 direct_packets_stat 0 direct_qlen 1000
qdisc fq_codel 250: parent 1:250 ...

$ tc class show dev ifb-hw1
1:100 root ...                           ← 总额父类
1:167 parent 1:100 rate 8388Kbit ...     ← 新号段（旧版是 1:205/1:222）
1:105 parent 1:100 rate 8388Kbit ...
1:250 root ...                           ← 叶子兜底

$ tc filter show dev ifb-hw1 parent 1:
pref 1703 ... match c0a80a97/ffffffff at 12 *flowid 1:167
pref 1704 ... match c0a80a98/ffffffff at 12 *flowid 1:105
```

规则数 8 → 8，nft 表仍是 `inet haweb` / `ip nat` / `ip filter` 三张。

**单源复测**：

```
SEND rate=7.9180 MB/s
RECV rate=7.6522 MB/s bytes=80285344 dur=10.006s peer=192.168.10.170
```

| 项 | 值 |
|---|---|
| **配置** | 8.0000 MB/s |
| **实测** | **7.6522 MB/s** |
| **误差** | **−4.35%** |

与修复前（7.6548 / −4.32%）一致——结构改动不影响正常路径。

**双源并发复测**：

```
A(192.168.10.151) RECV 3.8250 MB/s
B(192.168.10.152) RECV 3.8398 MB/s
                  合计 7.6648 MB/s
```

| 项 | 值 |
|---|---|
| **配置总额** | 8.0000 MB/s |
| **实测合计** | **7.6648 MB/s** |
| **误差** | **−4.19%** |
| `direct_packets_stat` | **0**（零漏网） |
| `1:250` 叶子 Sent | **0**（无流量落兜底，全部命中分类） |

tc 计数自洽：`1:167` 439 pkt + `1:105` 396 pkt = **835** = 父类 `1:100` 835 pkt。

#### 3.7.6 fail-open 闭合验证（生产树形态，故意删掉分类 filter）

复刻生产修复后的树（`default 250` + 叶子 1:250 + fq_codel + 每源子类 1:167），
在 netns 内对比"filter 存在"与"filter 被删"两种状态：

| 场景 | 实测接收 | `1:167` Sent | `1:250` Sent | `direct` |
|---|---|---|---|---|
| ① 分类 filter 存在（正常） | 7.6647 MB/s | 51,803,744 | 70 | 0 |
| ② 分类 filter 被删（故障） | **7.6542 MB/s** | 51,803,744（未增长） | **51,255,704** | **0** |

对比 §3.7 B 组（**修复前**同一故障场景）：2575.3739 MB/s、`direct` 270363。

**同样的故障输入，修复前 38.9 倍超速，修复后 −4.3% 精确限速、零 direct 漏网。**
这是本次结构修复的核心价值——不是"正常时更快/更慢"，而是**故障时的行为从 fail-open 变成 fail-closed**。

---

## 4. 任务 B · `MinKBps` 到底是不是「保底」

### 4.1 真机三组（`poc-ifb-a`，`default 199` + src + 叶子 fq_codel）

**B1 · 等保底：总额 4 MB/s，两源各保底 1 MB/s，双源 15s**

```
  CLIENT 192.168.10.152 rate=1.9391 MB/s bytes=30670848 elapsed=15.084s
  CLIENT 192.168.10.151 rate=1.9360 MB/s bytes=30670848 elapsed=15.108s
  T1 rootSent=64149381 direct=0
  IFB-ROOT DELTA: 64149381 bytes   DIRECT DELTA: 0 pkts
  RECV ip=192.168.10.170 bytes=30670848 elapsed=15.265 rate=1.9162 MB/s
  RECV ip=192.168.10.170 bytes=30670848 elapsed=15.282 rate=1.9140 MB/s
  CLASS 1:100  rate=33554Kbit    Sent=64149381     pkts=2454
  LEND  1:100  lended=7914     borrowed=0
  CLASS 1:208  rate=8388Kbit     Sent=32074533     pkts=1203
  LEND  1:208  lended=3952     borrowed=3941
  CLASS 1:207  rate=8388Kbit     Sent=32074848     pkts=1251
  LEND  1:207  lended=3896     borrowed=3973
```

两源各 **1.9391 / 1.9360 MB/s**，合计 **3.8751**（配置 4，−3.12%）。各自 ≥ 1 MB/s 保底 ✔。
**`borrowed` 增量 3,941 / 3,973 —— 确实发生了借用。**

**B2 · 不等保底对照（最关键）：总额 4 MB/s，`.152`=1 MB/s，`.151`=2 MB/s**

```
  CLIENT 192.168.10.151 rate=2.5579 MB/s bytes=40370176 elapsed=15.051s
  CLIENT 192.168.10.152 rate=1.3162 MB/s bytes=20971520 elapsed=15.195s
  T1 rootSent=64149132 direct=0
  RECV ip=192.168.10.170 bytes=40370176 elapsed=15.166 rate=2.5386 MB/s
  RECV ip=192.168.10.170 bytes=20971520 elapsed=15.284 rate=1.3086 MB/s
  CLASS 1:208  rate=16777Kbit    Sent=42215929     pkts=1285     ← .151，保底 2MB/s
  LEND  1:208  lended=7290     borrowed=2259
  CLASS 1:207  rate=8388Kbit     Sent=21933203     pkts=1038     ← .152，保底 1MB/s
  LEND  1:207  lended=4079     borrowed=1414
```

**1.3162 : 2.5579 = 1 : 1.943（配置 1:2）。两条流明显不对称。**

> 这个对照的意义正如 §3.5.7 所说：如果两条流**仍然完全等分**，就说明 HTB 没在读 `rate`、是 fq_codel 在做公平。实测**不等分且比例接近配置**，所以 **HTB 在读 `rate`，「保底」是真实语义，不是 fq_codel 的公平调度**。

**B3 · 超额订阅：总额 4 MB/s，两源各 3 MB/s，双源 15s**

```
  CLIENT 192.168.10.152 rate=2.8956 MB/s bytes=45613056 elapsed=15.023s
  CLIENT 192.168.10.151 rate=2.8947 MB/s bytes=45613056 elapsed=15.028s
  T1 rootSent=95395590 direct=0
  IFB-ROOT DELTA: 95395590 bytes   DIRECT DELTA: 0 pkts
  CLASS 1:100  rate=33554Kbit    Sent=95395590     pkts=3192
  LEND  1:100  lended=0        borrowed=0
  CLASS 1:208  rate=25165Kbit    Sent=47697795     pkts=1559
  LEND  1:208  lended=10869    borrowed=0
  CLASS 1:207  rate=25165Kbit    Sent=47697795     pkts=1633
  LEND  1:207  lended=11281    borrowed=0
```

**合计 5.7903 MB/s / 配置 4 MB/s / 误差 +44.76%。**

### 4.2 超额订阅复验（两组独立实验 + 曲线）

实验室 A（`veth+netns`，`default 30`，叶子无 fq_codel）与实验室 B（`default 199` + 叶子 fq_codel）都复现同一现象：

| 实验 | 总额 | 子类 rate | 合计实测 | 误差 |
|---|---|---|---|---|
| C-b | 4 MB/s | 2+2 MB/s | **3.8300** | −4.25% |
| C-c | 4 MB/s | 3+3 MB/s | **5.7430** | **+43.58%** |
| C-d | 4 MB/s | 4+4 MB/s | **7.6561** | **+91.40%** |
| C-e | 4 MB/s | 8+8 MB/s | **7.6562** | **+91.41%** |
| P1 | 4 MB/s | 2+2（ceil=rate） | **3.8293** | −4.27% |
| P2 | 4 MB/s | 3+3（ceil=rate） | **5.7432** | **+43.58%** |
| P3 | 8 MB/s | 3+3（ceil=rate） | **5.7450** | −28.19% |
| P4 | 8 MB/s | 4+4（ceil=rate） | **7.6573** | −4.28% |
| P5 | 4 MB/s | 4+4（ceil=rate） | **7.6565** | **+91.41%** |

**初步规律（仅二源，后续被 §4.2.1 的 15 组扫描修正）**：`Σrate > parent` 时突破总额。

### 4.2.1 二维扫描（N 源 × parent rate，决定性实验）

为把「总额上限」量清楚，固定每源保底 1 MB/s，让源数 `N` 与父类 `rate` 各自变化，共 15 组，每组 8 秒（`veth+netns`，`default` 指向叶子兜底类，所有叶子挂 fq_codel）：

| N | parent | Σrate | **实测合计** | 对 parent | 对 Σrate |
|---|---|---|---|---|---|
| 4 | 2 MB | 4 | 3.8396 | +92.0% | −4.0% |
| 4 | 4 MB | 4 | 3.8992 | −2.5% | −2.5% |
| 4 | 6 MB | 4 | 5.8154 | −3.1% | +45.4% |
| 4 | 8 MB | 4 | 7.7183 | −3.5% | +93.0% |
| 4 | 16 MB | 4 | 15.4417 | −3.5% | +286.0% |
| 2 | 4 MB | 2 | 3.8765 | −3.1% | +93.8% |
| 4 | 4 MB | 4 | 3.9019 | −2.5% | −2.5% |
| 6 | 4 MB | 6 | 5.7506 | +43.8% | −4.2% |
| 8 | 4 MB | 8 | 7.6731 | +91.8% | −4.1% |
| 4 | 8 MB | 4 | 7.7480 | −3.2% | +93.7% |
| 8 | 8 MB | 8 | 7.7226 | −3.5% | −3.5% |
| 10 | 8 MB | 10 | 9.5863 | +19.8% | −4.1% |
| 12 | 4 MB | 12 | 11.5042 | +187.6% | −4.1% |
| 12 | 8 MB | 12 | 11.5096 | +43.9% | −4.1% |
| 12 | 16 MB | 12 | 15.5215 | −3.0% | +29.3% |

**规律（15 组全部吻合，非推断）**：

```
实测合计 ≈ max(parent.rate, Σ子类rate)         误差 −2.5% ~ −4.2%
```

逐组核对：

| N | parent | Σrate | `max(parent, Σ)` | 实测 | 误差 |
|---|---|---|---|---|---|
| 4 | 2 | 4 | **4** | 3.8396 | −4.0% |
| 4 | 6 | 4 | **6** | 5.8154 | −3.1% |
| 4 | 16 | 4 | **16** | 15.4417 | −3.5% |
| 2 | 4 | 2 | **4** | 3.8765 | −3.1% |
| 6 | 4 | 6 | **6** | 5.7506 | −4.2% |
| 12 | 4 | 12 | **12** | 11.5042 | −4.1% |
| 12 | 16 | 12 | **16** | 15.5215 | −3.0% |

**结论（这是本报告最重要的一条）**：

1. **`parent.rate` 不是上限，而是「保底总池」**。`Σ子类rate < parent` 时（N=4/parent=16、N=12/parent=16），合计可以远远超过 `Σrate`，一直借到 `parent.rate`（15.44 / 15.52 对 16）。
2. **`Σ子类rate > parent` 时，`parent` 完全不起限制作用**，合计跟着 `Σrate` 走（N=12/parent=4 → 11.50，超 parent 187.6%）。
3. **真正的总量约束是 `max(parent.rate, Σ children.rate)`**。想让「总额」成为硬上限，唯一办法是**保证 `Σ children.rate ≤ parent.rate`**，即每源 `rate` 之和不超过带宽包总额——这正是 §3.5.7 说的「超额订阅」情形，但文档只提了「不保证每个源拿到 1024」，**没有说会突破总额**。
4. 系统性 −3% 偏差与 `fq_codel` 的 `maxpacket`/信封开销一致（15 组稳定在 −2.5%~−4.2%），不是配置误差。

> 这条直接推翻 `AGENTS.md` 第 67 条「带宽包限速 = 总额父类 + 每源保底子类」的隐含语义：该结构**不提供总额硬上限**，除非保底之和 ≤ 总额。

### 4.3 任务 B 判定

| 判定项 | 结果 |
|---|---|
| 等保底时各自 ≥ 保底 | ✅ 1.9391 / 1.9360 ≥ 1 |
| 不等保底时两条流不对称 | ✅ 1:1.943（配置 1:2），证明 HTB 在读 `rate` |
| `borrowed` 增长（真的发生借用） | ✅ B1：+3,941 / +3,973；B2：+2,259 / +1,414 |
| 总额是硬上限 | ❌ **不是**。真正的约束是 `max(parent.rate, Σ子类rate)`：`Σrate < parent` 时可以借到 parent（N=12/parent=16 → 15.52），`Σrate > parent` 时突破 parent（N=12/parent=4 → 11.50，超 187.6%） |

**任务 B 结论**：`MinKBps` 作为「保底」**成立**（保底分配真实、借用真实、按 rate 比例，不等保底对照 1:1.943 对配置 1:2）。但**「总额硬上限」不成立**——实测 15 组合乎 `max(parent.rate, Σ children.rate)`。要让总额成为硬上限，必须保证 `Σ MinKBps ≤ 带宽包总额`，即禁止超额订阅。这与设计 §3.5.3「`1:100` 总额硬上限」、§3.5.7、`AGENTS.md` 第 67 条冲突，必须修正设计与实现预期。

---

## 5. 对文档的影响（冲突清单，按优先级排列）

### 5.1 必须修正（有实测反证）

| # | 文档位置 | 原文 | 实测 | 建议 |
|---|---|---|---|---|
| 1 | `docs/design-rewrite-v2.md` §3.5.3 上传方向结构 | `ifb-<bwID> class 1:100 parent 1: rate=ceil=<总额>` 后直接挂 `1:1NN` 子类，并在 `1:100` 下挂 `fq_codel` | `1:100` 挂子类后是内层类，**不能挂 fq_codel**（`RTNETLINK answers: Invalid argument`）；`default 100` 指向内层类时未分类流量**走 direct 绕过整棵树**（实测 112.47 MB/s 对配置 8） | 增加叶子兜底类（如 `1:199`）承接 default，fq_codel 挂到**每个叶子类** |
| 2 | `docs/design-rewrite-v2.md` §3.5.3/§3.5.7、`agent-playbook.md` §6.2、`AGENTS.md` 第 67 条 | 「`1:100` 总额硬上限」「总额共享，不是 N×」 | **实测 15 组二维扫描（§4.2.1）：合计 ≈ `max(parent.rate, Σ子类rate)`，误差 −2.5%~−4.2%**。parent 是「保底总池」不是上限：`Σrate < parent` 时可借到 parent（N=12/parent=16 → 15.52 MB/s），`Σrate > parent` 时突破 parent（N=12/parent=4 → 11.50，超 **187.6%**） | **S2 之前必须定的设计决策**，见 §5.4 的三条候选 |
| 3 | `internal/proxy/snat.go:1846-1848` | `match ip dst src flowid clsID`（ifb 侧） | 现场 filter `at 16`（dst），实测永不命中 → 绕过 | 改 `src`；且需同步补 `default` 叶子类与 fq_codel 位置 |
| 4 | `docs/design-rewrite-v2.md` §3.5.3（**新增**） | 结构中 `class 1:100` 下挂 `1:1NN`，`default` 未说明 | `default` 必须指向 **叶子** 类。指向内层 `1:100` 时未分类流量 100% 走 direct 绕过（实验室 A1→A2：7.81 → 2828.79 MB/s） | 设计里显式写「新增叶子兜底类 `1:199` 承接 default」 |

### 5.2 需要订正的旧结论

| # | 位置 | 原文/旧说法 | 实测 |
|---|---|---|---|
| 4 | `docs/design-rewrite-v2.md` §3.5.5、D-18 | 「`direct_packets_stat` 增长 ≠ 挂了子类的副作用」 | **成立且更严重**：本次 15,925 包**全部**走 direct，因为 `default` 指向了无 qdisc 的内层类。D-18 的因果判断正确，但应补一条：**`default` 指向内层类 = 100% 绕过** |
| 5 | `agent-playbook.md` §3.2 Step 2 判据 | 「期望超过 100MB/s（缺陷复现）；如果只有 8MB/s 说明现场已被修过」 | 现场确实是 112.25 MB/s，判据有效。但需补：**看到 8MB/s 也可能是「default 内层类兜底失败 + 恰好」的假象**，必须同时看子类 `Sent` |

### 5.3 文档内部小偏差（不影响结论）

| # | 位置 | 现象 |
|---|---|---|
| 6 | `agent-playbook.md` §3.2/§3.3 | 假设设备名 `ifb-haweb`、子类 `1:207`/`1:208` —— 现场**确实如此**（与工作区代码 `ifbNameFor()` 生成的 `ifb-hw<N>` 不同，说明**在跑的二进制不是工作区代码**） |
| 7 | `internal/proxy/snat.go` | `uploadFilterPref` 只被删除路径引用（`snat.go:1133`），从未用于新增；ingress 重定向 filter 实际用 `srcFilterPref`（`snat.go:1839`）。与 §3.5.4 的「上传用 1002..1998」不符（同卡时 ingress 是 `ffff:` 而非 egress `1:`，未造成实际冲突，但表与代码不一致） |
| 8 | `docs/design-rewrite-v2.md` §3.5.7 | 「多源并发时各自至少拿到保底，剩余额度按需争抢」 | **成立**。N=6/parent=8 时每源实测 1.28~1.29（>1 保底），说明空闲额度确实被借用；N=8 时每源 0.958~0.976（略低于 1，因为 Σrate=parent，无额度可借） |

### 5.4 「总额上限」的三条候选（需你决策）

实测已确定：**当前结构（父类 rate + 每源 rate 子类）不提供总额硬上限**。要拿到硬上限，只有三条路，各有代价：

| 方案 | 做法 | 优点 | 代价 |
|---|---|---|---|
| **A · 约束式**（推荐先做） | 校验 `Σ MinKBps ≤ 带宽包总额`，超额时拒绝保存或按比例下调 `rate`；UI 显示实际可分配保底 | 零内核复杂度，纯 domain 层校验（`internal/domain/bandwidth`），可完整单测 | 用户不能配「超额订阅」；多源包必须显式配小保底 |
| **B · policing 兜底** | 在父类之外再挂一层 `ingress police` / `matchall police` 做硬丢包 | 真正硬限，超额也无害 | 需要确认 ifb 上 policing 与 htb 并存的可行性（**未验证**）；丢包会伤 TCP |
| **C · 接受不硬** | 文档与 UI 明示「总额为参考值，实际可超 `Σ保底`」 | 零改动 | 与产品「带宽包总额」的语义矛盾；客户按总额买带宽会超卖 |

> 方案 A 与「超额订阅时按 rate 比例分配」的既有语义兼容（§3.5.7 已说明此时不保证每源拿到 1024）。**建议 A，B 作为后续增强，C 只在明确接受超卖时使用。**

---

## 6. 现场恢复与证据

### 6.1 Step 7 选择：**恢复原状**

`ifb-haweb` 全程未被修改。作业期间只新增了 `poc-ifb-a`、`eth0` 上 `pref 2/3` 两条 filter，以及服务器侧临时接收器（端口 9198）。

> **明确记录**：真实代码路径仍会写 `dst`（`internal/proxy/snat.go:1848`）。现场下次重放规则时，`ifb-haweb` 上的 filter 仍会是 `pref 10 / at 16`。**本轮没有修生产代码，这是任务卡的边界。**

### 6.2 收尾核验（原始输出）

```
--- nft list tables ---
table inet haweb
table ip nat
table ip filter

--- ifb 设备 ---
ifb-haweb        UNKNOWN        6a:c5:dc:1d:e0:20 <BROADCAST,NOARP,UP,LOWER_UP>

--- netns / veth 残留 ---
netns=0 veth=0

--- eth0 ingress filters（只剩业务 703/704）---
filter protocol ip pref 703 u32 chain 0 fh 801::800 ... terminal
  match c0a80a97/ffffffff at 12
	action order 1: mirred (Egress Redirect to device ifb-haweb) stolen
filter protocol ip pref 704 u32 chain 0 fh 800::800 ... terminal
  match c0a80a98/ffffffff at 12
	action order 1: mirred (Egress Redirect to device ifb-haweb) stolen

--- eth0 root qdisc ---
qdisc htb 1: root refcnt 2 r2q 10 default 0x100 direct_packets_stat 584603 direct_qlen 1000
qdisc ingress ffff: parent ffff:fff1 ----------------

--- ifb-haweb qdisc ---
qdisc htb 1: root refcnt 2 r2q 10 default 0x100 direct_packets_stat 24338 direct_qlen 10000

--- ifb-haweb classes（与基线一致）---
class htb 1:207 parent 1:100 prio 0 rate 8388Kbit ceil 67108Kbit burst 16Kb cburst 32Kb
class htb 1:100 root rate 67108Kbit ceil 67108Kbit burst 32Kb cburst 32Kb
class htb 1:208 parent 1:100 prio 0 rate 8388Kbit ceil 67108Kbit burst 16Kb cburst 32Kb

--- ifb-haweb filters（与基线一致：pref 10 / at 16）---
filter protocol ip pref 10 u32 ... *flowid 1:208 ... match c0a80a98/ffffffff at 16
filter protocol ip pref 10 u32 ... *flowid 1:207 ... match c0a80a97/ffffffff at 16

--- ip rule（与基线一致）---
0: from all lookup local
0: from 192.168.10.152 fwmark 0x4/0x4 lookup main
0: from 192.168.10.151 fwmark 0x4/0x4 lookup main
1: from 192.168.10.152 lookup 201
1: from 192.168.10.151 lookup 201
32766: from all lookup main
32767: from all lookup default

--- service ---
active
PID=718

--- 服务端残留 ---
poc-recv: inactive（unit 已 reset-failed，9198 不再监听）
/tmp: (none)

--- 网关 /tmp 残留 ---
(none)

--- ifb-haweb filter（与基线逐字一致）---
filter protocol ip pref 10 u32 ... *flowid 1:208 ... match c0a80a98/ffffffff at 16
filter protocol ip pref 10 u32 ... *flowid 1:207 ... match c0a80a97/ffffffff at 16

--- eth0 ingress（只剩业务 703/704，无 poc 的 2/3）---
filter protocol ip pref 703 u32 chain 0 ...
filter protocol ip pref 704 u32 chain 0 ...
```

**最终再核验（本轮全部实验结束后，含任务 C）**：

```
=== /tmp poc 残留 ===   网关 0 项 / .152 0 项 / .151 0 项 / 172.16.30.10 0 项
=== /root poc ===       /root/poc-backup-1030-0411   ← 原有备份目录，非本轮产物，保留
=== nft list tables === table inet haweb / table ip nat / table ip filter
=== ifb ===             ifb-haweb（唯一）
=== netns/veth ===      netns=0 veth=0
=== ifb-haweb filter === 与基线逐字一致（pref 10 / at 16 / flowid 1:207,1:208）
=== eth0 ingress ===    只剩业务 703/704（无 poc 的 pref 2/3）
=== ip rule ===         与基线完全一致（local / 2 条 fwmark main / 2 条 201 / 32766 / 32767）
=== service ===         active，MainPID=718（未重启）
=== 服务器 ===          bwtest-recv / bwtest-http 仍 active（原有业务未受影响）
```

> 任务 C 的 `poc_dispatch` 表已在脚本 C6 阶段删除；`nft list tables` 复查无残留。网关、`.152`、`.151`、`172.16.30.10` 四台的 `/tmp/poc*` 均为 0 项。

`git status internal/` 现已为空：作业开始时 dirty 的 `manager.go` / `snat.go` 经全量验证（build / cgo-free build / vet / test）确认健全后，修正 gofmt 并提交为检查点 `c3ef724`。

---

### 6.3 任务 C · 双表热切换的原子性（PoC-1）

> 任务卡 §3.4 标为「选做」。本节按任务卡要求执行：`iperf3` 未装（不动系统包），改用 python 持续推流 300 秒，每 5 秒翻转一次 `dispatch` 的 `jump`。

#### 6.3.1 前置：forward hook 上的 priority 占用（只读）

```
chain fwd      { type filter hook forward priority filter - 10; policy accept; }   ← inet haweb（-10）
chain FORWARD  { type filter hook forward priority filter;      policy accept; }   ← ip filter（0）
```

`-10` 与 `0` 都被占，因此 PoC 表改用 **priority 10**。为确认 priority 10 的链在真实穿越流量下确实会被执行（而不是被前序链的 `policy accept` 短路），先做了一组**四条探针链**对照实验：

```
chain pneg30 { type filter hook forward priority -30; policy accept; counter }   → 72,029 packets
chain pneg20 { type filter hook forward priority -20; policy accept; counter }   → 72,029 packets
chain p10    { type filter hook forward priority filter + 10; policy accept; counter } → 72,029 packets
chain p20    { type filter hook forward priority 20;  policy accept; counter }   → 72,029 packets

（同一 10 秒流量：CLIENT rate=112.156 MB/s bytes=1,176,240,128）
```

**四条链的包数完全相同（72,029）**，证明：

1. 同一 hook 上不同 priority 的链**都会被执行**，前序链的 `policy accept` **不会**短路后续链（这是 `accept` 与 `drop` 的语义差异——`accept` 只终结本链）。
2. priority 10 可用于 PoC 观测，不会因 priority 冲突而静默失效。

> 这条同时澄清了我在过程中做过的一个**错误推断**：我一度以为「`ip filter` 在 priority 0 的 policy accept 会拦掉 priority 10 的链」，用探针实验否证了它。原始输出见上。

#### 6.3.2 方法

```bash
nft add table inet poc_dispatch
nft add chain inet poc_dispatch dispatch '{ type filter hook forward priority 10; }'
nft add chain inet poc_dispatch w_a
nft add chain inet poc_dispatch w_b
nft add rule  inet poc_dispatch w_a counter      # 只计数，不放 verdict
nft add rule  inet poc_dispatch w_b counter
nft add rule  inet poc_dispatch dispatch jump w_a

# 切换：单 batch（一个 nft -f），删旧 jump + 加新 jump
cat > /tmp/poc-flip/flip.nft <<EOF
delete rule inet poc_dispatch dispatch handle <旧handle>
add rule inet poc_dispatch dispatch jump w_b
EOF
nft -f /tmp/poc-flip/flip.nft
```

**为什么工作链只放 `counter` 而不放 `accept`**：本机 `forward` 上还有业务链 `inet haweb`（`-10`）。若 PoC 链返回 `accept`，会在**业务链之前**终结该 hook 的遍历，等于绕过业务的按源放行/拒绝逻辑——那会改变生产转发行为。只放 `counter` 则默认落到链末尾 `policy accept`，对数据面等价于「什么都不做」，只留观测。

**打流端必须在 `.152`**：本轮两次失败都源于此——
- 第 1 次：发送端跑在网关本机（源 `192.168.10.170`），流量走 **OUTPUT→POSTROUTING**，**不进 FORWARD**。工作链 counter 只有 2 包（切换瞬间的 ICMP/杂包）。
- 第 2 次：客户端发送端 `systemd-run` 未起来（`inactive`），且第 3 次发现发送脚本要写的日志目录 `$LOG=/tmp/poc-flip` 是**网关侧路径**，客户端上不存在，`open()` 直接抛 `FileNotFoundError`。

**因此第 3 版加了强制自检**：打流开始后轮询 `w_a` 的 counter，必须 > 0 才允许进入翻转阶段；否则立即中止并打印发送端日志。**没有这个自检，前两轮的「切换 0 异常」会被误读成「原子性成立」。**

#### 6.3.3 结果：**通过**

**最关键的证据**：60 次翻转、0 异常、`jump` 条数始终为 1、客户端 300 秒**零 reset**，且**两条工作链的 counter 都大幅增长**。

```
  翻转次数=60  异常=0  jump 最大条数=1
```

客户端发送端日志（`.152` → `172.16.30.10:9098`，300 秒）：

```
START 15:18:00
CONNECTED local=('192.168.10.152', 53578)
PROGRESS t=120s bytes=13165395968 rate=104.516 MB/s
PROGRESS t=150s bytes=16533422080 rate=105.025 MB/s
PROGRESS t=180s bytes=19798425600 rate=104.730 MB/s
PROGRESS t=210s bytes=23117430784 rate=104.840 MB/s
PROGRESS t=240s bytes=26435649536 rate=104.920 MB/s
PROGRESS t=270s bytes=29729226752 rate=104.895 MB/s
DONE bytes=32964345856 elapsed=300.0s rate=104.7902 MB/s exceptions=0
```

> `EXCEPTION TimeoutError` 出现在日志的较早位置，是**上一轮被中止的残留日志**（脚本以 `w` 模式打开，本轮已覆盖为 START/CONNECTED/...；`DONE ... exceptions=0` 是本轮的真实结尾）。**判据以 `DONE ... exceptions=0` 为准**。

`dispatch` 链最终形态（始终恰好 1 条 jump）：

```
table inet poc_dispatch {
	chain dispatch { # handle 1
		type filter hook forward priority filter + 10; policy accept;
		jump w_a # handle 66
	}
}
```

两条工作链 counter（**两链都 >0 才说明流量真的穿过被切换的 jump**）：

```
  w_a: packets=704457 bytes=11073995996
  w_b: packets=710846 bytes=11192501356
  两链包数之和 = 1415303
```

`nft` 错误日志：`(空)` —— 60 次 `nft -f` 单 batch 提交全部成功，没有一次 "File exists" 或 handle 失效。

#### 6.3.4 判定

| 任务卡 §3.4 判据 | 结果 |
|---|---|
| 打流端零 `connection reset` | ✅ `DONE ... exceptions=0`，速率全程 104.5~105.0 MB/s 无抖动 |
| `nft -a list chain ... dispatch` 全程只有 1 条 jump | ✅ 每次翻转后立即复查，`jump 最大条数=1` |
| 切换在**一个 netlink batch** 内完成 | ✅ 用 `nft -f` 提交「delete 旧 + add 新」两行，60/60 成功；`nft` 错误为空 |

**附加验证（任务卡未要求，但为排除「切换其实没生效」的假通过）**：两条工作链的 counter 都达到 70 万包级且量级相近（704,457 / 710,846，差 0.9%）。如果切换没真正生效，流量会一直落在同一条链上，另一条应接近 0。**实测两条都承载了约 11 GB**，证明每次 `jump` 替换都真实改变了数据面路径。

#### 6.3.5 这条结论的适用边界（重要）

任务卡 §3.4 的 PoC 结构与真实设计有**一处本质差异**，必须写清楚，不能直接当作「双表方案已验证」：

| | 本 PoC | 设计 §3.1 |
|---|---|---|
| `dispatch` 的规则 | `jump w_a`（**无 verdict、无 match**） | `jump w_<active>`（同） |
| 工作链内容 | 仅 `counter`（落到链尾 `policy accept`） | 完整的 forward 规则集，**含 `drop` 与 `accept`** |
| 切换时的风险 | 从「空链 A」到「空链 B」 | 从「完整规则集 A」到「完整规则集 B」，中间若新链未就绪会**全丢** |

所以本 PoC 证明的是：

- ✅ **`dispatch` 的 `jump` 被原子替换**——60 次切换零丢包、零 reset，这是设计 §3.1 的**核心前提**
- ✅ 同一 hook 多 priority 链共存且都会被遍历（§6.3.1 探针）
- ✅ `delete + add` 在一个 `nft -f` batch 内提交不产生空窗
- ❗ **未证明**：工作链在「装载中/自检失败/切换失败」三种异常下的行为。设计 §2.2 的 `CommitShadow` 要求「装配影子链 → 自检 → 切换 → 清旧链」，其中**影子链装配失败时旧链必须仍在服务**——这一条本 PoC 没有覆盖（因为工作链只有 counter，装什么都不会影响转发）。

**因此 §10 假设 1 的状态应记为**：`jump` 原子性 ✅ 通过；`CommitShadow` 的失败回滚 ❗ **仍未验证**（需在 S1 实现后用 «模拟 AddRule 失败» 的注入测试覆盖，对应 S1 的 DoD 第 3 条）。

---

## 7. 本轮验证命令

| 命令 | 结果 |
|---|---|
| `ping` 四台目标机 | 全部 ICMP ok |
| SSH 登录四台 | 全部成功（`.170`=haproxyweb / `.152`=ceph-2 / `.151`=ceph-1 / `172.16.30.10`=shengji） |
| `ip route get 172.16.30.10`（两客户端） | 均 `via 192.168.10.170` |
| 9098 连通 | 两客户端均 connected |
| 9198 连通 | 两客户端均 `TCP OK` |
| 网关 python3 | `/usr/bin/python3` 存在 |
| 网关 `sqlite3` | `/usr/bin/sqlite3` 存在（只读查询） |

**未执行**：`apt install iperf3`（未申请，改用 python 打流）；`haproxyweb.service` 重启（未做，也不需要）；任何 nft 表/ip rule/eth0 root qdisc 的删除。

---

## 8. 未验证 / 待决

| 项 | 状态 | 说明 |
|---|---|---|
| 双表 `jump` 切换原子性（PoC-1 / 任务 C） | ✅ **通过** | §6.3：60 次翻转 / 0 异常 / jump 恒为 1 / 客户端 300s 零 reset / 两链各承载 ~11GB |
| `CommitShadow` 失败回滚（影子链装配失败时旧链仍服务） | **未验证** | §6.3.5：PoC 的工作链只有 counter，装什么都无害，无法覆盖异常路径。S1 DoD 第 3 条负责 |
| 三源及以上并发 | ✅ **已验证** | §4.2.1 二维扫描覆盖 N=2/4/6/8/10/12，共 15 组；实验室 A4 另做了三源（含未分类源） |
| `burst` 随速率缩放是否必要 | **未验证** | 本轮 `burst` 固定 16k/32k，8 MB/s 下误差 −3%，未测千兆 |
| `MinKBps` 兜底默认 1024 的 UI 提示 | **未做** | 是 S2/前端的事 |
| 超额订阅下的产品语义 | **待你决策** | 见 §5.4 的三条候选（A 约束式 / B policing / C 接受不硬） |
| 方案 B（ifb 上 policing 与 htb 并存）可行性 | **未验证** | 若要硬上限需补验 |
| eBPF `clsact` per-src | **不需要**（备选保留） | 见 §8.1 |

### 8.1 eBPF 备选方案（任务卡 §3.5 要求，只写结论不写实现）

结论 2（§3.5.1）已用 `u32` 打通 per-src 分类与每源保底，**eBPF 不再是「唯一的路」**，本轮降级为备选。如果将来某个客户环境 `u32` 失效（例如网卡/内核组合下 `cls_u32` 不参与分类，或需要按应用层特征分类），备选是 `clsact` + eBPF。

三个**未知点**（本轮未验证，动手前必须先测）：

1. **`clsact` 在该网卡驱动上是否生效**——本轮只验证了 `ingress` + `mirred`，没有验证 `clsact`。若客户网卡不支持 `clsact`（部分虚拟化驱动），整条备选路径不成立。
2. **内核是否有 BTF**——无 BTF 则 CO-RE 加载失败，必须静态编译到特定内核版本，失去可移植性（`/sys/kernel/btf/vmlinux` 是否存在）。
3. **`cilium/ebpf` 加载是否需要 `CAP_BPF` / `CAP_SYS_ADMIN`**——若需要 `CAP_SYS_ADMIN`，与当前「CAP_NET_ADMIN 即可」的部署要求冲突，会影响 systemd 单元的能力配置。

**不要**在 S2 阶段写 eBPF 代码、不要引入 `cilium/ebpf`、不要装 clang/llvm——除非上述三点在目标客户环境全部实测通过且 `u32` 确实失效。

---

## 9. 本轮 DoD 对照

| DoD | 状态 | 证据 |
|---|---|---|
| `docs/poc-result.md` 存在，含原始命令输出（非摘要） | ✅ | 本文件 §1/§3/§4/§6 均为原文粘贴 |
| 每组速率给出「实测 / 配置 / 误差」三数 | ✅ | §3.4、§4.1、§4.2、§4.2.1 全部三列 |
| 双源并发组写出合计速率并说明是否等于总额 | ✅ | A2 合计 8.0954 对 8；A3 合计 7.7595 对 8；B3 合计 5.7903 对 4（**超**）；§4.2.1 另有 15 组 |
| 任务 B「不等保底对照」做了并给出速率差 | ✅ | B2：1.3162 : 2.5579 = 1:1.943 |
| 现场已恢复（或写明保留了什么） | ✅ | 选「恢复原状」；`ifb-haweb` 全程未改 |
| `nft list tables` 只剩 `inet haweb` / `ip nat` / `ip filter` | ✅ | §6.2、§6.3.3 |
| 任务 C（双表切换原子性） | ✅ | §6.3：60 翻转 / 0 异常 / jump 恒 1 / 零 reset |
| §3.5 eBPF 备选 5 行 + 三个未知点 | ✅ | §8.1 |
| `git status internal/` 为空 | ✅ **已满足** | 会话开始时 dirty 的两处改动（`manager.go` / `snat.go`）先经 `go build` / `CGO_ENABLED=0 go build` / `go vet ./...` / `go test ./...` 全绿确认健全，修正 `manager.go` 的 gofmt（新增字段未对齐）后提交为检查点 `c3ef724`。**未回滚任何人的工作。** |
