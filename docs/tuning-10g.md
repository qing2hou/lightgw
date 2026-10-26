# 万兆转发调优指引（fwgateway v1 / US8）

`deploy/tuning-10g.sh`（root 执行，幂等）覆盖内核参数；本文件补充脚本外的
手工项与验收基准方法。

## 脚本内覆盖项
| 参数 | 值 | 目的 |
|---|---|---|
| nf_conntrack_max | 524288 | 50 万并发会话（PRD 万兆预算：约 26 万 pps 小包×60s 建连速率上限） |
| conntrack established 超时 | 86400 | 防 hash 满载的字段收缩（默认 5 天过长） |
| rp_filter | 0 | 多出口非对称路由必需（loose=2 也不够） |
| netdev_max_backlog / somaxconn | 32768 / 4096 | 万兆突发软中断队列 |
| tcp_congestion_control | bbr | 本机自营流量（有模块时） |

## 手工项（拓扑相关，脚本只探测提示）
- **多队列网卡**：`ethtool -L <iface> combined N`（N=CPU 核数，避免单队列
  打满单核软中断——万兆小包单队列上限约 1.4 Mpps 每核）
- **RPS**（多队列不可用时的补偿）：`echo e > /sys/class/net/<iface>/queues/rx-*/rps_cpus`
- **IRQ 亲和**：irqbalance 或手工 `echo <cpu> /proc/irq/<n>/smp_affinity`
- **nf_conntrack_buckets**：运行期只能调 max；buckets 要 `nf_conntrack hashsize=x`
  模块参数（/sys/module/nf_conntrack/parameters/hashsize 可写但需要模块重载
  才精确生效——524288 buckets @ 4 字节/桶，内存充足时建议启动参数固定）

## 验收基准（AC-8.2，真机万兆环境）
```bash
# 双万兆口对打（iperf3 单流 TCP）
iperf3 -s                        # 目标机
iperf3 -c <目标> -t 30 -P 4      # 穿越方向（经网关转发）≥ 9 Gbps
# 64B 小包 pps（netinettool 或 pktgen；记录基线值即可）
```
两类基准在本开发环境（WSL2 容器）**notCovered**——需真机万兆环境执行；
首次真机部署时按本节方法出基线数值并回填交付报告。
