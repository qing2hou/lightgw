#!/bin/sh
# 万兆转发调优（M4/T301；AC-8.1）：conntrack 容量/哈希、内核网络栈参数。
# 只做幂等写入（写前比对，已经是目标值则跳过）；不动 IRQ/RPS（网卡拓扑
# 相关，见文档 tuning-10g.md 的手工指引）。
set -e
CONF=/etc/sysctl.d/99-haweb-10g.conf
write_sysctl() {
  key="$1"; val="$2"
  cur=$(cat "/proc/sys/${key//./\/}" 2>/dev/null || echo "?")
  if [ "$cur" = "$val" ]; then
    echo "ok    $key = $val（已就位）"
  else
    echo "$key = $val" >> "$CONF"
    echo "$key = $val" > "/proc/sys/${key//./\/}" 2>/dev/null \
      || echo "warn  $key 写入失败（内核参数不存在？）"
    echo "set   $key = $val（原 $cur）"
  fi
}
mkdir -p /etc/sysctl.d
: > "$CONF" || true

# ① conntrack：50 万会话容量（QA/PRD 万兆预算）。
#    nf_conntrack_buckets 默认 = 内存/16384（4G 机器约 26 万），不足时扩到
#    512K buckets（哈希桶数需在模块加载早期设定——运行期调 max 单项也有效）
write_sysctl net.netfilter.nf_conntrack_max 524288
# ② conntrack 高水位：established 超时收缩（孤儿连接堆积到 hash 满的防护；
#    默认 5 天过长，专线网关 1 天足够）
write_sysctl net.netfilter.nf_conntrack_tcp_timeout_established 86400
# ③ 转发性能：关闭源校验（多出口非对称路由必需；PRD 多出口场景）
write_sysctl net.ipv4.conf.all.rp_filter 0
write_sysctl net.ipv4.conf.default.rp_filter 0
# ④ 本机中断/软中断均衡基础（万兆 NAPI 下默认已优，明确保底）
write_sysctl net.core.netdev_max_backlog 32768
write_sysctl net.core.somaxconn 4096
# ⑤ BBR 拥塞控制（本机自营流量；转发流量的拥塞控制在端主机）
write_sysctl net.ipv4.tcp_congestion_control bbr 2>/dev/null || echo "skip  bbr（内核无模块）"
sysctl -p "$CONF" >/dev/null 2>&1 || true

# ⑥ 网卡多队列/RPS 提示（拓扑相关不改，输出指引）
echo "--- 网卡队列现状（多队列网卡确认 combined）:"
for i in $(ls /sys/class/net/ | grep -v lo); do
  if [ -f "/sys/class/net/$i/queues" ] || [ -d "/sys/class/net/$i/queues" ]; then
    n=$(ls -d /sys/class/net/$i/queues/rx-* 2>/dev/null | wc -l)
    echo "  $i: rx 队列 $n"
  fi
done
echo "--- RPS（多队列未生效时的补偿；见 tuning 文档）："
for f in /sys/class/net/*/queues/rx-*/rps_cpus; do
  echo "  $f = $(cat $f)"
done | head -8
echo "调优完成（配置已持久化 $CONF）"
