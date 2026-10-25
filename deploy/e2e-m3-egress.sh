#!/bin/sh
# M3 AC-5（多出口负载分担/会话亲和/出口下线切换）容器验证 —— QA P5 修复版。
#
# 原 000 根因（q.a. 定位）：旧拓扑把 client、t1、t2 建成三个互不路由的孤岛
# （t1/t2 只有到 192.168.100.0/24 经各自网关的回程，彼此不通 10.201/10.202 网段）。
# multipath 是 per-flow 确定性哈希：五元组分发到哪条 nexthop 与"目标在哪个岛"无关，
# 凡被哈希到"目标在对侧岛"的流（t1 无 10.202 段路由 / t2 无 10.201 段路由）SYN 必黑洞。
# 真实多出口语义是"两条上行最终可达同一上游"，因此本脚本给 t1↔t2 建互联（tr 链路）＋
# 交叉网段路由，srv 双宿（两腿各接一台上游），rp_filter 全关（非对称路由场景要求）。
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iproute2 curl python3 procps tcpdump conntrack >/dev/null 2>&1
for ns in haweb-c t1 t2 srv; do ip netns del $ns 2>/dev/null; done
for v in veth-c veth-gw-c e1 e2 e1t e2t u1 u1s u2 u2s tr1 tr2; do ip link del $v 2>/dev/null; done
ip route flush table 201 2>/dev/null
while ip rule del pref 1 2>/dev/null; do :; done
echo 1 > /proc/sys/net/ipv4/ip_forward; echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter

# ---------- 拓扑 ----------
# client(192.168.100.2-6) ──veth-gw-c── gw
# gw: e1(10.201.0.1)─ t1(10.201.0.2, u1:10.31.1.1, tr1:10.41.0.1)
#     e2(10.202.0.1)─ t2(10.202.0.2, u2:10.31.2.1, tr2:10.41.0.2)
# t1 ──tr── t2 互联；srv 双腿 10.31.1.2(u1s) / 10.31.2.2(u2s)
for ns in haweb-c t1 t2 srv; do ip netns add $ns; done
ip link add veth-c type veth peer name veth-gw-c
ip link add e1 type veth peer name e1t
ip link add e2 type veth peer name e2t
ip link add u1 type veth peer name u1s
ip link add u2 type veth peer name u2s
ip link add tr1 type veth peer name tr2
ip link set veth-c netns haweb-c; ip link set e1t netns t1; ip link set e2t netns t2
ip link set u1 netns t1; ip link set u1s netns srv
ip link set u2 netns t2; ip link set u2s netns srv
ip link set tr1 netns t1; ip link set tr2 netns t2
ip addr add 192.168.100.1/24 dev veth-gw-c
ip addr add 10.201.0.1/24 dev e1; ip addr add 10.202.0.1/24 dev e2
ip link set veth-gw-c up; ip link set e1 up; ip link set e2 up
for s in 2 3 4 5 6; do ip -n haweb-c addr add 192.168.100.$s/24 dev veth-c 2>/dev/null; done
ip -n haweb-c link set veth-c up; ip -n haweb-c link set lo up
ip -n haweb-c route add default via 192.168.100.1
ip -n t1 addr add 10.201.0.2/24 dev e1t; ip -n t1 link set e1t up; ip -n t1 link set lo up
ip -n t1 addr add 10.31.1.1/24 dev u1; ip -n t1 link set u1 up
ip -n t1 addr add 10.41.0.1/24 dev tr1; ip -n t1 link set tr1 up
ip -n t1 route add 192.168.100.0/24 via 10.201.0.1
ip -n t2 addr add 10.202.0.2/24 dev e2t; ip -n t2 link set e2t up; ip -n t2 link set lo up
ip -n t2 addr add 10.31.2.1/24 dev u2; ip -n t2 link set u2 up
ip -n t2 addr add 10.41.0.2/24 dev tr2; ip -n t2 link set tr2 up
ip -n t2 route add 192.168.100.0/24 via 10.202.0.1
# 上游互联交叉路由（真实多出口：任一上行可达全部目标段）
ip -n t2 route add 10.31.1.0/24 via 10.41.0.1
ip -n t1 route add 10.31.2.0/24 via 10.41.0.2 2>/dev/null
for ns in t1 t2 srv; do ip netns exec $ns sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $i; done'; done
ip -n srv addr add 10.31.1.2/24 dev u1s; ip -n srv link set u1s up
ip -n srv addr add 10.31.2.2/24 dev u2s; ip -n srv link set u2s up
ip -n srv link set lo up
ip -n srv route add default via 10.31.1.1 metric 100
ip -n srv route add default via 10.31.2.1 metric 200
setsid ip netns exec srv python3 -m http.server 80 >/dev/null 2>&1 &
sleep 1.5

# ---------- 产品等价形态 ----------
# egressNexthops 主层 multipath → EnsureEgressRoute(table 201, AllowSrcs, nexthops)
ip route replace default scope global table 201 nexthop via 10.201.0.2 dev e1 weight 1 nexthop via 10.202.0.2 dev e2 weight 1
for s in 2 3 4 5 6; do ip rule add from 192.168.100.$s lookup 201 pref 1; done

nohup timeout 150 tcpdump -ni e1 -l -c 5000 > /tmp/e1.txt 2>/dev/null &
nohup timeout 150 tcpdump -ni e2 -l -c 5000 > /tmp/e2.txt 2>/dev/null &
sleep 1
# 纯 SYN（同源+同目标方向；排除 S. ACK 行）
syn() { grep -cE "$2\.[0-9]+ > $3: Flags \[S\]," /tmp/$1.txt 2>/dev/null || true; }

echo "==== AC-5.1 多出口负载分担：5 源 × 2 目标 × 3 连接（root path，200 才计成功）"
okA=0; okB=0; tot=0
for s in 2 3 4 5 6; do for i in 1 2 3; do
  r=$(ip netns exec haweb-c curl -s -m 2 -o /dev/null -w "%{http_code}" --interface 192.168.100.$s http://10.31.1.2:80/)
  tot=$((tot+1)); [ "$r" = 200 ] && okA=$((okA+1))
  r=$(ip netns exec haweb-c curl -s -m 2 -o /dev/null -w "%{http_code}" --interface 192.168.100.$s http://10.31.2.2:80/)
  tot=$((tot+1)); [ "$r" = 200 ] && okB=$((okB+1))
done; done
e1t=$(grep -cE "192\.168\.100\.[0-9]+\.[0-9]+ > .*: Flags \[S\]," /tmp/e1.txt 2>/dev/null || true)
e2t=$(grep -cE "192\.168\.100\.[0-9]+\.[0-9]+ > .*: Flags \[S\]," /tmp/e2.txt 2>/dev/null || true)
echo "RESULT-5.1 reach=$okA+$okB/$tot；SYN 分布 e1=$e1t e2=$e2t（双路均>0 → 分担且双路可达）"

echo "==== AC-5.2 会话亲和：同源(192.168.100.2)同目标(10.31.1.2) 10 连续连接"
b1=$(syn e1 192.168.100.2 10.31.1.2.80); b2=$(syn e2 192.168.100.2 10.31.1.2.80)
for i in $(seq 1 10); do ip netns exec haweb-c curl -s -m 2 -o /dev/null --interface 192.168.100.2 http://10.31.1.2:80/; done
sleep 1
a1=$(syn e1 192.168.100.2 10.31.1.2.80); a2=$(syn e2 192.168.100.2 10.31.1.2.80)
d1=$((a1-b1)); d2=$((a2-b2))
if [ "$((d1+d2))" -eq 10 ] && { [ "$d1" -eq 0 ] || [ "$d2" -eq 0 ]; }; then
  echo "RESULT-5.2 PASS：10 连接全部走 $([ $d1 -gt 0 ] && echo e1 || echo e2)（e1=+$d1 e2=+$d2）"
else
  echo "RESULT-5.2 FAIL：e1=+$d1 e2=+$d2（应 10/0 或 0/10）"
fi

echo "==== AC-5.3 出口下线：撤 e1 nexthop（等价 egressNexthops 剔除 down 出口 + reapply）→ 新会话全走 e2"
b1=$(syn e1 192.168.100.3 10.31.1.2.80); b2=$(syn e2 192.168.100.3 10.31.1.2.80)
ip route replace default scope global table 201 via 10.202.0.2 dev e2
ok=0
for i in $(seq 1 10); do
  r=$(ip netns exec haweb-c curl -s -m 2 -o /dev/null -w "%{http_code}" --interface 192.168.100.3 http://10.31.1.2:80/)
  [ "$r" = 200 ] && ok=$((ok+1))
done
sleep 1
a1=$(syn e1 192.168.100.3 10.31.1.2.80); a2=$(syn e2 192.168.100.3 10.31.1.2.80)
echo "RESULT-5.3 reach=$ok/10；SYN 增量 e1=+$((a1-b1))（应为 0） e2=+$((a2-b2))（应为 10）"

echo "==== 回切：恢复 multipath → 双路回归"
ip route replace default scope global table 201 nexthop via 10.201.0.2 dev e1 weight 1 nexthop via 10.202.0.2 dev e2 weight 1
ok=0
for i in $(seq 1 10); do
  r=$(ip netns exec haweb-c curl -s -m 2 -o /dev/null -w "%{http_code}" --interface 192.168.100.4 http://10.31.1.2:80/)
  [ "$r" = 200 ] && ok=$((ok+1))
done
echo "RESULT-recover reach=$ok/10"

echo "==== conntrack（同源会话表项侧证）"
conntrack -L -p tcp 2>/dev/null | grep "src=192.168.100.2 " | grep -v TIME_WAIT | head -4
echo "DONE"
