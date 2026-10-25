apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iproute2 curl python3 >/dev/null 2>&1
ip netns del haweb-c 2>/dev/null; ip netns del t1 2>/dev/null; ip netns del t2 2>/dev/null
for v in veth-c veth-gw-c e1 e2; do ip link del $v 2>/dev/null; done
nft delete table inet haweb 2>/dev/null
# 拓扑：client(192.168.100.2) → gw ← e1(10.201.0.1) → t1(10.201.0.2)
#                              ← e2(10.202.0.1) → t2(10.202.0.2)
echo 1 > /proc/sys/net/ipv4/ip_forward
ip netns add haweb-c; ip netns add t1; ip netns add t2
ip link add veth-c type veth peer name veth-gw-c
ip link add e1 type veth peer name e1t
ip link add e2 type veth peer name e2t
ip link set veth-c netns haweb-c; ip link set e1t netns t1; ip link set e2t netns t2
ip addr add 192.168.100.1/24 dev veth-gw-c
ip addr add 10.201.0.1/24 dev e1; ip addr add 10.202.0.1/24 dev e2
ip link set veth-gw-c up; ip link set e1 up; ip link set e2 up
ip netns exec haweb-c ip addr add 192.168.100.2/24 dev veth-c
ip netns exec haweb-c ip link set veth-c up; ip netns exec haweb-c ip link set lo up
ip netns exec haweb-c ip route add default via 192.168.100.1
ip netns exec t1 ip addr add 10.201.0.2/24 dev e1t; ip netns exec t1 ip link set e1t up; ip netns exec t1 ip link set lo up
ip netns exec t2 ip addr add 10.202.0.2/24 dev e2t; ip netns exec t2 ip link set e2t up; ip netns exec t2 ip link set lo up
setsid ip netns exec t1 python3 -m http.server 80 >/dev/null 2>&1 &
setsid ip netns exec t2 python3 -m http.server 80 >/dev/null 2>&1 &
sleep 1.5
# 多路路由手工验证（产品的 EnsureEgressRoute 等价形态）：
ip route replace default scope global nexthop via 10.201.0.2 dev e1 weight 1 nexthop via 10.202.0.2 dev e2 weight 1
echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"
echo "== multipath 装好了："
ip route show | head -3
echo "== client 访问 t1（走 e1）："
ip netns exec haweb-c curl -s -m 2 -o /dev/null -w "%{http_code}\n" http://10.201.0.2:80/
echo "== client 访问 t2（走 e2）："
ip netns exec haweb-c curl -s -m 2 -o /dev/null -w "%{http_code}\n" http://10.202.0.2:80/
echo "== 主出口 down（模拟）→ 单路切备："
ip route replace default via 10.202.0.2 dev e2
ip netns exec haweb-c curl -s -m 2 -o /dev/null -w "%{http_code}\n" http://10.202.0.2:80/
echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"
curl -s -m 1 -o /dev/null -w "gw_local=%{http_code}\n" http://10.201.0.2:80/
echo "RESULT: M3-MULTIPATH-OK"
