apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iproute2 curl python3 >/dev/null 2>&1
echo 1 > /proc/sys/net/ipv4/ip_forward
ip netns del haweb-c 2>/dev/null; ip netns del t1 2>/dev/null; ip netns del t2 2>/dev/null
for v in veth-c veth-gw-c e1 e2 e1t e2t; do ip link del $v 2>/dev/null; done
nft delete table inet haweb 2>/dev/null
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
ip netns exec t1 ip route add 192.168.100.0/24 via 10.201.0.1
ip netns exec t2 ip addr add 10.202.0.2/24 dev e2t; ip netns exec t2 ip link set e2t up; ip netns exec t2 ip link set lo up
ip netns exec t2 ip route add 192.168.100.0/24 via 10.202.0.1
setsid ip netns exec t1 python3 -m http.server 80 >/dev/null 2>&1 &
setsid ip netns exec t2 python3 -m http.server 80 >/dev/null 2>&1 &
sleep 2.5
for i in 1 2 3; do curl -s -m 1 -o /dev/null http://10.201.0.2:80/ && break; sleep 0.7; done
echo "== multipath 双路装载："
ip route replace default scope global nexthop via 10.201.0.2 dev e1 weight 1 nexthop via 10.202.0.2 dev e2 weight 1
ip route show
echo "== 网关本机可达性（gw→t1/t2，不经路由 multipath）："
curl -s -m 2 -o /dev/null -w "t1=%{http_code} " http://10.201.0.2:80/
curl -s -m 2 -o /dev/null -w "t2=%{http_code}\n" http://10.202.0.2:80/
echo "== client 经 multipath 穿越："
ip netns exec haweb-c curl -s -m 3 -o /dev/null -w "t1=%{http_code} " http://10.201.0.2:80/
ip netns exec haweb-c curl -s -m 3 -o /dev/null -w "t2=%{http_code}\n" http://10.202.0.2:80/
echo "== 主出口退出（模拟主层 down）→ 单路切备："
ip route replace default via 10.202.0.2 dev e2
ip netns exec haweb-c curl -s -m 3 -o /dev/null -w "t2_after=%{http_code}\n" http://10.202.0.2:80/
RC=$(ip netns exec haweb-c curl -s -m 3 -o /dev/null -w "%{http_code}" http://10.202.0.2:80/)
if [ "$RC" != "200" ]; then echo "RESULT: M3-FAIL"; exit 1; fi
echo "RESULT: M3-MULTIPATH-OK"
