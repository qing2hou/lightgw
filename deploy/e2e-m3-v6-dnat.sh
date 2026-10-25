apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iproute2 curl python3 nftables >/dev/null 2>&1
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
ip netns del c6 2>/dev/null; ip netns del b6 2>/dev/null
ip link del vc6 2>/dev/null; ip link del vb6 2>/dev/null
nft delete table inet haweb 2>/dev/null
ip netns add c6; ip netns add b6
ip link add vc6 type veth peer name vgc6
ip link add vb6 type veth peer name vgb6
ip link set vc6 netns c6; ip link set vb6 netns b6
ip -6 addr add fd00:1::1/64 dev vgc6
ip -6 addr add fd00:2::1/64 dev vgb6
ip link set vgc6 up; ip link set vgb6 up
ip netns exec c6 ip -6 addr add fd00:1::2/64 dev vc6
ip netns exec c6 ip link set vc6 up; ip netns exec c6 ip link set lo up
ip netns exec c6 ip -6 route add default via fd00:1::1
ip netns exec b6 ip -6 addr add fd00:2::2/64 dev vb6
ip netns exec b6 ip link set vb6 up; ip netns exec b6 ip link set lo up
ip netns exec b6 ip -6 route add default via fd00:2::1
setsid ip netns exec b6 python3 -m http.server 80 --bind :: >/dev/null 2>&1 &
sleep 1.5
# v6 dnat：发布 fd00:2::1:80 → 后端 fd00:2::2:80（同族 v6）——走产品编译层：
# 用 /poc 的 e2e-dnat 变体不行（场景写死 v4）——直接 nft 手工铺编译层等价形态：
nft add table inet haweb 2>/dev/null
nft add chain inet haweb pre_mark '{ type filter hook prerouting priority mangle; }'
nft add chain inet haweb dstnat '{ type nat hook prerouting priority dstnat; }'
nft add chain inet haweb fwd '{ type filter hook forward priority -10; }'
nft add rule inet haweb pre_mark ct state established,related meta mark set mark or 0x1
nft add rule inet haweb dstnat ip6 daddr fd00:2::1 tcp dport 80 dnat ip6 to [fd00:2::2]:80
nft add rule inet haweb fwd ip6 daddr fd00:2::2 tcp dport 80 ip6 saddr fd00:1::2 counter mark set mark or 0x1
echo "== c6 → 发布地址 fd00:2::1:80（v6 DNAT 穿越）："
ip netns exec c6 curl -s -m 2 -o /dev/null -w "code=%{http_code}\n" "http://[fd00:2::1]:80/"
echo "== 基线（未授权源+默认拒绝尾行不在位——策略容器 policy accept）："
nft list table inet haweb | grep -c "dnat"
