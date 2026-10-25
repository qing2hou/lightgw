#!/bin/sh
# T007 共存矩阵：三类宿主形态 × 引擎行为（debian:bookworm --privileged）
set -x
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq nftables iptables >/dev/null 2>&1

echo "===== 场景 A：docker 模拟（iptables-nft，DOCKER 链 + FORWARD policy DROP）====="
iptables -t filter -N DOCKER 2>/dev/null
iptables -t filter -N DOCKER-USER 2>/dev/null
iptables -P FORWARD DROP
iptables -A FORWARD -j DOCKER-USER
iptables -A FORWARD -j DOCKER
iptables -A FORWARD -o docker0 -j ACCEPT  # 既有放行行
iptables -A DOCKER -d 172.17.0.2/32 -j ACCEPT
echo "-- 宿主规则就位："
iptables -L FORWARD --line-numbers -n | head -8
/poc -smoke-hostsim
echo "-- 引擎动作后宿主 FORWARD 应原样保留（含 DOCKER 行）："
iptables -L FORWARD --line-numbers -n | head -10
echo "-- haweb 表应在："
nft list table inet haweb | head -6

echo "===== 场景 B：iptables-legacy 直写（nf_tables 外的另一套）====="
# legacy 工具在 bookworm 容器即 iptables-legacy 命令；写入 xtables（不走 nf_tables）
iptables-legacy -t filter -P FORWARD DROP 2>/dev/null || iptables-legacy -P FORWARD DROP
cat /proc/net/ip_tables_names
/poc -smoke-legacy; echo "legacy 冒烟退出码=$?（非 0 = fail-fast 生效）"

echo "===== 场景 C：vanilla（无任何宿主防火墙）====="
iptables-legacy -F 2>/dev/null; iptables-legacy -X 2>/dev/null; iptables-legacy -P FORWARD ACCEPT 2>/dev/null
iptables -F 2>/dev/null; iptables -X 2>/dev/null; iptables -P FORWARD ACCEPT
nft delete table ip filter 2>/dev/null
nft list tables
/poc -smoke
echo "矩阵完成"
