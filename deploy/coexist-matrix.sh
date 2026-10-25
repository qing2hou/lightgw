#!/bin/sh
# T007 共存矩阵：四类宿主形态 × 引擎行为（debian:bookworm --privileged）
# 执行：sh coexist-matrix.sh 2>&1 | tee /tmp/matrix-run.log
# 退出码判定：grep -c "^FAIL" /tmp/matrix-run.log 必须为 0
# （QA 复验教训：bare sh 无 set -e/--pipefail，脚本内 FAIL 行会被静默吞掉——
#  判定责任交给执行者，脚本头写清约定）
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
/poc -smoke-legacy; echo "legacy 冒烟退出码=$?（fail-fast 生效时输出 PASS + LegacyConflictError 文本并退出 0；看上方 PASS/FAIL 行判定）"

echo "===== 场景 C：vanilla（无任何宿主防火墙；清 A/B 残留）====="
iptables-legacy -F 2>/dev/null; iptables-legacy -X 2>/dev/null
iptables-legacy -t filter -P FORWARD ACCEPT 2>/dev/null
iptables -F 2>/dev/null; iptables -X 2>/dev/null
iptables -t filter -P FORWARD ACCEPT 2>/dev/null
nft delete table ip filter 2>/dev/null
nft delete table inet filter 2>/dev/null
nft delete table inet haweb 2>/dev/null
iptables-legacy -F 2>/dev/null; iptables-legacy -X 2>/dev/null; iptables-legacy -P FORWARD ACCEPT 2>/dev/null
iptables -F 2>/dev/null; iptables -X 2>/dev/null; iptables -P FORWARD ACCEPT
nft delete table ip filter 2>/dev/null
nft list tables
/poc -smoke
echo "矩阵完成"

echo "===== 场景 D：firewalld 形态（inet filter FORWARD policy drop + FWDI_ 链族）====="
# firewalld nftables backend 特征：inet 家族 filter 表 + FORWARD base chain
# （firewalld 默认把 FORWARD policy 设 drop，放行走 FWDI_<zone> 链族）+
# FWDI_public/FWDI_trusted 链。断言：锚点装 inet filter FORWARD 链头、
# FWDI_* 链与 haweb 表共存不动（QA 增量复验定的完整形态）。
iptables-legacy -t filter -P FORWARD ACCEPT 2>/dev/null
nft delete table inet haweb 2>/dev/null
nft add table inet filter
nft add chain inet filter 'FORWARD { type filter hook forward priority 10; policy drop; }'
nft add chain inet filter FWDI_public
nft add chain inet filter FWDI_trusted
echo "-- firewalld 形态就位："
nft list tables
/poc -smoke-hostsim
echo "-- 锚点应装 inet filter FORWARD 链头、FWDI_* 不动："
nft list chain inet filter FORWARD
nft list tables

echo "===== 矩阵完成（判定：grep -c '^FAIL' 不为 0 即失败）====="
