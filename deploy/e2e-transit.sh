#!/bin/sh
# M1 端到端穿越验证（AC-1.1）：veth+netns 拓扑，真实 fw 编译层+nft 引擎路径
# 前置：宿主已构建 /tmp/poc-runner（go build -o /tmp/poc-runner ./cmd/poc）
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq iproute2 iptables tcpdump iputils-ping >/dev/null 2>&1
/poc -e2e
