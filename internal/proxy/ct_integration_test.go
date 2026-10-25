//go:build ctverify

// QA P1-1 集成验证（容器 root 环境跑）：
//
//	docker run --rm --privileged -v $PWD:/src -w /src -e GOPROXY=off \
//	  -e GOFLAGS=-mod=mod golang:xxx go test -tags ctverify ./internal/proxy/ -run TestCTIntegration -v
package proxy

import (
	"strings"
	"testing"
)

func TestCTIntegration(t *testing.T) {
	lines := readConntrackTable()
	if lines == nil {
		t.Skip("conntrack 表不可读（无 conntrack 二进制且 /proc 不可读）")
	}
	t.Logf("解析到 %d 条 tcp/udp 表项", len(lines))
	for _, ln := range lines {
		if strings.Contains(ln, "192.168.100.2") {
			t.Logf("目标会话: %s", ln)
		}
	}
}
