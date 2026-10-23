VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -X main.version=$(VERSION)

.PHONY: web build build-go run test vet clean

# 构建前端（输出到 web/dist，由 go:embed 嵌入）
web:
	cd web && npm install && npm run build

# 构建单二进制
build: web
	go build -ldflags "$(LDFLAGS)" -o bin/haproxyweb .

# 仅构建后端（使用已有的 web/dist）
build-go:
	go build -ldflags "$(LDFLAGS)" -o bin/haproxyweb .

# 本地开发：仅启动后端（前端由 vite dev server 提供，代理 /api 到 8080）
dev:
	cd web && npm run dev & \
	go run .

test:
	go test ./...

vet:
	go vet ./...

# 只清理构建产物；数据目录（SQLite、密钥）不属于构建产物，绝不删除
clean:
	rm -f bin/haproxyweb
	rm -rf web/dist
