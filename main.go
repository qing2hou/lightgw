package main

import (
	"embed"
	"flag"
	"log"

	"haproxyweb/internal/platform/app"
)

//go:embed all:web/dist
var distFS embed.FS

// version 由构建时 -ldflags 注入（git describe），开发态为 dev。
var version = "dev"

func main() {
	configPath := flag.String("c", "", "配置文件路径（默认 ./config.yaml）")
	checkMode := flag.Bool("check", false, "校验配置与数据库后退出（升级/改配置前使用）")
	flag.Parse()

	// 全部装配逻辑在 platform/app.Run：main 只负责参数解析与分发，
	// 这样启动流程可以被集成测试直接调用（S5 DoD：main.go ≤ 100 行）。
	if err := app.Run(app.Options{
		ConfigPath: *configPath,
		CheckOnly:  *checkMode,
		Version:    version,
		WebAssets:  distFS,
	}); err != nil {
		log.Fatalf("%v", err)
	}
}
