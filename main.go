package main

import (
	"flag"
	"github.com/1uLang/zero-trust-control/internal/cache"
	"github.com/1uLang/zero-trust-control/internal/config"
	"github.com/1uLang/zero-trust-control/internal/logs"
	"github.com/1uLang/zero-trust-control/internal/sdp"
	"github.com/1uLang/zero-trust-control/internal/spa"
	log "github.com/sirupsen/logrus"
)

var (
	cfgFile = flag.String("c", "config.yaml", "set config file")
)

func main() {
	// 参数解析
	flag.Parse()
	// 初始化配置文件
	config.Init(*cfgFile)
	// 初始化log
	logs.Init()
	// 初始化redis
	if err := cache.SetRedis(); err != nil {
		log.Fatal("init redis failed : ", err)
		return
	}
	// 启动 spa 服务
	go spa.RunServe()

	// 启动 sdp 服务
	sdp.RunServe()
}
