package spa

import (
	"github.com/1uLang/libnet"
	"github.com/1uLang/libspa"
	libspasrv "github.com/1uLang/libspa/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type server struct{}

func (s server) OnConnect(conn *libnet.Connection) {
	log.Info("[SPA Serve]new connection ", conn.RemoteAddr())
}

func (s server) OnAuthority(body *libspa.Body, err error) (*libspasrv.Allow, error) {
	log.Info("==== spa body : ", body, err)
	// todo : 对客户端设备及身份进行验证
	// todo: 认证结果 写入到日志数据库中
	return &libspasrv.Allow{TcpPorts: viper.GetIntSlice("spa.allow.tcpPort"), UdpPorts: viper.GetIntSlice("spa.allow.udpPort")}, nil
}

func (s server) OnClose(conn *libnet.Connection, err error) {}

func RunServe() error {
	spaSrv := libspasrv.New()
	spaSrv.Port = viper.GetInt("spa.port")
	spaSrv.Protocol = viper.GetString("spa.protocol")
	spaSrv.Test = viper.GetBool("debug")
	spaSrv.SPATimeout = viper.GetInt("timeout.spa")
	spaSrv.RawTimeout = viper.GetInt("timeout.authority")
	spaSrv.Method = viper.GetString("spa.method")
	spaSrv.KEY = viper.GetString("spa.key")
	spaSrv.IV = viper.GetString("spa.iv")
	return spaSrv.Run()
}
