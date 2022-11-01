package spa

import (
	"errors"
	"github.com/1uLang/libnet/connection"
	"github.com/1uLang/libnet/encrypt"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/libspa"
	libspasrv "github.com/1uLang/libspa/server"
	"github.com/spf13/viper"
	"time"
)

type server struct {
}

func (s server) OnConnect(conn *connection.Connection) {

}

func (s server) OnAuthority(body *libspa.Body, err error) (*libspasrv.Allow, error) {

	// todo : 对客户端设备及身份进行验证
	// todo: 认证结果 写入到日志数据库中
	return &libspasrv.Allow{TcpPorts: viper.GetIntSlice("spa.allow.tcpPort"), UdpPorts: viper.GetIntSlice("spa.allow.udpPort")}, nil
}

func (s server) OnClose(conn *connection.Connection, err error) {
}

var srv = server{}

func RunServe() error {
	spaSrv := libspasrv.New()
	spaSrv.Port = viper.GetInt("spa.port")
	spaSrv.Protocol = viper.GetString("spa.protocol")
	spaSrv.Test = viper.GetBool("debug")
	spaSrv.Timeout = viper.GetInt("timeout.spa")
	method, err := encrypt.NewMethod(viper.GetString("spa.method"))
	if err != nil {
		return errors.New("获取本地IP失败：" + err.Error())
	}
	return spaSrv.Run(srv,
		options.WithEncryptMethod(method),
		options.WithEncryptMethodPublicKey([]byte(viper.GetString("spa.key"))),
		options.WithEncryptMethodPrivateKey([]byte(viper.GetString("spa.iv"))),
		options.WithTimeout(time.Duration(viper.GetInt("timeout.connect"))*time.Second))
}
