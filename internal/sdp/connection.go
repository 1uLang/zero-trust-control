package sdp

import (
	"errors"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/utils/maps"
	"github.com/1uLang/zero-trust-control/internal/clients"
	"github.com/1uLang/zero-trust-control/internal/gateways"
	message2 "github.com/1uLang/zero-trust-control/internal/message"
	log "github.com/sirupsen/logrus"
	"net"
)

type connect struct {
	*libnet.Connection
}

func newConnection(c *libnet.Connection) *connect {
	return &connect{c}
}

// 处理消息
func (this *connect) onMessage(msg *message2.Message) {
	switch msg.MsgId() {
	case message2.LoginRequestCode:
		this.handleLoginMessage(msg)
	case message2.KeepaliveRequestCode:
		this.handleKeepaliveMessage(msg)
	case message2.AHLogoutRequestCode:
		this.handleAHLogoutMessage(msg)
	case message2.IHLogoutRequestCode:
		this.handleIHLogoutMessage(msg)
	case message2.CustomRequestCode:
		this.handleCustomMessage(msg)
	}
}

// 控制器 处理ih/ah 登录消息
func (this *connect) handleLoginMessage(msg *message2.Message) {
	isOk := false
	var code int
	var isClient bool
	var isGateway bool
	data, err := msg.DecodeData()
	if err != nil {
		this.replyError("msg decode options err : " + err.Error())
		return
	}
	defer func() {
		if !isOk {
			_ = this.Close("handleAuthMessage failed")
		}
	}()
	replyMap := maps.Map{}
	fmt.Println("===== new login message data:", data)
	if data.GetInt("type") == message2.ConnectionClient {
		isClient = true
		code, err = clients.Login(data)
	} else if data.GetInt("type") == message2.ConnectionGateway {
		isGateway = true
		code, err = gateways.Login(data)
	} else {
		code = -1
		err = errors.New("错误的连接类型")
	}
	// 登录异常
	if code != 0 {
		defer func() {
			this.Close("")
		}() //断开tcp连接
	}
	replyMap = maps.Map{
		"code":    code,
		"message": err.Error(),
	}
	reply := &message2.Message{
		Type: message2.LoginResponseCode,
		Data: replyMap.AsJSON(),
	}
	_, err = this.writeClient(reply.Marshal())
	if err != nil {
		this.replyError("write client err : " + err.Error())
		return
	}
	isOk = true
	if isClient {
		this.handleClientLogin(data)
	} else if isGateway {
		this.handleGatewayLogin(data)
	}
}

// 控制器 处理心跳
func (this *connect) handleKeepaliveMessage(msg *message2.Message) {
}

// 控制器 自定义消息
func (this *connect) handleCustomMessage(msg *message2.Message) {
	//todo: 处理自定义消息
}

// 控制器 处理网关登录消息
func (this *connect) handleClientLogin(m maps.Map) {
	//todo: 通知客户端所关联的所有网关
	//todo: 向客户端发送所关联的网关信息列表
}

// 控制器 处理网关登录消息
func (this *connect) handleGatewayLogin(m maps.Map) {
	//todo: 向网关发送其保护的源站服务信息

	reply := &message2.Message{
		Type: message2.LoginResponseCode,
		Data: maps.Map{
			"ips": []string{"182.150.0.71"},
		}.AsJSON(),
	}
	_, err := this.writeClient(reply.Marshal())
	if err != nil {
		this.replyError("[gateway login response]write client err : " + err.Error())
		return
	}
}

// 控制器 处理网关注销消息
func (this *connect) handleAHLogoutMessage(msg *message2.Message) {
	//todo: 向网关发送其保护的源站服务信息
}

// 控制器 处理客户端注销消息
func (this *connect) handleIHLogoutMessage(msg *message2.Message) {
	//todo: 向网关发送其保护的源站服务信息
}

// 向客户端回复错误信息
func (this *connect) writeClient(msg []byte) (n int, err error) {

	// 加入认证丢包重发机制
	resend := 5
SEND:
	n, err = this.Write(msg)
	if err != nil {
		resend--
		if resend > 0 {
			goto SEND
		} else {
			return
		}
	}
	return
}
func (this *connect) replyError(msg string) {
	reply := &message2.Message{
		Type: message2.CustomRequestCode,
		Data: maps.Map{
			"error": msg,
		}.AsJSON(),
	}
	_, _ = this.Write(reply.Marshal())
}

func (this *connect) onError(err error) {
	if err == nil {
		return
	}
	_, ok := err.(*net.OpError)
	if !ok {
		log.Fatal(err)
	}
	_ = this.Close("onError: " + err.Error())
}
