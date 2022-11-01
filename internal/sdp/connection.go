package sdp

import (
	"errors"
	"github.com/1uLang/libnet/connection"
	"github.com/1uLang/zero-trust-control/internal/clients"
	"github.com/1uLang/zero-trust-control/internal/gateways"
	"github.com/1uLang/zero-trust-control/internal/message"
	"github.com/1uLang/zero-trust-control/utils/maps"
)

const (
	connection_type = iota
	connection_client
	connection_gateway
)

type connect struct {
	*connection.Connection
}

func newConnection(c *connection.Connection) connect {
	return connect{c}
}

// 处理消息
func (this *connect) onMessage(msg *message.Message) {
	switch msg.Code {
	case message.LoginRequestCode:
		this.handleLoginMessage(msg)
	case message.KeepaliveRequestCode:
		this.handleKeepaliveMessage(msg)
	case message.AHLogoutRequestCode:
		this.handleAHLogoutMessage(msg)
	case message.IHLogoutRequestCode:
		this.handleIHLogoutMessage(msg)
	case message.CustomRequestCode:
		this.handleCustomMessage(msg)
	}
}

// 控制器 处理ih/ah 登录消息
func (this *connect) handleLoginMessage(msg *message.Message) {
	isOk := false
	var code int
	var isClient bool
	var isGateway bool
	data, err := msg.DecodeOptions()
	if err != nil {
		this.replyError("msg decode options err : " + err.Error())
		return
	}
	// 加入认证丢包重发机制
	resend := 5
	defer func() {
		if !isOk {
			_ = this.Close("handleAuthMessage failed")
		}
	}()
	replyMap := maps.Map{}

	if data.GetInt("type") == connection_client {
		isClient = true
		code, err = clients.Login(data)
	} else if data.GetInt("type") == connection_gateway {
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
	reply := &message.Message{
		Code: message.LoginResponseCode,
		Data: replyMap.AsJSON(),
	}
SEND:
	_, err = this.writeClient(reply.Marshal())
	if err != nil {
		resend--
		if resend > 0 {
			goto SEND
		} else {
			this.replyError("write client err : " + err.Error())
			return
		}
	}
	isOk = true
	if isClient {
		this.handleClientLogin(data)
	} else if isGateway {
		this.handleGatewayLogin(data)
	}
}

// 控制器 处理心跳
func (this *connect) handleKeepaliveMessage(msg *message.Message) {
	//todo: 续租 redis中 网关/客户端 认证信息
}

// 控制器 自定义消息
func (this *connect) handleCustomMessage(msg *message.Message) {
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
}

// 控制器 处理网关注销消息
func (this *connect) handleAHLogoutMessage(msg *message.Message) {
	//todo: 向网关发送其保护的源站服务信息
}

// 控制器 处理客户端注销消息
func (this *connect) handleIHLogoutMessage(msg *message.Message) {
	//todo: 向网关发送其保护的源站服务信息
}

// 向客户端回复错误信息
func (this *connect) writeClient(msg []byte) (n int, err error) {

	return this.Write(msg)
}
func (this *connect) replyError(msg string) {
	reply := &message.Message{
		Code: message.CustomRequestCode,
		Data: maps.Map{
			"error": msg,
		}.AsJSON(),
	}
	_, _ = this.Write(reply.Marshal())
}
