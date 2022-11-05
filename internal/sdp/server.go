package sdp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/encrypt"
	"github.com/1uLang/libnet/message"
	"github.com/1uLang/libnet/options"
	message2 "github.com/1uLang/zero-trust-control/internal/message"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
)

type server struct {
}

var svr = server{}

func (this server) OnConnect(conn *libnet.Connection) {
	log.Info("[SDP Serve]new connection ", conn.RemoteAddr())
	// setup buffer
	c := newConnection(conn)
	buffer := message.NewBuffer(message2.CheckHeader)
	buffer.OptValidateId = true
	buffer.OnMessage(func(msg message.MessageI) {
		c.onMessage(msg.(*message2.Message))
	})
	buffer.OnError(c.onError)
	err := conn.SetBuffer(buffer)
	if err != nil {
		log.Fatal("[SDP Serve] set connection buffer error", err)
		conn.Close("set connection buffer" + err.Error())
	}
}

func (this server) OnMessage(c *libnet.Connection, bytes []byte) {}

func (this server) OnClose(conn *libnet.Connection, reason string) {

	log.Warn("[SDP Serve]close connection ", conn.RemoteAddr(), "  ", reason)
}

func RunServe() error {

	opts := []options.Option{}
	if viper.GetString("sdp.encrypt.method") != "" {
		method, err := encrypt.NewMethodInstance(viper.GetString("sdp.encrypt.method"), viper.GetString("sdp.encrypt.key"), viper.GetString("sdp.encrypt.key"))
		if err != nil {
			return errors.New("初始化加密方法错误：" + err.Error())
		}
		opts = append(opts, options.WithEncryptMethod(method))
	}
	caCertFile, err := os.ReadFile(viper.GetString("sdp.ca"))
	if err != nil {
		log.Fatalf("error reading CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertFile)

	certificate, err := tls.LoadX509KeyPair(viper.GetString("sdp.cert"), viper.GetString("sdp.key"))
	if err != nil {
		log.Fatalf("could not load certificate: %v", err)
	}
	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{certificate},
		ClientCAs:                caCertPool,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		InsecureSkipVerify: true,
	}
	return libnet.NewServe(fmt.Sprintf(":%d", viper.GetInt("sdp.port")), svr, opts...).RunTLS(tlsConfig)
}
