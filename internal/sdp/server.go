package sdp

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/1uLang/libnet"
	"github.com/1uLang/libnet/connection"
	"github.com/1uLang/libnet/encrypt"
	"github.com/1uLang/libnet/options"
	"github.com/1uLang/zero-trust-control/internal/message"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
)

type server struct {
	clientBuffer *message.Buffer
}

var svr = server{}

func (this server) OnConnect(conn *connection.Connection) {

}

func (this server) OnMessage(c *connection.Connection, bytes []byte) {
	// setup buffer
	this.clientBuffer = message.NewBuffer()
	this.clientBuffer.OnMessage(newConnection(connect).onMessage)
	if len(bytes) > 0 {
		this.clientBuffer.Write(bytes)
	}
}

func (this server) OnClose(conn *connection.Connection, err error) {
}

func RunServe() error {

	method, err := encrypt.NewMethod(viper.GetString("sdp.encrypt.method"))
	if err != nil {
		return errors.New("获取本地IP失败：" + err.Error())
	}
	sdpSvr, err := libnet.NewServe(fmt.Sprintf(":%d", viper.GetInt("sdp.port")), svr,
		options.WithEncryptMethod(method),
		options.WithEncryptMethodPublicKey([]byte(viper.GetString("sdp.encrypt.key"))),
		options.WithEncryptMethodPrivateKey([]byte(viper.GetString("sdp.encrypt.iv"))),
	)
	if err != nil {
		log.Fatal("[SDP Control] start serve failed : ", err)
		return err
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
	return sdpSvr.RunTLS(tlsConfig)
}
