package client

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	// "encoding/pem"
	// "io"
	// "log"
	// "net"
	"sync"

	"github.com/ulfaric/srmcp/certs"
)

type ConnectedServer struct {
	ID          string
	DataConn    map[int]*tls.Conn
}

type Client struct {
	ID          string
	Cert        *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CACert      *x509.Certificate
	ControlConn *tls.Conn
	Servers     map[string]*ConnectedServer
	mu          sync.Mutex
}

func NewClient(certFile, keyFile, caCertFile string) (*Client, error) {
	cert, err := certs.LoadCertificate(certFile)
	if err != nil {
		return nil, err
	}

	key, err := certs.LoadPrivateKey(keyFile)
	if err != nil {
		return nil, err
	}

	caCert, err := certs.LoadCertificate(caCertFile)
	if err != nil {
		return nil, err
	}

	return &Client{
		Cert:       cert,
		PrivateKey: key,
		CACert:     caCert,
		Servers:    make(map[string]*ConnectedServer),
	}, nil
}

