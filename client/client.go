package client

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/certs"
	"github.com/ulfaric/srmcp/messages"
)

type ConnectedServer struct {
	ID          string
	Address     string
	ControlConn *tls.Conn
	DataConn    map[int]*tls.Conn
}

type Client struct {
	ID         string
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
	CACert     *x509.Certificate
	Servers    map[string]*ConnectedServer
	mu         sync.Mutex
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

	id := uuid.New()

	return &Client{
		ID:         id.String(),
		Cert:       cert,
		PrivateKey: key,
		CACert:     caCert,
		Servers:    make(map[string]*ConnectedServer),
	}, nil
}

func (c *Client) Connect(addr string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.PrivateKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      x509.NewCertPool(),
	}
	config.RootCAs.AddCert(c.CACert)

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		log.Printf("failed to connect with server at %s: %v", addr, err)
		return err
	}

	connectedServer := &ConnectedServer{
		Address:     addr,
		ControlConn: conn,
		DataConn:    make(map[int]*tls.Conn),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.Servers[addr] = connectedServer
	log.Printf("Connected to server at %s", addr)

	err = c.SendHello(addr)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to send Hello message to server: %v", err)
	}

	go c.listenForServerControlMessages(conn)
	return nil

}

func (c *Client) SendHello(addr string) (error) {
	helloMessage := &messages.Header{
		MessageType: "HEL",
		SenderID:    c.ID,
		Timestamp:   time.Now().Format(time.RFC3339Nano),
		Length:      0,
	}

	bytes, err := srmcp.Serializer(helloMessage)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %v", err)
	}

	_, err = c.Servers[addr].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send Hello message to server: %v", err)
	}
	return nil
}

func (c *Client) listenForServerControlMessages(conn *tls.Conn) {
	for {
		headerBuffer := make([]byte, 88)
		_, err := conn.Read(headerBuffer)
		if err != nil {
			if err == io.EOF {
				log.Printf("Server at %s closed control connection", conn.RemoteAddr().String())
				return
			}
			return
		}
		var header messages.Header
		err = srmcp.Deserializer(headerBuffer, &header)
		if err != nil {
			log.Printf("Failed to deserialize message header: %v", err)
		}

		bodyBuffer := make([]byte, header.Length)
		_, err = conn.Read(bodyBuffer)
		if err != nil {
			log.Printf("Failed to read message body: %v", err)
		}

		switch header.MessageType {
		case "HEL":
			c.Servers[conn.RemoteAddr().String()].ID = header.SenderID
			log.Printf("Received HEL message from server %s", header.SenderID)
		}

	}
}

func (c *Client) Close(addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	server, ok := c.Servers[addr]
	if !ok {
		log.Printf("Server at %s not found", addr)
		return nil
	}
	server.ControlConn.Close()
	for _, conn := range server.DataConn {
		log.Printf("Closed data connection to server at %s", addr)
		conn.Close()
	}
	delete(c.Servers, addr)
	log.Printf("Disconnected from server at %s", addr)
	return nil
}
