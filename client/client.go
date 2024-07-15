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
	ID            string
	Address       string
	ControlConn   *tls.Conn
	DataConn      map[int]*tls.Conn
	ServerKey []byte
	ClientKey []byte
	mu            sync.Mutex
}

type Client struct {
	ID            string
	Cert          *x509.Certificate
	PrivateKey    *rsa.PrivateKey
	CACert        *x509.Certificate
	Servers       map[string]*ConnectedServer
	mu            sync.Mutex
}

// NewClient creates a new client with the given certificate, private key, and CA certificate.
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

// Connect connects the client to the server at the given address.
func (c *Client) Connect(addr string) error {
	// Create a new TLS connection to the server.
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
		log.Fatalf("failed to connect with server at %s: %v", addr, err)
		return err
	}
	// Create a new ConnectedServer struct and add it to the client's map of servers.
	connectedServer := &ConnectedServer{
		Address:     addr,
		ControlConn: conn,
		DataConn:    make(map[int]*tls.Conn),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Servers[addr] = connectedServer
	log.Printf("Connected to server at %s", addr)
	// Start listening for control messages from the server.
	go c.listenForServerControlMessages(conn)
	// Send a Hello message to the server.
	err = c.Hello(addr)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to send Hello message to server: %v", err)
	}
	return nil
}

// Hello sends a HEL message to the server at the given address.
func (c *Client) Hello(addr string) error {
	// Create a new Hello message with the client's ID and the current time.
	helloMessage := messages.NewHello(c.ID, time.Now())
	// Serialize the Hello message.
	bytes, err := helloMessage.Encode()
	if err != nil {
		return fmt.Errorf("failed to serialize Hello message: %v", err)
	}
	// Send the Hello message to the server.
	_, err = c.Servers[addr].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send Hello message to server: %v", err)
	}
	return nil
}

// HandShake sends a HSH message to the server at the given address.
func (c *Client) HandShake(addr string) error {
	// create a new encryption key
	key, err := srmcp.GenerateRandomKey()
	c.Servers[addr].ClientKey = key
	log.Printf("Generated client encryption key: %x", key)
	if err != nil {
		return fmt.Errorf("failed to generate encryption key: %v", err)
	}
	// create a new handshake message with the client's ID and the encryption key
	handshakeMessage := messages.NewHandShake(key)
	body, err := handshakeMessage.Encode()
	if err != nil {
		return fmt.Errorf("failed to serialize handshake message: %v", err)
	}
	header := messages.Header{
		MessageType: srmcp.HandShake,
		SenderID:    c.ID,
		Timestamp:   time.Now().Format(time.RFC3339Nano),
		Length:      uint32(len(body)),
	}
	headerBytes, err := srmcp.Serializer(header)
	if err != nil {
		return fmt.Errorf("failed to serialize handshake header: %v", err)
	}
	bytes := append(headerBytes, body...)
	// send the handshake message to the server
	_, err = c.Servers[addr].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send handshake message to server: %v", err)
	}
	return nil
}

func (c *Client) Subscribe(addr string) error {
	subscribeMessage := messages.NewSubscribe(c.ID, time.Now())
	bytes, err := subscribeMessage.Encode()
	if err != nil {
		return fmt.Errorf("failed to serialize subscribe message: %v", err)
	}
	_, err = c.Servers[addr].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send subscribe message to server: %v", err)
	}
	return nil
}

// listenForServerControlMessages listens for control messages from the server.
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
			log.Fatalf("Failed to deserialize message header: %v", err)
		}

		bodyBuffer := make([]byte, header.Length)
		_, err = conn.Read(bodyBuffer)
		if err != nil {
			log.Fatalf("Failed to read message body: %v", err)
		}

		switch header.MessageType {
		case srmcp.Hello:
			c.Servers[conn.RemoteAddr().String()].ID = header.SenderID
			log.Printf("Received HEL message from server %s", header.SenderID)
		case srmcp.HandShake:
			body, err := srmcp.Decrypt(c.Servers[conn.RemoteAddr().String()].ClientKey, bodyBuffer)
			if err != nil {
				log.Fatalf("Failed to decrypt handshake message: %v", err)
			}
			var handshakeMessage messages.HandShake
			err = srmcp.Deserializer(body, &handshakeMessage)
			if err != nil {
				log.Fatalf("Failed to deserialize handshake message: %v", err)
			}
			c.Servers[conn.RemoteAddr().String()].mu.Lock()
			defer c.Servers[conn.RemoteAddr().String()].mu.Unlock()
			c.Servers[conn.RemoteAddr().String()].ServerKey = handshakeMessage.EncryptionKey
			log.Printf("Received HSH message from server %s, encryption key: %x", header.SenderID, handshakeMessage.EncryptionKey)
			c.Subscribe(conn.RemoteAddr().String())
		case srmcp.SubscriptionResponse:
			log.Printf("Received SBR message from server %s", header.SenderID)
			body, err := srmcp.Decrypt(c.Servers[conn.RemoteAddr().String()].ServerKey, bodyBuffer)
			if err != nil {
				log.Fatalf("Failed to decrypt subscription response message: %v", err)
			}
			var subscriptionResponse messages.SubscriptionResponse
			err = srmcp.Deserializer(body, &subscriptionResponse)
			if err != nil {
				log.Fatalf("Failed to deserialize subscription response message: %v", err)
			}
			log.Printf("Subscription response: %d", subscriptionResponse.DataPort)
		}

	}
}

// Close closes the connection to the server at the given address.
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
