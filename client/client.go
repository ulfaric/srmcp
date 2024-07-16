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
	Port        uint32
	ControlConn *tls.Conn
	DataConn    map[uint32]*tls.Conn
	ServerKey   []byte
	ClientKey   []byte
	mu          sync.Mutex
}

type Client struct {
	ID         string
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
	CACert     *x509.Certificate
	Servers    map[string]*ConnectedServer
	mu         sync.Mutex
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
func (c *Client) Connect(addr string, port uint32) error {
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

	serverAddr := fmt.Sprintf("%s:%d", addr, port)
	conn, err := tls.Dial("tcp", serverAddr, config)
	if err != nil {
		log.Fatalf("failed to connect with server at %s: %v", addr, err)
		return err
	}
	// Create a new ConnectedServer struct and add it to the client's map of servers.
	connectedServer := &ConnectedServer{
		Address:     addr,
		Port:        port,
		ControlConn: conn,
		DataConn:    make(map[uint32]*tls.Conn),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	serverIndex := fmt.Sprintf("%s:%d", addr, port)
	c.Servers[serverIndex] = connectedServer
	log.Printf("Connected to server at %s", addr)
	// Start listening for control messages from the server.
	go c.ListenForServerControlMessages(conn)
	// Send a Hello message to the server.
	err = c.Hello(serverIndex)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to send Hello message to server: %v", err)
	}
	return nil
}

func (c *Client) ListenForServerControlMessages(conn *tls.Conn) {
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
			c.handleHello(conn, header)
		case srmcp.HandShake:
			c.handleHandShake(conn, header, bodyBuffer)
		case srmcp.DataLinkRep:
			c.handleDataLinkRep(conn, header, bodyBuffer)
		default:
			log.Printf("Received unknown message type from server %s: %s", header.SenderID, header.MessageType)
		}
	}
}

// handleHello handles a HEL message from a server.
func (c *Client) handleHello(conn *tls.Conn, header messages.Header) {
	serverAddr := conn.RemoteAddr().String()
	c.mu.Lock()
	defer c.mu.Unlock()
	server, ok := c.Servers[serverAddr]
	if !ok {
		log.Printf("Server at %s not found", serverAddr)
		return
	}
	server.ID = header.SenderID
	log.Printf("Received HEL message from server %s", header.SenderID)
}

// handleHandShake handles a HSH message from a server.
func (c *Client) handleHandShake(conn *tls.Conn, header messages.Header, bodyBuffer []byte) {
	serverIndex := conn.RemoteAddr().String()
	c.mu.Lock()
	server, ok := c.Servers[serverIndex]
	c.mu.Unlock()
	if !ok {
		log.Printf("Server at %s not found", serverIndex)
		return
	}

	// Decrypt the message body using the client's private key.
	body, err := srmcp.Decrypt(server.ClientKey, bodyBuffer)
	if err != nil {
		log.Fatalf("Failed to decrypt handshake message: %v", err)
		return
	}
	// Deserialize the decrypted message body.
	var handshakeMessage messages.HandShake
	err = srmcp.Deserializer(body, &handshakeMessage)
	if err != nil {
		log.Fatalf("Failed to deserialize handshake message: %v", err)
		return
	}
	// Store the server's encryption key.
	c.mu.Lock()
	defer c.mu.Unlock()
	server.ServerKey = handshakeMessage.EncryptionKey
	log.Printf("Received HSH message from server %s, encryption key: %x", header.SenderID, handshakeMessage.EncryptionKey)
	// Send a datalink request to the server.
	c.ReqDataLink(serverIndex)
}

// handleDataLinkRep handles a DLP message from a server.
func (c *Client) handleDataLinkRep(conn *tls.Conn, header messages.Header, bodyBuffer []byte) {
	serverIndex := conn.RemoteAddr().String()
	c.mu.Lock()
	server, ok := c.Servers[serverIndex]
	c.mu.Unlock()
	if !ok {
		log.Printf("Server at %s not found", serverIndex)
		return
	}
	
	body, err := srmcp.Decrypt(server.ServerKey, bodyBuffer)
	if err != nil {
		log.Fatalf("Failed to decrypt datalink response message: %v", err)
		return
	}
	var dataLinkRep messages.DataLinkRep
	err = srmcp.Deserializer(body, &dataLinkRep)
	if err != nil {
		log.Fatalf("Failed to deserialize datalink response message: %v", err)
		return
	}
	log.Printf("Received DLP message from server %s, DataPort: %d", header.SenderID, dataLinkRep.DataPort)
	c.ConnectDataLink(serverIndex, dataLinkRep.DataPort)
}

// Close closes the connection to the server at the given address.
func (c *Client) Close(severIndex string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	server, ok := c.Servers[severIndex]
	if !ok {
		log.Printf("Server at %s not found", severIndex)
		return nil
	}
	server.ControlConn.Close()
	log.Printf("Client closed control connection to server at %s", server.ControlConn.RemoteAddr().String())
	for _, conn := range server.DataConn {
		log.Printf("Client closed data connection to server at %s", conn.RemoteAddr().String())
		conn.Close()
	}
	delete(c.Servers, severIndex)
	log.Printf("Disconnected from server at %s", severIndex)
	return nil
}

func (c *Client) ConnectDataLink(serverIndex string, port uint32) error {
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
	serverDataLinkAddr := fmt.Sprintf("%s:%d", c.Servers[serverIndex].Address, port)
	conn, err := tls.Dial("tcp", serverDataLinkAddr, config)
	if err != nil {
		log.Fatalf("failed to connect with server datalink at %s: %v", serverDataLinkAddr, err)
		return err
	}

	// Add the data connection to the server's map of data connections.
	c.Servers[serverIndex].mu.Lock()
	defer c.Servers[serverIndex].mu.Unlock()
	c.Servers[serverIndex].DataConn[port] = conn
	log.Printf("Connected to server datalink at %s", serverDataLinkAddr)
	return nil
}

// Hello sends a HEL message to the server at the given address.
func (c *Client) Hello(serverIndex string) error {
	// Create a new Hello message with the client's ID and the current time.
	helloMessage := messages.NewHello(c.ID, time.Now())
	// Serialize the Hello message.
	bytes, err := helloMessage.Encode()
	if err != nil {
		return fmt.Errorf("failed to serialize Hello message: %v", err)
	}
	// Send the Hello message to the server.
	_, err = c.Servers[serverIndex].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send Hello message to server: %v", err)
	}
	return nil
}

// HandShake sends a HSH message to the server at the given address.
func (c *Client) HandShake(serverIndex string) error {
	// create a new encryption key
	key, err := srmcp.GenerateRandomKey()
	c.Servers[serverIndex].ClientKey = key
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
	_, err = c.Servers[serverIndex].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send handshake message to server: %v", err)
	}
	return nil
}

// ReqDataLink sends a datalink request to the server at the given address.
func (c *Client) ReqDataLink(serverIndex string) error {
	subscribeMessage := messages.NewDataLinkReq(c.ID, time.Now())
	bytes, err := subscribeMessage.Encode()
	if err != nil {
		return fmt.Errorf("failed to serialize subscribe message: %v", err)
	}
	_, err = c.Servers[serverIndex].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send subscribe message to server: %v", err)
	}
	return nil
}