package client

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/google/uuid"
	"github.com/ulfaric/srmcp/certs"
)

type ConnectedServer struct {
	ID           string
	Address      string
	Port         uint32
	ControlConn  *tls.Conn
	DataConn     map[uint32]*tls.Conn
	PublicKey    *kyber1024.PublicKey
	PrivateKey   *kyber1024.PrivateKey
	SharedSecret []byte
	Transactions map[string]*Transaction
	mu           sync.Mutex
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
		Transactions: make(map[string]*Transaction),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	serverIndex := fmt.Sprintf("%s:%d", addr, port)
	c.Servers[serverIndex] = connectedServer
	log.Printf("Connected to server at %s", addr)
	// Start listening for control messages from the server.
	go c.HandleControlConn(conn)
	// Send a Hello message to the server.
	err = c.Hello(serverIndex)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to send Hello message to server: %v", err)
	}
	err = c.HandShake(serverIndex)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to send HandShake message to server: %v", err)
	}
	return nil
}

// Close closes the connection to the server at the given address.
func (c *Client) Close(serverIndex string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	server, ok := c.Servers[serverIndex]
	if !ok {
		log.Printf("Server at %s not found", serverIndex)
		return nil
	}
	server.ControlConn.Close()
	log.Printf("Client closed control connection to server %s on %s", c.Servers[serverIndex].ID, server.ControlConn.RemoteAddr().String())
	for _, conn := range server.DataConn {
		log.Printf("Client closed data connection to server %s on %s", c.Servers[serverIndex].ID, conn.RemoteAddr().String())
		conn.Close()
	}
	log.Printf("Disconnected from server %s", c.Servers[serverIndex].ID)
	delete(c.Servers, serverIndex)
	return nil
}
