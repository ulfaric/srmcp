package server

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ulfaric/srmcp/certs"
	"github.com/ulfaric/srmcp/messages"
	"github.com/ulfaric/srmcp/node"
)

// ConnectedClient represents a connected client.
type ConnectedClient struct {
	ID           string
	ControlConn  *tls.Conn
	DataConn	 map[uint32]*tls.Conn
	ServerKey    []byte
	ClientKey    []byte
	mu           sync.Mutex
}

// Server represents a server with secured IP socket, control channel, and a list of connected clients.
type Server struct {
	ID                string
	Address           string
	Port              int
	Cert              *x509.Certificate
	PrivateKey        *rsa.PrivateKey
	CACert            *x509.Certificate
	ControlListener   net.Listener
	Clients           map[string]*ConnectedClient
	Nodes             map[string]*node.Node
	AvaliableDataPort []uint32
	mu                sync.Mutex
}

// NewServer creates a new Server instance by reading the certificate and key from files.
func NewServer(certFile, keyFile, caCertFile, address string, port int) (*Server, error) {
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
	var availableDataPorts []uint32

	for i := uint32(40000); i <= 49999; i++ {
		availableDataPorts = append(availableDataPorts, i)
	}
	return &Server{
		ID:                id.String(),
		Address:           address,
		Port:              port,
		Cert:              cert,
		PrivateKey:        key,
		CACert:            caCert,
		Clients:           make(map[string]*ConnectedClient),
		Nodes:             make(map[string]*node.Node),
		AvaliableDataPort: availableDataPorts,
	}, nil
}

// Run starts the server by establishing the control connection.
func (s *Server) Run() error {
	log.Println("Starting server...")
	err := s.StartControlConn()
	if err != nil {
		return err
	}
	return nil
}

// Stop gracefully shuts down the server by cancelling the context, closing the control listener, and waiting for all connections to finish.
func (s *Server) Stop() {
	log.Println("Shutting down server...")
	s.ControlListener.Close()
	log.Println("Server has been shut down.")
}

// Hello sends a HEL message to the server at the given address.
func (s *Server) Hello(addr string) error {
	// Create a new Hello message with the client's ID and the current time.
	helloMessage := messages.NewHello(s.ID, time.Now())
	// Serialize the Hello message.
	bytes, err := helloMessage.Encode()
	if err != nil {
		return fmt.Errorf("failed to serialize Hello message: %v", err)
	}
	// Send the Hello message to the server.
	_, err = s.Clients[addr].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send Hello message to server: %v", err)
	}
	return nil
}

// AddNode adds a new node to the server's node list.
func (s *Server) AddNode(name string, value interface{}) {
	id := uuid.New().String()
	s.Nodes[id] = node.NewNode(id, name, value)
}

// RemoveNode removes a node from the server's node list.
func (s *Server) RemoveNode(id string) {
	delete(s.Nodes, id)
}
