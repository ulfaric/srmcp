package server

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"sync"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/google/uuid"
	"github.com/ulfaric/srmcp/certs"
	"github.com/ulfaric/srmcp/node"
)

// ConnectedClient represents a connected client.
type ConnectedClient struct {
	ID           string
	ControlConn  *tls.Conn
	DataConn     []*tls.Conn
	SharedSecret []byte
	PublicKey    *kyber1024.PublicKey
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
	for {
		conn, err := s.ControlListener.Accept()
		if err != nil {
			continue
		} else {
			go s.HandleControlConn(conn)
		}
	}
}

// Stop gracefully shuts down the server by cancelling the context, closing the control listener, and waiting for all connections to finish.
func (s *Server) Stop() {
	log.Println("Shutting down server...")
	s.ControlListener.Close()
	for _, client := range s.Clients {
		client.ControlConn.Close()
		for _, conn := range client.DataConn {
			conn.Close()
		}
	}
	log.Println("Server has been shut down.")
}

// AddNode adds a new node to the server's node list.
func (s *Server) AddNode(name string, value interface{}, readFunc *func() (interface{}, error), writeFunc *func(interface{}) error) *node.Node {
	id := uuid.New().String()
	s.Nodes[id] = &node.Node{
		ID:    id,
		Name:  name,
		Value: value,
		Read:  readFunc,
		Write: writeFunc,
	}
	return s.Nodes[id]
}

// GetNodesByName returns all nodes with the given name.
func (s *Server) GetNodesByName(name string) []*node.Node {
	var matchingNodes []*node.Node
	for _, n := range s.Nodes {
		if n.Name == name {
			matchingNodes = append(matchingNodes, n)
		}
	}
	return matchingNodes
}


// RemoveNode removes a node from the server's node list.
func (s *Server) RemoveNode(id string) {
	delete(s.Nodes, id)
}
