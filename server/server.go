package server

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net"
	"sync"
	"io"

	"github.com/ulfaric/srmcp/certs"
)

// Client represents a connected client.
type Client struct {
	ID   string
	Conn net.Conn
	Cert *x509.Certificate
}

// Server represents a server with secured IP socket, control channel, and a list of connected clients.
type Server struct {
	Cert        *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CACert      *x509.Certificate
	ControlConn net.Conn
	Clients     map[string]*Client
	mu          sync.Mutex
}

// NewServer creates a new Server instance by reading the certificate and key from files.
func NewServer(certFile, keyFile, caCertFile string) (*Server, error) {
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

	return &Server{
		Cert:       cert,
		PrivateKey: key,
		CACert:     caCert,
		Clients:    make(map[string]*Client),
	}, nil
}

// AddClient adds a new client to the server's client list.
func (s *Server) AddClient(id string, conn net.Conn, cert *x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Clients[id] = &Client{
		ID:   id,
		Conn: conn,
		Cert: cert,
	}
}

// RemoveClient removes a client from the server's client list.
func (s *Server) RemoveClient(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Clients, id)
}

// GetClient retrieves a client from the server's client list.
func (s *Server) GetClient(id string) (*Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, exists := s.Clients[id]
	return client, exists
}

// StartTLSListener starts a TLS listener for the server.
func (s *Server) StartTLSListener(addr string) (net.Listener, error) {
	cert, err := tls.X509KeyPair(EncodeCertificatePEM(s.Cert), EncodePrivateKeyPEM(s.PrivateKey))
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certs.LoadCertPool(s.CACert),
		// InsecureSkipVerify: true,
		// VerifyPeerCertificate: s.verifyClientCertificate,
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}

	return listener, nil
}

// verifyClientCertificate is a custom client certificate verification function.
func (s *Server) verifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// Parse the client's certificate
	clientCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}

	// Verify that the client's certificate was signed by the same CA
	roots := x509.NewCertPool()
	roots.AddCert(s.CACert)
	opts := x509.VerifyOptions{
		Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := clientCert.Verify(opts); err != nil {
		return err
	}

	return nil
}

// Run starts the server and listens for incoming TLS connections.
func (s *Server) Run(addr string) {
	listener, err := s.StartTLSListener(addr)
	if err != nil {
		log.Fatalf("Failed to start TLS listener: %v", err)
		return
	}
	defer listener.Close()

	log.Printf("Server is listening on %s\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	tlsConn := conn.(*tls.Conn)

	err := tlsConn.Handshake()
	if err != nil {
		// Simply close the connection without logging the error or sending alerts
		log.Printf("Failed to perform TLS handshake: %v", err)
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Println("No client certificate provided")
		return
	}

	clientCert := state.PeerCertificates[0]

	clientID := conn.RemoteAddr().String()
	s.AddClient(clientID, conn, clientCert)
	log.Printf("Client %s connected.", clientID)
	// Read and log incoming messages
	buf := make([]byte, 1024)
	for {
		n, err := tlsConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from client %s: %v", clientID, err)
				s.RemoveClient(clientID)
				return
			}
		}
		if n == 0 {
			continue
		}
		message := string(buf[:n])
		log.Printf("Received message from client %s: %s", clientID, message)
	}

}

func EncodeCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func EncodePrivateKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
