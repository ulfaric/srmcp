package server

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net"
	"sync"

	"github.com/ulfaric/srmcp/certs"
)

// ConnectedClient represents a connected client.
type ConnectedClient struct {
	ID       string
	DataConn map[int]*tls.Conn
}

// Server represents a server with secured IP socket, control channel, and a list of connected clients.
type Server struct {
	Cert            *x509.Certificate
	PrivateKey      *rsa.PrivateKey
	CACert          *x509.Certificate
	ControlListener net.Listener
	Clients         map[string]*ConnectedClient
	mu              sync.Mutex
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
		Clients:    make(map[string]*ConnectedClient),
	}, nil
}

func (s *Server) StartControlConn(addr string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(s.PrivateKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
	}
	config.ClientCAs.AddCert(s.CACert)

	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}
	s.ControlListener = listener
	log.Printf("Server Control channel listening on %s", addr)

	go s.AcceptControlConn()
	return nil
}

func (s *Server) AcceptControlConn() {
	for {
		conn, err := s.ControlListener.Accept()
		if err != nil {
			return
		}
		go s.handleControlConn(conn)
	}
}

func (s *Server) handleControlConn(conn net.Conn) {
	defer conn.Close()
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("Control Channel Handshake failed with Client at %s: %v", tlsConn.RemoteAddr().String(), err)
		return
	}

	for {
		buf := make([]byte, 1024)
		n, err := tlsConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Printf("Client at %s closed connection", tlsConn.RemoteAddr().String())
				return
			}
			log.Printf("Failed to read from client at %s: %v", tlsConn.RemoteAddr().String(), err)
			return
		}
		log.Printf("Received %d bytes from client at %s: %s", n, tlsConn.RemoteAddr().String(), string(buf))
	}
}



// Run starts the server by establishing the control connection.
func (s *Server) Run(addr string) error {
	log.Println("Starting server...")
	err := s.StartControlConn(addr)
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
