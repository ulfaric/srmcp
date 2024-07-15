package server

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/certs"
	"github.com/ulfaric/srmcp/messages"
)

// ConnectedClient represents a connected client.
type ConnectedClient struct {
	ID            string
	Address       string
	ControlConn   *tls.Conn
	DataConn      map[int]*tls.Conn
	EncryptionKey []byte
	mu            sync.Mutex
}

// Server represents a server with secured IP socket, control channel, and a list of connected clients.
type Server struct {
	ID              string
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

	id := uuid.New()

	return &Server{
		ID:         id.String(),
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

	log.Printf("Control Channel Handshake successful with Client at %s", tlsConn.RemoteAddr().String())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Clients[tlsConn.RemoteAddr().String()] = &ConnectedClient{
		Address:     tlsConn.RemoteAddr().String(),
		ControlConn: tlsConn,
		DataConn:    make(map[int]*tls.Conn),
	}
	log.Printf("Client at %s connected", tlsConn.RemoteAddr().String())

	for {
		headerBuffer := make([]byte, 88)
		_, err := tlsConn.Read(headerBuffer)
		if err != nil {
			if err == io.EOF {
				log.Printf("Client at %s closed control connection", tlsConn.RemoteAddr().String())
				return
			}
			log.Fatalf("Failed to read from client at %s: %v", tlsConn.RemoteAddr().String(), err)
			return
		}
		var header messages.Header
		err = srmcp.Deserializer(headerBuffer, &header)
		if err != nil {
			log.Fatalf("Failed to deserialize message header: %v", err)
		}

		bodyBuffer := make([]byte, header.Length)
		_, err = tlsConn.Read(bodyBuffer)
		if err != nil {
			log.Fatalf("Failed to read message body: %v", err)
		}

		switch header.MessageType {
		case srmcp.Hello:
			s.Clients[tlsConn.RemoteAddr().String()].ID = header.SenderID
			log.Printf("Received HEL message from client %s", header.SenderID)
			err = s.Hello(tlsConn.RemoteAddr().String())
			if err != nil {
				log.Fatalf("Failed to send Hello message to client at %s: %v", tlsConn.RemoteAddr().String(), err)
			}
		case srmcp.HandShake:
			var handshakeMessage messages.HandShake
			err = srmcp.Deserializer(bodyBuffer, &handshakeMessage)
			if err != nil {
				log.Fatalf("Failed to deserialize handshake message: %v", err)
			}
			s.Clients[tlsConn.RemoteAddr().String()].mu.Lock()
			defer s.Clients[tlsConn.RemoteAddr().String()].mu.Unlock()
			s.Clients[tlsConn.RemoteAddr().String()].EncryptionKey = handshakeMessage.EncryptionKey
			log.Printf("Received HSH message from client %s, encryption key: %x", header.SenderID, handshakeMessage.EncryptionKey)
			err = s.HandShake(tlsConn.RemoteAddr().String())
			if err != nil {
				log.Fatalf("Failed to send Handshake message to client at %s: %v", tlsConn.RemoteAddr().String(), err)
			}
		}

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

func (s *Server) HandShake(addr string) error {
	// create a new encryption key
	key, err := srmcp.GenerateRandomKey()
	log.Printf("Generated server encryption key: %x", key)
	if err != nil {
		return fmt.Errorf("failed to generate encryption key: %v", err)
	}
	// create a new handshake message with the client's ID and the encryption key
	handshakeMessage := messages.NewHandShake(key)
	body, err := handshakeMessage.Encode()
	if err != nil {
		return fmt.Errorf("failed to serialize handshake message: %v", err)
	}
	//encrypt the handshake message body
	encryptedBody, err := srmcp.Encrypt(s.Clients[addr].EncryptionKey, body)
	if err != nil {
		return fmt.Errorf("failed to encrypt handshake message body: %v", err)
	}
	// create the handshake message header
	header := messages.Header{
		MessageType: srmcp.HandShake,
		SenderID:    s.ID,
		Timestamp:   time.Now().Format(time.RFC3339Nano),
		Length:      uint32(len(encryptedBody)),
	}
	headerBytes, err := srmcp.Serializer(header)
	if err != nil {
		return fmt.Errorf("failed to serialize handshake header: %v", err)
	}
	bytes := append(headerBytes, encryptedBody...)
	// send the handshake message to the server
	_, err = s.Clients[addr].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send handshake message to server: %v", err)
	}
	return nil
}
