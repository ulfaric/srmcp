package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/messages"
)

// StartControlConn starts the control connection by listening on the server's address and port.
func (s *Server) StartControlConn() error {
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

	addr := fmt.Sprintf("%s:%d", s.Address, s.Port)
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}
	s.ControlListener = listener
	log.Printf("Server Control channel listening on %s", addr)

	go s.AcceptControlConn()
	return nil
}

// AcceptControlConn accepts incoming control connections from clients.
func (s *Server) AcceptControlConn() {
	for {
		conn, err := s.ControlListener.Accept()
		if err != nil {
			return
		}
		go s.HandleControlConn(conn)
	}
}

// HandleControlConn handles the control connection with the client.
func (s *Server) HandleControlConn(conn net.Conn) {
	defer conn.Close()
	tlsConn := conn.(*tls.Conn)
	clientIndex := tlsConn.RemoteAddr().String()
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("Control Channel Handshake failed with Client from %s: %v", clientIndex, err)
		return
	}

	log.Printf("Control Channel Handshake successful with Client from %s", clientIndex)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Clients[clientIndex] = &ConnectedClient{
		ControlConn: tlsConn,
		DataConn:    make(map[uint32]*tls.Conn),
	}
	log.Printf("Client from %s connected", clientIndex)

	for {
		headerBuffer := make([]byte, 88)
		_, err := tlsConn.Read(headerBuffer)
		if err != nil {
			if err == io.EOF {
				log.Printf("Client %s closed control connection", s.Clients[clientIndex].ID)
				return
			}
			log.Fatalf("Failed to read from client %s: %v", s.Clients[clientIndex].ID, err)
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
			s.HandleHello(clientIndex, header)
		case srmcp.HandShake:
			s.HandleHandShake(bodyBuffer, clientIndex, header)
		case srmcp.DataLinkReq:
			s.HandleDateLinkReq(header, clientIndex)
		default:
			log.Printf("Received unknown message type from client %s", header.SenderID)
		}

	}
}

// HandleDateLinkReq handles the DLR message from the client.
func (s *Server) HandleDateLinkReq(header messages.Header, clientIndex string) {
	log.Printf("Received DLR message from client %s", header.SenderID)
	dataport := s.AvaliableDataPort[rand.Intn(len(s.AvaliableDataPort))]
	s.StartDataConn(clientIndex, dataport)
	s.DataLinkRep(clientIndex, dataport)
}

// HandleHandShake handles the HSH message from the client.
func (s *Server) HandleHandShake(bodyBuffer []byte, clientIndex string, header messages.Header) {
	var handshakeMessage messages.HandShake
	err := srmcp.Deserializer(bodyBuffer, &handshakeMessage)
	if err != nil {
		log.Fatalf("Failed to deserialize handshake message: %v", err)
	}
	s.Clients[clientIndex].mu.Lock()
	s.Clients[clientIndex].ClientKey = handshakeMessage.EncryptionKey
	s.Clients[clientIndex].mu.Unlock()
	log.Printf("Received HSH message from client %s, encryption key: %x", header.SenderID, handshakeMessage.EncryptionKey)
	err = s.HandShake(clientIndex)
	if err != nil {
		log.Fatalf("Failed to send Handshake message to client %s: %v", s.Clients[clientIndex].ID, err)
	}
}

// HandleHello handles the HEL message from the client.
func (s *Server) HandleHello(clientIndex string, header messages.Header) {
	s.Clients[clientIndex].mu.Lock()
	s.Clients[clientIndex].ID = header.SenderID
	s.Clients[clientIndex].mu.Unlock()
	log.Printf("Received HEL message from client %s", header.SenderID)
	err := s.Hello(clientIndex)
	if err != nil {
		log.Fatalf("Failed to send Hello message to client %s: %v", s.Clients[clientIndex].ID, err)
	}
}

// HandShake sends a HSH message to the client at the given address.
func (s *Server) HandShake(clientIndex string) error {
	// create a new encryption key
	key, err := srmcp.GenerateRandomKey()
	s.Clients[clientIndex].ServerKey = key
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
	encryptedBody, err := srmcp.Encrypt(s.Clients[clientIndex].ClientKey, body)
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
	_, err = s.Clients[clientIndex].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send handshake message to server: %v", err)
	}
	return nil
}

// DataLinkRep sends a DLR message to the client at the given address.
func (s *Server) DataLinkRep(clientIndex string, dataport uint32) {
	var bytes []byte
	// create a new subscription response message with the data port
	subscriptionResponse := messages.NewDataLinkRep(uint32(dataport))
	body, err := subscriptionResponse.Encode()
	if err != nil {
		log.Fatalf("Failed to serialize subscription response message: %v", err)
	}
	encryptedBody, err := srmcp.Encrypt(s.Clients[clientIndex].ServerKey, body)
	if err != nil {
		log.Fatalf("Failed to encrypt subscription response message: %v", err)
	}
	header := messages.Header{
		MessageType: srmcp.DataLinkRep,
		SenderID:    s.ID,
		Timestamp:   time.Now().Format(time.RFC3339Nano),
		Length:      uint32(len(encryptedBody)),
	}
	headerBytes, err := srmcp.Serializer(header)
	if err != nil {
		log.Fatalf("Failed to serialize subscription response header: %v", err)
	}
	bytes = append(headerBytes, encryptedBody...)
	// send the subscription response message to the client
	_, err = s.Clients[clientIndex].ControlConn.Write(bytes)
	if err != nil {
		log.Fatalf("Failed to send subscription response message to client %s: %v", s.Clients[clientIndex].ID, err)
	}
}
