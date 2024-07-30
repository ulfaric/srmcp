package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/messages"
	"github.com/ulfaric/srmcp/node"
)

func (s *Server) DigestEncryptedMessage(conn *tls.Conn, clientIndex string) (*messages.Header, []byte, error) {
	// Read the pre-header
	preHeaderBuffer := make([]byte, 8)
	if _, err := io.ReadFull(conn, preHeaderBuffer); err != nil {
		return nil, nil, err
	}

	// Extract the header and body lengths
	headerLength := binary.BigEndian.Uint32(preHeaderBuffer[:4])
	bodyLength := binary.BigEndian.Uint32(preHeaderBuffer[4:])

	// Read the header
	headerBuffer := make([]byte, headerLength)
	if _, err := io.ReadFull(conn, headerBuffer); err != nil {
		return nil, nil, err
	}
	headerBytes, err := srmcp.Decrypt(s.Clients[clientIndex].SharedSecret, headerBuffer)
	if err != nil {
		return nil, nil, err
	}

	// Deserialize the header
	var header messages.Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, err
	}

	// Validate the header
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(header); err != nil {
		return nil, nil, err
	}

	// Read the body
	bodyBuffer := make([]byte, bodyLength)
	if _, err := io.ReadFull(conn, bodyBuffer); err != nil {
		return nil, nil, err

	}

	return &header, bodyBuffer, nil
}

// StartDataConn starts the data connection by listening on the server's address and a random port.
func (s *Server) StartDataConn(clientIndex string, dataport uint32, timeout int) error {
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

	addr := fmt.Sprintf("%s:%d", s.Address, dataport)
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}
	log.Printf("New Datalink for client %s is listening on %s", s.Clients[clientIndex].ID, addr)

	go s.AcceptDataConn(clientIndex, listener, dataport)
	go func() {
		time.Sleep(time.Duration(timeout) * time.Second)
		err := listener.Close()
		if err == nil {
			log.Printf("Datalink listener on %s for client %s closed due to inactivity", listener.Addr().String(), s.Clients[clientIndex].ID)
		}
	}()
	return nil
}

// AcceptDataConn accepts incoming data connections from clients.
func (s *Server) AcceptDataConn(clientIndex string, listener net.Listener, dataport uint32) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	go s.HandleDataConn(conn, clientIndex, dataport)
	listener.Close()
	log.Printf("Datalink listener on %s accepted connection from client %s and closed", listener.Addr().String(), s.Clients[clientIndex].ID)
}

// HandleDataConn handles the data connection with the client.
func (s *Server) HandleDataConn(conn net.Conn, clientIndex string, dataport uint32) {
	// TLS Handshake
	defer func() {
		conn.Close()
		s.mu.Lock()
		s.AvaliableDataPort = append(s.AvaliableDataPort, dataport)
		s.mu.Unlock()
	}()
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("Data Channel Handshake failed with Client %s: %v", s.Clients[clientIndex].ID, err)
		return
	}
	log.Printf("Data Channel Handshake successful with Client %s", s.Clients[clientIndex].ID)

	// Add the data connection to the client's data connection map
	s.Clients[clientIndex].mu.Lock()
	s.Clients[clientIndex].DataConn = append(s.Clients[clientIndex].DataConn, tlsConn)
	s.Clients[clientIndex].mu.Unlock()
	log.Printf("Client %s connected to data channel on port %d", s.Clients[clientIndex].ID, dataport)

	// Read data from the client
	for {
		header, _, err := s.DigestEncryptedMessage(tlsConn, clientIndex)
		if err == nil {
			switch header.MessageType {
			case srmcp.Discovery:
				s.HandleDiscovery(clientIndex, header)
			}
		} else {
			continue
		}
	}
}

func (s *Server) HandleDiscovery(clientIndex string, header *messages.Header) {
	nodesInfo := make([]*node.NodeInfo, 0)
	for nodeID := range s.Nodes {
		nodesInfo = append(nodesInfo, node.GetNodeInfo(s.Nodes[nodeID]))
	}
	nodesInfoBytes, err := json.Marshal(nodesInfo)
	if err != nil {
		log.Printf("Failed to marshal node information: %v", err)
		return
	}
	encryptedNodesInfo, err := srmcp.Encrypt(s.Clients[clientIndex].SharedSecret, nodesInfoBytes)
	if err != nil {
		log.Printf("Failed to encrypt node information: %v", err)
		return
	}

	responseHeader := &messages.Header{
		MessageType:   srmcp.Discovery,
		SenderID:      s.ID,
		Timestamp:     time.Now(),
		TransactionID: header.TransactionID,
		Index:         1.0,
	}
	responseHeaderBytes, err := json.Marshal(responseHeader)
	if err != nil {
		log.Printf("Failed to marshal response header: %v", err)
		return
	}
	encryptedResponseHeader, err := srmcp.Encrypt(s.Clients[clientIndex].SharedSecret, responseHeaderBytes)
	if err != nil {
		log.Printf("Failed to encrypt response header: %v", err)
		return
	}

	preHeader := messages.PreHeader{
		HeaderLength: uint32(len(encryptedResponseHeader)),
		BodyLength:   uint32(len(encryptedNodesInfo)),
	}
	preHeaderBytes := preHeader.Serialize()

	bytes := append(preHeaderBytes, encryptedResponseHeader...)
	bytes = append(bytes, encryptedNodesInfo...)

	dataportIndex := rand.Intn(len(s.Clients[clientIndex].DataConn))
	_, err = s.Clients[clientIndex].DataConn[dataportIndex].Write(bytes)
	if err != nil {
		log.Printf("Failed to send discovery response to client %s: %v", s.Clients[clientIndex].ID, err)
		return
	}
	log.Printf("Sent discovery response to client %s", s.Clients[clientIndex].ID)
}

func (s *Server) HandleRead(clientIndex string, header *messages.Header) {

}
