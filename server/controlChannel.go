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

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/go-playground/validator/v10"
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/messages"
)

func DigestMessage(conn *tls.Conn) (*messages.Header, []byte, error) {
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

	// Deserialize the header
	var header messages.Header
	if err := json.Unmarshal(headerBuffer, &header); err != nil {
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
	return nil
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
	s.Clients[clientIndex] = &ConnectedClient{
		ControlConn: tlsConn,
		DataConn:    make([]*tls.Conn, 0),
	}
	s.mu.Unlock()
	log.Printf("Client from %s connected", clientIndex)

	for {
		header, body, err := DigestMessage(tlsConn)
		if err == nil {
			switch header.MessageType {
			case srmcp.HandShake:
				go s.HandleHandShake(clientIndex, header, body)
			case srmcp.DataLinkReq:
				go s.HandleDateLinkReq(header, clientIndex)
			default:
				log.Printf("Received unknown message type from client %s", header.SenderID)
			}
		} else {
			continue
		}

	}
}

// HandleHandShake handles the HSH message from the client.
func (s *Server) HandleHandShake(clientIndex string, header *messages.Header, bodyBuffer []byte) {
	// Extract the client ID
	s.Clients[clientIndex].mu.Lock()
	s.Clients[clientIndex].ID = header.SenderID
	s.Clients[clientIndex].mu.Unlock()
	// Unpack the public key
	var handshakeMessage messages.HandShake
	json.Unmarshal(bodyBuffer, &handshakeMessage)
	var publicKey kyber1024.PublicKey
	publicKey.Unpack(handshakeMessage.PublicKey)
	s.Clients[clientIndex].mu.Lock()
	s.Clients[clientIndex].PublicKey = &publicKey
	s.Clients[clientIndex].mu.Unlock()
	log.Printf("Received HSH message from client %s", header.SenderID)

	// Encapsulate the shared secret
	cipherText := make([]byte, kyber1024.CiphertextSize)
	sharedSecret := make([]byte, kyber1024.SharedKeySize)
	s.Clients[clientIndex].PublicKey.EncapsulateTo(cipherText, sharedSecret, nil)
	s.Clients[clientIndex].mu.Lock()
	s.Clients[clientIndex].SharedSecret = sharedSecret
	s.Clients[clientIndex].mu.Unlock()
	log.Printf("Encapsulated shared secret for client %s: %x", header.SenderID, sharedSecret)

	// prepare the response
	handshakeResponse := messages.HandShakeResponse{
		CipherText: cipherText,
	}
	bodyBytes, err := json.Marshal(handshakeResponse)
	if err != nil {
		log.Printf("Failed to serialize handshake response message: %v", err)
	}
	reponseHeader := messages.Header{
		MessageType:   srmcp.HandShake,
		SenderID:      s.ID,
		Timestamp:     time.Now(),
		TransactionID: header.TransactionID,
		Index:         1.0,
		Segment:       1,
	}
	headerBytes, err := json.Marshal(reponseHeader)
	if err != nil {
		log.Printf("Failed to serialize handshake response header: %v", err)
	}
	responsePreHeader := messages.PreHeader{
		HeaderLength: uint32(len(headerBytes)),
		BodyLength:   uint32(len(bodyBytes)),
	}
	preHeaderBytes := responsePreHeader.Serialize()
	bytes := append(preHeaderBytes, headerBytes...)
	bytes = append(bytes, bodyBytes...)
	_, err = s.Clients[clientIndex].ControlConn.Write(bytes)
	if err != nil {
		log.Printf("Failed to send Handshake response message to client %s: %v", header.SenderID, err)
	}

}

func (s *Server) HandleDateLinkReq(header *messages.Header, clientIndex string) {
	log.Printf("Received DLR message from client %s", header.SenderID)
	dataport := s.AvaliableDataPort[rand.Intn(len(s.AvaliableDataPort))]
	s.StartDataConn(clientIndex, dataport, 5)

	// Send the response
	respheader := messages.Header{
		MessageType:   srmcp.DataLinkRep,
		SenderID:      s.ID,
		Timestamp:     time.Now(),
		TransactionID: header.TransactionID,
		Index:         1.0,
		Segment:       1,
	}
	respheaderBytes, err := json.Marshal(respheader)
	if err != nil {
		log.Printf("Failed to serialize DataLinkRep message header: %v", err)
	}

	bodyBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bodyBytes, dataport)
	encryptedBodyBytes, err := srmcp.Encrypt(s.Clients[clientIndex].SharedSecret, bodyBytes)
	if err != nil {
		log.Printf("Failed to encrypt DataLinkRep message body: %v", err)
	}
	responsePreHeader := messages.PreHeader{
		HeaderLength: uint32(len(respheaderBytes)),
		BodyLength:   uint32(len(encryptedBodyBytes)),
	}
	preHeaderBytes := responsePreHeader.Serialize()
	bytes := append(preHeaderBytes, respheaderBytes...)
	bytes = append(bytes, encryptedBodyBytes...)
	_, err = s.Clients[clientIndex].ControlConn.Write(bytes)
	if err != nil {
		log.Printf("Failed to send DataLinkRep message to client %s: %v", header.SenderID, err)
	}

}
