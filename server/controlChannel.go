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

	go s.AcceptControlConn()
	return nil
}

// AcceptControlConn accepts incoming control connections from clients.
func (s *Server) AcceptControlConn() {
	for {
		conn, err := s.ControlListener.Accept()
		if err != nil {
			continue
		} else {
			go s.HandleControlConn(conn)
		}
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
		header, body, err := DigestMessage(tlsConn)
		if err == nil {
			switch header.MessageType {
			case srmcp.Hello:
				s.HandleHello(clientIndex, header)
			case srmcp.HandShake:
				s.HandleHandShake(clientIndex, header, body)
			case srmcp.DataLinkReq:
				s.HandleDateLinkReq(header, clientIndex)
			default:
				log.Printf("Received unknown message type from client %s", header.SenderID)
			}
		} else {
			continue
		}

	}
}

// Hello sends a HEL message to the client.
func (s *Server) Hello(clientIndex string, header *messages.Header) error {
	repHeader := messages.Header{
		MessageType: srmcp.Hello,
		SenderID:    s.ID,
		Timestamp:   time.Now(),
		TransactionID: header.TransactionID,
	}
	headerBytes, err := json.Marshal(repHeader)
	if err != nil {
		log.Printf("Failed to serialize Hello message header: %v", err)
	}

	preHeader := messages.PreHeader{
		HeaderLength: uint32(len(headerBytes)),
		BodyLength:   0,
	}
	preHeaderBytes := preHeader.Serialize()

	bytes := append(preHeaderBytes, headerBytes...)
	_, err = s.Clients[clientIndex].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send Hello message to client at %s: %v", clientIndex, err)
	}
	return nil

}

func (s *Server) HandleHello(clientIndex string, header *messages.Header) {
	s.Clients[clientIndex].mu.Lock()
	s.Clients[clientIndex].ID = header.SenderID
	s.Clients[clientIndex].mu.Unlock()
	log.Printf("Received HEL message from client %s", header.SenderID)
	err := s.Hello(clientIndex, header)
	if err != nil {
		log.Print(err)
	}
}

func (s *Server) HandleHandShake(clientIndex string, header *messages.Header, bodyBuffer []byte) {
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
		MessageType: srmcp.HandShake,
		SenderID:    s.ID,
		Timestamp:   time.Now(),
		TransactionID: header.TransactionID,
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
		MessageType: srmcp.DataLinkRep,
		SenderID:    s.ID,
		Timestamp:   time.Now(),
		TransactionID: header.TransactionID,
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

// // HandleDateLinkReq handles the DLR message from the client.
// func (s *Server) HandleDateLinkReq(header messages.Header, clientIndex string) {
// 	log.Printf("Received DLR message from client %s", header.SenderID)
// 	dataport := s.AvaliableDataPort[rand.Intn(len(s.AvaliableDataPort))]
// 	s.StartDataConn(clientIndex, dataport)
// 	s.DataLinkRep(clientIndex, dataport)
// }

// // HandleHandShake handles the HSH message from the client.
// func (s *Server) HandleHandShake(bodyBuffer []byte, clientIndex string, header messages.Header) {
// 	var handshakeMessage messages.HandShake
// 	err := srmcp.Deserializer(bodyBuffer, &handshakeMessage)
// 	if err != nil {
// 		log.Printf("Failed to deserialize handshake message: %v", err)
// 	}
// 	s.Clients[clientIndex].mu.Lock()
// 	s.Clients[clientIndex].ClientKey = handshakeMessage.EncryptionKey
// 	s.Clients[clientIndex].mu.Unlock()
// 	log.Printf("Received HSH message from client %s, encryption key: %x", header.SenderID, handshakeMessage.EncryptionKey)
// 	err = s.HandShake(clientIndex)
// 	if err != nil {
// 		log.Printf("Failed to send Handshake message to client %s: %v", s.Clients[clientIndex].ID, err)
// 	}
// }

// // HandleHello handles the HEL message from the client.
// func (s *Server) HandleHello(clientIndex string, header messages.Header) {
// 	s.Clients[clientIndex].mu.Lock()
// 	s.Clients[clientIndex].ID = header.SenderID
// 	s.Clients[clientIndex].mu.Unlock()
// 	log.Printf("Received HEL message from client %s", header.SenderID)
// 	err := s.Hello(clientIndex)
// 	if err != nil {
// 		log.Printf("Failed to send Hello message to client %s: %v", s.Clients[clientIndex].ID, err)
// 	}
// }

// // HandShake sends a HSH message to the client at the given address.
// func (s *Server) HandShake(clientIndex string) error {
// 	// create a new encryption key
// 	key, err := srmcp.GenerateRandomKey()
// 	s.Clients[clientIndex].ServerKey = key
// 	log.Printf("Generated server encryption key: %x", key)
// 	if err != nil {
// 		return fmt.Errorf("failed to generate encryption key: %v", err)
// 	}
// 	// create a new handshake message with the client's ID and the encryption key
// 	handshakeMessage := messages.NewHandShake(key)
// 	body, err := handshakeMessage.Encode()
// 	if err != nil {
// 		return fmt.Errorf("failed to serialize handshake message: %v", err)
// 	}
// 	//encrypt the handshake message body
// 	encryptedBody, err := srmcp.Encrypt(s.Clients[clientIndex].ClientKey, body)
// 	if err != nil {
// 		return fmt.Errorf("failed to encrypt handshake message body: %v", err)
// 	}
// 	// create the handshake message header
// 	header := messages.Header{
// 		MessageType: srmcp.HandShake,
// 		SenderID:    s.ID,
// 		Timestamp:   time.Now().Format(time.RFC3339Nano),
// 		Length:      uint32(len(encryptedBody)),
// 	}
// 	headerBytes, err := srmcp.Serializer(header)
// 	if err != nil {
// 		return fmt.Errorf("failed to serialize handshake header: %v", err)
// 	}
// 	bytes := append(headerBytes, encryptedBody...)
// 	// send the handshake message to the server
// 	_, err = s.Clients[clientIndex].ControlConn.Write(bytes)
// 	if err != nil {
// 		return fmt.Errorf("failed to send handshake message to server: %v", err)
// 	}
// 	return nil
// }

// // DataLinkRep sends a DLR message to the client at the given address.
// func (s *Server) DataLinkRep(clientIndex string, dataport uint32) {
// 	var bytes []byte
// 	// create a new subscription response message with the data port
// 	subscriptionResponse := messages.NewDataLinkRep(uint32(dataport))
// 	body, err := subscriptionResponse.Encode()
// 	if err != nil {
// 		log.Printf("Failed to serialize subscription response message: %v", err)
// 	}
// 	encryptedBody, err := srmcp.Encrypt(s.Clients[clientIndex].ServerKey, body)
// 	if err != nil {
// 		log.Printf("Failed to encrypt subscription response message: %v", err)
// 	}
// 	header := messages.Header{
// 		MessageType: srmcp.DataLinkRep,
// 		SenderID:    s.ID,
// 		Timestamp:   time.Now().Format(time.RFC3339Nano),
// 		Length:      uint32(len(encryptedBody)),
// 	}
// 	headerBytes, err := srmcp.Serializer(header)
// 	if err != nil {
// 		log.Printf("Failed to serialize subscription response header: %v", err)
// 	}
// 	bytes = append(headerBytes, encryptedBody...)
// 	// send the subscription response message to the client
// 	_, err = s.Clients[clientIndex].ControlConn.Write(bytes)
// 	if err != nil {
// 		log.Printf("Failed to send subscription response message to client %s: %v", s.Clients[clientIndex].ID, err)
// 	}
// }
