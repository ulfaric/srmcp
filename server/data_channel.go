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

// Validator instance for struct validation
var validate = validator.New(validator.WithRequiredStructEnabled())

// DigestEncryptedMessage reads and returns the encrypted message header and body from the connection
func (s *Server) DigestEncryptedMessage(conn *tls.Conn, clientIndex string) ([]byte, []byte, error) {
	preHeaderBuffer := make([]byte, 8)
	if _, err := io.ReadFull(conn, preHeaderBuffer); err != nil {
		return nil, nil, err
	}

	// Extract header and body lengths from the pre-header buffer
	headerLength := binary.BigEndian.Uint32(preHeaderBuffer[:4])
	bodyLength := binary.BigEndian.Uint32(preHeaderBuffer[4:])

	// Read the header
	headerBuffer := make([]byte, headerLength)
	if _, err := io.ReadFull(conn, headerBuffer); err != nil {
		return nil, nil, err
	}

	// Read the body
	bodyBuffer := make([]byte, bodyLength)
	if _, err := io.ReadFull(conn, bodyBuffer); err != nil {
		return nil, nil, err
	}

	return headerBuffer, bodyBuffer, nil
}

// StartDataConn initializes a new data connection for the client
func (s *Server) StartDataConn(clientIndex string, dataport uint32, timeout int) error {
	// Encode server certificate and private key to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Cert.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(s.PrivateKey)})

	// Load the certificate and key pair
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}

	// Configure TLS settings
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    x509.NewCertPool(),
	}
	config.ClientCAs.AddCert(s.CACert)

	// Start listening on the specified address and port
	addr := fmt.Sprintf("%s:%d", s.Address, dataport)
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}
	log.Printf("New Datalink for client %s is listening on %s", s.Clients[clientIndex].ID, addr)

	// Accept data connections in a separate goroutine
	go s.AcceptDataConn(clientIndex, listener, dataport)
	// Close the listener after the timeout period
	go func() {
		time.Sleep(time.Duration(timeout) * time.Second)
		if err := listener.Close(); err == nil {
			log.Printf("Datalink listener on %s for client %s closed due to inactivity", listener.Addr().String(), s.Clients[clientIndex].ID)
		}
	}()
	return nil
}

// AcceptDataConn accepts a new data connection from the listener
func (s *Server) AcceptDataConn(clientIndex string, listener net.Listener, dataport uint32) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	// Handle the data connection in a separate goroutine
	go s.HandleDataConn(conn, clientIndex, dataport)
	listener.Close()
	log.Printf("Datalink listener on %s accepted connection from client %s and closed", listener.Addr().String(), s.Clients[clientIndex].ID)
}

// Segmenting splits the encrypted body into smaller chunks for transmission
func (s *Server) Segmenting(header *messages.Header, clientIndex string, encryptedBody []byte) [][]byte {
	// Determine the number of chunks
	numChunks := rand.Intn(len(s.Clients[clientIndex].DataConn)) + 1
	dataLen := len(encryptedBody)
	chunkSize := (dataLen + numChunks - 1) / numChunks
	segments := make([][]byte, 0, numChunks)
	for i := 0; i < dataLen; i += chunkSize {
		end := i + chunkSize
		if end > dataLen {
			end = dataLen
		}
		segments = append(segments, encryptedBody[i:end])
	}
	log.Printf("Split %s response into %d chunks for client %s", header.MessageType, numChunks, s.Clients[clientIndex].ID)
	return segments
}

// TransmitSegments sends the segmented data to the client
func (s *Server) TransmitSegments(segments [][]byte, header *messages.Header, clientIndex string) error {
	for i, chunk := range segments {
		index := float64(i+1) / float64(len(segments))
		responseHeader := &messages.Header{
			MessageType:   header.MessageType,
			SenderID:      s.ID,
			Timestamp:     time.Now(),
			TransactionID: header.TransactionID,
			Index:         index,
			Segment:       len(segments),
		}

		// Marshal the response header to JSON
		responseHeaderBytes, err := json.Marshal(responseHeader)
		if err != nil {
			log.Printf("Failed to marshal response header: %v", err)
			return err
		}

		// Encrypt the response header
		encryptedResponseHeader, err := srmcp.Encrypt(s.Clients[clientIndex].SharedSecret, responseHeaderBytes)
		if err != nil {
			log.Printf("Failed to encrypt response header: %v", err)
			return err
		}

		// Create the pre-header
		preHeader := messages.PreHeader{
			HeaderLength: uint32(len(encryptedResponseHeader)),
			BodyLength:   uint32(len(chunk)),
		}

		preHeaderBytes := preHeader.Serialize()

		// Combine pre-header, encrypted header, and chunk into a single byte slice
		bytes := append(preHeaderBytes, encryptedResponseHeader...)
		bytes = append(bytes, chunk...)

		// Send the combined byte slice to the client
		dataportIndex := rand.Intn(len(s.Clients[clientIndex].DataConn))
		if _, err = s.Clients[clientIndex].DataConn[dataportIndex].Write(bytes); err != nil {
			log.Printf("Failed to send read response to client %s: %v", s.Clients[clientIndex].ID, err)
			return err
		}
		log.Printf("Sent read response chunk %f to client %s", index, s.Clients[clientIndex].ID)
	}
	return nil
}

// HandleDataConn handles the data connection for the client
func (s *Server) HandleDataConn(conn net.Conn, clientIndex string, dataport uint32) {
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

	s.Clients[clientIndex].mu.Lock()
	s.Clients[clientIndex].DataConn = append(s.Clients[clientIndex].DataConn, tlsConn)
	s.Clients[clientIndex].mu.Unlock()
	log.Printf("Client %s connected to data channel on port %d", s.Clients[clientIndex].ID, dataport)

	for {
		// Read and decrypt the message header and body
		headerBuffer, bodyBuffer, err := s.DigestEncryptedMessage(tlsConn, clientIndex)
		if err != nil {
			log.Printf("Closes data channel with client %s on port %d, %v", clientIndex, dataport, err)
			return
		}

		headerBytes, err := srmcp.Decrypt(s.Clients[clientIndex].SharedSecret, headerBuffer)
		if err != nil {
			log.Printf("Failed to decrypt data message header from client %s: %v", s.Clients[clientIndex].ID, err)
			continue
		}

		var header messages.Header
		if err := json.Unmarshal(headerBytes, &header); err != nil {
			log.Printf("Failed to unmarshal data message header from client %s: %v", s.Clients[clientIndex].ID, err)
			continue
		}

		if err := validate.Struct(header); err != nil {
			log.Printf("Invalid data message header from client %s: %v", s.Clients[clientIndex].ID, err)
			continue
		}

		// Handle the message based on its type
		switch header.MessageType {
		case srmcp.Discovery:
			go s.HandleDiscovery(clientIndex, &header)
		case srmcp.Read:
			go s.HandleRead(clientIndex, &header, bodyBuffer)
		case srmcp.Write:
			go s.HandleWrite(clientIndex, &header, bodyBuffer)
		}
	}
}

// HandleDiscovery processes a discovery request from the client
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
		Segment:       1,
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
	if _, err = s.Clients[clientIndex].DataConn[dataportIndex].Write(bytes); err != nil {
		log.Printf("Failed to send discovery response to client %s: %v", s.Clients[clientIndex].ID, err)
		return
	}
	log.Printf("Sent discovery response to client %s", s.Clients[clientIndex].ID)
}

// HandleRead processes a read request from the client
func (s *Server) HandleRead(clientIndex string, header *messages.Header, body []byte) {
	decryptedBody, err := srmcp.Decrypt(s.Clients[clientIndex].SharedSecret, body)
	if err != nil {
		log.Printf("Failed to decrypt read request from client %s: %v", s.Clients[clientIndex].ID, err)
		return
	}

	var readRequest messages.Read
	if err := json.Unmarshal(decryptedBody, &readRequest); err != nil {
		log.Printf("Failed to unmarshal read request from client %s: %v", s.Clients[clientIndex].ID, err)
		return
	}

	if err := validate.Struct(readRequest); err != nil {
		log.Printf("Invalid read request from client %s: %v", s.Clients[clientIndex].ID, err)
		return
	}
	log.Printf("Received read request from client %s", s.Clients[clientIndex].ID)

	readResponse := make([]*messages.ReadResponse, 0)
	for index, nodeID := range readRequest.NodeIDs {
		node, ok := s.Nodes[nodeID]
		if !ok {
			log.Printf("Node %s not found", nodeID)
			continue
		}
		if node.Name != readRequest.NodeNames[index] {
			log.Printf("Node %s name mismatch", nodeID)
			continue
		}
		if node.Read != nil {
			v, err := (*node.Read)()
			if err != nil {
				log.Printf("Failed to read node %s: %v", nodeID, err)
				continue
			}
			node.Value = v
		}
		readResponse = append(readResponse, &messages.ReadResponse{
			NodeID:   nodeID,
			NodeName: node.Name,
			Value:    node.Value,
		})
	}

	readResponseBytes, err := json.Marshal(readResponse)
	if err != nil {
		log.Printf("Failed to marshal read response: %v", err)
		return
	}

	encryptedReadResponse, err := srmcp.Encrypt(s.Clients[clientIndex].SharedSecret, readResponseBytes)
	if err != nil {
		log.Printf("Failed to encrypt read response: %v", err)
		return
	}
	log.Printf("Prepared read response for client %s", s.Clients[clientIndex].ID)

	segments := s.Segmenting(header, clientIndex, encryptedReadResponse)
	if err := s.TransmitSegments(segments, header, clientIndex); err != nil {
		log.Printf("Failed to send read response to client %s: %v", s.Clients[clientIndex].ID, err)
	}
}

// HandleWrite processes a write request from the client
func (s *Server) HandleWrite(clientIndex string, header *messages.Header, body []byte) {
	decryptedBody, err := srmcp.Decrypt(s.Clients[clientIndex].SharedSecret, body)
	if err != nil {
		log.Printf("Failed to decrypt write request from client %s: %v", s.Clients[clientIndex].ID, err)
		return
	}

	var writeRequest messages.Write
	if err := json.Unmarshal(decryptedBody, &writeRequest); err != nil {
		log.Printf("Failed to unmarshal write request from client %s: %v", s.Clients[clientIndex].ID, err)
		return
	}

	if err := validate.Struct(writeRequest); err != nil {
		log.Printf("Invalid write request from client %s: %v", s.Clients[clientIndex].ID, err)
		return
	}
	log.Printf("Received write request from client %s", s.Clients[clientIndex].ID)

	node, ok := s.Nodes[writeRequest.NodeID]
	if !ok {
		log.Printf("Node %s not found", writeRequest.NodeID)
		return
	}
	if node.Name != writeRequest.NodeName {
		log.Printf("Node %s name mismatch", writeRequest.NodeID)
		return
	}
	if node.Write != nil {
		if err := (*node.Write)(writeRequest.Value); err != nil {
			log.Printf("Failed to write node %s: %v", writeRequest.NodeID, err)
			return
		}
		node.Value = writeRequest.Value
	} else {
		node.Value = writeRequest.Value
	}
	log.Printf("Updated node %s value to %v", writeRequest.NodeID, writeRequest.Value)

	responseHeader := &messages.Header{
		MessageType:   srmcp.Write,
		SenderID:      s.ID,
		Timestamp:     time.Now(),
		TransactionID: header.TransactionID,
		Index:         1.0,
		Segment:       1,
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

	writeResponse := &messages.WriteResponse{
		NodeID:   node.ID,
		NodeName: node.Name,
		Value:    node.Value,
	}
	writeResponseBytes, err := json.Marshal(writeResponse)
	if err != nil {
		log.Printf("Failed to marshal write response: %v", err)
		return
	}
	encryptedWriteResponse, err := srmcp.Encrypt(s.Clients[clientIndex].SharedSecret, writeResponseBytes)
	if err != nil {
		log.Printf("Failed to encrypt write response: %v", err)
		return
	}

	responsePreHeader := messages.PreHeader{
		HeaderLength: uint32(len(encryptedResponseHeader)),
		BodyLength:   uint32(len(encryptedWriteResponse)),
	}
	responsePreHeaderBytes := responsePreHeader.Serialize()

	bytes := append(responsePreHeaderBytes, encryptedResponseHeader...)
	bytes = append(bytes, encryptedWriteResponse...)

	dataportIndex := rand.Intn(len(s.Clients[clientIndex].DataConn))
	if _, err = s.Clients[clientIndex].DataConn[dataportIndex].Write(bytes); err != nil {
		log.Printf("Failed to send write response to client %s: %v", s.Clients[clientIndex].ID, err)
	}
	log.Printf("Sent write response to client %s", s.Clients[clientIndex].ID)
}
