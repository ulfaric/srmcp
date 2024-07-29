package client

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
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

func (c *Client) HandleControlConn(conn *tls.Conn) {
	defer conn.Close()
	serverIndex := conn.RemoteAddr().String()
	for {
		header, body, err := DigestMessage(conn)
		if err == nil {
			c.Servers[serverIndex].mu.Lock()
			c.Servers[serverIndex].Transactions[header.TransactionID].ResponseHeader = append(c.Servers[serverIndex].Transactions[header.TransactionID].ResponseHeader, header)
			c.Servers[serverIndex].Transactions[header.TransactionID].ResponseBody = append(c.Servers[serverIndex].Transactions[header.TransactionID].ResponseBody, body)
			c.Servers[serverIndex].mu.Unlock()

		} else {
			continue
		}
	}
}

// HandShake sends a HSH message to the server which contains the kypber public key of the client.
func (c *Client) HandShake(serverIndex string) error {
	// Preparing the header
	header := messages.Header{
		MessageType:   srmcp.HandShake,
		SenderID:      c.ID,
		Timestamp:     time.Now(),
		TransactionID: uuid.New().String(),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to serialize HandShake message header: %v", err)
	}

	// Prepare the Kyber1024 Key Pair
	publicKey, privateKey, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate encryption key: %v", err)
	}
	c.Servers[serverIndex].mu.Lock()
	c.Servers[serverIndex].PublicKey = publicKey
	c.Servers[serverIndex].PrivateKey = privateKey
	c.Servers[serverIndex].mu.Unlock()

	// Prepare the HandShake message
	publicKeyBytes := make([]byte, kyber1024.PublicKeySize)
	publicKey.Pack(publicKeyBytes)
	handshakeMessage := messages.HandShake{
		PublicKey: publicKeyBytes,
	}
	bodyBytes, err := json.Marshal(handshakeMessage)
	if err != nil {
		return fmt.Errorf("failed to serialize HandShake message body: %v", err)
	}

	// Prepare the PreHeader
	preHeader := messages.PreHeader{
		HeaderLength: uint32(len(headerBytes)),
		BodyLength:   uint32(len(bodyBytes)),
	}
	preHeaderBytes := preHeader.Serialize()

	// Send the HandShake message
	bytes := append(preHeaderBytes, headerBytes...)
	bytes = append(bytes, bodyBytes...)
	_, err = c.Servers[serverIndex].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send HandShake message to server at %s: %v", serverIndex, err)
	}
	transaction := NewTransaction(c, serverIndex, &header, bodyBytes, 100)
	c.Servers[serverIndex].Transactions[transaction.ID] = transaction
	return nil
}

func (c *Client) RequestDataLink(serverIndex string) error {
	header := messages.Header{
		MessageType: srmcp.DataLinkReq,
		SenderID:    c.ID,
		Timestamp:   time.Now(),
		TransactionID: uuid.New().String(),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to serialize DataLinkReq message header: %v", err)
	}

	preHeader := messages.PreHeader{
		HeaderLength: uint32(len(headerBytes)),
		BodyLength:   0,
	}
	preHeaderBytes := preHeader.Serialize()

	bytes := append(preHeaderBytes, headerBytes...)

	_, err = c.Servers[serverIndex].ControlConn.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send DataLinkReq message to server at %s: %v", serverIndex, err)
	}
	transaction := NewTransaction(c, serverIndex, &header, nil, 100)
	c.Servers[serverIndex].Transactions[transaction.ID] = transaction
	return nil
}

// // handleHandShake handles a HSH message from a server.
// func (c *Client) handleHandShake(conn *tls.Conn, header messages.Header, bodyBuffer []byte) {
// 	serverIndex := conn.RemoteAddr().String()
// 	c.mu.Lock()
// 	server, ok := c.Servers[serverIndex]
// 	c.mu.Unlock()
// 	if !ok {
// 		log.Printf("Server at %s not found", serverIndex)
// 		return
// 	}

// 	// Decrypt the message body using the client's private key.
// 	body, err := srmcp.Decrypt(server.ClientKey, bodyBuffer)
// 	if err != nil {
// 		log.Printf("Failed to decrypt handshake message: %v", err)
// 		return
// 	}
// 	// Deserialize the decrypted message body.
// 	var handshakeMessage messages.HandShake
// 	err = srmcp.Deserializer(body, &handshakeMessage)
// 	if err != nil {
// 		log.Printf("Failed to deserialize handshake message: %v", err)
// 		return
// 	}
// 	// Store the server's encryption key.
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	server.ServerKey = handshakeMessage.EncryptionKey
// 	log.Printf("Received HSH message from server %s, encryption key: %x", header.SenderID, handshakeMessage.EncryptionKey)
// }

// // handleDataLinkRep handles a DLP message from a server.
// func (c *Client) handleDataLinkRep(conn *tls.Conn, header messages.Header, bodyBuffer []byte) {
// 	serverIndex := conn.RemoteAddr().String()
// 	c.mu.Lock()
// 	server, ok := c.Servers[serverIndex]
// 	c.mu.Unlock()
// 	if !ok {
// 		log.Printf("Server at %s not found", serverIndex)
// 		return
// 	}

// 	body, err := srmcp.Decrypt(server.ServerKey, bodyBuffer)
// 	if err != nil {
// 		log.Printf("Failed to decrypt datalink response message: %v", err)
// 		return
// 	}
// 	var dataLinkRep messages.DataLinkRep
// 	err = srmcp.Deserializer(body, &dataLinkRep)
// 	if err != nil {
// 		log.Printf("Failed to deserialize datalink response message: %v", err)
// 		return
// 	}
// 	log.Printf("Received DLP message from server %s, DataPort: %d", header.SenderID, dataLinkRep.DataPort)
// 	c.ConnectDataLink(serverIndex, dataLinkRep.DataPort)
// }

// func (c *Client) ConnectDataLink(serverIndex string, port uint32) error {
// 	// Create a new TLS connection to the server.
// 	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
// 	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.PrivateKey)})
// 	cert, err := tls.X509KeyPair(certPEM, keyPEM)
// 	if err != nil {
// 		return err
// 	}
// 	config := &tls.Config{
// 		Certificates: []tls.Certificate{cert},
// 		RootCAs:      x509.NewCertPool(),
// 	}
// 	config.RootCAs.AddCert(c.CACert)
// 	serverDataLinkAddr := fmt.Sprintf("%s:%d", c.Servers[serverIndex].Address, port)
// 	conn, err := tls.Dial("tcp", serverDataLinkAddr, config)
// 	if err != nil {
// 		log.Printf("failed to connect with server %s datalink on %s: %v", c.Servers[serverIndex].ID, serverDataLinkAddr, err)
// 		return err
// 	}

// 	// Add the data connection to the server's map of data connections.
// 	c.Servers[serverIndex].mu.Lock()
// 	defer c.Servers[serverIndex].mu.Unlock()
// 	c.Servers[serverIndex].DataConn[port] = conn
// 	log.Printf("Connected to server %s datalink on %s", c.Servers[serverIndex].ID, serverDataLinkAddr)
// 	return nil
// }

// // Hello sends a HEL message to the server at the given address.
// func (c *Client) Hello(serverIndex string) error {
// 	// Create a new Hello message with the client's ID and the current time.
// 	helloMessage := messages.NewHello(c.ID, time.Now())
// 	// Serialize the Hello message.
// 	bytes, err := helloMessage.Encode()
// 	if err != nil {
// 		return fmt.Errorf("failed to serialize Hello message: %v", err)
// 	}
// 	// Send the Hello message to the server.
// 	_, err = c.Servers[serverIndex].ControlConn.Write(bytes)
// 	if err != nil {
// 		return fmt.Errorf("failed to send Hello message to server: %v", err)
// 	}
// 	return nil
// }

// // HandShake sends a HSH message to the server at the given address.
// func (c *Client) HandShake(serverIndex string) error {
// 	// create a new encryption key
// 	key, err := srmcp.GenerateRandomKey()
// 	c.Servers[serverIndex].ClientKey = key
// 	log.Printf("Generated client encryption key: %x", key)
// 	if err != nil {
// 		return fmt.Errorf("failed to generate encryption key: %v", err)
// 	}
// 	// create a new handshake message with the client's ID and the encryption key
// 	handshakeMessage := messages.NewHandShake(key)
// 	body, err := handshakeMessage.Encode()
// 	if err != nil {
// 		return fmt.Errorf("failed to serialize handshake message: %v", err)
// 	}
// 	header := messages.Header{
// 		MessageType: srmcp.HandShake,
// 		SenderID:    c.ID,
// 		Timestamp:   time.Now().Format(time.RFC3339Nano),
// 		Length:      uint32(len(body)),
// 	}
// 	headerBytes, err := srmcp.Serializer(header)
// 	if err != nil {
// 		return fmt.Errorf("failed to serialize handshake header: %v", err)
// 	}
// 	bytes := append(headerBytes, body...)
// 	// send the handshake message to the server
// 	_, err = c.Servers[serverIndex].ControlConn.Write(bytes)
// 	if err != nil {
// 		return fmt.Errorf("failed to send handshake message to server: %v", err)
// 	}
// 	return nil
// }

// // ReqDataLink sends a datalink request to the server at the given address.
// func (c *Client) ReqDataLink(serverIndex string) error {
// 	subscribeMessage := messages.NewDataLinkReq(c.ID, time.Now())
// 	bytes, err := subscribeMessage.Encode()
// 	if err != nil {
// 		return fmt.Errorf("failed to serialize subscribe message: %v", err)
// 	}
// 	_, err = c.Servers[serverIndex].ControlConn.Write(bytes)
// 	if err != nil {
// 		return fmt.Errorf("failed to send subscribe message to server: %v", err)
// 	}
// 	return nil
// }
