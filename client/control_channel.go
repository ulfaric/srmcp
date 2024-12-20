package client

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/messages"
)

// DigestMessage reads and parses a message from the TLS connection.
func DigestMessage(conn *tls.Conn) ([]byte, []byte, error) {
	// conn.SetDeadline(time.Now().Add(time.Second * 1))
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

	// Read the body
	bodyBuffer := make([]byte, bodyLength)
	if _, err := io.ReadFull(conn, bodyBuffer); err != nil {
		return nil, nil, err
	}

	return headerBuffer, bodyBuffer, nil
}

// HandleControlConn handles the control connection for the client.
func (c *Client) HandleControlConn(conn *tls.Conn) {
	defer conn.Close()
	serverIndex := conn.RemoteAddr().String()

	for {
		headerBuffer, bodyBuffer, err := DigestMessage(conn)
		if err != nil {
			log.Printf("closes control channel with server %s, %v", serverIndex, err)
			return
		}

		// Deserialize the header
		var header messages.Header
		if err := json.Unmarshal(headerBuffer, &header); err != nil {
			log.Printf("Failed to deserialize control message header from server %s", serverIndex)
			continue
		}

		// Validate the header
		validate := validator.New(validator.WithRequiredStructEnabled())
		if err := validate.Struct(header); err != nil {
			log.Printf("Invalid control message header from server %s: %v", serverIndex, err)
			continue
		}

		// Process the transaction
		c.Servers[serverIndex].mu.Lock()
		transaction := c.Servers[serverIndex].Transactions[header.TransactionID]
		transaction.ResponseHeader = &header
		transaction.ResponseBody[header.Index] = bodyBuffer
		transaction.Segment = header.Segment
		c.Servers[serverIndex].mu.Unlock()
	}
}

// HandShake sends a HSH message to the server which contains the kypber public key of the client.
func (c *Client) HandShake(serverIndex string, timeout int) error {
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

	// Create a new transaction
	transaction := NewTransaction(c, serverIndex, &header, bodyBytes, timeout)
	c.Servers[serverIndex].Transactions[transaction.ID] = transaction
	for {
		if transaction.isCompleted() {
			break
		}
	}
	return transaction.Error
}

// RequestDataLink sends a DataLinkReq message to the server.
func (c *Client) RequestDataLink(serverIndex string, timeout int) error {
	header := messages.Header{
		MessageType:   srmcp.DataLinkReq,
		SenderID:      c.ID,
		Timestamp:     time.Now(),
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
	transaction := NewTransaction(c, serverIndex, &header, nil, timeout)
	c.Servers[serverIndex].Transactions[transaction.ID] = transaction
	for {
		if transaction.isCompleted() {
			break
		}
	}
	return transaction.Error
}