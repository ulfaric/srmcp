package client

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/messages"
	"github.com/ulfaric/srmcp/node"
)

func (c *Client) DigestEncryptedMessage(conn *tls.Conn, serverIndex string) (*messages.Header, []byte, error) {
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
	headerBytes, err := srmcp.Decrypt(c.Servers[serverIndex].SharedSecret, headerBuffer)
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

func (c *Client) HandleDataConn(conn *tls.Conn, serverIndex string) {
	defer conn.Close()
	for {
		header, body, err := c.DigestEncryptedMessage(conn, serverIndex)
		if err == nil {
			transcation := c.Servers[serverIndex].Transactions[header.TransactionID]
			c.Servers[serverIndex].mu.Lock()
			transcation.ResponseHeader = header
			transcation.ResponseBody[header.Index] = body
			transcation.Segment = header.Segment
			c.Servers[serverIndex].mu.Unlock()
		} else {
			continue
		}
	}

}

// Discover sends a Discover message to the server with the given index.
func (c *Client) Discover(serverIndex string, timeout int) error {

	// Prepare the header
	header := messages.Header{
		MessageType:   srmcp.Discovery,
		SenderID:      c.ID,
		Timestamp:     time.Now(),
		TransactionID: uuid.New().String(),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to marshal Discover message header: %w", err)
	}

	// Encrypt the header
	encryptedHeader, err := srmcp.Encrypt(c.Servers[serverIndex].SharedSecret, headerBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt Discover message header: %w", err)
	}

	// Prepare pre-header
	preHeader := messages.PreHeader{
		HeaderLength: uint32(len(encryptedHeader)),
		BodyLength:   0,
	}
	preHeaderBytes := preHeader.Serialize()

	// Prepare the bytes
	bytes := append(preHeaderBytes, encryptedHeader...)

	// Randomly select a data link
	datalink_index := rand.Intn(len(c.Servers[serverIndex].DataConn))
	_, err = c.Servers[serverIndex].DataConn[datalink_index].Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send Discover message: %w", err)
	}

	// Create a new transaction
	transaction := NewTransaction(c, serverIndex, &header, nil, timeout)
	c.Servers[serverIndex].Transactions[header.TransactionID] = transaction
	return nil
}

// Read sends a Read message to the server with the given index.
func (c *Client) Read(serverIndex string, nodeNames []string, timeout int) ([]*node.Node, error) {
	// Prepare the header
	header := messages.Header{
		MessageType:   srmcp.Read,
		SenderID:      c.ID,
		Timestamp:     time.Now(),
		TransactionID: uuid.New().String(),
	}
	// Serialize header
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Discover message header: %w", err)
	}
	// Encrypt the header
	encryptedHeader, err := srmcp.Encrypt(c.Servers[serverIndex].SharedSecret, headerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt Discover message header: %w", err)
	}

	// Prepare the Body
	validNodes := make([]*node.Node, 0)
	validNodeIDs := make([]string, 0)
	validNodeNames := make([]string, 0)
	foundNodes := 0
	for _, nodeName := range nodeNames {
		for _, node := range c.Servers[serverIndex].Nodes {
			if node.Name == nodeName {
				validNodeIDs = append(validNodeIDs, node.ID)
				validNodeNames = append(validNodeNames, node.Name)
				validNodes = append(validNodes, node)
				foundNodes++
			}
		}
	}
	if foundNodes == 0 {
		return nil, fmt.Errorf("no valid nodes found")
	}
	body := messages.Read{
		NodeIDs:   validNodeIDs,
		NodeNames: validNodeNames,
	}
	// Serialize the body
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Discover message header: %w", err)
	}
	// Encrypt the body
	encryptedBody, err := srmcp.Encrypt(c.Servers[serverIndex].SharedSecret, bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt Discover message header: %w", err)
	}

	// Prepare pre-header
	preHeader := messages.PreHeader{
		HeaderLength: uint32(len(encryptedHeader)),
		BodyLength:   uint32(len(encryptedBody)),
	}
	preHeaderBytes := preHeader.Serialize()

	// Prepare the bytes
	bytes := append(preHeaderBytes, encryptedHeader...)
	bytes = append(bytes, encryptedBody...)

	// Randomly select a data link
	datalink_index := rand.Intn(len(c.Servers[serverIndex].DataConn))
	_, err = c.Servers[serverIndex].DataConn[datalink_index].Write(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send Discover message: %w", err)
	}

	// Create a new transaction
	transaction := NewTransaction(c, serverIndex, &header, bodyBytes, timeout)
	c.Servers[serverIndex].Transactions[header.TransactionID] = transaction

	for {
		if transaction.isCompleted() {
			break
		}
	}
	return validNodes, transaction.Error
}

func (c *Client) Write(serverIndex string, nodeName string, value interface{}, timeout int) error {
	// Prepare the header
	header := messages.Header{
		MessageType:   srmcp.Write,
		SenderID:      c.ID,
		Timestamp:     time.Now(),
		TransactionID: uuid.New().String(),
	}
	// Serialize header
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to marshal Discover message header: %w", err)
	}
	// Encrypt the header
	encryptedHeader, err := srmcp.Encrypt(c.Servers[serverIndex].SharedSecret, headerBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt Discover message header: %w", err)
	}

	// Prepare the Body
	var validNode *node.Node
	for _, node := range c.Servers[serverIndex].Nodes {
		if node.Name == nodeName {
			validNode = node
		}
	}
	if validNode == nil {
		return fmt.Errorf("no valid node with %s found", nodeName)
	}
	body := messages.Write{
		NodeID:   validNode.ID,
		NodeName: validNode.Name,
		Value:    value,
	}
	// Serialize the body
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal Discover message header: %w", err)
	}
	// Encrypt the body
	encryptedBody, err := srmcp.Encrypt(c.Servers[serverIndex].SharedSecret, bodyBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt Discover message header: %w", err)
	}

	// Prepare pre-header
	preHeader := messages.PreHeader{
		HeaderLength: uint32(len(encryptedHeader)),
		BodyLength:   uint32(len(encryptedBody)),
	}
	preHeaderBytes := preHeader.Serialize()

	// Prepare the bytes
	bytes := append(preHeaderBytes, encryptedHeader...)
	bytes = append(bytes, encryptedBody...)

	// Randomly select a data link
	datalink_index := rand.Intn(len(c.Servers[serverIndex].DataConn))
	_, err = c.Servers[serverIndex].DataConn[datalink_index].Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to send Discover message: %w", err)
	}

	// Create a new transaction
	transaction := NewTransaction(c, serverIndex, &header, bodyBytes, timeout)
	c.Servers[serverIndex].Transactions[header.TransactionID] = transaction

	for {
		if transaction.isCompleted() {
			break
		}
	}
	return transaction.Error
}
