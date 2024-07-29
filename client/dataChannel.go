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

func (c *Client) HandleDataConn(conn *tls.Conn, serverIndex string){
	defer conn.Close()
	for {
		header, body, err := c.DigestEncryptedMessage(conn, serverIndex)
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

func (c *Client) GetNodes(serverIndex string) error {

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
	transaction := NewTransaction(c, serverIndex, &header, nil, 100)
	c.Servers[serverIndex].Transactions[header.TransactionID] = transaction
	return nil
}
