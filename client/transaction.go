package client

import (
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/messages"
)

var ErrTimeOut = errors.New("timeout error")

type Transaction struct {
	ID             string
	Client         *Client
	ServerIndex    string
	StartedAt      time.Time
	Completed      bool
	RequestHeader  *messages.Header
	RequestBody    []byte
	ResponseHeader []*messages.Header
	ResponseBody   [][]byte
	Timeout        int
	Error          error
}

func NewTransaction(client *Client, serverIndex string, requestHeader *messages.Header, requestBody []byte, timeout int) *Transaction {
	t := Transaction{
		ID:            requestHeader.TransactionID,
		Client:        client,
		ServerIndex:   serverIndex,
		StartedAt:     time.Now(),
		RequestHeader: requestHeader,
		RequestBody:   requestBody,
		Timeout:       timeout,
	}
	go t.TimeOut()
	go t.Process()
	return &t
}

// TimeOut checks if the transaction has timed out and sets the error if it has.
func (t *Transaction) TimeOut() {
	for {
		if !t.Completed {
			if time.Since(t.StartedAt) > time.Millisecond*time.Duration(t.Timeout) {
				t.Error = ErrTimeOut
				t.Completed = true
				log.Printf("Transaction %s - %s timed out",t.Client.ID, t.RequestHeader.MessageType)
				return
			}
		} else {
			return
		}
	}
}

// Process processes the transaction based on the message type.
func (t *Transaction) Process() {
	for {
		if t.Completed {
			return
		}
		switch t.RequestHeader.MessageType {
		case srmcp.Hello:
			t.handleHello()
		case srmcp.HandShake:
			t.HandleHandShake()
		}
	}
}

// HandleHello handles a HEL message from a server.
func (t *Transaction) handleHello() {
	for {

		if t.Completed {
			return
		}

		if len(t.ResponseHeader) == 0 {
			continue
		}

		t.Client.Servers[t.ServerIndex].mu.Lock()
		defer t.Client.Servers[t.ServerIndex].mu.Unlock()
		t.Client.Servers[t.ServerIndex].ID = t.ResponseHeader[0].SenderID
		t.Completed = true
		log.Printf("Received HEL message from server %s", t.Client.Servers[t.ServerIndex].ID)
		return
	}
}

// HandleHandShake handles a HSH message from a server.
func (t *Transaction) HandleHandShake() {
	for {
		if t.Completed {
			return
		}

		if len(t.ResponseHeader) == 0 {
			continue
		}

		if len(t.ResponseBody) == 0 {
			continue
		}

		var handshakeMessage messages.HandShakeResponse
		err := json.Unmarshal(t.ResponseBody[0], &handshakeMessage)
		if err != nil {
			t.Error = err
			t.Completed = true
			return
		}
		sharedSecrete := make([]byte, kyber1024.SharedKeySize)
		t.Client.Servers[t.ServerIndex].PrivateKey.DecapsulateTo(sharedSecrete, handshakeMessage.CipherText)
		t.Client.Servers[t.ServerIndex].mu.Lock()
		t.Client.Servers[t.ServerIndex].SharedSecret = sharedSecrete
		t.Client.Servers[t.ServerIndex].mu.Unlock()
		t.Completed = true
		log.Printf("Received HSH message from server %s, encryption key: %x", t.Client.Servers[t.ServerIndex].ID, sharedSecrete)
		return
	}
}
