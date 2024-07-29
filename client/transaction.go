package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
				log.Printf("Transaction %s - %s timed out", t.Client.ID, t.RequestHeader.MessageType)
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
		case srmcp.DataLinkReq:
			t.HandleDataLinkRep()
		default:
			t.Error = errors.New("unknown message type")
			t.Completed = true
			log.Printf("Unknown message type")
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

func (t *Transaction) HandleDataLinkRep() {
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

		dataportBytes, err := srmcp.Decrypt(t.Client.Servers[t.ServerIndex].SharedSecret, t.ResponseBody[0])
		if err != nil {
			t.Error = err
			t.Completed = true
			log.Printf("Failed to decrypt data link response from server %s", t.Client.Servers[t.ServerIndex].ID)
		}
		dataport := binary.BigEndian.Uint32(dataportBytes)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: t.Client.Cert.Raw})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(t.Client.PrivateKey)})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Error = err
			t.Completed = true
			log.Printf("Failed to load client certificate and key")
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      x509.NewCertPool(),
		}
		config.RootCAs.AddCert(t.Client.CACert)
		serverDataLinkAddr := fmt.Sprintf("%s:%d", t.Client.Servers[t.ServerIndex].Address, dataport)
		conn, err := tls.Dial("tcp", serverDataLinkAddr, config)
		if err != nil {
			t.Error = err
			t.Completed = true
			log.Printf("Failed to connect to Data Link on server %s, port %d", t.Client.Servers[t.ServerIndex].Address, dataport)
		}
		t.Client.Servers[t.ServerIndex].mu.Lock()
		t.Client.Servers[t.ServerIndex].DataConn[dataport] = conn
		t.Client.Servers[t.ServerIndex].mu.Unlock()
		t.Completed = true
		log.Printf("Connected to Data Link on server %s, port %d", t.Client.Servers[t.ServerIndex].Address, dataport)
		return
	}

}
