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
	"sort"
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
	ResponseHeader *messages.Header
	ResponseBody   map[float64][]byte
	Segment        int
	Timeout        int
	Error          error
}

func NewTransaction(client *Client, serverIndex string, requestHeader *messages.Header, requestBody []byte, timeout int) *Transaction {
	t := Transaction{
		ID:            requestHeader.TransactionID,
		Client:        client,
		ServerIndex:   serverIndex,
		StartedAt:     time.Now(),
		Completed:     false,
		RequestHeader: requestHeader,
		RequestBody:   requestBody,
		ResponseBody:  make(map[float64][]byte),
		Segment:       0,
		Timeout:       timeout,
		Error:         nil,
	}
	go t.TimeOut()
	go t.Process()
	return &t
}

// isCompleted checks if the transaction has completed.
func (t *Transaction) isCompleted() bool {
	return t.Completed
}

// setCompleted sets the error and completes the transaction.
func (t *Transaction) setCompleted(err error) {
	t.Error = err
	t.Completed = true
}

// TimeOut checks if the transaction has timed out and sets the error if it has.
func (t *Transaction) TimeOut() {
	for {
		if !t.isCompleted() {
			if time.Since(t.StartedAt) > time.Millisecond*time.Duration(t.Timeout) {
				t.setCompleted(ErrTimeOut)
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
		if t.isCompleted() {
			return
		}

		if t.Segment != 0 && t.Segment == len(t.ResponseBody) {
			switch t.RequestHeader.MessageType {
			case srmcp.HandShake:
				t.HandleHandShake()
			case srmcp.DataLinkReq:
				t.HandleDataLinkRep()
			case srmcp.Discovery:
				t.HandleDiscovery()
			case srmcp.Read:
				t.HandleReadResponse()
			default:
				t.setCompleted(errors.New("unknown message type"))
				log.Printf("Unknown message type")
			}
		}

	}
}

// HandleHandShake handles a HSH message from a server.
func (t *Transaction) HandleHandShake() {
	for {
		if t.isCompleted() {
			return
		}

		t.Client.Servers[t.ServerIndex].mu.Lock()
		t.Client.Servers[t.ServerIndex].ID = t.ResponseHeader.SenderID
		t.Client.Servers[t.ServerIndex].mu.Unlock()

		var handshakeMessage messages.HandShakeResponse
		err := json.Unmarshal(t.ResponseBody[1.0], &handshakeMessage)
		if err != nil {
			t.setCompleted(err)
			return
		} else {
			sharedSecrete := make([]byte, kyber1024.SharedKeySize)
			t.Client.Servers[t.ServerIndex].PrivateKey.DecapsulateTo(sharedSecrete, handshakeMessage.CipherText)
			t.Client.Servers[t.ServerIndex].mu.Lock()
			t.Client.Servers[t.ServerIndex].SharedSecret = sharedSecrete
			t.Client.Servers[t.ServerIndex].mu.Unlock()
			t.setCompleted(nil)
			log.Printf("Received HSH message from server %s, encryption key: %x", t.Client.Servers[t.ServerIndex].ID, sharedSecrete)
			return
		}
	}
}

// HandleDataLinkRep handles a DLR message from a server.
func (t *Transaction) HandleDataLinkRep() {
	for {
		if t.isCompleted() {
			return
		}
		dataportBytes, err := srmcp.Decrypt(t.Client.Servers[t.ServerIndex].SharedSecret, t.ResponseBody[1.0])
		if err != nil {
			t.setCompleted(err)
			log.Printf("Failed to decrypt data link response from server %s, %s", t.Client.Servers[t.ServerIndex].ID, err)
			return
		}
		dataport := binary.BigEndian.Uint32(dataportBytes)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: t.Client.Cert.Raw})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(t.Client.PrivateKey)})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.setCompleted(err)
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
			t.setCompleted(err)
			log.Printf("Failed to connect to Data Link on server %s, port %d", t.Client.Servers[t.ServerIndex].Address, dataport)
			return
		} else {
			t.Client.Servers[t.ServerIndex].mu.Lock()
			t.Client.Servers[t.ServerIndex].DataConn = append(t.Client.Servers[t.ServerIndex].DataConn, conn)
			t.Client.Servers[t.ServerIndex].mu.Unlock()
			t.setCompleted(nil)
			log.Printf("Connected to Data Link on server %s, port %d", t.Client.Servers[t.ServerIndex].Address, dataport)
			go t.Client.HandleDataConn(conn, t.ServerIndex)
			return
		}
	}

}

func (t *Transaction) HandleDiscovery() {
	for {
		if t.isCompleted() {
			return
		}

		decryptedBody, err := srmcp.Decrypt(t.Client.Servers[t.ServerIndex].SharedSecret, t.ResponseBody[1.0])
		if err != nil {
			t.setCompleted(err)
			log.Printf("Failed to decrypt discovery response from server %s", t.Client.Servers[t.ServerIndex].ID)
			return
		} else {
			log.Printf("Received discovery response from server %s", t.Client.Servers[t.ServerIndex].ID)
			t.setCompleted(nil)
			go t.Client.InitializeNodes(t.ServerIndex, decryptedBody)
			return
		}
	}
}

func (t *Transaction) HandleReadResponse() {
	for {
		if t.isCompleted() {
			return
		}

		// Reorder the body
		var indexes []float64
		for index := range t.ResponseBody {
			indexes = append(indexes, index)
		}
		sort.Float64s(indexes)
		log.Printf("Received read response from server %s, indexes: %v", t.Client.Servers[t.ServerIndex].ID, indexes)
		var encryptedBody []byte
		for _, index := range indexes {
			encryptedBody = append(encryptedBody, t.ResponseBody[index]...)
		}

		// Decrypt the body
		decryptedBody, err := srmcp.Decrypt(t.Client.Servers[t.ServerIndex].SharedSecret, encryptedBody)
		if err != nil {
			t.setCompleted(err)
			log.Printf("Failed to decrypt read response from server %s: %s", t.Client.Servers[t.ServerIndex].ID, err)
			return
		} else {
			// Unmarshal the body
			var readResponse []messages.ReadResponse
			err := json.Unmarshal(decryptedBody, &readResponse)
			if err != nil {
				t.setCompleted(err)
				log.Printf("Failed to unmarshal read response from server %s: %s", t.Client.Servers[t.ServerIndex].ID, err)
				return
			}
			// Update the node value
			for _, node := range readResponse {
				t.Client.Servers[t.ServerIndex].mu.Lock()
				t.Client.Servers[t.ServerIndex].Nodes[node.NodeID].Value = node.Value
				t.Client.Servers[t.ServerIndex].mu.Unlock()
				log.Printf("Received read response from server %s, node %s value updated to %v", t.Client.Servers[t.ServerIndex].ID, t.Client.Servers[t.ServerIndex].Nodes[node.NodeID].Name, t.Client.Servers[t.ServerIndex].Nodes[node.NodeID].Value)
			}
			t.setCompleted(nil)
			return
		}
	}
}
