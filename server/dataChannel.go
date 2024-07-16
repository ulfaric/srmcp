package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/ulfaric/srmcp"
	"github.com/ulfaric/srmcp/messages"
)

// StartDataConn starts the data connection by listening on the server's address and a random port.
func (s *Server) StartDataConn(clientIndex string, dataport uint32) error {
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

	addr := fmt.Sprintf("%s:%d", s.Address, dataport)
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}
	log.Printf("New Datalink for client %s is listening on %s", s.Clients[clientIndex].ID, addr)

	go s.AcceptDataConn(clientIndex, listener, dataport)
	go func() {
		time.Sleep(5 * time.Second)
		err := listener.Close()
		if err == nil {
			log.Printf("Datalink listener on %s for client %s closed due to inactivity", listener.Addr().String(), s.Clients[clientIndex].ID)
		}
	}()
	return nil
}

// AcceptDataConn accepts incoming data connections from clients.
func (s *Server) AcceptDataConn(clientIndex string, listener net.Listener, dataport uint32) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	go s.HandleDataConn(conn, clientIndex, dataport)
	listener.Close()
	log.Printf("Datalink listener on %s accepted connection from client %s and closed", listener.Addr().String(), s.Clients[clientIndex].ID)
}

// HandleDataConn handles the data connection with the client.
func (s *Server) HandleDataConn(conn net.Conn, clientIndex string, dataport uint32) {
	// TLS Handshake
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

	// Add the data connection to the client's data connection map
	s.Clients[clientIndex].mu.Lock()
	s.Clients[clientIndex].DataConn[dataport] = tlsConn
	s.Clients[clientIndex].mu.Unlock()
	log.Printf("Client %s connected to data channel on %s", s.Clients[clientIndex].ID, tlsConn.RemoteAddr().String())

	// Read data from the client
	for {
		headerBuffer := make([]byte, 88)
		_, err := tlsConn.Read(headerBuffer)
		if err != nil {
			if err == io.EOF {
				log.Printf("Client %s closed datalink connection on %s", s.Clients[clientIndex].ID, tlsConn.RemoteAddr().String())
				return
			}
			log.Printf("Failed to read from client %s on datalink %s: %v", s.Clients[clientIndex].ID, tlsConn.RemoteAddr().String(), err)
			return
		}
		var header messages.Header
		err = srmcp.Deserializer(headerBuffer, &header)
		if err != nil {
			log.Printf("Failed to deserialize message header: %v", err)
		}

	}
}
