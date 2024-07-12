package test

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ulfaric/srmcp/certs"
	"github.com/ulfaric/srmcp/server"
)

func TestServer(t *testing.T) {
	// Create a temporary directory to store certs and keys
	dir, err := os.MkdirTemp("", "testcerts")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Generate CA certificate and key
	caCertPath := filepath.Join(dir, "ca_cert.pem")
	caKeyPath := filepath.Join(dir, "ca_key.pem")
	caCert, caKey, err := certs.CreateCA(caCertPath, caKeyPath, "Test CA", "US", 10)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Generate server certificate and key
	serverCertPath := filepath.Join(dir, "server_cert.pem")
	serverKeyPath := filepath.Join(dir, "server_key.pem")
	_, _, err = certs.CreateServerCert(caCert, caKey, serverCertPath, serverKeyPath, "Test Server", "US", 1, "localhost")
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Generate client certificate and key
	clientCertPath := filepath.Join(dir, "client_cert.pem")
	clientKeyPath := filepath.Join(dir, "client_key.pem")
	_, _, err = certs.CreateClientCert(caCert, caKey, clientCertPath, clientKeyPath, "Test Client", "US", 1, "localhost")
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	// Create server instance
	srv, err := server.NewServer(serverCertPath, serverKeyPath, caCertPath)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in a separate goroutine
	go func() {
		if err := srv.Run("127.0.0.1:8888"); err != nil {
			t.Errorf("Server failed to start: %v", err)
		}
	}()

	// Allow server time to start
	time.Sleep(2 * time.Second)

	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}

	// Load CA certificate
	caCertData, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCertData); !ok {
		t.Fatalf("Failed to append CA certificate to pool")
	}

	// Setup TLS configuration for client
	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
	}

	// Establish a TLS connection to the server
	conn, err := tls.Dial("tcp", "127.0.0.1:8888", config)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Send a message to the server
	message := "Hello, Server!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		t.Fatalf("Failed to write to server: %v", err)
	}
	conn.Close()
	// Allow some time for server to process the message
	time.Sleep(1 * time.Second)

	// Shut down the server
	srv.Stop()

}
