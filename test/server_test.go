package test

import (
	"crypto/tls"
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
	server, err := server.NewServer(serverCertPath, serverKeyPath, caCertPath)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in a separate goroutine
	go server.Run("127.0.0.1:8443")

	// Allow server time to start
	time.Sleep(1 * time.Second)

	// Load client certificate and key
	clientCert, err := certs.LoadCertificate(clientCertPath)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}
	clientKey, err := certs.LoadPrivateKey(clientKeyPath)
	if err != nil {
		t.Fatalf("Failed to load client private key: %v", err)
	}

	// Create TLS configuration for client
	caCert, _ = certs.LoadCertificate(caCertPath)
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{clientCert.Raw},
				PrivateKey:  clientKey,
			},
		},
		RootCAs:    certs.LoadCertPool(caCert),
		ServerName: "localhost", // Ensure the server name matches the certificate
	}

	// Connect to server as client
	conn, err := tls.Dial("tcp", "localhost:8443", clientTLSConfig)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()
	time.Sleep(1 * time.Second)

	// Check if client is added to server's client list
	clientID := conn.LocalAddr().String()
	_, exists := server.GetClient(clientID)
	if !exists {
		t.Fatalf("Client was not added to server's client list")
	}
}

func TestServerWithDifferentCA(t *testing.T) {
	// Create a temporary directory to store certs and keys
	dir, err := os.MkdirTemp("", "testcerts")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Generate CA certificate and key for server
	serverCACertPath := filepath.Join(dir, "server_ca_cert.pem")
	serverCAKeyPath := filepath.Join(dir, "server_ca_key.pem")
	serverCACert, serverCAKey, err := certs.CreateCA(serverCACertPath, serverCAKeyPath, "Server CA", "US", 10)
	if err != nil {
		t.Fatalf("Failed to create server CA: %v", err)
	}

	// Generate CA certificate and key for client
	clientCACertPath := filepath.Join(dir, "client_ca_cert.pem")
	clientCAKeyPath := filepath.Join(dir, "client_ca_key.pem")
	clientCACert, clientCAKey, err := certs.CreateCA(clientCACertPath, clientCAKeyPath, "Client CA", "US", 10)
	if err != nil {
		t.Fatalf("Failed to create client CA: %v", err)
	}

	// Generate server certificate and key
	serverCertPath := filepath.Join(dir, "server_cert.pem")
	serverKeyPath := filepath.Join(dir, "server_key.pem")
	_, _, err = certs.CreateServerCert(serverCACert, serverCAKey, serverCertPath, serverKeyPath, "Test Server", "US", 1, "localhost")
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Generate client certificate and key
	clientCertPath := filepath.Join(dir, "client_cert.pem")
	clientKeyPath := filepath.Join(dir, "client_key.pem")
	_, _, err = certs.CreateClientCert(clientCACert, clientCAKey, clientCertPath, clientKeyPath, "Test Client", "US", 1, "localhost")
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	// Create server instance
	server, err := server.NewServer(serverCertPath, serverKeyPath, serverCACertPath)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in a separate goroutine
	go server.Run("127.0.0.1:8443")

	// Allow server time to start
	time.Sleep(1 * time.Second)

	// Load client certificate and key
	clientCert, err := certs.LoadCertificate(clientCertPath)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}
	clientKey, err := certs.LoadPrivateKey(clientKeyPath)
	if err != nil {
		t.Fatalf("Failed to load client private key: %v", err)
	}

	// Create TLS configuration for client
	clientCACert, _ = certs.LoadCertificate(clientCACertPath)
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{clientCert.Raw},
				PrivateKey:  clientKey,
			},
		},
		RootCAs: certs.LoadCertPool(clientCACert),
		InsecureSkipVerify: true, // Skip verification of server certificate
	}

	// Connect to server as client
	conn, err := tls.Dial("tcp", "localhost:8443", clientTLSConfig)
	if err == nil {
		defer conn.Close()
		t.Fatalf("Client connected to server with different CA, connection should have failed")
	} else {
		t.Logf("Client failed to connect to server with different CA, as expected: %s", err)
	}
}

