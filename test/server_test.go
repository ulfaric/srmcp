package test

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ulfaric/srmcp/server"
	"github.com/ulfaric/srmcp/certs"
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
	go server.Run(":8443")

	// Allow server time to start
	time.Sleep(1 * time.Second)

	// Load client certificate and key
	clientCert, err := loadCertificate(clientCertPath)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}
	clientKey, err := loadPrivateKey(clientKeyPath)
	if err != nil {
		t.Fatalf("Failed to load client private key: %v", err)
	}

	// Create TLS configuration for client
	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{clientCert.Raw},
				PrivateKey:  clientKey,
			},
		},
		RootCAs: LoadCertPool(caCert),
		InsecureSkipVerify: true,
	}

	// Connect to server as client
	conn, err := tls.Dial("tcp", "localhost:8443", clientTLSConfig)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()
	time.Sleep(1)
	
	// Check if client is added to server's client list
	clientID := conn.RemoteAddr().String()
	client, exists := server.GetClient(clientID)
	if !exists {
		t.Fatalf("Client was not added to server's client list")
	}
	if client.Cert.Subject.CommonName != "Test Client" {
		t.Fatalf("Client certificate subject does not match expected value")
	}
}

// Helper functions to load certificates and keys from files
func loadCertificate(filename string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func LoadCertPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}