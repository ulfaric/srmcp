package test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	"github.com/ulfaric/srmcp/tls"
)

func TestCreateCA(t *testing.T) {
	caCert, caKey, err := tls.CreateCA("certs/ca_cert.pem", "keys/ca_key.pem", "My CA Organization", "US", 10)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	if caCert == nil || caKey == nil {
		t.Fatalf("CA certificate or key is nil")
	}
}

func TestCreateServerCert(t *testing.T) {
	caCert, caKey, err := tls.CreateCA("", "", "My CA Organization", "US", 10)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	serverCert, serverKey, err := tls.CreateServerCert(caCert, caKey, "certs/server_cert.pem", "keys/server_key.pem", "My Server Organization", "US", 1)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}
	if serverCert == nil || serverKey == nil {
		t.Fatalf("Server certificate or key is nil")
	}
}

func TestCreateClientCert(t *testing.T) {
	caCert, caKey, err := tls.CreateCA("", "", "My CA Organization", "US", 10)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}
	clientCert, clientKey, err := tls.CreateClientCert(caCert, caKey, "certs/client_cert.pem", "keys/client_key.pem", "My Client Organization", "US", 1)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}
	if clientCert == nil || clientKey == nil {
		t.Fatalf("Client certificate or key is nil")
	}
}

func TestCertTrust(t *testing.T) {
	// Recreate CA
	caCert, caKey, err := tls.CreateCA("certs/ca_cert.pem", "keys/ca_key.pem", "My CA Organization", "US", 10)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Recreate server certificate
	_, _, err = tls.CreateServerCert(caCert, caKey, "certs/server_cert.pem", "keys/server_key.pem", "My Server Organization", "US", 1)
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	// Recreate client certificate
	_, _, err = tls.CreateClientCert(caCert, caKey, "certs/client_cert.pem", "keys/client_key.pem", "My Client Organization", "US", 1)
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	// Read CA cert
	caCertPEM, err := os.ReadFile("certs/ca_cert.pem")
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCert, err = parseCert(caCertPEM)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Read server cert
	serverCertPEM, err := os.ReadFile("certs/server_cert.pem")
	if err != nil {
		t.Fatalf("Failed to read server certificate: %v", err)
	}
	serverCert, err := parseCert(serverCertPEM)
	if err != nil {
		t.Fatalf("Failed to parse server certificate: %v", err)
	}

	// Read client cert
	clientCertPEM, err := os.ReadFile("certs/client_cert.pem")
	if err != nil {
		t.Fatalf("Failed to read client certificate: %v", err)
	}
	clientCert, err := parseCert(clientCertPEM)
	if err != nil {
		t.Fatalf("Failed to parse client certificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err = serverCert.Verify(opts)
	if err != nil {
		t.Fatalf("Failed to verify server certificate: %v", err)
	}

	_, err = clientCert.Verify(opts)
	if err != nil {
		t.Fatalf("Failed to verify client certificate: %v", err)
	}
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}
