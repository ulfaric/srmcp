package test

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/ulfaric/srmcp/certs"
	"github.com/ulfaric/srmcp/client"
	"github.com/ulfaric/srmcp/server"
)

func TestClientServerConnection(t *testing.T) {
	// Generate CA, server, and client certificates
	caCertPath := "ca_cert.pem"
	caKeyPath := "ca_key.pem"
	serverCertPath := "server_cert.pem"
	serverKeyPath := "server_key.pem"
	clientCertPath := "client_cert.pem"
	clientKeyPath := "client_key.pem"

	caCert, caKey, err := certs.CreateCA(caCertPath, caKeyPath, "Test CA", "US", 1)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	_, _, err = certs.CreateServerCert(caCert, caKey, serverCertPath, serverKeyPath, "Test Server", "US", 1, "localhost")
	if err != nil {
		t.Fatalf("Failed to create server certificate: %v", err)
	}

	_, _, err = certs.CreateClientCert(caCert, caKey, clientCertPath, clientKeyPath, "Test Client", "US", 1, "localhost")
	if err != nil {
		t.Fatalf("Failed to create client certificate: %v", err)
	}

	defer func() {
		// Clean up generated files
		os.Remove(caCertPath)
		os.Remove(caKeyPath)
		os.Remove(serverCertPath)
		os.Remove(serverKeyPath)
		os.Remove(clientCertPath)
		os.Remove(clientKeyPath)
	}()

	// Start the server
	srv, err := server.NewServer(serverCertPath, serverKeyPath, caCertPath, "127.0.0.1", 8080)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	parentNode := srv.AddNode("parentNode", "0asdaw")
	childNode := srv.AddNode("childNode", 1)
	parentNode.AddChild(childNode)

	serverAddr := "127.0.0.1:8080"
	go func() {
		if err := srv.Run(); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(1 * time.Second)

	// Connect the client
	clt, err := client.NewClient(clientCertPath, clientKeyPath, caCertPath)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	err = clt.Connect("127.0.0.1", 8080, 100)
	if err != nil {
		t.Fatalf("Client failed to connect to server: %v", err)
	}
	time.Sleep(1 * time.Second)

	// Request a data link
	clt.RequestDataLink(serverAddr, 100)
	time.Sleep(1 * time.Second)

	// Send a discovery message
	clt.Discover(serverAddr, 100)
	time.Sleep(1 * time.Second)

	// Send a read message
	nodes := []string{"parentNode"}
	clt.Read(serverAddr, nodes, 1000)
	time.Sleep(1 * time.Second)

	// Clean up
	clt.Close(serverAddr)
	time.Sleep(1 * time.Second)
	srv.Stop()
}
