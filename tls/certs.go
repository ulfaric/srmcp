// certs.go

package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// Generate a UUID serial number
func generateSerialNumber() (*big.Int, error) {
	serialNumberUUID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(serialNumberUUID[:]), nil
}

// CreateCA creates a new Certificate Authority.
func CreateCA(certPath, keyPath, organization, country string, validYears int) (*x509.Certificate, *rsa.PrivateKey, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
			Country:      []string{country},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(validYears, 0, 0), // Valid for given years
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	if certPath != "" && keyPath != "" {
		err = saveCertAndKey(certPath, keyPath, caBytes, privKey)
		if err != nil {
			return nil, nil, err
		}
	}

	return ca, privKey, nil
}

// CreateServerCert creates a new server certificate signed by the CA.
func CreateServerCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, certPath, keyPath, organization, country string, validYears int, dnsNames ...string) (*x509.Certificate, *rsa.PrivateKey, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	// Get host machine's IP addresses
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil, err
	}

	var ipAddresses []net.IP
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ipAddresses = append(ipAddresses, ipNet.IP)
			}
		}
	}
	ipAddresses = append(ipAddresses, net.ParseIP("127.0.0.1")) // Include localhost
	dnsNames = append(dnsNames, "localhost")                   // Include localhost

	serverCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
			Country:      []string{country},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(validYears, 0, 0), // Valid for given years
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: ipAddresses,
		DNSNames:    dnsNames,
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverCert, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	if certPath != "" && keyPath != "" {
		err = saveCertAndKey(certPath, keyPath, serverCertBytes, privKey)
		if err != nil {
			return nil, nil, err
		}
	}

	return serverCert, privKey, nil
}

// CreateClientCert creates a new client certificate signed by the CA.
func CreateClientCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, certPath, keyPath, organization, country string, validYears int, dnsNames ...string) (*x509.Certificate, *rsa.PrivateKey, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	// Get host machine's IP addresses
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil, err
	}

	var ipAddresses []net.IP
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ipAddresses = append(ipAddresses, ipNet.IP)
			}
		}
	}
	ipAddresses = append(ipAddresses, net.ParseIP("127.0.0.1")) // Include localhost
	dnsNames = append(dnsNames, "localhost")                   // Include localhost

	clientCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
			Country:      []string{country},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(validYears, 0, 0), // Valid for given years
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: ipAddresses,
		DNSNames:    dnsNames,
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientCert, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	if certPath != "" && keyPath != "" {
		err = saveCertAndKey(certPath, keyPath, clientCertBytes, privKey)
		if err != nil {
			return nil, nil, err
		}
	}

	return clientCert, privKey, nil
}

func saveCertAndKey(certPath, keyPath string, certBytes []byte, privKey *rsa.PrivateKey) error {
	// Ensure the directory for the certificate path exists
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return err
	}

	// Ensure the directory for the key path exists
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return err
	}

	// Save the certificate
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}

	// Save the private key
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	err = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return err
	}

	return nil
}