// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// TestCertificates holds test certificate data.
type TestCertificates struct {
	CAKey     *rsa.PrivateKey
	CACert    *x509.Certificate
	CACertPEM []byte
	CAKeyPEM  []byte

	ServerKey     *rsa.PrivateKey
	ServerCert    *x509.Certificate
	ServerCertPEM []byte
	ServerKeyPEM  []byte

	ClientKey     *rsa.PrivateKey
	ClientCert    *x509.Certificate
	ClientCertPEM []byte
	ClientKeyPEM  []byte

	TempDir string
}

// GenerateTestCertificates generates test CA, server, and client certificates.
func GenerateTestCertificates() (*TestCertificates, error) {
	tc := &TestCertificates{}

	// Generate CA
	if err := tc.generateCA(); err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	// Generate server certificate
	if err := tc.generateServerCert(); err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Generate client certificate
	if err := tc.generateClientCert(); err != nil {
		return nil, fmt.Errorf("failed to generate client certificate: %w", err)
	}

	return tc, nil
}

// generateCA generates a CA certificate and key.
func (tc *TestCertificates) generateCA() error {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}
	tc.CAKey = caKey

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"Test CA"},
			Country:       []string{"US"},
			Province:      []string{"Test"},
			Locality:      []string{"Test City"},
			CommonName:    "Test Root CA",
			StreetAddress: []string{},
			PostalCode:    []string{},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	tc.CACert = caCert

	// Encode to PEM
	tc.CACertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	tc.CAKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})

	return nil
}

// generateServerCert generates a server certificate signed by the CA.
func (tc *TestCertificates) generateServerCert() error {
	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}
	tc.ServerKey = serverKey

	// Create server certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:    []string{"localhost", "*.local", "*.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Sign with CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, tc.CACert, &serverKey.PublicKey, tc.CAKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Parse the certificate
	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}
	tc.ServerCert = serverCert

	// Encode to PEM
	tc.ServerCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})

	tc.ServerKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	return nil
}

// generateClientCert generates a client certificate signed by the CA.
func (tc *TestCertificates) generateClientCert() error {
	// Generate client private key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate client key: %w", err)
	}
	tc.ClientKey = clientKey

	// Create client certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "test-client",
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		EmailAddresses: []string{"test@example.com"},
	}

	// Sign with CA
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, tc.CACert, &clientKey.PublicKey, tc.CAKey)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Parse the certificate
	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %w", err)
	}
	tc.ClientCert = clientCert

	// Encode to PEM
	tc.ClientCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertDER,
	})

	tc.ClientKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientKey),
	})

	return nil
}

// WriteToFiles writes certificates to temporary files.
func (tc *TestCertificates) WriteToFiles() error {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	tc.TempDir = tempDir

	// Write CA certificate
	if err := os.WriteFile(tc.CACertPath(), tc.CACertPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Write CA key
	if err := os.WriteFile(tc.CAKeyPath(), tc.CAKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	// Write server certificate
	if err := os.WriteFile(tc.ServerCertPath(), tc.ServerCertPEM, 0600); err != nil {
		return fmt.Errorf("failed to write server certificate: %w", err)
	}

	// Write server key
	if err := os.WriteFile(tc.ServerKeyPath(), tc.ServerKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write server key: %w", err)
	}

	// Write client certificate
	if err := os.WriteFile(tc.ClientCertPath(), tc.ClientCertPEM, 0600); err != nil {
		return fmt.Errorf("failed to write client certificate: %w", err)
	}

	// Write client key
	if err := os.WriteFile(tc.ClientKeyPath(), tc.ClientKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write client key: %w", err)
	}

	return nil
}

// Cleanup removes temporary certificate files.
func (tc *TestCertificates) Cleanup() {
	if tc.TempDir != "" {
		os.RemoveAll(tc.TempDir)
	}
}

// CACertPath returns the path to the CA certificate file.
func (tc *TestCertificates) CACertPath() string {
	return filepath.Join(tc.TempDir, "ca.crt")
}

// CAKeyPath returns the path to the CA key file.
func (tc *TestCertificates) CAKeyPath() string {
	return filepath.Join(tc.TempDir, "ca.key")
}

// ServerCertPath returns the path to the server certificate file.
func (tc *TestCertificates) ServerCertPath() string {
	return filepath.Join(tc.TempDir, "server.crt")
}

// ServerKeyPath returns the path to the server key file.
func (tc *TestCertificates) ServerKeyPath() string {
	return filepath.Join(tc.TempDir, "server.key")
}

// ClientCertPath returns the path to the client certificate file.
func (tc *TestCertificates) ClientCertPath() string {
	return filepath.Join(tc.TempDir, "client.crt")
}

// ClientKeyPath returns the path to the client key file.
func (tc *TestCertificates) ClientKeyPath() string {
	return filepath.Join(tc.TempDir, "client.key")
}

// GetServerTLSConfig returns a TLS config for the server.
func (tc *TestCertificates) GetServerTLSConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(tc.ServerCertPEM, tc.ServerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(tc.CACertPEM)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// GetServerMTLSConfig returns a TLS config for the server with mTLS.
func (tc *TestCertificates) GetServerMTLSConfig() (*tls.Config, error) {
	cfg, err := tc.GetServerTLSConfig()
	if err != nil {
		return nil, err
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	return cfg, nil
}

// GetClientTLSConfig returns a TLS config for the client.
func (tc *TestCertificates) GetClientTLSConfig() (*tls.Config, error) {
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(tc.CACertPEM)

	return &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

// GetClientMTLSConfig returns a TLS config for the client with mTLS.
func (tc *TestCertificates) GetClientMTLSConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(tc.ClientCertPEM, tc.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(tc.CACertPEM)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// GenerateExpiredCertificate generates an expired certificate for testing.
func GenerateExpiredCertificate() (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Expired Test"},
			CommonName:   "expired.test",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM, nil
}

// GenerateSelfSignedCertificate generates a self-signed certificate.
func GenerateSelfSignedCertificate(commonName string, dnsNames []string, ipAddresses []net.IP) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Self-Signed Test"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM, nil
}

// GenerateECDSACertificate generates an ECDSA certificate.
func GenerateECDSACertificate(commonName string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ECDSA Test"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// GenerateInvalidCertificate generates invalid certificate data for testing.
func GenerateInvalidCertificate() (certPEM, keyPEM []byte) {
	certPEM = []byte("-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----\n")
	keyPEM = []byte("-----BEGIN RSA PRIVATE KEY-----\nINVALID\n-----END RSA PRIVATE KEY-----\n")
	return certPEM, keyPEM
}

// GenerateMismatchedCertAndKey generates a certificate and a different key (mismatched).
func GenerateMismatchedCertAndKey() (certPEM, keyPEM []byte, err error) {
	// Generate certificate with one key
	cert1, _, err := GenerateSelfSignedCertificate("test1", []string{"localhost"}, nil)
	if err != nil {
		return nil, nil, err
	}

	// Generate a different key
	_, key2, err := GenerateSelfSignedCertificate("test2", []string{"localhost"}, nil)
	if err != nil {
		return nil, nil, err
	}

	return cert1, key2, nil
}

// GenerateTestCertificatesWithDNS generates test certificates with custom DNS names.
func GenerateTestCertificatesWithDNS(dnsNames []string) (*TestCertificates, error) {
	tc := &TestCertificates{}

	// Generate CA
	if err := tc.generateCA(); err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	// Generate server certificate with custom DNS names
	if err := tc.generateServerCertWithDNS(dnsNames); err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Generate client certificate
	if err := tc.generateClientCert(); err != nil {
		return nil, fmt.Errorf("failed to generate client certificate: %w", err)
	}

	return tc, nil
}

// generateServerCertWithDNS generates a server certificate with custom DNS names.
func (tc *TestCertificates) generateServerCertWithDNS(dnsNames []string) error {
	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}
	tc.ServerKey = serverKey

	// Create server certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	commonName := "localhost"
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:    dnsNames,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Sign with CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, tc.CACert, &serverKey.PublicKey, tc.CAKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Parse the certificate
	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}
	tc.ServerCert = serverCert

	// Encode to PEM
	tc.ServerCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})

	tc.ServerKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	return nil
}
