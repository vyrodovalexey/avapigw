// Package cert provides self-signed certificate generation and management for webhooks.
// It handles CA and server certificate generation, rotation, and injection into
// Kubernetes webhook configurations.
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	// DefaultKeySize is the default RSA key size for certificates.
	DefaultKeySize = 2048

	// DefaultValidity is the default certificate validity period.
	DefaultValidity = 365 * 24 * time.Hour

	// DefaultRotationThreshold is the default time before expiry to trigger rotation.
	DefaultRotationThreshold = 30 * 24 * time.Hour

	// CACommonName is the common name for the CA certificate.
	CACommonName = "avapigw-webhook-ca"

	// CAOrganization is the organization for the CA certificate.
	CAOrganization = "avapigw"
)

// CertificateBundle holds CA and server certificates with their private keys.
type CertificateBundle struct {
	// CACert is the PEM-encoded CA certificate.
	CACert []byte

	// CAKey is the PEM-encoded CA private key.
	CAKey []byte

	// ServerCert is the PEM-encoded server certificate.
	ServerCert []byte

	// ServerKey is the PEM-encoded server private key.
	ServerKey []byte

	// ExpiresAt is the expiration time of the server certificate.
	ExpiresAt time.Time
}

// GeneratorConfig holds configuration for certificate generation.
type GeneratorConfig struct {
	// ServiceName is the name of the webhook service.
	ServiceName string

	// ServiceNamespace is the namespace of the webhook service.
	ServiceNamespace string

	// DNSNames are additional DNS names for the server certificate.
	DNSNames []string

	// Validity is the certificate validity period.
	Validity time.Duration

	// KeySize is the RSA key size (default 2048).
	KeySize int
}

// Validate validates the generator configuration.
func (c *GeneratorConfig) Validate() error {
	if c.ServiceName == "" {
		return fmt.Errorf("service name is required")
	}
	if c.ServiceNamespace == "" {
		return fmt.Errorf("service namespace is required")
	}
	if c.Validity <= 0 {
		return fmt.Errorf("validity must be positive")
	}
	if c.KeySize != 0 && c.KeySize < 2048 {
		return fmt.Errorf("key size must be at least 2048 bits")
	}
	return nil
}

// Generator generates self-signed certificates for webhooks.
type Generator struct {
	config *GeneratorConfig
}

// NewGenerator creates a new certificate generator with the given configuration.
func NewGenerator(cfg *GeneratorConfig) *Generator {
	if cfg.KeySize == 0 {
		cfg.KeySize = DefaultKeySize
	}
	if cfg.Validity == 0 {
		cfg.Validity = DefaultValidity
	}

	return &Generator{
		config: cfg,
	}
}

// Generate generates a new certificate bundle including CA and server certificates.
func (g *Generator) Generate() (*CertificateBundle, error) {
	// Generate CA certificate
	caCert, caKey, err := g.GenerateCA()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	// Generate server certificate signed by CA
	serverCert, serverKey, expiresAt, err := g.GenerateServerCert(caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	return &CertificateBundle{
		CACert:     caCert,
		CAKey:      caKey,
		ServerCert: serverCert,
		ServerKey:  serverKey,
		ExpiresAt:  expiresAt,
	}, nil
}

// GenerateCA generates a self-signed CA certificate and private key.
// Returns the CA certificate PEM, CA private key PEM, and any error.
func (g *Generator) GenerateCA() (caCertPEM []byte, caKeyPEM []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, g.config.KeySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   CACommonName,
			Organization: []string{CAOrganization},
		},
		NotBefore:             now,
		NotAfter:              now.Add(g.config.Validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

// GenerateServerCert generates a server certificate signed by the CA.
// Returns the server certificate PEM, server private key PEM, expiration time, and any error.
func (g *Generator) GenerateServerCert(caCertPEM, caKeyPEM []byte) (serverCertPEM []byte, serverKeyPEM []byte, expiresAt time.Time, err error) {
	// Parse CA certificate
	caCert, err := ParseCertificate(caCertPEM)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, g.config.KeySize)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("failed to generate server private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Build DNS names for the certificate
	dnsNames := g.buildDNSNames()

	now := time.Now()
	expiresAt = now.Add(g.config.Validity)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   g.config.ServiceName,
			Organization: []string{CAOrganization},
		},
		NotBefore:             now,
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
	}

	// Sign the server certificate with the CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	return certPEM, keyPEM, expiresAt, nil
}

// buildDNSNames builds the list of DNS names for the server certificate.
func (g *Generator) buildDNSNames() []string {
	// Standard Kubernetes service DNS names
	dnsNames := []string{
		g.config.ServiceName,
		fmt.Sprintf("%s.%s", g.config.ServiceName, g.config.ServiceNamespace),
		fmt.Sprintf("%s.%s.svc", g.config.ServiceName, g.config.ServiceNamespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", g.config.ServiceName, g.config.ServiceNamespace),
	}

	// Add any additional DNS names from config
	if len(g.config.DNSNames) > 0 {
		dnsNames = append(dnsNames, g.config.DNSNames...)
	}

	return dnsNames
}

// NeedsRotation checks if a certificate needs rotation based on the rotation threshold.
// Returns true if the certificate expires within the threshold period.
func NeedsRotation(certPEM []byte, rotationThreshold time.Duration) (bool, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate expires within the threshold
	rotationTime := cert.NotAfter.Add(-rotationThreshold)
	return time.Now().After(rotationTime), nil
}

// ParseCertificate parses a PEM-encoded certificate.
func ParseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE PEM block, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// parsePrivateKey parses a PEM-encoded RSA private key.
func parsePrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("expected RSA PRIVATE KEY PEM block, got %s", block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}

// generateSerialNumber generates a random serial number for certificates.
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}

// GetCertificateExpiry returns the expiration time of a PEM-encoded certificate.
func GetCertificateExpiry(certPEM []byte) (time.Time, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// IsCertificateValid checks if a certificate is currently valid (not expired and not before valid period).
func IsCertificateValid(certPEM []byte) (bool, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return false, err
	}

	now := time.Now()
	return now.After(cert.NotBefore) && now.Before(cert.NotAfter), nil
}
