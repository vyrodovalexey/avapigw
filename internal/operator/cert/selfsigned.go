// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// SelfSignedProviderConfig contains configuration for the self-signed certificate provider.
type SelfSignedProviderConfig struct {
	// CACommonName is the common name for the CA certificate.
	CACommonName string

	// CAValidity is the validity period for the CA certificate.
	CAValidity time.Duration

	// CertValidity is the validity period for issued certificates.
	CertValidity time.Duration

	// RotateBefore is the duration before expiry to rotate certificates.
	RotateBefore time.Duration

	// KeySize is the RSA key size in bits.
	KeySize int

	// Organization is the organization for certificates.
	Organization []string

	// SecretName is the name of the Kubernetes secret to store certificates.
	SecretName string

	// SecretNamespace is the namespace of the Kubernetes secret.
	SecretNamespace string
}

// selfSignedProvider implements Manager using self-signed certificates.
type selfSignedProvider struct {
	config *SelfSignedProviderConfig
	logger observability.Logger

	mu     sync.RWMutex
	ca     *Certificate
	certs  map[string]*Certificate
	closed atomic.Bool
}

// NewSelfSignedProvider creates a new self-signed certificate provider.
func NewSelfSignedProvider(config *SelfSignedProviderConfig) (Manager, error) {
	if config == nil {
		config = &SelfSignedProviderConfig{}
	}

	// Set defaults using constants
	if config.CACommonName == "" {
		config.CACommonName = DefaultCACommonName
	}
	if config.CAValidity == 0 {
		config.CAValidity = DefaultCAValidity
	}
	if config.CertValidity == 0 {
		config.CertValidity = DefaultCertValidity
	}
	if config.RotateBefore == 0 {
		config.RotateBefore = DefaultRotateBefore
	}
	if config.KeySize == 0 {
		config.KeySize = DefaultKeySize
	}
	if len(config.Organization) == 0 {
		config.Organization = []string{DefaultOrganization}
	}

	p := &selfSignedProvider{
		config: config,
		logger: observability.GetGlobalLogger().With(observability.String("component", "cert-manager")),
		certs:  make(map[string]*Certificate),
	}

	// Generate CA certificate
	ca, err := p.generateCA()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}
	p.ca = ca

	p.logger.Info("self-signed certificate provider initialized",
		observability.String("ca_cn", config.CACommonName),
		observability.Duration("ca_validity", config.CAValidity),
	)

	return p, nil
}

// GetCertificate returns a certificate for the given request.
func (p *selfSignedProvider) GetCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	// Check context cancellation at the start
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	if req == nil || req.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}

	p.mu.RLock()
	cert, ok := p.certs[req.CommonName]
	p.mu.RUnlock()

	if ok && cert.IsValid() && !cert.IsExpiringSoon(p.config.RotateBefore) {
		return cert, nil
	}

	// Check context again before expensive operation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before certificate generation: %w", err)
	}

	// Generate new certificate
	return p.issueCertificate(ctx, req)
}

// GetCA returns the CA certificate pool.
func (p *selfSignedProvider) GetCA(ctx context.Context) (*x509.CertPool, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.ca == nil {
		return nil, fmt.Errorf("CA certificate not available")
	}

	pool := x509.NewCertPool()
	pool.AddCert(p.ca.Certificate)
	return pool, nil
}

// RotateCertificate rotates the certificate for the given request.
func (p *selfSignedProvider) RotateCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	// Check context cancellation at the start
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	if req == nil || req.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}

	return p.issueCertificate(ctx, req)
}

// Close closes the certificate provider.
func (p *selfSignedProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed.Store(true)
	p.certs = nil
	p.ca = nil

	return nil
}

// generateCA generates a new CA certificate.
func (p *selfSignedProvider) generateCA() (*Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, p.config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   p.config.CACommonName,
			Organization: p.config.Organization,
		},
		NotBefore:             now,
		NotAfter:              now.Add(p.config.CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return &Certificate{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		SerialNumber:   serialNumber.String(),
		Expiration:     cert.NotAfter,
	}, nil
}

// issueCertificate issues a new certificate signed by the CA.
func (p *selfSignedProvider) issueCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	// Check context before acquiring lock
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before acquiring lock: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check context after acquiring lock
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled after acquiring lock: %w", err)
	}

	if p.ca == nil {
		return nil, fmt.Errorf("CA certificate not available")
	}

	// Generate private key (expensive operation)
	privateKey, err := rsa.GenerateKey(rand.Reader, p.config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Check context after key generation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled after key generation: %w", err)
	}

	// Generate serial number
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	validity := p.config.CertValidity
	if req.TTL > 0 {
		validity = req.TTL
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: p.config.Organization,
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add DNS names
	if len(req.DNSNames) > 0 {
		template.DNSNames = req.DNSNames
	}

	// Add IP addresses
	for _, ipStr := range req.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Sign with CA
	caKey, ok := p.ca.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA private key is not RSA")
	}

	// Check context before certificate creation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before certificate creation: %w", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, p.ca.Certificate, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	certificate := &Certificate{
		Certificate:    cert,
		PrivateKey:     privateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		CAChainPEM:     p.ca.CertificatePEM,
		SerialNumber:   serialNumber.String(),
		Expiration:     cert.NotAfter,
	}

	// Cache the certificate
	p.certs[req.CommonName] = certificate

	p.logger.Info("certificate issued",
		observability.String("common_name", req.CommonName),
		observability.Time("expiration", cert.NotAfter),
	)

	return certificate, nil
}

// generateSerialNumber generates a random serial number.
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// Ensure selfSignedProvider implements Manager.
var _ Manager = (*selfSignedProvider)(nil)
