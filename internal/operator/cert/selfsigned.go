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
	// Persistence is enabled only when both SecretName and SecretClient are
	// set: the CA (certificate + key) and the current serving certificate
	// are stored in the Secret so the CA survives operator restarts and the
	// gateway can mount ca.crt for TLS verification.
	SecretName string

	// SecretNamespace is the namespace of the Kubernetes secret.
	SecretNamespace string

	// SecretClient is the Kubernetes client used to load and persist the
	// certificate Secret. When nil, persistence is disabled and the CA is
	// held in memory only (legacy behavior).
	SecretClient SecretStore
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
// It is a convenience wrapper around NewSelfSignedProviderWithContext for
// callers without a context (Secret persistence bootstrap is bounded
// internally when enabled).
func NewSelfSignedProvider(config *SelfSignedProviderConfig) (Manager, error) {
	return NewSelfSignedProviderWithContext(context.Background(), config)
}

// NewSelfSignedProviderWithContext creates a new self-signed certificate
// provider. When Secret persistence is configured (SecretName +
// SecretClient), the CA is loaded from the Secret when present and still
// valid (reuse-if-valid) and regenerated + persisted otherwise
// (regenerate-if-expired), so the CA is stable across operator restarts.
func NewSelfSignedProviderWithContext(ctx context.Context, config *SelfSignedProviderConfig) (Manager, error) {
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

	// Bootstrap the CA: reuse a persisted CA when valid, otherwise
	// generate a fresh one (and persist it when a store is configured).
	ca, err := p.bootstrapCA(ctx)
	if err != nil {
		return nil, err
	}
	p.ca = ca

	cm := GetCertMetrics()
	cm.expirySeconds.WithLabelValues(config.CACommonName).Set(time.Until(ca.Expiration).Seconds())

	p.logger.Info("self-signed certificate provider initialized",
		observability.String("ca_cn", config.CACommonName),
		observability.Duration("ca_validity", config.CAValidity),
		observability.Bool("secret_persistence", p.persistenceEnabled()),
		observability.Time("ca_expiration", ca.Expiration),
	)

	return p, nil
}

// bootstrapCA returns the provider CA: a persisted CA when reusable, or a
// newly generated (and best-effort persisted) one.
func (p *selfSignedProvider) bootstrapCA(ctx context.Context) (*Certificate, error) {
	if p.persistenceEnabled() {
		if ca := p.loadPersistedCA(ctx); ca != nil {
			return ca, nil
		}
	}

	ca, err := p.generateCA()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	if p.persistenceEnabled() {
		// Persistence failures are non-fatal: the provider keeps working
		// with the in-memory CA, but restarts will regenerate it.
		if persisted := p.persistCA(ctx, ca); persisted != nil {
			// Another replica persisted a valid CA first; adopt it so all
			// replicas issue from the same CA (TOCTOU-safe adoption).
			return persisted, nil
		}
	}

	return ca, nil
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

// GetCAPEM returns the PEM-encoded CA certificate.
func (p *selfSignedProvider) GetCAPEM(_ context.Context) ([]byte, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.ca == nil || len(p.ca.CertificatePEM) == 0 {
		return nil, fmt.Errorf("CA certificate not available")
	}

	return p.ca.CertificatePEM, nil
}

// RotateCertificate rotates the certificate for the given request.
func (p *selfSignedProvider) RotateCertificate(
	ctx context.Context,
	req *CertificateRequest,
) (*Certificate, error) {
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

	GetCertMetrics().rotationsTotal.WithLabelValues(
		providerSelfSigned,
	).Inc()

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
		Type:  pemTypeCertificate,
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
// RSA key generation and certificate creation are performed outside the lock
// to avoid blocking concurrent certificate reads during expensive crypto operations.
// Only the final assignment to the cache is done under the write lock.
func (p *selfSignedProvider) issueCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	// Check context before expensive operations
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before key generation: %w", err)
	}

	// Generate private key OUTSIDE the lock (expensive crypto operation)
	privateKey, err := rsa.GenerateKey(rand.Reader, p.config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Check context after key generation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled after key generation: %w", err)
	}

	// Generate serial number (cheap, but no reason to hold lock)
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Read CA data under read lock to build the certificate
	p.mu.RLock()
	if p.ca == nil {
		p.mu.RUnlock()
		return nil, fmt.Errorf("CA certificate not available")
	}
	caCert := p.ca.Certificate
	caKey, ok := p.ca.PrivateKey.(*rsa.PrivateKey)
	caPEM := p.ca.CertificatePEM
	p.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("CA private key is not RSA")
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

	// Check context before certificate creation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before certificate creation: %w", err)
	}

	// Sign with CA OUTSIDE the lock (crypto operation)
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privateKey.PublicKey, caKey)
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
		Type:  pemTypeCertificate,
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
		CAChainPEM:     caPEM,
		SerialNumber:   serialNumber.String(),
		Expiration:     cert.NotAfter,
	}

	// Acquire write lock ONLY for the cache assignment
	p.mu.Lock()
	p.certs[req.CommonName] = certificate
	p.mu.Unlock()

	cm := GetCertMetrics()
	cm.issuedTotal.WithLabelValues(providerSelfSigned).Inc()
	cm.expirySeconds.WithLabelValues(
		req.CommonName,
	).Set(time.Until(cert.NotAfter).Seconds())

	// Persist the freshly issued serving certificate alongside the CA so
	// it survives operator restarts (best-effort; failures are logged).
	p.persistServingCertificate(ctx, certificate)

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
