// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// CertificateMode defines the certificate provisioning mode.
type CertificateMode string

const (
	// CertModeSelfSigned uses self-signed certificates.
	CertModeSelfSigned CertificateMode = "selfsigned"
	// CertModeVault uses Vault PKI for certificates.
	CertModeVault CertificateMode = "vault"
	// CertModeFile serves pre-provisioned certificates from files
	// (for example a mounted Kubernetes Secret).
	CertModeFile CertificateMode = "file"
	// CertModeCertManager indicates certificates are provisioned externally
	// by cert-manager into a mounted directory. It is served through the
	// file provider; internal webhook certificate provisioning is skipped.
	CertModeCertManager CertificateMode = "cert-manager"
)

// Manager is the interface for certificate management.
type Manager interface {
	// GetCertificate returns a certificate for the given request.
	GetCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error)

	// GetCA returns the CA certificate pool.
	GetCA(ctx context.Context) (*x509.CertPool, error)

	// GetCAPEM returns the PEM-encoded CA bundle. The PEM form is used for
	// distribution (webhook caBundle injection, Secret persistence) without
	// issuing a throwaway leaf certificate just to read its chain.
	GetCAPEM(ctx context.Context) ([]byte, error)

	// RotateCertificate rotates the certificate for the given request.
	RotateCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error)

	// Close closes the certificate manager and releases resources.
	Close() error
}

// ManagerConfig contains configuration for the certificate manager.
type ManagerConfig struct {
	// Mode is the certificate provisioning mode.
	Mode CertificateMode

	// SelfSigned contains self-signed certificate configuration.
	SelfSigned *SelfSignedProviderConfig

	// Vault contains Vault PKI configuration.
	Vault *VaultProviderConfig

	// File contains file-based certificate configuration (used by the
	// file and cert-manager modes).
	File *FileProviderConfig
}

// NewManager creates a new certificate manager based on the configuration.
func NewManager(ctx context.Context, config *ManagerConfig) (Manager, error) {
	if config == nil {
		config = &ManagerConfig{Mode: CertModeSelfSigned}
	}

	switch config.Mode {
	case CertModeVault:
		if config.Vault == nil {
			return nil, fmt.Errorf("vault configuration required for vault mode")
		}
		return NewVaultProvider(ctx, config.Vault)
	case CertModeFile, CertModeCertManager:
		if config.File == nil {
			return nil, fmt.Errorf("file configuration required for %s mode", config.Mode)
		}
		return NewFileProvider(config.File)
	default:
		// Default to self-signed certificates (includes CertModeSelfSigned and any unknown mode)
		return NewSelfSignedProviderWithContext(ctx, config.SelfSigned)
	}
}

// CertificateRequest contains the parameters for certificate issuance.
type CertificateRequest struct {
	// CommonName is the certificate common name.
	CommonName string

	// DNSNames are the DNS subject alternative names.
	DNSNames []string

	// IPAddresses are the IP subject alternative names.
	IPAddresses []string

	// TTL is the certificate TTL.
	TTL time.Duration
}

// Certificate represents an issued certificate.
type Certificate struct {
	// Certificate is the parsed X.509 certificate.
	Certificate *x509.Certificate

	// PrivateKey is the private key.
	PrivateKey crypto.PrivateKey

	// CertificatePEM is the PEM-encoded certificate.
	CertificatePEM []byte

	// PrivateKeyPEM is the PEM-encoded private key.
	PrivateKeyPEM []byte

	// CAChainPEM is the PEM-encoded CA chain.
	CAChainPEM []byte

	// SerialNumber is the certificate serial number.
	SerialNumber string

	// Expiration is the certificate expiration time.
	Expiration time.Time
}

// IsExpiringSoon returns true if the certificate is expiring within the given duration.
func (c *Certificate) IsExpiringSoon(within time.Duration) bool {
	if c == nil || c.Certificate == nil {
		return true
	}
	return time.Until(c.Expiration) < within
}

// IsValid returns true if the certificate is valid (not expired).
func (c *Certificate) IsValid() bool {
	if c == nil || c.Certificate == nil {
		return false
	}
	return time.Now().Before(c.Expiration)
}

// TLSCertificate returns a tls.Certificate from the Certificate.
func (c *Certificate) TLSCertificate() (*tls.Certificate, error) {
	if c == nil || len(c.CertificatePEM) == 0 || len(c.PrivateKeyPEM) == 0 {
		return nil, fmt.Errorf("certificate or private key is missing")
	}

	cert, err := tls.X509KeyPair(c.CertificatePEM, c.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &cert, nil
}
