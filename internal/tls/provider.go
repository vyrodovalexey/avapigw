package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// CertificateProvider defines the interface for certificate providers.
// Implementations can load certificates from various sources such as files,
// inline data, or external secret managers like HashiCorp Vault.
type CertificateProvider interface {
	// GetCertificate returns a certificate for the given client hello info.
	// This is used as the GetCertificate callback in tls.Config for SNI support.
	GetCertificate(ctx context.Context, info *tls.ClientHelloInfo) (*tls.Certificate, error)

	// GetClientCA returns the CA certificate pool for client certificate validation.
	// Returns nil if client validation is not configured.
	GetClientCA(ctx context.Context) (*x509.CertPool, error)

	// Watch returns a channel that receives certificate events.
	// The channel is closed when the provider is closed or the context is canceled.
	Watch(ctx context.Context) <-chan CertificateEvent

	// Close releases resources held by the provider.
	Close() error
}

// CertificateEventType represents the type of certificate event.
type CertificateEventType int

// Certificate event type constants.
const (
	// CertificateEventLoaded indicates a certificate was initially loaded.
	CertificateEventLoaded CertificateEventType = iota

	// CertificateEventReloaded indicates a certificate was reloaded.
	CertificateEventReloaded

	// CertificateEventExpiring indicates a certificate is about to expire.
	CertificateEventExpiring

	// CertificateEventError indicates an error occurred during certificate operations.
	CertificateEventError
)

// String returns the string representation of the event type.
func (t CertificateEventType) String() string {
	switch t {
	case CertificateEventLoaded:
		return "loaded"
	case CertificateEventReloaded:
		return "reloaded"
	case CertificateEventExpiring:
		return "expiring"
	case CertificateEventError:
		return "error"
	default:
		return "unknown"
	}
}

// CertificateEvent represents an event from a certificate provider.
type CertificateEvent struct {
	// Type is the type of event.
	Type CertificateEventType

	// Certificate is the certificate associated with the event (may be nil for errors).
	Certificate *tls.Certificate

	// Error is the error associated with the event (for CertificateEventError).
	Error error

	// Message provides additional context about the event.
	Message string
}

// CertificateInfo contains metadata about a certificate.
type CertificateInfo struct {
	// Subject is the certificate subject.
	Subject string

	// Issuer is the certificate issuer.
	Issuer string

	// SerialNumber is the certificate serial number.
	SerialNumber string

	// NotBefore is when the certificate becomes valid.
	NotBefore string

	// NotAfter is when the certificate expires.
	NotAfter string

	// DNSNames are the DNS names in the certificate.
	DNSNames []string

	// IPAddresses are the IP addresses in the certificate.
	IPAddresses []string

	// EmailAddresses are the email addresses in the certificate.
	EmailAddresses []string

	// IsCA indicates if this is a CA certificate.
	IsCA bool
}

// ExtractCertificateInfo extracts metadata from a certificate.
func ExtractCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	if cert == nil {
		return nil
	}

	info := &CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:     cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		IsCA:         cert.IsCA,
	}

	if len(cert.DNSNames) > 0 {
		info.DNSNames = make([]string, len(cert.DNSNames))
		copy(info.DNSNames, cert.DNSNames)
	}

	if len(cert.IPAddresses) > 0 {
		info.IPAddresses = make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			info.IPAddresses[i] = ip.String()
		}
	}

	if len(cert.EmailAddresses) > 0 {
		info.EmailAddresses = make([]string, len(cert.EmailAddresses))
		copy(info.EmailAddresses, cert.EmailAddresses)
	}

	return info
}

// VaultProviderFactory is a function that creates a CertificateProvider from Vault TLS configuration.
// This factory pattern avoids circular imports between the tls and vault packages.
// The factory is provided by the application bootstrap code, which has access to both packages.
//
// Parameters:
//   - config: The Vault TLS configuration specifying PKI mount, role, common name, etc.
//   - logger: The logger for the provider to use.
//
// Returns:
//   - CertificateProvider: A provider that manages certificates via Vault PKI.
//   - error: An error if the provider could not be created.
type VaultProviderFactory func(config *VaultTLSConfig, logger observability.Logger) (CertificateProvider, error)

// NopProvider is a certificate provider that returns no certificates.
// It is useful for testing or when TLS is disabled.
type NopProvider struct {
	closed bool
}

// NewNopProvider creates a new NopProvider.
func NewNopProvider() *NopProvider {
	return &NopProvider{}
}

// GetCertificate returns ErrCertificateNotFound.
func (p *NopProvider) GetCertificate(_ context.Context, _ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p.closed {
		return nil, ErrProviderClosed
	}
	return nil, ErrCertificateNotFound
}

// GetClientCA returns nil.
func (p *NopProvider) GetClientCA(_ context.Context) (*x509.CertPool, error) {
	if p.closed {
		return nil, ErrProviderClosed
	}
	return nil, nil
}

// Watch returns a closed channel.
func (p *NopProvider) Watch(_ context.Context) <-chan CertificateEvent {
	ch := make(chan CertificateEvent)
	close(ch)
	return ch
}

// Close marks the provider as closed.
func (p *NopProvider) Close() error {
	p.closed = true
	return nil
}

// Ensure NopProvider implements CertificateProvider.
var _ CertificateProvider = (*NopProvider)(nil)
