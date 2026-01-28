package mtls

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Common errors for mTLS validation.
var (
	// ErrNoCertificate indicates that no client certificate was provided.
	ErrNoCertificate = errors.New("no client certificate provided")

	// ErrCertificateExpired indicates that the certificate has expired.
	ErrCertificateExpired = errors.New("certificate has expired")

	// ErrCertificateNotYetValid indicates that the certificate is not yet valid.
	ErrCertificateNotYetValid = errors.New("certificate is not yet valid")

	// ErrCertificateRevoked indicates that the certificate has been revoked.
	ErrCertificateRevoked = errors.New("certificate has been revoked")

	// ErrCertificateUntrusted indicates that the certificate is not trusted.
	ErrCertificateUntrusted = errors.New("certificate is not trusted")

	// ErrInvalidCertificateChain indicates that the certificate chain is invalid.
	ErrInvalidCertificateChain = errors.New("invalid certificate chain")
)

// CertificateInfo contains information extracted from a client certificate.
type CertificateInfo struct {
	// SubjectDN is the subject distinguished name.
	SubjectDN string `json:"subject_dn,omitempty"`

	// IssuerDN is the issuer distinguished name.
	IssuerDN string `json:"issuer_dn,omitempty"`

	// SerialNumber is the certificate serial number.
	SerialNumber string `json:"serial_number,omitempty"`

	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time `json:"not_before,omitempty"`

	// NotAfter is when the certificate expires.
	NotAfter time.Time `json:"not_after,omitempty"`

	// DNSNames contains the DNS SANs.
	DNSNames []string `json:"dns_names,omitempty"`

	// URIs contains the URI SANs.
	URIs []string `json:"uris,omitempty"`

	// EmailAddresses contains the email SANs.
	EmailAddresses []string `json:"email_addresses,omitempty"`

	// SPIFFEID is the SPIFFE ID extracted from URI SANs.
	SPIFFEID string `json:"spiffe_id,omitempty"`

	// Fingerprint is the certificate fingerprint (SHA-256).
	Fingerprint string `json:"fingerprint,omitempty"`

	// Subject contains parsed subject fields.
	Subject *SubjectInfo `json:"subject,omitempty"`
}

// SubjectInfo contains parsed subject fields.
type SubjectInfo struct {
	CommonName         string   `json:"cn,omitempty"`
	Organization       []string `json:"o,omitempty"`
	OrganizationalUnit []string `json:"ou,omitempty"`
	Country            []string `json:"c,omitempty"`
	Province           []string `json:"st,omitempty"`
	Locality           []string `json:"l,omitempty"`
}

// Validator validates client certificates.
type Validator interface {
	// Validate validates a client certificate and returns certificate information.
	Validate(ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate) (*CertificateInfo, error)
}

// validator implements the Validator interface.
type validator struct {
	config  *Config
	caPool  *x509.CertPool
	logger  observability.Logger
	metrics *Metrics
}

// ValidatorOption is a functional option for the validator.
type ValidatorOption func(*validator)

// WithValidatorLogger sets the logger for the validator.
func WithValidatorLogger(logger observability.Logger) ValidatorOption {
	return func(v *validator) {
		v.logger = logger
	}
}

// WithValidatorMetrics sets the metrics for the validator.
func WithValidatorMetrics(metrics *Metrics) ValidatorOption {
	return func(v *validator) {
		v.metrics = metrics
	}
}

// WithCAPool sets the CA certificate pool.
func WithCAPool(pool *x509.CertPool) ValidatorOption {
	return func(v *validator) {
		v.caPool = pool
	}
}

// NewValidator creates a new mTLS validator.
func NewValidator(config *Config, opts ...ValidatorOption) (Validator, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	v := &validator{
		config: config,
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(v)
	}

	// Initialize CA pool if not provided
	if v.caPool == nil {
		pool, err := createCAPool(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA pool: %w", err)
		}
		v.caPool = pool
	}

	// Initialize metrics if not provided
	if v.metrics == nil {
		v.metrics = NewMetrics("gateway")
	}

	return v, nil
}

// createCAPool creates a CA certificate pool from configuration.
func createCAPool(config *Config) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	// Add CA from PEM data
	if config.CACert != "" {
		if !pool.AppendCertsFromPEM([]byte(config.CACert)) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
	}

	// Add CA from file
	if config.CAFile != "" {
		// File reading would be implemented here
		return nil, fmt.Errorf("CA file loading not yet implemented")
	}

	return pool, nil
}

// Validate validates a client certificate and returns certificate information.
func (v *validator) Validate(
	ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate,
) (*CertificateInfo, error) {
	start := time.Now()

	if cert == nil {
		v.metrics.RecordValidation("error", "no_certificate", time.Since(start))
		return nil, ErrNoCertificate
	}

	// Validate certificate chain
	if err := v.validateChain(cert, chain); err != nil {
		v.metrics.RecordValidation("error", "invalid_chain", time.Since(start))
		return nil, err
	}

	// Check expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		v.metrics.RecordValidation("error", "not_yet_valid", time.Since(start))
		return nil, ErrCertificateNotYetValid
	}
	if now.After(cert.NotAfter) {
		v.metrics.RecordValidation("error", "expired", time.Since(start))
		return nil, ErrCertificateExpired
	}

	// Check revocation if enabled
	if v.config.Revocation != nil && v.config.Revocation.Enabled {
		if err := v.checkRevocation(ctx, cert); err != nil {
			v.metrics.RecordValidation("error", "revoked", time.Since(start))
			return nil, err
		}
	}

	// Extract certificate information
	info := v.extractInfo(cert)

	v.metrics.RecordValidation("success", "valid", time.Since(start))
	v.logger.Debug("certificate validated",
		observability.String("subject", info.SubjectDN),
		observability.String("fingerprint", info.Fingerprint),
	)

	return info, nil
}

// validateChain validates the certificate chain.
func (v *validator) validateChain(cert *x509.Certificate, chain []*x509.Certificate) error {
	opts := x509.VerifyOptions{
		Roots:         v.caPool,
		Intermediates: x509.NewCertPool(),
	}

	// Add intermediate certificates
	for _, intermediate := range chain {
		opts.Intermediates.AddCert(intermediate)
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCertificateUntrusted, err)
	}

	return nil
}

// checkRevocation checks if the certificate has been revoked.
func (v *validator) checkRevocation(ctx context.Context, cert *x509.Certificate) error {
	// CRL checking
	if v.config.Revocation.CRL != nil && v.config.Revocation.CRL.Enabled {
		if err := v.checkCRL(ctx, cert); err != nil {
			return err
		}
	}

	// OCSP checking
	if v.config.Revocation.OCSP != nil && v.config.Revocation.OCSP.Enabled {
		if err := v.checkOCSP(ctx, cert); err != nil {
			return err
		}
	}

	return nil
}

// checkCRL checks the certificate against CRLs.
func (v *validator) checkCRL(_ context.Context, _ *x509.Certificate) error {
	// CRL checking implementation would go here
	// This is a placeholder for the actual implementation
	return nil
}

// checkOCSP checks the certificate using OCSP.
func (v *validator) checkOCSP(_ context.Context, _ *x509.Certificate) error {
	// OCSP checking implementation would go here
	// This is a placeholder for the actual implementation
	return nil
}

// extractInfo extracts information from the certificate.
func (v *validator) extractInfo(cert *x509.Certificate) *CertificateInfo {
	info := &CertificateInfo{
		SubjectDN:      cert.Subject.String(),
		IssuerDN:       cert.Issuer.String(),
		SerialNumber:   cert.SerialNumber.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		Fingerprint:    calculateFingerprint(cert),
		Subject: &SubjectInfo{
			CommonName:         cert.Subject.CommonName,
			Organization:       cert.Subject.Organization,
			OrganizationalUnit: cert.Subject.OrganizationalUnit,
			Country:            cert.Subject.Country,
			Province:           cert.Subject.Province,
			Locality:           cert.Subject.Locality,
		},
	}

	// Extract URIs
	for _, uri := range cert.URIs {
		info.URIs = append(info.URIs, uri.String())
	}

	// Extract SPIFFE ID
	if v.config.ExtractIdentity != nil && v.config.ExtractIdentity.SPIFFE {
		info.SPIFFEID = extractSPIFFEID(cert)
	}

	return info
}

// calculateFingerprint calculates the SHA-256 fingerprint of a certificate.
func calculateFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// extractSPIFFEID extracts the SPIFFE ID from a certificate's URI SANs.
func extractSPIFFEID(cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if strings.HasPrefix(uri.String(), "spiffe://") {
			return uri.String()
		}
	}
	return ""
}

// GetIdentity returns the primary identity from the certificate info.
func (c *CertificateInfo) GetIdentity(config *IdentityExtractionConfig) string {
	if config == nil {
		return c.SubjectDN
	}

	// Try each identity source in priority order
	if identity := c.getIdentityFromSPIFFE(config); identity != "" {
		return identity
	}
	if identity := c.getIdentityFromSubject(config); identity != "" {
		return identity
	}
	if identity := c.getIdentityFromSANs(config); identity != "" {
		return identity
	}

	// Default to subject DN
	return c.SubjectDN
}

// getIdentityFromSPIFFE extracts identity from SPIFFE ID if configured.
func (c *CertificateInfo) getIdentityFromSPIFFE(config *IdentityExtractionConfig) string {
	if config.SPIFFE && c.SPIFFEID != "" {
		return c.SPIFFEID
	}
	return ""
}

// getIdentityFromSubject extracts identity from subject field if configured.
func (c *CertificateInfo) getIdentityFromSubject(config *IdentityExtractionConfig) string {
	if config.SubjectField == "" || c.Subject == nil {
		return ""
	}
	switch config.SubjectField {
	case "CN":
		return c.Subject.CommonName
	case "O":
		if len(c.Subject.Organization) > 0 {
			return c.Subject.Organization[0]
		}
	case "OU":
		if len(c.Subject.OrganizationalUnit) > 0 {
			return c.Subject.OrganizationalUnit[0]
		}
	}
	return ""
}

// getIdentityFromSANs extracts identity from Subject Alternative Names if configured.
func (c *CertificateInfo) getIdentityFromSANs(config *IdentityExtractionConfig) string {
	if config.SANDNS && len(c.DNSNames) > 0 {
		return c.DNSNames[0]
	}
	if config.SANURI && len(c.URIs) > 0 {
		return c.URIs[0]
	}
	if config.SANEmail && len(c.EmailAddresses) > 0 {
		return c.EmailAddresses[0]
	}
	return ""
}

// ParseSPIFFEID parses a SPIFFE ID into its components.
func ParseSPIFFEID(spiffeID string) (*SPIFFEIDInfo, error) {
	if !strings.HasPrefix(spiffeID, "spiffe://") {
		return nil, fmt.Errorf("invalid SPIFFE ID: must start with spiffe://")
	}

	u, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	return &SPIFFEIDInfo{
		TrustDomain: u.Host,
		Path:        u.Path,
	}, nil
}

// SPIFFEIDInfo contains parsed SPIFFE ID information.
type SPIFFEIDInfo struct {
	TrustDomain string
	Path        string
}

// Ensure validator implements Validator.
var _ Validator = (*validator)(nil)
