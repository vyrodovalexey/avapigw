package vault

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// PKIClient provides PKI secrets engine operations.
type PKIClient interface {
	// IssueCertificate issues a new certificate.
	IssueCertificate(ctx context.Context, opts *PKIIssueOptions) (*Certificate, error)

	// SignCSR signs a certificate signing request.
	SignCSR(ctx context.Context, csr []byte, opts *PKISignOptions) (*Certificate, error)

	// GetCA returns the CA certificate.
	GetCA(ctx context.Context, mount string) (*x509.CertPool, error)

	// GetCRL returns the certificate revocation list.
	GetCRL(ctx context.Context, mount string) ([]byte, error)

	// RevokeCertificate revokes a certificate.
	RevokeCertificate(ctx context.Context, mount, serial string) error
}

// PKIIssueOptions contains options for certificate issuance.
type PKIIssueOptions struct {
	// Mount is the PKI secrets engine mount path.
	Mount string

	// Role is the PKI role name.
	Role string

	// CommonName is the certificate common name.
	CommonName string

	// AltNames are the subject alternative names (DNS).
	AltNames []string

	// IPSANs are the IP subject alternative names.
	IPSANs []string

	// TTL is the certificate TTL.
	TTL time.Duration

	// Format is the output format (pem, der, pem_bundle).
	Format string
}

// PKISignOptions contains options for CSR signing.
type PKISignOptions struct {
	// Mount is the PKI secrets engine mount path.
	Mount string

	// Role is the PKI role name.
	Role string

	// CommonName is the certificate common name (optional, uses CSR CN if empty).
	CommonName string

	// AltNames are additional subject alternative names.
	AltNames []string

	// IPSANs are additional IP subject alternative names.
	IPSANs []string

	// TTL is the certificate TTL.
	TTL time.Duration

	// Format is the output format (pem, der, pem_bundle).
	Format string
}

// Certificate represents an issued certificate.
type Certificate struct {
	// Certificate is the parsed X.509 certificate.
	Certificate *x509.Certificate

	// PrivateKey is the private key (nil for CSR signing).
	PrivateKey crypto.PrivateKey

	// CertificatePEM is the PEM-encoded certificate.
	CertificatePEM string

	// PrivateKeyPEM is the PEM-encoded private key.
	PrivateKeyPEM string

	// CAChainPEM is the PEM-encoded CA chain.
	CAChainPEM string

	// SerialNumber is the certificate serial number.
	SerialNumber string

	// Expiration is the certificate expiration time.
	Expiration time.Time
}

// pkiClient implements PKIClient.
type pkiClient struct {
	client *vaultClient
}

// newPKIClient creates a new PKI client.
func newPKIClient(client *vaultClient) *pkiClient {
	return &pkiClient{client: client}
}

// IssueCertificate issues a new certificate.
func (p *pkiClient) IssueCertificate(ctx context.Context, opts *PKIIssueOptions) (*Certificate, error) {
	if opts == nil {
		return nil, NewVaultError("pki_issue", "", "options are required")
	}

	if opts.Mount == "" {
		return nil, NewVaultError("pki_issue", "", "mount is required")
	}

	if opts.Role == "" {
		return nil, NewVaultError("pki_issue", "", "role is required")
	}

	if opts.CommonName == "" {
		return nil, NewVaultError("pki_issue", "", "common name is required")
	}

	start := time.Now()
	path := fmt.Sprintf("%s/issue/%s", opts.Mount, opts.Role)

	data := map[string]interface{}{
		"common_name": opts.CommonName,
	}

	if len(opts.AltNames) > 0 {
		data["alt_names"] = strings.Join(opts.AltNames, ",")
	}

	if len(opts.IPSANs) > 0 {
		data["ip_sans"] = strings.Join(opts.IPSANs, ",")
	}

	if opts.TTL > 0 {
		data["ttl"] = opts.TTL.String()
	}

	if opts.Format != "" {
		data["format"] = opts.Format
	}

	// Execute with retry
	var secret interface{}
	err := p.client.executeWithRetry(ctx, func() error {
		var err error
		secret, err = p.client.api.Logical().WriteWithContext(ctx, path, data)
		return err
	})

	if err != nil {
		p.client.metrics.RecordRequest("pki_issue", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("pki_issue", path, "failed to issue certificate", err)
	}

	vaultSecret, ok := secret.(*vaultapi.Secret)
	if !ok || vaultSecret == nil || vaultSecret.Data == nil {
		p.client.metrics.RecordRequest("pki_issue", "error", time.Since(start))
		return nil, NewVaultError("pki_issue", path, "no data in response")
	}

	cert := p.parseCertificateResponse(vaultSecret.Data)

	p.client.metrics.RecordRequest("pki_issue", "success", time.Since(start))
	p.client.logger.Info("certificate issued",
		observability.String("common_name", opts.CommonName),
		observability.String("serial", cert.SerialNumber),
		observability.Time("expiration", cert.Expiration),
	)

	return cert, nil
}

// SignCSR signs a certificate signing request.
func (p *pkiClient) SignCSR(ctx context.Context, csr []byte, opts *PKISignOptions) (*Certificate, error) {
	if opts == nil {
		return nil, NewVaultError("pki_sign", "", "options are required")
	}

	if opts.Mount == "" {
		return nil, NewVaultError("pki_sign", "", "mount is required")
	}

	if opts.Role == "" {
		return nil, NewVaultError("pki_sign", "", "role is required")
	}

	if len(csr) == 0 {
		return nil, NewVaultError("pki_sign", "", "CSR is required")
	}

	start := time.Now()
	path := fmt.Sprintf("%s/sign/%s", opts.Mount, opts.Role)

	data := map[string]interface{}{
		"csr": string(csr),
	}

	if opts.CommonName != "" {
		data["common_name"] = opts.CommonName
	}

	if len(opts.AltNames) > 0 {
		data["alt_names"] = strings.Join(opts.AltNames, ",")
	}

	if len(opts.IPSANs) > 0 {
		data["ip_sans"] = strings.Join(opts.IPSANs, ",")
	}

	if opts.TTL > 0 {
		data["ttl"] = opts.TTL.String()
	}

	if opts.Format != "" {
		data["format"] = opts.Format
	}

	secret, err := p.client.api.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.client.metrics.RecordRequest("pki_sign", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("pki_sign", path, "failed to sign CSR", err)
	}

	if secret == nil || secret.Data == nil {
		p.client.metrics.RecordRequest("pki_sign", "error", time.Since(start))
		return nil, NewVaultError("pki_sign", path, "no data in response")
	}

	cert := p.parseCertificateResponse(secret.Data)

	p.client.metrics.RecordRequest("pki_sign", "success", time.Since(start))
	p.client.logger.Info("CSR signed",
		observability.String("serial", cert.SerialNumber),
		observability.Time("expiration", cert.Expiration),
	)

	return cert, nil
}

// GetCA returns the CA certificate.
func (p *pkiClient) GetCA(ctx context.Context, mount string) (*x509.CertPool, error) {
	if mount == "" {
		return nil, NewVaultError("pki_get_ca", "", "mount is required")
	}

	start := time.Now()
	path := fmt.Sprintf("%s/cert/ca", mount)

	// Check cache first
	if p.client.cache != nil {
		if cached, ok := p.client.cache.get(path); ok {
			p.client.metrics.RecordCacheHit()
			if pool, ok := cached.(*x509.CertPool); ok {
				return pool, nil
			}
		}
		p.client.metrics.RecordCacheMiss()
	}

	secret, err := p.client.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		p.client.metrics.RecordRequest("pki_get_ca", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("pki_get_ca", path, "failed to get CA certificate", err)
	}

	if secret == nil || secret.Data == nil {
		p.client.metrics.RecordRequest("pki_get_ca", "error", time.Since(start))
		return nil, NewVaultError("pki_get_ca", path, "no data in response")
	}

	caPEM, ok := secret.Data["certificate"].(string)
	if !ok {
		p.client.metrics.RecordRequest("pki_get_ca", "error", time.Since(start))
		return nil, NewVaultError("pki_get_ca", path, "certificate not found in response")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		p.client.metrics.RecordRequest("pki_get_ca", "error", time.Since(start))
		return nil, NewVaultError("pki_get_ca", path, "failed to parse CA certificate")
	}

	// Cache the result
	if p.client.cache != nil {
		p.client.cache.set(path, pool)
	}

	p.client.metrics.RecordRequest("pki_get_ca", "success", time.Since(start))
	return pool, nil
}

// GetCRL returns the certificate revocation list.
func (p *pkiClient) GetCRL(ctx context.Context, mount string) ([]byte, error) {
	if mount == "" {
		return nil, NewVaultError("pki_get_crl", "", "mount is required")
	}

	start := time.Now()
	path := fmt.Sprintf("%s/cert/crl", mount)

	secret, err := p.client.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		p.client.metrics.RecordRequest("pki_get_crl", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("pki_get_crl", path, "failed to get CRL", err)
	}

	if secret == nil || secret.Data == nil {
		p.client.metrics.RecordRequest("pki_get_crl", "error", time.Since(start))
		return nil, NewVaultError("pki_get_crl", path, "no data in response")
	}

	// The /cert/crl endpoint returns the CRL in the "certificate" field
	crl, ok := secret.Data["certificate"].(string)
	if !ok {
		p.client.metrics.RecordRequest("pki_get_crl", "error", time.Since(start))
		return nil, NewVaultError("pki_get_crl", path, "CRL not found in response")
	}

	p.client.metrics.RecordRequest("pki_get_crl", "success", time.Since(start))
	return []byte(crl), nil
}

// RevokeCertificate revokes a certificate.
func (p *pkiClient) RevokeCertificate(ctx context.Context, mount, serial string) error {
	if mount == "" {
		return NewVaultError("pki_revoke", "", "mount is required")
	}

	if serial == "" {
		return NewVaultError("pki_revoke", "", "serial is required")
	}

	start := time.Now()
	path := fmt.Sprintf("%s/revoke", mount)

	data := map[string]interface{}{
		"serial_number": serial,
	}

	_, err := p.client.api.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		p.client.metrics.RecordRequest("pki_revoke", "error", time.Since(start))
		return NewVaultErrorWithCause("pki_revoke", path, "failed to revoke certificate", err)
	}

	p.client.metrics.RecordRequest("pki_revoke", "success", time.Since(start))
	p.client.logger.Info("certificate revoked",
		observability.String("serial", serial),
	)

	return nil
}

// parseCertificateResponse parses the certificate response from Vault.
func (p *pkiClient) parseCertificateResponse(data map[string]interface{}) *Certificate {
	cert := &Certificate{}

	p.extractCertificatePEM(cert, data)
	p.extractPrivateKeyPEM(cert, data)
	p.extractCAChain(cert, data)
	p.extractMetadata(cert, data)

	return cert
}

// extractCertificatePEM extracts and parses the certificate PEM from response data.
func (p *pkiClient) extractCertificatePEM(cert *Certificate, data map[string]interface{}) {
	certPEM, ok := data["certificate"].(string)
	if !ok {
		return
	}

	cert.CertificatePEM = certPEM
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		cert.Certificate = x509Cert
		cert.Expiration = x509Cert.NotAfter
	}
}

// extractPrivateKeyPEM extracts and parses the private key PEM from response data.
func (p *pkiClient) extractPrivateKeyPEM(cert *Certificate, data map[string]interface{}) {
	keyPEM, ok := data["private_key"].(string)
	if !ok {
		return
	}

	cert.PrivateKeyPEM = keyPEM
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return
	}

	key, err := parsePrivateKey(block.Bytes)
	if err == nil {
		cert.PrivateKey = key
	}
}

// extractCAChain extracts the CA chain from response data.
func (p *pkiClient) extractCAChain(cert *Certificate, data map[string]interface{}) {
	if caChain, ok := data["ca_chain"].([]interface{}); ok {
		chainPEMs := make([]string, 0, len(caChain))
		for _, ca := range caChain {
			if caStr, ok := ca.(string); ok {
				chainPEMs = append(chainPEMs, caStr)
			}
		}
		cert.CAChainPEM = strings.Join(chainPEMs, "\n")
		return
	}

	if issuingCA, ok := data["issuing_ca"].(string); ok {
		cert.CAChainPEM = issuingCA
	}
}

// extractMetadata extracts serial number and expiration from response data.
func (p *pkiClient) extractMetadata(cert *Certificate, data map[string]interface{}) {
	if serial, ok := data["serial_number"].(string); ok {
		cert.SerialNumber = serial
	}

	if expiration, ok := data["expiration"].(float64); ok {
		cert.Expiration = time.Unix(int64(expiration), 0)
	}
}

// parsePrivateKey parses a private key from DER bytes.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	// Try PKCS8 first
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}

	// Try PKCS1 RSA
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	// Try EC
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// disabledPKIClient is a PKI client that returns ErrVaultDisabled.
type disabledPKIClient struct{}

func (c *disabledPKIClient) IssueCertificate(_ context.Context, _ *PKIIssueOptions) (*Certificate, error) {
	return nil, ErrVaultDisabled
}

func (c *disabledPKIClient) SignCSR(_ context.Context, _ []byte, _ *PKISignOptions) (*Certificate, error) {
	return nil, ErrVaultDisabled
}

func (c *disabledPKIClient) GetCA(_ context.Context, _ string) (*x509.CertPool, error) {
	return nil, ErrVaultDisabled
}

func (c *disabledPKIClient) GetCRL(_ context.Context, _ string) ([]byte, error) {
	return nil, ErrVaultDisabled
}

func (c *disabledPKIClient) RevokeCertificate(_ context.Context, _, _ string) error {
	return ErrVaultDisabled
}

// Ensure implementations satisfy the interface.
var (
	_ PKIClient = (*pkiClient)(nil)
	_ PKIClient = (*disabledPKIClient)(nil)
)
