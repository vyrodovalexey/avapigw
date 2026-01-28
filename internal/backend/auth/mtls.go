package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Default configuration values for mTLS.
const (
	DefaultCertificateCacheTTL = 1 * time.Hour
	DefaultCertRenewBefore     = 10 * time.Minute
)

// MTLSProvider implements mTLS authentication for backend connections.
type MTLSProvider struct {
	name    string
	config  *config.BackendMTLSAuthConfig
	logger  observability.Logger
	metrics *Metrics
	vault   vault.Client

	// Certificate cache
	mu              sync.RWMutex
	tlsConfig       *tls.Config
	certificate     *tls.Certificate
	certificateInfo *certificateInfo
	caPool          *x509.CertPool

	// Lifecycle
	closed    atomic.Bool
	stopCh    chan struct{}
	stoppedCh chan struct{}
}

// certificateInfo holds metadata about the current certificate.
type certificateInfo struct {
	notBefore    time.Time
	notAfter     time.Time
	serialNumber string
	subject      string
}

// NewMTLSProvider creates a new mTLS authentication provider.
func NewMTLSProvider(name string, cfg *config.BackendMTLSAuthConfig, opts ...ProviderOption) (*MTLSProvider, error) {
	if cfg == nil {
		return nil, NewConfigError("config", "mTLS configuration is required")
	}

	if !cfg.Enabled {
		return nil, NewConfigError("enabled", "mTLS authentication is not enabled")
	}

	if err := cfg.Validate(); err != nil {
		return nil, NewConfigErrorWithCause("config", "invalid mTLS configuration", err)
	}

	p := &MTLSProvider{
		name:      name,
		config:    cfg,
		logger:    observability.NopLogger(),
		metrics:   NopMetrics(),
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(p)
	}

	p.logger = p.logger.With(
		observability.String("provider", name),
		observability.String("auth_type", "mtls"),
	)

	return p, nil
}

// Name returns the provider name.
func (p *MTLSProvider) Name() string {
	return p.name
}

// Type returns the authentication type.
func (p *MTLSProvider) Type() string {
	return "mtls"
}

// ApplyHTTP applies mTLS authentication to an HTTP request.
// Note: For mTLS, the TLS configuration must be applied to the HTTP transport,
// not to individual requests. This method returns an error if the TLS config
// is not available.
func (p *MTLSProvider) ApplyHTTP(ctx context.Context, _ *http.Request) error {
	if p.closed.Load() {
		return ErrProviderClosed
	}

	start := time.Now()

	// Ensure TLS config is loaded
	_, err := p.getTLSConfig(ctx)
	if err != nil {
		p.metrics.RecordRequest(p.name, "mtls", "error", time.Since(start))
		p.metrics.RecordError(p.name, "mtls", "tls_config")
		return NewProviderErrorWithCause(p.name, "apply_http", "failed to get TLS config", err)
	}

	p.metrics.RecordRequest(p.name, "mtls", "success", time.Since(start))
	p.logger.Debug("mTLS authentication ready for HTTP request")

	return nil
}

// ApplyGRPC returns gRPC dial options for mTLS authentication.
func (p *MTLSProvider) ApplyGRPC(ctx context.Context) ([]grpc.DialOption, error) {
	if p.closed.Load() {
		return nil, ErrProviderClosed
	}

	start := time.Now()

	tlsConfig, err := p.getTLSConfig(ctx)
	if err != nil {
		p.metrics.RecordRequest(p.name, "mtls", "error", time.Since(start))
		p.metrics.RecordError(p.name, "mtls", "tls_config")
		return nil, NewProviderErrorWithCause(p.name, "apply_grpc", "failed to get TLS config", err)
	}

	creds := credentials.NewTLS(tlsConfig)

	p.metrics.RecordRequest(p.name, "mtls", "success", time.Since(start))
	p.logger.Debug("created gRPC credentials for mTLS authentication")

	return []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}, nil
}

// Refresh refreshes the certificate.
func (p *MTLSProvider) Refresh(ctx context.Context) error {
	if p.closed.Load() {
		return ErrProviderClosed
	}

	start := time.Now()

	// Force refresh by clearing cache
	p.mu.Lock()
	p.tlsConfig = nil
	p.certificate = nil
	p.certificateInfo = nil
	p.mu.Unlock()

	// Get new TLS config
	_, err := p.getTLSConfig(ctx)
	if err != nil {
		p.metrics.RecordRefresh(p.name, "mtls", "error", time.Since(start))
		return NewProviderErrorWithCause(p.name, "refresh", "failed to refresh certificate", err)
	}

	p.metrics.RecordRefresh(p.name, "mtls", "success", time.Since(start))
	p.logger.Info("mTLS certificate refreshed")

	return nil
}

// Close closes the provider and releases resources.
func (p *MTLSProvider) Close() error {
	if p.closed.Swap(true) {
		return nil
	}

	close(p.stopCh)

	p.logger.Info("mTLS provider closed")
	return nil
}

// GetTLSConfig returns the TLS configuration for HTTP transport.
func (p *MTLSProvider) GetTLSConfig(ctx context.Context) (*tls.Config, error) {
	return p.getTLSConfig(ctx)
}

// getTLSConfig returns the TLS configuration, loading it if necessary.
func (p *MTLSProvider) getTLSConfig(ctx context.Context) (*tls.Config, error) {
	// Check cache first
	p.mu.RLock()
	if p.tlsConfig != nil && p.isCertificateValid() {
		cfg := p.tlsConfig.Clone()
		p.mu.RUnlock()
		p.metrics.RecordCacheHit()
		return cfg, nil
	}
	p.mu.RUnlock()

	p.metrics.RecordCacheMiss()

	// Acquire write lock to load certificate
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.tlsConfig != nil && p.isCertificateValid() {
		return p.tlsConfig.Clone(), nil
	}

	// Load certificate based on source
	var cert *tls.Certificate
	var certInfo *certificateInfo
	var err error

	if p.config.Vault != nil && p.config.Vault.Enabled {
		cert, certInfo, err = p.loadVaultCertificate(ctx)
	} else {
		cert, certInfo, err = p.loadFileCertificate()
	}

	if err != nil {
		return nil, err
	}

	// Load CA pool if configured
	caPool, err := p.loadCAPool(ctx)
	if err != nil {
		return nil, err
	}

	// Build TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Cache the config
	p.tlsConfig = tlsConfig
	p.certificate = cert
	p.certificateInfo = certInfo
	p.caPool = caPool

	if certInfo != nil {
		p.metrics.SetTokenExpiry(p.name, "mtls", certInfo.notAfter)
	}

	p.logger.Debug("TLS config loaded",
		observability.Bool("from_vault", p.config.Vault != nil && p.config.Vault.Enabled),
	)

	return tlsConfig.Clone(), nil
}

// isCertificateValid checks if the cached certificate is still valid.
func (p *MTLSProvider) isCertificateValid() bool {
	if p.certificateInfo == nil {
		return false
	}

	// Check if certificate is about to expire
	renewTime := p.certificateInfo.notAfter.Add(-DefaultCertRenewBefore)
	return time.Now().Before(renewTime)
}

// loadFileCertificate loads the certificate from files.
func (p *MTLSProvider) loadFileCertificate() (*tls.Certificate, *certificateInfo, error) {
	if p.config.CertFile == "" {
		return nil, nil, NewConfigError("certFile", "certificate file is required")
	}

	if p.config.KeyFile == "" {
		return nil, nil, NewConfigError("keyFile", "key file is required")
	}

	cert, err := tls.LoadX509KeyPair(p.config.CertFile, p.config.KeyFile)
	if err != nil {
		return nil, nil, NewProviderErrorWithCause(p.name, "load_certificate", "failed to load certificate", err)
	}

	// Parse the leaf certificate for metadata
	var certInfo *certificateInfo
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			cert.Leaf = leaf
			certInfo = &certificateInfo{
				notBefore:    leaf.NotBefore,
				notAfter:     leaf.NotAfter,
				serialNumber: leaf.SerialNumber.String(),
				subject:      leaf.Subject.String(),
			}
		}
	}

	p.logger.Debug("loaded certificate from file",
		observability.String("certFile", p.config.CertFile),
	)

	return &cert, certInfo, nil
}

// loadVaultCertificate loads the certificate from Vault PKI.
func (p *MTLSProvider) loadVaultCertificate(ctx context.Context) (*tls.Certificate, *certificateInfo, error) {
	if p.vault == nil || !p.vault.IsEnabled() {
		return nil, nil, NewProviderError(p.name, "vault_certificate", "vault client not available")
	}

	if p.config.Vault == nil {
		return nil, nil, NewConfigError("vault", "vault configuration is required")
	}

	// Parse TTL
	var ttl time.Duration
	if p.config.Vault.TTL != "" {
		var err error
		ttl, err = time.ParseDuration(p.config.Vault.TTL)
		if err != nil {
			return nil, nil, NewConfigErrorWithCause("vault.ttl", "invalid TTL format", err)
		}
	}

	opts := &vault.PKIIssueOptions{
		Mount:      p.config.Vault.PKIMount,
		Role:       p.config.Vault.Role,
		CommonName: p.config.Vault.CommonName,
		AltNames:   p.config.Vault.AltNames,
		TTL:        ttl,
		Format:     "pem",
	}

	vaultCert, err := p.vault.PKI().IssueCertificate(ctx, opts)
	if err != nil {
		return nil, nil, NewProviderErrorWithCause(
			p.name, "vault_certificate", "failed to issue certificate from vault", err)
	}

	// Create tls.Certificate from PEM data
	cert, err := tls.X509KeyPair([]byte(vaultCert.CertificatePEM), []byte(vaultCert.PrivateKeyPEM))
	if err != nil {
		return nil, nil, NewProviderErrorWithCause(p.name, "vault_certificate", "failed to create TLS certificate", err)
	}

	// Parse the leaf certificate for metadata
	var certInfo *certificateInfo
	if vaultCert.Certificate != nil {
		cert.Leaf = vaultCert.Certificate
		certInfo = &certificateInfo{
			notBefore:    vaultCert.Certificate.NotBefore,
			notAfter:     vaultCert.Certificate.NotAfter,
			serialNumber: vaultCert.SerialNumber,
			subject:      vaultCert.Certificate.Subject.String(),
		}
	}

	p.logger.Debug("loaded certificate from vault",
		observability.String("commonName", p.config.Vault.CommonName),
		observability.String("serial", vaultCert.SerialNumber),
	)

	return &cert, certInfo, nil
}

// loadCAPool loads the CA certificate pool.
func (p *MTLSProvider) loadCAPool(ctx context.Context) (*x509.CertPool, error) {
	// Try Vault CA first
	if p.config.Vault != nil && p.config.Vault.Enabled {
		pool, err := p.vault.PKI().GetCA(ctx, p.config.Vault.PKIMount)
		if err == nil {
			return pool, nil
		}
		p.logger.Warn("failed to load CA from vault, falling back to file",
			observability.Error(err),
		)
	}

	// Try file-based CA
	if p.config.CAFile != "" {
		caCert, err := os.ReadFile(p.config.CAFile)
		if err != nil {
			msg := fmt.Sprintf("failed to read CA file %s", p.config.CAFile)
			return nil, NewProviderErrorWithCause(p.name, "load_ca", msg, err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, NewProviderError(p.name, "load_ca", "failed to parse CA certificate")
		}

		return pool, nil
	}

	// Use system CA pool
	return nil, nil
}

// Ensure MTLSProvider implements Provider.
var _ Provider = (*MTLSProvider)(nil)
