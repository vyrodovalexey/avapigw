// Package backend provides backend service management for the API Gateway.
package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// TLSConfigBuilder builds TLS configurations for backend connections.
type TLSConfigBuilder struct {
	config  *config.BackendTLSConfig
	logger  observability.Logger
	metrics tlspkg.MetricsRecorder

	vaultClient   vault.Client
	vaultProvider *vault.VaultProvider

	// Cached TLS config
	mu        sync.RWMutex
	tlsConfig *tls.Config
}

// TLSConfigBuilderOption is a functional option for configuring TLSConfigBuilder.
type TLSConfigBuilderOption func(*TLSConfigBuilder)

// WithTLSLogger sets the logger for the TLS config builder.
func WithTLSLogger(logger observability.Logger) TLSConfigBuilderOption {
	return func(b *TLSConfigBuilder) {
		b.logger = logger
	}
}

// WithTLSMetrics sets the metrics recorder for the TLS config builder.
func WithTLSMetrics(metrics tlspkg.MetricsRecorder) TLSConfigBuilderOption {
	return func(b *TLSConfigBuilder) {
		b.metrics = metrics
	}
}

// WithTLSVaultClient sets the Vault client for Vault-based backend certificate management.
func WithTLSVaultClient(client vault.Client) TLSConfigBuilderOption {
	return func(b *TLSConfigBuilder) {
		b.vaultClient = client
	}
}

// NewTLSConfigBuilder creates a new TLS config builder.
func NewTLSConfigBuilder(cfg *config.BackendTLSConfig, opts ...TLSConfigBuilderOption) *TLSConfigBuilder {
	b := &TLSConfigBuilder{
		config:  cfg,
		logger:  observability.NopLogger(),
		metrics: tlspkg.NewNopMetrics(),
	}

	for _, opt := range opts {
		opt(b)
	}

	return b
}

// Build builds a tls.Config for backend connections.
func (b *TLSConfigBuilder) Build() (*tls.Config, error) {
	if b.config == nil || !b.config.Enabled {
		return nil, nil
	}

	// Check cache first
	b.mu.RLock()
	if b.tlsConfig != nil {
		cfg := b.tlsConfig.Clone()
		b.mu.RUnlock()
		return cfg, nil
	}
	b.mu.RUnlock()

	// Build new config
	b.mu.Lock()
	defer b.mu.Unlock()

	// Double-check after acquiring write lock
	if b.tlsConfig != nil {
		return b.tlsConfig.Clone(), nil
	}

	tlsConfig, err := b.buildTLSConfig()
	if err != nil {
		return nil, err
	}

	b.tlsConfig = tlsConfig
	return tlsConfig.Clone(), nil
}

// BuildWithServerName builds a tls.Config with a specific server name.
func (b *TLSConfigBuilder) BuildWithServerName(serverName string) (*tls.Config, error) {
	baseCfg, err := b.Build()
	if err != nil {
		return nil, err
	}

	if baseCfg == nil {
		return nil, nil
	}

	// Clone and set server name
	cfg := baseCfg.Clone()
	cfg.ServerName = serverName

	return cfg, nil
}

// buildTLSConfig builds the actual TLS configuration.
func (b *TLSConfigBuilder) buildTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: b.config.InsecureSkipVerify, //nolint:gosec // Intentional for dev/testing
	}

	// Set server name if specified
	if b.config.ServerName != "" {
		cfg.ServerName = b.config.ServerName
	}

	// Set TLS versions
	if err := b.setTLSVersions(cfg); err != nil {
		return nil, err
	}

	// Set cipher suites
	if err := b.setCipherSuites(cfg); err != nil {
		return nil, err
	}

	// Set ALPN protocols
	if len(b.config.ALPN) > 0 {
		cfg.NextProtos = b.config.ALPN
	}

	// Load CA certificate for server verification
	if err := b.loadCACertificate(cfg); err != nil {
		return nil, err
	}

	// Load client certificate for mTLS
	if b.config.IsMutual() {
		if err := b.loadClientCertificate(cfg); err != nil {
			return nil, err
		}
	}

	b.logger.Debug("built backend TLS config",
		observability.String("mode", b.config.GetEffectiveMode()),
		observability.String("minVersion", b.config.GetEffectiveMinVersion()),
		observability.Bool("insecureSkipVerify", b.config.InsecureSkipVerify),
	)

	return cfg, nil
}

// setTLSVersions sets the minimum and maximum TLS versions.
func (b *TLSConfigBuilder) setTLSVersions(cfg *tls.Config) error {
	// Set minimum version
	minVersion := b.config.GetEffectiveMinVersion()
	minVer, err := parseTLSVersion(minVersion)
	if err != nil {
		return fmt.Errorf("invalid minVersion: %w", err)
	}
	cfg.MinVersion = minVer

	// Set maximum version if specified
	if b.config.MaxVersion != "" {
		maxVer, err := parseTLSVersion(b.config.MaxVersion)
		if err != nil {
			return fmt.Errorf("invalid maxVersion: %w", err)
		}
		cfg.MaxVersion = maxVer
	}

	return nil
}

// setCipherSuites sets the allowed cipher suites.
func (b *TLSConfigBuilder) setCipherSuites(cfg *tls.Config) error {
	if len(b.config.CipherSuites) == 0 {
		// Use default secure cipher suites
		cfg.CipherSuites = tlspkg.DefaultSecureCipherSuites()
		return nil
	}

	suites, err := tlspkg.ParseCipherSuites(b.config.CipherSuites)
	if err != nil {
		return fmt.Errorf("invalid cipher suites: %w", err)
	}
	cfg.CipherSuites = suites

	return nil
}

// loadCACertificate loads the CA certificate for server verification.
func (b *TLSConfigBuilder) loadCACertificate(cfg *tls.Config) error {
	if b.config.CAFile == "" {
		// Use system CA pool
		return nil
	}

	caCert, err := os.ReadFile(b.config.CAFile)
	if err != nil {
		return fmt.Errorf("failed to read CA file %s: %w", b.config.CAFile, err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate from %s", b.config.CAFile)
	}

	cfg.RootCAs = caPool

	b.logger.Debug("loaded CA certificate for backend TLS",
		observability.String("caFile", b.config.CAFile),
	)

	return nil
}

// Vault provider timeout constants for backend TLS.
const (
	// vaultProviderStartTimeout is the timeout for starting the Vault provider.
	vaultProviderStartTimeout = 30 * time.Second

	// vaultCertificateFetchTimeout is the timeout for fetching a certificate from the Vault provider.
	vaultCertificateFetchTimeout = 5 * time.Second
)

// loadClientCertificate loads the client certificate for mTLS.
func (b *TLSConfigBuilder) loadClientCertificate(cfg *tls.Config) error {
	// Check if Vault is configured for client certificates
	if b.config.Vault != nil && b.config.Vault.Enabled {
		return b.loadVaultClientCertificate(cfg)
	}

	// Load from files
	if b.config.CertFile == "" || b.config.KeyFile == "" {
		return fmt.Errorf("certFile and keyFile are required for mTLS")
	}

	cert, err := tls.LoadX509KeyPair(b.config.CertFile, b.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %w", err)
	}

	cfg.Certificates = []tls.Certificate{cert}

	// Update metrics
	b.metrics.UpdateCertificateExpiryFromTLS(&cert, "backend_client")

	b.logger.Debug("loaded client certificate for backend mTLS",
		observability.String("certFile", b.config.CertFile),
		observability.String("keyFile", b.config.KeyFile),
	)

	return nil
}

// loadVaultClientCertificate configures Vault-based client certificate for mTLS.
//
//nolint:contextcheck // TLS callback has no context; bounded background contexts are appropriate
func (b *TLSConfigBuilder) loadVaultClientCertificate(cfg *tls.Config) error {
	if b.vaultClient == nil {
		return fmt.Errorf("vault client is required when vault TLS is enabled for backend")
	}

	// Parse TTL from config
	var ttl time.Duration
	if b.config.Vault.TTL != "" {
		var err error
		ttl, err = time.ParseDuration(b.config.Vault.TTL)
		if err != nil {
			return fmt.Errorf("invalid vault TTL %q: %w", b.config.Vault.TTL, err)
		}
	}

	providerConfig := &vault.VaultProviderConfig{
		PKIMount:   b.config.Vault.PKIMount,
		Role:       b.config.Vault.Role,
		CommonName: b.config.Vault.CommonName,
		AltNames:   b.config.Vault.AltNames,
		TTL:        ttl,
	}
	provider, err := vault.NewVaultProvider(
		b.vaultClient,
		providerConfig,
		vault.WithVaultProviderLogger(b.logger),
	)
	if err != nil {
		return fmt.Errorf("failed to create vault provider for backend TLS: %w", err)
	}

	// Start the provider to issue initial certificate
	startCtx, startCancel := context.WithTimeout(context.Background(), vaultProviderStartTimeout)
	defer startCancel()
	if err := provider.Start(startCtx); err != nil {
		_ = provider.Close()
		return fmt.Errorf("failed to start vault provider for backend TLS: %w", err)
	}

	// Store provider for lifecycle management
	b.vaultProvider = provider

	// Use GetClientCertificate callback for dynamic cert loading.
	// The TLS library callback does not provide a context, so we create a
	// bounded background context for each certificate fetch operation.
	cfg.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		certCtx, certCancel := context.WithTimeout(context.Background(), vaultCertificateFetchTimeout)
		defer certCancel()
		cert, certErr := provider.GetCertificate(certCtx, nil)
		if certErr != nil {
			return nil, certErr
		}
		// Update metrics on each certificate fetch
		b.metrics.UpdateCertificateExpiryFromTLS(cert, "backend_client")
		return cert, nil
	}

	b.logger.Info("vault-based client certificate configured for backend mTLS",
		observability.String("commonName", b.config.Vault.CommonName),
	)
	return nil
}

// Invalidate invalidates the cached TLS config, forcing a rebuild on next Build call.
func (b *TLSConfigBuilder) Invalidate() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tlsConfig = nil
}

// Close releases resources held by the TLS config builder.
// If a Vault provider was created, it will be stopped and closed.
func (b *TLSConfigBuilder) Close() error {
	if b.vaultProvider != nil {
		return b.vaultProvider.Close()
	}
	return nil
}

// parseTLSVersion parses a TLS version string to the corresponding constant.
func parseTLSVersion(version string) (uint16, error) {
	switch version {
	case "TLS10":
		return tls.VersionTLS10, nil
	case "TLS11":
		return tls.VersionTLS11, nil
	case "TLS12":
		return tls.VersionTLS12, nil
	case "TLS13":
		return tls.VersionTLS13, nil
	case "":
		return tls.VersionTLS12, nil // Default to TLS 1.2
	default:
		return 0, fmt.Errorf("unknown TLS version: %s", version)
	}
}

// BackendTLSTransport creates an HTTP transport with TLS configuration for backend connections.
type BackendTLSTransport struct {
	builder   *TLSConfigBuilder
	transport *http.Transport
	logger    observability.Logger
}

// NewBackendTLSTransport creates a new backend TLS transport.
func NewBackendTLSTransport(cfg *config.BackendTLSConfig, logger observability.Logger) (*BackendTLSTransport, error) {
	builder := NewTLSConfigBuilder(cfg, WithTLSLogger(logger))

	tlsConfig, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &BackendTLSTransport{
		builder:   builder,
		transport: transport,
		logger:    logger,
	}, nil
}

// Transport returns the underlying HTTP transport.
func (t *BackendTLSTransport) Transport() *http.Transport {
	return t.transport
}

// TLSConfig returns the TLS configuration.
func (t *BackendTLSTransport) TLSConfig() *tls.Config {
	return t.transport.TLSClientConfig
}

// Close releases resources held by the transport.
func (t *BackendTLSTransport) Close() error {
	return t.builder.Close()
}
