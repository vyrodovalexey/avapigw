// Package backend provides backend service management for the API Gateway.
package backend

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// TLSConfigBuilder builds TLS configurations for backend connections.
type TLSConfigBuilder struct {
	config  *config.BackendTLSConfig
	logger  observability.Logger
	metrics tlspkg.MetricsRecorder

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

// loadClientCertificate loads the client certificate for mTLS.
func (b *TLSConfigBuilder) loadClientCertificate(cfg *tls.Config) error {
	// Check if Vault is configured for client certificates
	if b.config.Vault != nil && b.config.Vault.Enabled {
		b.logger.Debug("Vault-based client certificates configured (will be loaded at runtime)")
		// Vault certificates are loaded dynamically at runtime
		// This would require integration with the Vault PKI provider
		return nil
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

// Invalidate invalidates the cached TLS config, forcing a rebuild on next Build call.
func (b *TLSConfigBuilder) Invalidate() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tlsConfig = nil
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
