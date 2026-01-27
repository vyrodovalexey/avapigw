package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TLS manager timeout constants.
const (
	// DefaultClientCALoadTimeout is the default timeout for loading client CA certificates.
	DefaultClientCALoadTimeout = 10 * time.Second

	// DefaultCertificateLoadTimeout is the default timeout for loading certificates.
	DefaultCertificateLoadTimeout = 5 * time.Second

	// DefaultExpiryCheckInterval is the default interval for checking certificate expiry.
	DefaultExpiryCheckInterval = 1 * time.Hour

	// DefaultExpiryWarningThreshold is the default threshold for warning about expiring certificates.
	DefaultExpiryWarningThreshold = 7 * 24 * time.Hour
)

// Manager manages TLS configuration and certificate lifecycle.
type Manager struct {
	config   *Config
	provider CertificateProvider
	metrics  MetricsRecorder
	logger   observability.Logger

	tlsConfig *tls.Config
	validator *Validator

	vaultProviderFactory VaultProviderFactory

	mu      sync.RWMutex
	started bool
	closed  bool
	stopCh  chan struct{}
}

// ManagerOption is a functional option for configuring Manager.
type ManagerOption func(*Manager)

// WithManagerLogger sets the logger for the manager.
func WithManagerLogger(logger observability.Logger) ManagerOption {
	return func(m *Manager) {
		m.logger = logger
	}
}

// WithManagerMetrics sets the metrics recorder for the manager.
func WithManagerMetrics(metrics MetricsRecorder) ManagerOption {
	return func(m *Manager) {
		m.metrics = metrics
	}
}

// WithCertificateProvider sets a custom certificate provider.
func WithCertificateProvider(provider CertificateProvider) ManagerOption {
	return func(m *Manager) {
		m.provider = provider
	}
}

// WithVaultProviderFactory sets the Vault provider factory for Vault-based certificate management.
// The factory is called when Vault TLS is configured and enabled, creating a CertificateProvider
// that manages certificates via Vault PKI secrets engine.
func WithVaultProviderFactory(factory VaultProviderFactory) ManagerOption {
	return func(m *Manager) {
		m.vaultProviderFactory = factory
	}
}

// NewManager creates a new TLS manager.
func NewManager(config *Config, opts ...ManagerOption) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	m := &Manager{
		config:  config.Clone(),
		logger:  observability.NopLogger(),
		metrics: NewNopMetrics(),
		stopCh:  make(chan struct{}),
	}

	for _, opt := range opts {
		opt(m)
	}

	// Create validator if client validation is configured
	if config.ClientValidation != nil && config.ClientValidation.Enabled {
		m.validator = NewValidator(config.ClientValidation)
	}

	// Create certificate provider if not provided
	if m.provider == nil {
		if err := m.createProvider(); err != nil {
			return nil, err
		}
	}

	// Build initial TLS config
	if err := m.buildTLSConfig(); err != nil {
		return nil, err
	}

	return m, nil
}

// createProvider creates the appropriate certificate provider based on configuration.
func (m *Manager) createProvider() error {
	mode := m.config.Mode
	if mode == "" {
		mode = TLSModeSimple
	}

	// For passthrough or insecure modes, use a nop provider
	if mode == TLSModePassthrough || mode == TLSModeAutoPassthrough || mode == TLSModeInsecure {
		m.provider = NewNopProvider()
		return nil
	}

	// Check if Vault is configured
	if m.config.Vault != nil && m.config.Vault.Enabled {
		if m.vaultProviderFactory == nil {
			return NewConfigurationError("vault",
				"vault provider factory is required when vault TLS is enabled")
		}
		provider, err := m.vaultProviderFactory(m.config.Vault, m.logger)
		if err != nil {
			return fmt.Errorf("failed to create vault provider: %w", err)
		}
		m.provider = provider
		return nil
	}

	// Use file provider
	provider, err := NewFileProvider(
		m.config.ServerCertificate,
		m.config.ClientValidation,
		WithFileProviderLogger(m.logger),
	)
	if err != nil {
		return err
	}

	m.provider = provider
	return nil
}

// buildTLSConfig builds the tls.Config from the configuration.
func (m *Manager) buildTLSConfig() error {
	mode := m.config.Mode
	if mode == "" {
		mode = TLSModeSimple
	}

	// For insecure mode, return nil config
	if mode == TLSModeInsecure {
		m.logger.Warn("TLS is disabled (INSECURE mode) - this should only be used in development")
		m.tlsConfig = nil
		return nil
	}

	// For passthrough modes, we don't terminate TLS
	if mode == TLSModePassthrough || mode == TLSModeAutoPassthrough {
		m.logger.Info("TLS passthrough mode enabled")
		m.tlsConfig = nil
		return nil
	}

	// Set TLS versions
	minVersion := m.config.MinVersion
	if minVersion == "" {
		minVersion = TLSVersion12
	}

	tlsConfig := &tls.Config{
		GetCertificate: m.getCertificateCallback(),
		MinVersion:     minVersion.ToTLSVersion(), // #nosec G402 -- MinVersion is validated above
	}

	maxVersion := m.config.MaxVersion
	if maxVersion == "" {
		maxVersion = TLSVersion13
	}
	tlsConfig.MaxVersion = maxVersion.ToTLSVersion()

	// Warn about legacy TLS versions
	if minVersion.IsLegacy() {
		m.logger.Warn("legacy TLS version enabled",
			observability.String("minVersion", string(minVersion)),
		)
	}

	// Set cipher suites
	cipherSuites, err := ParseCipherSuites(m.config.CipherSuites)
	if err != nil {
		return err
	}
	// Log when cipher suite configuration is empty and defaults are used
	if len(m.config.CipherSuites) == 0 {
		m.logger.Info("no cipher suites configured, using secure defaults",
			observability.Int("defaultCipherSuiteCount", len(cipherSuites)),
		)
	}
	tlsConfig.CipherSuites = cipherSuites

	// Set curve preferences
	curves, err := ParseCurvePreferences(m.config.CurvePreferences)
	if err != nil {
		return err
	}
	tlsConfig.CurvePreferences = curves

	// Set ALPN protocols
	if len(m.config.ALPN) > 0 {
		tlsConfig.NextProtos = m.config.ALPN
	}

	// Set session tickets
	tlsConfig.SessionTicketsDisabled = m.config.SessionTicketsDisabled

	// Configure client authentication
	if err := m.configureClientAuth(tlsConfig); err != nil {
		return err
	}

	// Handle InsecureSkipVerify
	if m.config.InsecureSkipVerify {
		m.logger.Warn("InsecureSkipVerify is enabled - certificate verification is disabled")
		tlsConfig.InsecureSkipVerify = true
	}

	m.tlsConfig = tlsConfig
	return nil
}

// configureClientAuth configures client certificate authentication.
func (m *Manager) configureClientAuth(tlsConfig *tls.Config) error {
	mode := m.config.Mode
	if mode == "" {
		mode = TLSModeSimple
	}

	switch mode {
	case TLSModeSimple:
		tlsConfig.ClientAuth = tls.NoClientCert

	case TLSModeMutual:
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		if err := m.loadClientCA(tlsConfig); err != nil {
			return err
		}
		tlsConfig.VerifyPeerCertificate = m.verifyClientCertificate

	case TLSModeOptionalMutual:
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		if err := m.loadClientCA(tlsConfig); err != nil {
			return err
		}
		tlsConfig.VerifyPeerCertificate = m.verifyClientCertificate
	}

	return nil
}

// loadClientCA loads the client CA certificate pool.
func (m *Manager) loadClientCA(tlsConfig *tls.Config) error {
	ctx, cancel := m.createContextWithTimeout(DefaultClientCALoadTimeout)
	defer cancel()

	pool, err := m.provider.GetClientCA(ctx)
	if err != nil {
		return WrapError(err, "failed to load client CA")
	}

	if pool == nil {
		return NewConfigurationError("clientValidation", "client CA required for mTLS")
	}

	tlsConfig.ClientCAs = pool
	return nil
}

// getCertificateCallback returns the GetCertificate callback for tls.Config.
func (m *Manager) getCertificateCallback() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		start := time.Now()

		ctx, cancel := m.createContextWithTimeout(DefaultCertificateLoadTimeout)
		defer cancel()

		cert, err := m.provider.GetCertificate(ctx, hello)
		if err != nil {
			m.metrics.RecordHandshakeError("certificate_error")
			m.logger.Error("failed to get certificate",
				observability.String("serverName", hello.ServerName),
				observability.Error(err),
			)
			return nil, err
		}

		duration := time.Since(start)
		m.logger.Debug("certificate selected",
			observability.String("serverName", hello.ServerName),
			observability.Duration("duration", duration),
		)

		return cert, nil
	}
}

// verifyClientCertificate is the VerifyPeerCertificate callback.
func (m *Manager) verifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		mode := m.config.Mode
		if mode == TLSModeMutual {
			m.metrics.RecordClientCertValidation(false, "no_certificate")
			return ErrClientCertRequired
		}
		return nil
	}

	// Parse the client certificate
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		m.metrics.RecordClientCertValidation(false, "parse_error")
		return NewCertificateErrorWithCause("", "failed to parse client certificate", err)
	}

	// Validate using our validator
	if m.validator != nil {
		if err := m.validator.ValidateClientCertificate(cert); err != nil {
			m.metrics.RecordClientCertValidation(false, "validation_failed")
			m.logger.Warn("client certificate validation failed",
				observability.String("subject", cert.Subject.CommonName),
				observability.Error(err),
			)
			return err
		}
	}

	m.metrics.RecordClientCertValidation(true, "")
	m.logger.Debug("client certificate validated",
		observability.String("subject", cert.Subject.CommonName),
		observability.String("issuer", cert.Issuer.CommonName),
	)

	return nil
}

// Start starts the manager and begins watching for certificate changes.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	m.mu.Unlock()

	// Start the provider if it supports starting
	if starter, ok := m.provider.(interface{ Start(context.Context) error }); ok {
		if err := starter.Start(ctx); err != nil {
			return err
		}
	}

	// Start watching for certificate events
	go m.watchCertificateEvents(ctx)

	// Start certificate expiry monitoring
	go m.monitorCertificateExpiry(ctx)

	m.logger.Info("TLS manager started",
		observability.String("mode", string(m.config.Mode)),
	)

	return nil
}

// watchCertificateEvents watches for certificate events from the provider.
func (m *Manager) watchCertificateEvents(ctx context.Context) {
	eventCh := m.provider.Watch(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case event, ok := <-eventCh:
			if !ok {
				return
			}
			//nolint:contextcheck // Event handler creates its own context for operations
			m.handleCertificateEvent(event)
		}
	}
}

// handleCertificateEvent handles a certificate event.
func (m *Manager) handleCertificateEvent(event CertificateEvent) {
	switch event.Type {
	case CertificateEventLoaded:
		m.logger.Info("certificate loaded", observability.String("message", event.Message))
		m.metrics.RecordCertificateReload(true)
		if event.Certificate != nil {
			m.metrics.UpdateCertificateExpiryFromTLS(event.Certificate, "server")
		}

	case CertificateEventReloaded:
		m.logger.Info("certificate reloaded", observability.String("message", event.Message))
		m.metrics.RecordCertificateReload(true)
		if event.Certificate != nil {
			m.metrics.UpdateCertificateExpiryFromTLS(event.Certificate, "server")
		}
		// Rebuild TLS config with new certificate
		if err := m.rebuildTLSConfig(); err != nil {
			m.logger.Error("failed to rebuild TLS config after reload", observability.Error(err))
		}

	case CertificateEventExpiring:
		m.logger.Warn("certificate expiring soon", observability.String("message", event.Message))

	case CertificateEventError:
		m.logger.Error("certificate error",
			observability.String("message", event.Message),
			observability.Error(event.Error),
		)
		m.metrics.RecordCertificateReload(false)
	}
}

// monitorCertificateExpiry periodically checks certificate expiry.
func (m *Manager) monitorCertificateExpiry(ctx context.Context) {
	ticker := time.NewTicker(DefaultExpiryCheckInterval)
	defer ticker.Stop()

	// Check immediately on start
	m.checkCertificateExpiry() //nolint:contextcheck // Background check creates its own context

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkCertificateExpiry() //nolint:contextcheck // Background check creates its own context
		}
	}
}

// checkCertificateExpiry checks the current certificate expiry.
func (m *Manager) checkCertificateExpiry() {
	ctx, cancel := m.createContextWithTimeout(DefaultCertificateLoadTimeout)
	defer cancel()

	cert, err := m.provider.GetCertificate(ctx, nil)
	if err != nil {
		return
	}

	if cert == nil || len(cert.Certificate) == 0 {
		return
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	m.metrics.UpdateCertificateExpiry(x509Cert, "server")

	// Check if expiring soon
	expired, expiringSoon, timeUntil := CheckCertificateExpiration(x509Cert, DefaultExpiryWarningThreshold)

	if expired {
		m.logger.Error("server certificate has expired",
			observability.String("subject", x509Cert.Subject.CommonName),
			observability.Time("expiredAt", x509Cert.NotAfter),
		)
	} else if expiringSoon {
		m.logger.Warn("server certificate expiring soon",
			observability.String("subject", x509Cert.Subject.CommonName),
			observability.Duration("timeUntilExpiry", timeUntil),
		)
	}
}

// rebuildTLSConfig rebuilds the TLS configuration.
func (m *Manager) rebuildTLSConfig() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Reload client CA if needed
	if m.tlsConfig != nil && m.config.ClientValidation != nil && m.config.ClientValidation.Enabled {
		ctx, cancel := m.createContextWithTimeout(DefaultClientCALoadTimeout)
		defer cancel()

		pool, err := m.provider.GetClientCA(ctx)
		if err != nil {
			return err
		}
		m.tlsConfig.ClientCAs = pool
	}

	return nil
}

// createContextWithTimeout creates a new context with the specified timeout duration.
//
// This helper method ensures consistent context creation across the TLS manager
// for operations that require time-bounded execution, such as:
//   - Loading certificates from file system or external providers
//   - Loading client CA certificates for mTLS validation
//   - Checking certificate expiry status
//
// The returned cancel function must be called to release resources associated
// with the context, typically using defer immediately after calling this method:
//
//	ctx, cancel := m.createContextWithTimeout(DefaultCertificateLoadTimeout)
//	defer cancel()
//
// Parameters:
//   - timeout: The maximum duration for the context before it is automatically canceled.
//
// Returns:
//   - context.Context: A new context that will be canceled after the timeout expires.
//   - context.CancelFunc: A function to cancel the context early and release resources.
func (m *Manager) createContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// GetTLSConfig returns the current TLS configuration.
func (m *Manager) GetTLSConfig() *tls.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tlsConfig
}

// GetConfig returns the TLS configuration.
func (m *Manager) GetConfig() *Config {
	return m.config.Clone()
}

// GetMode returns the TLS mode.
func (m *Manager) GetMode() TLSMode {
	mode := m.config.Mode
	if mode == "" {
		return TLSModeSimple
	}
	return mode
}

// IsEnabled returns true if TLS is enabled.
func (m *Manager) IsEnabled() bool {
	mode := m.GetMode()
	return mode != TLSModeInsecure
}

// IsMTLSEnabled returns true if mutual TLS is enabled.
func (m *Manager) IsMTLSEnabled() bool {
	mode := m.GetMode()
	return mode == TLSModeMutual || mode == TLSModeOptionalMutual
}

// Close stops the manager and releases resources.
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	close(m.stopCh)

	if m.provider != nil {
		if err := m.provider.Close(); err != nil {
			return err
		}
	}

	m.logger.Info("TLS manager closed")
	return nil
}

// RecordConnection records a TLS connection for metrics.
func (m *Manager) RecordConnection(state *tls.ConnectionState) {
	if state == nil {
		return
	}

	m.metrics.RecordConnection(state.Version, state.CipherSuite, m.GetMode())
}

// RecordHandshake records a TLS handshake for metrics.
func (m *Manager) RecordHandshake(duration time.Duration, state *tls.ConnectionState) {
	if state == nil {
		return
	}

	m.metrics.RecordHandshakeDuration(duration, state.Version, m.GetMode())
}

// CreateClientTLSConfig creates a TLS configuration for client connections.
func (m *Manager) CreateClientTLSConfig(serverName string) *tls.Config {
	if !m.IsEnabled() {
		return nil
	}

	minVersion := m.config.MinVersion
	if minVersion == "" {
		minVersion = TLSVersion12
	}

	maxVersion := m.config.MaxVersion
	if maxVersion == "" {
		maxVersion = TLSVersion13
	}

	// Note: InsecureSkipVerify is intentionally configurable for development/testing
	// environments. In production, this should always be false.
	clientConfig := &tls.Config{
		ServerName:         serverName,
		MinVersion:         minVersion.ToTLSVersion(),
		MaxVersion:         maxVersion.ToTLSVersion(),
		InsecureSkipVerify: m.config.InsecureSkipVerify, // #nosec G402 -- configurable for dev/test
	}

	// Set cipher suites
	if cipherSuites, err := ParseCipherSuites(m.config.CipherSuites); err == nil {
		clientConfig.CipherSuites = cipherSuites
	}

	// Set curve preferences
	if curves, err := ParseCurvePreferences(m.config.CurvePreferences); err == nil {
		clientConfig.CurvePreferences = curves
	}

	// Set ALPN
	if len(m.config.ALPN) > 0 {
		clientConfig.NextProtos = m.config.ALPN
	}

	return clientConfig
}
