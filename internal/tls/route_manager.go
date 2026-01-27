// Package tls provides TLS configuration and certificate management.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// RouteTLSManager timeout constants.
const (
	// DefaultRouteCertificateLoadTimeout is the default timeout for loading route certificates.
	DefaultRouteCertificateLoadTimeout = 5 * time.Second

	// DefaultRouteExpiryCheckInterval is the default interval for checking route certificate expiry.
	DefaultRouteExpiryCheckInterval = 1 * time.Hour
)

// ErrNoCertificateFound indicates that no certificate was found for the given SNI.
var ErrNoCertificateFound = errors.New("no certificate found for SNI")

// RouteTLSConfig contains TLS configuration for a specific route.
type RouteTLSConfig struct {
	// CertFile is the path to the route-specific certificate file.
	CertFile string

	// KeyFile is the path to the route-specific private key file.
	KeyFile string

	// SNIHosts is the list of SNI hostnames this certificate should be used for.
	SNIHosts []string

	// MinVersion is the minimum TLS version for this route.
	MinVersion TLSVersion

	// MaxVersion is the maximum TLS version for this route.
	MaxVersion TLSVersion

	// CipherSuites is the list of allowed cipher suites for this route.
	CipherSuites []string

	// ClientValidation configures client certificate validation for this route.
	ClientValidation *ClientValidationConfig

	// Vault configures Vault-based certificate management for this route.
	Vault *VaultTLSConfig
}

// routeCertEntry holds certificate information for a route.
type routeCertEntry struct {
	routeName string
	config    *RouteTLSConfig
	provider  CertificateProvider
	sniHosts  []string
}

// RouteTLSManager manages TLS certificates for multiple routes.
// It provides SNI-based certificate selection and supports certificate hot-reload.
type RouteTLSManager struct {
	baseManager *Manager // Listener-level TLS manager (fallback)
	logger      observability.Logger
	metrics     MetricsRecorder

	// Route certificate storage
	routeEntries map[string]*routeCertEntry // Route name -> certificate entry
	sniMapping   map[string]string          // SNI hostname -> route name (exact match)
	wildcardSNI  map[string]string          // Wildcard pattern -> route name

	mu      sync.RWMutex
	started bool
	closed  bool
	stopCh  chan struct{}
}

// RouteTLSManagerOption is a functional option for configuring RouteTLSManager.
type RouteTLSManagerOption func(*RouteTLSManager)

// WithRouteTLSManagerLogger sets the logger for the route TLS manager.
func WithRouteTLSManagerLogger(logger observability.Logger) RouteTLSManagerOption {
	return func(m *RouteTLSManager) {
		m.logger = logger
	}
}

// WithRouteTLSManagerMetrics sets the metrics recorder for the route TLS manager.
func WithRouteTLSManagerMetrics(metrics MetricsRecorder) RouteTLSManagerOption {
	return func(m *RouteTLSManager) {
		m.metrics = metrics
	}
}

// WithBaseManager sets the base TLS manager for fallback certificate selection.
func WithBaseManager(baseManager *Manager) RouteTLSManagerOption {
	return func(m *RouteTLSManager) {
		m.baseManager = baseManager
	}
}

// NewRouteTLSManager creates a new route-level TLS manager.
func NewRouteTLSManager(opts ...RouteTLSManagerOption) *RouteTLSManager {
	m := &RouteTLSManager{
		logger:       observability.NopLogger(),
		metrics:      NewNopMetrics(),
		routeEntries: make(map[string]*routeCertEntry),
		sniMapping:   make(map[string]string),
		wildcardSNI:  make(map[string]string),
		stopCh:       make(chan struct{}),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// AddRoute adds a route with its TLS configuration.
// If the route already exists, it will be updated.
func (m *RouteTLSManager) AddRoute(routeName string, cfg *RouteTLSConfig) error {
	if routeName == "" {
		return NewConfigurationError("routeName", "route name cannot be empty")
	}

	if cfg == nil {
		return NewConfigurationError("config", "route TLS config cannot be nil")
	}

	// Validate configuration
	if err := m.validateRouteConfig(cfg); err != nil {
		return fmt.Errorf("invalid route TLS config for %s: %w", routeName, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove existing route if present
	m.removeRouteUnlocked(routeName)

	// Create certificate provider for this route
	provider, err := m.createRouteProvider(routeName, cfg)
	if err != nil {
		return fmt.Errorf("failed to create certificate provider for route %s: %w", routeName, err)
	}

	// Create route entry
	entry := &routeCertEntry{
		routeName: routeName,
		config:    cfg,
		provider:  provider,
		sniHosts:  cfg.SNIHosts,
	}

	// Store route entry
	m.routeEntries[routeName] = entry

	// Update SNI mappings
	for _, host := range cfg.SNIHosts {
		if strings.HasPrefix(host, "*.") {
			// Wildcard pattern
			m.wildcardSNI[host] = routeName
		} else {
			// Exact match
			m.sniMapping[strings.ToLower(host)] = routeName
		}
	}

	m.logger.Info("route TLS configuration added",
		observability.String("route", routeName),
		observability.Int("sniHosts", len(cfg.SNIHosts)),
	)

	return nil
}

// RemoveRoute removes a route's TLS configuration.
func (m *RouteTLSManager) RemoveRoute(routeName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.removeRouteUnlocked(routeName)
}

// removeRouteUnlocked removes a route without acquiring the lock.
// Caller must hold the write lock.
func (m *RouteTLSManager) removeRouteUnlocked(routeName string) {
	entry, exists := m.routeEntries[routeName]
	if !exists {
		return
	}

	// Close the provider
	if entry.provider != nil {
		if err := entry.provider.Close(); err != nil {
			m.logger.Warn("failed to close route certificate provider",
				observability.String("route", routeName),
				observability.Error(err),
			)
		}
	}

	// Remove SNI mappings
	for _, host := range entry.sniHosts {
		if strings.HasPrefix(host, "*.") {
			delete(m.wildcardSNI, host)
		} else {
			delete(m.sniMapping, strings.ToLower(host))
		}
	}

	// Remove route entry
	delete(m.routeEntries, routeName)

	m.logger.Info("route TLS configuration removed",
		observability.String("route", routeName),
	)
}

// GetCertificate returns the appropriate certificate based on SNI.
// It first tries exact SNI match, then wildcard match, and finally falls back to the base manager.
func (m *RouteTLSManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	serverName := strings.ToLower(hello.ServerName)

	// Try exact SNI match first
	if routeName, ok := m.sniMapping[serverName]; ok {
		cert, err := m.getCertificateForRoute(routeName, hello)
		if err == nil {
			m.recordCertificateSelection(routeName, serverName, "exact")
			return cert, nil
		}
		m.logger.Warn("failed to get route certificate, trying fallback",
			observability.String("route", routeName),
			observability.String("serverName", serverName),
			observability.Error(err),
		)
	}

	// Try wildcard match
	if cert, routeName := m.tryWildcardMatch(hello); cert != nil {
		m.recordCertificateSelection(routeName, serverName, "wildcard")
		return cert, nil
	}

	// Fall back to base manager
	if m.baseManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultRouteCertificateLoadTimeout)
		defer cancel()

		if m.baseManager.provider != nil {
			cert, err := m.baseManager.provider.GetCertificate(ctx, hello)
			if err == nil {
				m.logger.Debug("using base manager certificate",
					observability.String("serverName", serverName),
				)
				return cert, nil
			}
		}
	}

	m.logger.Debug("no certificate found for SNI",
		observability.String("serverName", serverName),
	)

	return nil, ErrNoCertificateFound
}

// getCertificateForRoute gets the certificate for a specific route.
func (m *RouteTLSManager) getCertificateForRoute(
	routeName string,
	hello *tls.ClientHelloInfo,
) (*tls.Certificate, error) {
	entry, exists := m.routeEntries[routeName]
	if !exists {
		return nil, fmt.Errorf("route %s not found", routeName)
	}

	if entry.provider == nil {
		return nil, fmt.Errorf("no certificate provider for route %s", routeName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultRouteCertificateLoadTimeout)
	defer cancel()

	return entry.provider.GetCertificate(ctx, hello)
}

// tryWildcardMatch attempts to match wildcard SNI patterns.
// Returns the certificate and route name if a match is found.
func (m *RouteTLSManager) tryWildcardMatch(
	hello *tls.ClientHelloInfo,
) (cert *tls.Certificate, routeName string) {
	serverName := strings.ToLower(hello.ServerName)

	for pattern, routeName := range m.wildcardSNI {
		if matchWildcard(pattern, serverName) {
			cert, err := m.getCertificateForRoute(routeName, hello)
			if err == nil {
				return cert, routeName
			}
			m.logger.Warn("failed to get wildcard route certificate",
				observability.String("route", routeName),
				observability.String("pattern", pattern),
				observability.String("serverName", serverName),
				observability.Error(err),
			)
		}
	}

	return nil, ""
}

// matchWildcard checks if a server name matches a wildcard pattern.
// Pattern format: *.example.com matches foo.example.com but not foo.bar.example.com
func matchWildcard(pattern, serverName string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	// Get the domain part after the wildcard
	domain := strings.ToLower(pattern[2:])
	serverName = strings.ToLower(serverName)

	// Check if server name ends with the domain
	if !strings.HasSuffix(serverName, domain) {
		return false
	}

	// Get the prefix (the part that matches the wildcard)
	prefix := serverName[:len(serverName)-len(domain)]

	// The prefix should be a single label (no dots) and end with a dot
	if prefix == "" {
		return false
	}

	// Remove trailing dot from prefix
	prefix = strings.TrimSuffix(prefix, ".")

	// Prefix should not contain any dots (single label only)
	return !strings.Contains(prefix, ".")
}

// recordCertificateSelection records metrics for certificate selection.
func (m *RouteTLSManager) recordCertificateSelection(routeName, serverName, matchType string) {
	m.logger.Debug("route certificate selected",
		observability.String("route", routeName),
		observability.String("serverName", serverName),
		observability.String("matchType", matchType),
	)
}

// GetTLSConfig returns a tls.Config with SNI-based certificate selection.
func (m *RouteTLSManager) GetTLSConfig() *tls.Config {
	// Start with base config if available
	var baseTLSConfig *tls.Config
	if m.baseManager != nil {
		baseTLSConfig = m.baseManager.GetTLSConfig()
	}

	if baseTLSConfig == nil {
		baseTLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	// Clone the base config
	tlsConfig := baseTLSConfig.Clone()

	// Override GetCertificate to use our SNI-based selection
	tlsConfig.GetCertificate = m.GetCertificate

	return tlsConfig
}

// Start starts all route TLS managers and begins watching for certificate changes.
func (m *RouteTLSManager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	m.mu.Unlock()

	// Start providers for all routes
	m.mu.RLock()
	for routeName, entry := range m.routeEntries {
		if starter, ok := entry.provider.(interface{ Start(context.Context) error }); ok {
			if err := starter.Start(ctx); err != nil {
				m.mu.RUnlock()
				return fmt.Errorf("failed to start provider for route %s: %w", routeName, err)
			}
		}
	}
	m.mu.RUnlock()

	// Start watching for certificate events
	go m.watchRouteEvents(ctx)

	// Start certificate expiry monitoring
	go m.monitorCertificateExpiry(ctx)

	m.logger.Info("route TLS manager started",
		observability.Int("routes", len(m.routeEntries)),
	)

	return nil
}

// watchRouteEvents watches for certificate events from all route providers.
func (m *RouteTLSManager) watchRouteEvents(ctx context.Context) {
	m.mu.RLock()
	entries := make([]*routeCertEntry, 0, len(m.routeEntries))
	for _, entry := range m.routeEntries {
		entries = append(entries, entry)
	}
	m.mu.RUnlock()

	for _, entry := range entries {
		go m.watchSingleRouteEvents(ctx, entry)
	}
}

// watchSingleRouteEvents watches events for a single route.
func (m *RouteTLSManager) watchSingleRouteEvents(ctx context.Context, entry *routeCertEntry) {
	if entry.provider == nil {
		return
	}

	eventCh := entry.provider.Watch(ctx)

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
			m.handleRouteEvent(entry.routeName, event)
		}
	}
}

// handleRouteEvent handles a certificate event for a route.
func (m *RouteTLSManager) handleRouteEvent(routeName string, event CertificateEvent) {
	switch event.Type {
	case CertificateEventLoaded:
		m.logger.Info("route certificate loaded",
			observability.String("route", routeName),
			observability.String("message", event.Message),
		)
		m.metrics.RecordCertificateReload(true)

	case CertificateEventReloaded:
		m.logger.Info("route certificate reloaded",
			observability.String("route", routeName),
			observability.String("message", event.Message),
		)
		m.metrics.RecordCertificateReload(true)

	case CertificateEventExpiring:
		m.logger.Warn("route certificate expiring soon",
			observability.String("route", routeName),
			observability.String("message", event.Message),
		)

	case CertificateEventError:
		m.logger.Error("route certificate error",
			observability.String("route", routeName),
			observability.String("message", event.Message),
			observability.Error(event.Error),
		)
		m.metrics.RecordCertificateReload(false)
	}
}

// monitorCertificateExpiry periodically checks certificate expiry for all routes.
func (m *RouteTLSManager) monitorCertificateExpiry(ctx context.Context) {
	ticker := time.NewTicker(DefaultRouteExpiryCheckInterval)
	defer ticker.Stop()

	// Check immediately on start
	//nolint:contextcheck // Background check creates its own context for each route
	m.checkAllCertificateExpiry()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			//nolint:contextcheck // Background check creates its own context for each route
			m.checkAllCertificateExpiry()
		}
	}
}

// checkAllCertificateExpiry checks certificate expiry for all routes.
func (m *RouteTLSManager) checkAllCertificateExpiry() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for routeName, entry := range m.routeEntries {
		m.checkRouteCertificateExpiry(routeName, entry)
	}
}

// checkRouteCertificateExpiry checks certificate expiry for a single route.
func (m *RouteTLSManager) checkRouteCertificateExpiry(routeName string, entry *routeCertEntry) {
	if entry.provider == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultRouteCertificateLoadTimeout)
	defer cancel()

	cert, err := entry.provider.GetCertificate(ctx, nil)
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

	// Update metrics
	m.metrics.UpdateCertificateExpiry(x509Cert, "route_"+routeName)

	// Check if expiring soon
	expired, expiringSoon, timeUntil := CheckCertificateExpiration(x509Cert, DefaultExpiryWarningThreshold)

	if expired {
		m.logger.Error("route certificate has expired",
			observability.String("route", routeName),
			observability.String("subject", x509Cert.Subject.CommonName),
			observability.Time("expiredAt", x509Cert.NotAfter),
		)
	} else if expiringSoon {
		m.logger.Warn("route certificate expiring soon",
			observability.String("route", routeName),
			observability.String("subject", x509Cert.Subject.CommonName),
			observability.Duration("timeUntilExpiry", timeUntil),
		)
	}
}

// ReloadRoute reloads the certificate for a specific route.
func (m *RouteTLSManager) ReloadRoute(routeName string) error {
	m.mu.RLock()
	entry, exists := m.routeEntries[routeName]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("route %s not found", routeName)
	}

	// If the provider supports reloading, trigger it
	if reloader, ok := entry.provider.(interface{ Reload() error }); ok {
		if err := reloader.Reload(); err != nil {
			m.logger.Error("failed to reload route certificate",
				observability.String("route", routeName),
				observability.Error(err),
			)
			return err
		}
		m.logger.Info("route certificate reloaded",
			observability.String("route", routeName),
		)
	}

	return nil
}

// Close closes all route TLS managers and releases resources.
func (m *RouteTLSManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	close(m.stopCh)

	// Close all route providers
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for routeName, entry := range m.routeEntries {
		if entry.provider != nil {
			if err := entry.provider.Close(); err != nil {
				errs = append(errs, fmt.Errorf("failed to close provider for route %s: %w", routeName, err))
			}
		}
	}

	// Clear all mappings
	m.routeEntries = make(map[string]*routeCertEntry)
	m.sniMapping = make(map[string]string)
	m.wildcardSNI = make(map[string]string)

	m.logger.Info("route TLS manager closed")

	if len(errs) > 0 {
		return fmt.Errorf("errors closing route TLS manager: %v", errs)
	}

	return nil
}

// RouteCount returns the number of routes with TLS configuration.
func (m *RouteTLSManager) RouteCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.routeEntries)
}

// HasRoute returns true if the route has TLS configuration.
func (m *RouteTLSManager) HasRoute(routeName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.routeEntries[routeName]
	return exists
}

// GetRouteNames returns the names of all routes with TLS configuration.
func (m *RouteTLSManager) GetRouteNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.routeEntries))
	for name := range m.routeEntries {
		names = append(names, name)
	}
	return names
}

// validateRouteConfig validates the route TLS configuration.
func (m *RouteTLSManager) validateRouteConfig(cfg *RouteTLSConfig) error {
	hasFiles := cfg.CertFile != "" || cfg.KeyFile != ""
	hasVault := cfg.Vault != nil && cfg.Vault.Enabled

	if !hasFiles && !hasVault {
		return NewConfigurationError("config", "either certFile/keyFile or vault configuration is required")
	}

	if hasFiles {
		if cfg.CertFile == "" {
			return NewConfigurationError("certFile", "certFile is required when keyFile is specified")
		}
		if cfg.KeyFile == "" {
			return NewConfigurationError("keyFile", "keyFile is required when certFile is specified")
		}
	}

	if hasVault {
		if err := cfg.Vault.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// createRouteProvider creates a certificate provider for a route.
func (m *RouteTLSManager) createRouteProvider(routeName string, cfg *RouteTLSConfig) (CertificateProvider, error) {
	// Check if Vault is configured
	if cfg.Vault != nil && cfg.Vault.Enabled {
		// Vault provider would be implemented separately
		return nil, NewConfigurationError("vault", "Vault provider not yet implemented for route TLS")
	}

	// Use file provider
	certConfig := &CertificateConfig{
		Source:   CertificateSourceFile,
		CertFile: cfg.CertFile,
		KeyFile:  cfg.KeyFile,
	}

	var clientValidation *ClientValidationConfig
	if cfg.ClientValidation != nil && cfg.ClientValidation.Enabled {
		clientValidation = cfg.ClientValidation
	}

	provider, err := NewFileProvider(
		certConfig,
		clientValidation,
		WithFileProviderLogger(m.logger),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create file provider for route %s: %w", routeName, err)
	}

	return provider, nil
}
