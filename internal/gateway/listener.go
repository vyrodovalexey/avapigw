package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// Listener represents an HTTP/HTTPS listener.
type Listener struct {
	config               config.Listener
	server               *http.Server
	handler              http.Handler
	logger               observability.Logger
	running              atomic.Bool
	tlsManager           *tlspkg.Manager
	routeTLSManager      *tlspkg.RouteTLSManager
	tlsMetrics           tlspkg.MetricsRecorder
	vaultProviderFactory tlspkg.VaultProviderFactory
}

// ListenerOption is a functional option for configuring a listener.
type ListenerOption func(*Listener)

// WithListenerLogger sets the logger for the listener.
func WithListenerLogger(logger observability.Logger) ListenerOption {
	return func(l *Listener) {
		l.logger = logger
	}
}

// WithTLSMetrics sets the TLS metrics for the listener.
func WithTLSMetrics(metrics tlspkg.MetricsRecorder) ListenerOption {
	return func(l *Listener) {
		l.tlsMetrics = metrics
	}
}

// WithRouteTLSManager sets the route TLS manager for the listener.
// This enables route-level TLS certificate override based on SNI.
func WithRouteTLSManager(manager *tlspkg.RouteTLSManager) ListenerOption {
	return func(l *Listener) {
		l.routeTLSManager = manager
	}
}

// WithVaultProviderFactory sets the Vault provider factory for the listener.
// This enables Vault-based certificate management for TLS.
func WithVaultProviderFactory(factory tlspkg.VaultProviderFactory) ListenerOption {
	return func(l *Listener) {
		l.vaultProviderFactory = factory
	}
}

// NewListener creates a new listener.
func NewListener(
	cfg config.Listener,
	handler http.Handler,
	opts ...ListenerOption,
) (*Listener, error) {
	l := &Listener{
		config:     cfg,
		handler:    handler,
		logger:     observability.NopLogger(),
		tlsMetrics: tlspkg.NewNopMetrics(),
	}

	for _, opt := range opts {
		opt(l)
	}

	// Initialize TLS if configured
	if cfg.TLS != nil && cfg.Protocol == "HTTPS" {
		if err := l.initTLS(); err != nil {
			return nil, fmt.Errorf("failed to initialize TLS: %w", err)
		}
	}

	return l, nil
}

// initTLS initializes the TLS manager.
func (l *Listener) initTLS() error {
	tlsCfg := l.convertToTLSConfig(l.config.TLS)

	managerOpts := []tlspkg.ManagerOption{
		tlspkg.WithManagerLogger(l.logger),
		tlspkg.WithManagerMetrics(l.tlsMetrics),
	}
	if l.vaultProviderFactory != nil {
		managerOpts = append(managerOpts, tlspkg.WithVaultProviderFactory(l.vaultProviderFactory))
	}

	manager, err := tlspkg.NewManager(tlsCfg, managerOpts...)
	if err != nil {
		return fmt.Errorf("failed to create TLS manager: %w", err)
	}

	l.tlsManager = manager
	return nil
}

// convertToTLSConfig converts ListenerTLSConfig to tls.Config.
func (l *Listener) convertToTLSConfig(cfg *config.ListenerTLSConfig) *tlspkg.Config {
	if cfg == nil {
		return nil
	}

	tlsCfg := &tlspkg.Config{
		Mode:               tlspkg.TLSMode(cfg.Mode),
		MinVersion:         tlspkg.TLSVersion(cfg.MinVersion),
		MaxVersion:         tlspkg.TLSVersion(cfg.MaxVersion),
		CipherSuites:       cfg.CipherSuites,
		ALPN:               cfg.ALPN,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	// Server certificate
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		tlsCfg.ServerCertificate = &tlspkg.CertificateConfig{
			Source:   tlspkg.CertificateSourceFile,
			CertFile: cfg.CertFile,
			KeyFile:  cfg.KeyFile,
		}
	}

	// Client validation
	if cfg.CAFile != "" || cfg.RequireClientCert {
		tlsCfg.ClientValidation = &tlspkg.ClientValidationConfig{
			Enabled:           true,
			CAFile:            cfg.CAFile,
			RequireClientCert: cfg.RequireClientCert,
		}
	}

	// Vault configuration
	if cfg.Vault != nil && cfg.Vault.Enabled {
		tlsCfg.Vault = &tlspkg.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   cfg.Vault.PKIMount,
			Role:       cfg.Vault.Role,
			CommonName: cfg.Vault.CommonName,
			AltNames:   cfg.Vault.AltNames,
		}
	}

	return tlsCfg
}

// Name returns the listener name.
func (l *Listener) Name() string {
	return l.config.Name
}

// Port returns the listener port.
func (l *Listener) Port() int {
	return l.config.Port
}

// Address returns the listener address.
func (l *Listener) Address() string {
	bind := l.config.Bind
	if bind == "" {
		bind = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", bind, l.config.Port)
}

// Start starts the listener.
func (l *Listener) Start(ctx context.Context) error {
	if l.running.Load() {
		return fmt.Errorf("listener %s is already running", l.config.Name)
	}

	addr := l.Address()

	// Get timeout configuration
	timeouts := l.config.Timeouts

	// Build HTTP server with configurable timeouts
	l.server = &http.Server{
		Addr:              addr,
		Handler:           l.wrapHandler(l.handler),
		ReadTimeout:       timeouts.GetEffectiveReadTimeout(),
		ReadHeaderTimeout: timeouts.GetEffectiveReadHeaderTimeout(),
		WriteTimeout:      timeouts.GetEffectiveWriteTimeout(),
		IdleTimeout:       timeouts.GetEffectiveIdleTimeout(),
		MaxHeaderBytes:    config.DefaultMaxHeaderSize,
	}

	// Configure TLS if enabled
	if l.routeTLSManager != nil {
		// Use route TLS manager for SNI-based certificate selection
		tlsConfig := l.routeTLSManager.GetTLSConfig()
		if tlsConfig != nil {
			l.server.TLSConfig = tlsConfig
		}
	} else if l.tlsManager != nil {
		tlsConfig := l.tlsManager.GetTLSConfig()
		if tlsConfig != nil {
			l.server.TLSConfig = tlsConfig
		}
	}

	// Create listener with context
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	l.running.Store(true)

	l.logger.Info("listener started",
		observability.String("name", l.config.Name),
		observability.String("address", addr),
		observability.String("protocol", l.config.Protocol),
		observability.Bool("tls", l.tlsManager != nil),
	)

	go l.serve(ln)

	return nil
}

// wrapHandler wraps the handler with TLS-related middleware.
func (l *Listener) wrapHandler(handler http.Handler) http.Handler {
	// Add HSTS header if configured
	if l.config.TLS != nil && l.config.TLS.HSTS != nil && l.config.TLS.HSTS.Enabled {
		handler = l.hstsMiddleware(handler)
	}

	// Add HTTPS redirect if configured
	if l.config.TLS != nil && l.config.TLS.HTTPSRedirect {
		handler = l.httpsRedirectMiddleware(handler)
	}

	return handler
}

// hstsMiddleware adds HSTS header.
func (l *Listener) hstsMiddleware(next http.Handler) http.Handler {
	hsts := l.config.TLS.HSTS
	maxAge := hsts.MaxAge
	if maxAge == 0 {
		maxAge = 31536000 // Default: 1 year
	}
	value := fmt.Sprintf("max-age=%d", maxAge)
	if hsts.IncludeSubDomains {
		value += "; includeSubDomains"
	}
	if hsts.Preload {
		value += "; preload"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", value)
		next.ServeHTTP(w, r)
	})
}

// isAllowedHost checks if the given host is in the list of allowed hosts.
func (l *Listener) isAllowedHost(host string) bool {
	for _, allowedHost := range l.config.Hosts {
		if strings.EqualFold(host, allowedHost) {
			return true
		}
	}
	return false
}

// extractHostWithoutPort extracts the host part from a host:port string.
// It handles IPv6 addresses correctly (e.g., [::1]:8080).
func extractHostWithoutPort(hostWithPort string) string {
	colonIdx := strings.LastIndex(hostWithPort, ":")
	if colonIdx == -1 {
		return hostWithPort
	}
	// Check if this is an IPv6 address (contains brackets)
	bracketIdx := strings.LastIndex(hostWithPort, "]")
	if bracketIdx != -1 && colonIdx < bracketIdx {
		// Port separator is inside brackets, not a real port
		return hostWithPort
	}
	return hostWithPort[:colonIdx]
}

// getSafeRedirectHost determines the safe host to use for HTTPS redirect.
// Returns the redirect host and a boolean indicating if the redirect should proceed.
func (l *Listener) getSafeRedirectHost(requestHost string) (string, bool) {
	if len(l.config.Hosts) == 0 {
		// No hosts configured, reject the request to prevent open redirect
		l.logger.Warn("HTTPS redirect rejected: no allowed hosts configured",
			observability.String("host", requestHost),
		)
		return "", false
	}

	host := extractHostWithoutPort(requestHost)
	if l.isAllowedHost(host) {
		// Host is allowed, use the original request host (with port if present)
		return requestHost, true
	}

	// Host is not allowed, use the first configured host
	redirectHost := l.config.Hosts[0]
	l.logger.Warn("HTTPS redirect blocked untrusted host",
		observability.String("untrusted_host", requestHost),
		observability.String("redirect_host", redirectHost),
	)
	return redirectHost, true
}

// httpsRedirectMiddleware redirects HTTP to HTTPS.
// It validates the Host header against configured allowed hosts to prevent open redirect attacks.
func (l *Listener) httpsRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			next.ServeHTTP(w, r)
			return
		}

		redirectHost, ok := l.getSafeRedirectHost(r.Host)
		if !ok {
			http.Error(w, "Bad Request: untrusted host", http.StatusBadRequest)
			return
		}

		target := "https://" + redirectHost + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

// serve starts serving requests.
func (l *Listener) serve(ln net.Listener) {
	var err error
	if l.tlsManager != nil && l.server.TLSConfig != nil {
		// Use TLS listener
		tlsLn := tls.NewListener(ln, l.server.TLSConfig)
		err = l.server.Serve(tlsLn)
	} else {
		err = l.server.Serve(ln)
	}

	if err != nil && err != http.ErrServerClosed {
		l.logger.Error("listener error",
			observability.String("name", l.config.Name),
			observability.Error(err),
		)
	}
	l.running.Store(false)
}

// Stop stops the listener gracefully.
func (l *Listener) Stop(ctx context.Context) error {
	if !l.running.Load() {
		return nil
	}

	l.logger.Info("stopping listener",
		observability.String("name", l.config.Name),
	)

	// Close route TLS manager
	if l.routeTLSManager != nil {
		if err := l.routeTLSManager.Close(); err != nil {
			l.logger.Error("failed to close route TLS manager",
				observability.String("name", l.config.Name),
				observability.Error(err),
			)
		}
	}

	// Close TLS manager
	if l.tlsManager != nil {
		if err := l.tlsManager.Close(); err != nil {
			l.logger.Error("failed to close TLS manager",
				observability.String("name", l.config.Name),
				observability.Error(err),
			)
		}
	}

	if err := l.server.Shutdown(ctx); err != nil {
		if closeErr := l.server.Close(); closeErr != nil {
			return fmt.Errorf("failed to close listener: %w", closeErr)
		}
		return fmt.Errorf("failed to shutdown listener gracefully: %w", err)
	}

	l.running.Store(false)

	l.logger.Info("listener stopped",
		observability.String("name", l.config.Name),
	)

	return nil
}

// IsRunning returns true if the listener is running.
func (l *Listener) IsRunning() bool {
	return l.running.Load()
}

// IsTLSEnabled returns true if TLS is enabled.
func (l *Listener) IsTLSEnabled() bool {
	return l.tlsManager != nil
}

// GetTLSManager returns the TLS manager (for testing and advanced use cases).
func (l *Listener) GetTLSManager() *tlspkg.Manager {
	return l.tlsManager
}

// GetRouteTLSManager returns the route TLS manager (for testing and advanced use cases).
func (l *Listener) GetRouteTLSManager() *tlspkg.RouteTLSManager {
	return l.routeTLSManager
}

// IsRouteTLSEnabled returns true if route-level TLS is enabled.
func (l *Listener) IsRouteTLSEnabled() bool {
	return l.routeTLSManager != nil && l.routeTLSManager.RouteCount() > 0
}
