package gateway

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcmiddleware "github.com/vyrodovalexey/avapigw/internal/grpc/middleware"
	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
	grpcserver "github.com/vyrodovalexey/avapigw/internal/grpc/server"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// defaultGracefulStopTimeout is the default timeout for gracefully stopping the gRPC server.
const defaultGracefulStopTimeout = 30 * time.Second

// GRPCListener represents a gRPC listener.
type GRPCListener struct {
	config               config.Listener
	server               *grpcserver.Server
	router               *grpcrouter.Router
	proxy                *grpcproxy.Proxy
	metrics              *grpcmiddleware.GRPCMetrics
	logger               observability.Logger
	running              atomic.Bool
	tlsManager           *tlspkg.Manager
	routeTLSManager      *tlspkg.RouteTLSManager
	tlsMetrics           tlspkg.MetricsRecorder
	vaultProviderFactory tlspkg.VaultProviderFactory
	auditLogger          audit.Logger
	rateLimiter          *grpcmiddleware.GRPCRateLimiter
	circuitBreaker       *grpcmiddleware.GRPCCircuitBreaker
	metricsRegistry      *prometheus.Registry
	authMetrics          *auth.Metrics
	vaultClient          vault.Client
	backendRegistry      *backend.Registry
}

// GRPCListenerOption is a functional option for configuring a gRPC listener.
type GRPCListenerOption func(*GRPCListener)

// WithGRPCListenerLogger sets the logger for the gRPC listener.
func WithGRPCListenerLogger(logger observability.Logger) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.logger = logger
	}
}

// WithGRPCRouter sets the router for the gRPC listener.
func WithGRPCRouter(router *grpcrouter.Router) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.router = router
	}
}

// WithGRPCMetrics sets the metrics for the gRPC listener.
func WithGRPCMetrics(metrics *grpcmiddleware.GRPCMetrics) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.metrics = metrics
	}
}

// WithGRPCTLSManager sets the TLS manager for the gRPC listener.
func WithGRPCTLSManager(manager *tlspkg.Manager) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.tlsManager = manager
	}
}

// WithGRPCTLSMetrics sets the TLS metrics for the gRPC listener.
func WithGRPCTLSMetrics(metrics tlspkg.MetricsRecorder) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.tlsMetrics = metrics
	}
}

// WithGRPCRouteTLSManager sets the route TLS manager for the gRPC listener.
// This enables route-level TLS certificate override based on SNI.
func WithGRPCRouteTLSManager(manager *tlspkg.RouteTLSManager) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.routeTLSManager = manager
	}
}

// WithGRPCVaultProviderFactory sets the Vault provider factory for the gRPC listener.
// This enables Vault-based certificate management for TLS.
func WithGRPCVaultProviderFactory(factory tlspkg.VaultProviderFactory) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.vaultProviderFactory = factory
	}
}

// WithGRPCAuditLogger sets the audit logger for the gRPC listener.
func WithGRPCAuditLogger(logger audit.Logger) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.auditLogger = logger
	}
}

// WithGRPCRateLimiter sets the rate limiter for the gRPC listener.
func WithGRPCRateLimiter(limiter *grpcmiddleware.GRPCRateLimiter) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.rateLimiter = limiter
	}
}

// WithGRPCCircuitBreaker sets the circuit breaker for the gRPC listener.
func WithGRPCCircuitBreaker(cb *grpcmiddleware.GRPCCircuitBreaker) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.circuitBreaker = cb
	}
}

// WithGRPCMetricsRegistry sets the Prometheus registry for gRPC proxy
// metrics. When provided, gRPC proxy metrics (connection pool, direct
// requests, streaming, etc.) are registered with this registry instead
// of the default global registerer, ensuring they appear on the
// gateway's /metrics endpoint.
func WithGRPCMetricsRegistry(registry *prometheus.Registry) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.metricsRegistry = registry
	}
}

// WithGRPCAuthMetrics sets the authentication metrics for the gRPC listener.
// When provided, per-route authentication operations in the gRPC proxy
// director emit Prometheus metrics for observability.
func WithGRPCAuthMetrics(metrics *auth.Metrics) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.authMetrics = metrics
	}
}

// WithGRPCVaultClient sets the vault client for the gRPC listener.
// When provided, per-route API key authentication in the gRPC proxy
// can use Vault as the key store.
func WithGRPCVaultClient(client vault.Client) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.vaultClient = client
	}
}

// WithGRPCBackendRegistry sets the backend registry for the gRPC listener.
// When set, the gRPC proxy director resolves backend names to actual host
// addresses using the backend's load balancer.
func WithGRPCBackendRegistry(registry *backend.Registry) GRPCListenerOption {
	return func(l *GRPCListener) {
		l.backendRegistry = registry
	}
}

// NewGRPCListener creates a new gRPC listener.
func NewGRPCListener(
	cfg config.Listener,
	opts ...GRPCListenerOption,
) (*GRPCListener, error) {
	l := &GRPCListener{
		config: cfg,
		logger: observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(l)
	}

	// Create router if not provided
	if l.router == nil {
		l.router = grpcrouter.New()
	}

	// Create proxy with metrics registry so gRPC proxy metrics
	// appear on the gateway's /metrics endpoint.
	proxyOpts := []grpcproxy.ProxyOption{
		grpcproxy.WithProxyLogger(l.logger),
	}
	if l.metricsRegistry != nil {
		proxyOpts = append(proxyOpts, grpcproxy.WithMetricsRegistry(l.metricsRegistry))
	}
	if l.authMetrics != nil {
		proxyOpts = append(proxyOpts, grpcproxy.WithAuthMetrics(l.authMetrics))
	}
	if l.vaultClient != nil {
		proxyOpts = append(proxyOpts, grpcproxy.WithProxyVaultClient(l.vaultClient))
	}
	if l.backendRegistry != nil {
		proxyOpts = append(proxyOpts, grpcproxy.WithBackendRegistry(l.backendRegistry))
	}
	l.proxy = grpcproxy.New(l.router, proxyOpts...)

	// Build interceptors
	unaryInterceptors, streamInterceptors := l.buildInterceptors()

	// Get gRPC config or use defaults
	grpcCfg := cfg.GRPC
	if grpcCfg == nil {
		grpcCfg = config.DefaultGRPCListenerConfig()
	}

	// Build server options (preallocate with capacity for base options + potential TLS options)
	serverOpts := make([]grpcserver.Option, 0, 8)
	serverOpts = append(serverOpts,
		grpcserver.WithLogger(l.logger),
		grpcserver.WithAddress(l.Address()),
		grpcserver.WithUnaryInterceptors(unaryInterceptors...),
		grpcserver.WithStreamInterceptors(streamInterceptors...),
		grpcserver.WithUnknownServiceHandler(l.proxy.StreamHandler()),
	)

	// Configure TLS
	tlsOpts, err := l.buildTLSOptions(grpcCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS: %w", err)
	}
	serverOpts = append(serverOpts, tlsOpts...)

	// Create server
	server, err := grpcserver.New(grpcCfg, serverOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC server: %w", err)
	}

	l.server = server

	return l, nil
}

// buildTLSOptions builds TLS-related server options.
func (l *GRPCListener) buildTLSOptions(grpcCfg *config.GRPCListenerConfig) ([]grpcserver.Option, error) {
	// Check if route TLS manager is provided (takes precedence)
	if l.routeTLSManager != nil {
		return l.buildTLSOptionsFromRouteTLSManager(), nil
	}

	// Check if TLS manager is provided externally
	if l.tlsManager != nil {
		return l.buildTLSOptionsFromManager(), nil
	}

	// Check TLS configuration from gRPC config
	if grpcCfg == nil || grpcCfg.TLS == nil {
		return nil, nil
	}

	return l.buildTLSOptionsFromConfig(grpcCfg.TLS)
}

// buildTLSOptionsFromRouteTLSManager builds TLS options using the route TLS manager.
func (l *GRPCListener) buildTLSOptionsFromRouteTLSManager() []grpcserver.Option {
	opts := []grpcserver.Option{grpcserver.WithTLSConfig(l.routeTLSManager.GetTLSConfig())}
	if l.tlsMetrics != nil {
		opts = append(opts, grpcserver.WithTLSMetrics(l.tlsMetrics))
	}

	l.logger.Info("gRPC listener using route TLS manager",
		observability.String("name", l.config.Name),
		observability.Int("routes", l.routeTLSManager.RouteCount()),
	)
	return opts
}

// buildTLSOptionsFromManager builds TLS options using the externally provided TLS manager.
func (l *GRPCListener) buildTLSOptionsFromManager() []grpcserver.Option {
	opts := []grpcserver.Option{grpcserver.WithTLSManager(l.tlsManager)}
	if l.tlsMetrics != nil {
		opts = append(opts, grpcserver.WithTLSMetrics(l.tlsMetrics))
	}

	l.logger.Info("gRPC listener using TLS manager",
		observability.String("name", l.config.Name),
		observability.String("mode", string(l.tlsManager.GetMode())),
	)
	return opts
}

// buildTLSOptionsFromConfig builds TLS options from TLS configuration.
func (l *GRPCListener) buildTLSOptionsFromConfig(tlsCfg *config.TLSConfig) ([]grpcserver.Option, error) {
	// Validate TLS configuration
	if err := tlsCfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid TLS configuration: %w", err)
	}

	// Check if insecure mode (covers both !Enabled and Mode==INSECURE)
	if tlsCfg.IsInsecure() {
		l.logger.Warn("gRPC listener running in INSECURE mode",
			observability.String("name", l.config.Name),
		)
		return []grpcserver.Option{grpcserver.WithInsecure()}, nil
	}

	return l.configureTLSFromConfig(tlsCfg)
}

// configureTLSFromConfig configures TLS options from TLS configuration.
func (l *GRPCListener) configureTLSFromConfig(tlsCfg *config.TLSConfig) ([]grpcserver.Option, error) {
	var opts []grpcserver.Option

	// Create TLS manager from config
	manager, err := l.createTLSManagerFromConfig(tlsCfg)
	if err != nil {
		fallbackOpts, fallbackErr := l.handleTLSManagerCreationError(tlsCfg, err)
		if fallbackErr != nil {
			return nil, fallbackErr
		}
		opts = fallbackOpts
	} else {
		l.tlsManager = manager
		opts = append(opts, grpcserver.WithTLSManager(manager))
		if l.tlsMetrics != nil {
			opts = append(opts, grpcserver.WithTLSMetrics(l.tlsMetrics))
		}
	}

	// Configure ALPN enforcement
	if tlsCfg.RequireALPN {
		opts = append(opts, grpcserver.WithALPNEnforcement(true))
	}

	// Configure client cert metadata extraction for mTLS
	if tlsCfg.IsMutual() || tlsCfg.IsOptionalMutual() {
		opts = append(opts, grpcserver.WithClientCertMetadata(true))
	}

	l.logger.Info("gRPC listener TLS configured",
		observability.String("name", l.config.Name),
		observability.String("mode", tlsCfg.GetEffectiveMode()),
		observability.Bool("mtls", tlsCfg.IsMutual()),
	)

	return opts, nil
}

// handleTLSManagerCreationError handles TLS manager creation failure by falling back to file-based TLS.
// Returns an error if no fallback cert/key files are available.
func (l *GRPCListener) handleTLSManagerCreationError(
	tlsCfg *config.TLSConfig,
	err error,
) ([]grpcserver.Option, error) {
	// Record metric for TLS manager creation failure
	if l.tlsMetrics != nil {
		l.tlsMetrics.RecordHandshakeError("tls_manager_creation_failed")
	}

	if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		l.logger.Warn("failed to create TLS manager, falling back to file-based TLS",
			observability.String("name", l.config.Name),
			observability.String("certFile", tlsCfg.CertFile),
			observability.Error(err),
		)
		return []grpcserver.Option{grpcserver.WithTLSCredentials(tlsCfg.CertFile, tlsCfg.KeyFile)}, nil
	}

	l.logger.Error("failed to create TLS manager and no fallback cert/key files available",
		observability.String("name", l.config.Name),
		observability.Error(err),
	)
	return nil, fmt.Errorf("TLS manager creation failed and no fallback cert/key files configured: %w", err)
}

// createTLSManagerFromConfig creates a TLS manager from TLSConfig.
func (l *GRPCListener) createTLSManagerFromConfig(cfg *config.TLSConfig) (*tlspkg.Manager, error) {
	// Convert config.TLSConfig to tlspkg.Config
	tlsConfig := &tlspkg.Config{
		Mode:               tlspkg.TLSMode(cfg.GetEffectiveMode()),
		MinVersion:         tlspkg.TLSVersion(cfg.GetEffectiveMinVersion()),
		CipherSuites:       cfg.CipherSuites,
		ALPN:               cfg.GetEffectiveALPN(),
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	// Set max version if specified
	if cfg.MaxVersion != "" {
		tlsConfig.MaxVersion = tlspkg.TLSVersion(cfg.MaxVersion)
	}

	// Configure server certificate from file
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		tlsConfig.ServerCertificate = &tlspkg.CertificateConfig{
			Source:   tlspkg.CertificateSourceFile,
			CertFile: cfg.CertFile,
			KeyFile:  cfg.KeyFile,
		}
	}

	// Configure Vault-based TLS if enabled
	if cfg.Vault != nil && cfg.Vault.Enabled {
		tlsConfig.Vault = &tlspkg.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   cfg.Vault.PKIMount,
			Role:       cfg.Vault.Role,
			CommonName: cfg.Vault.CommonName,
			AltNames:   cfg.Vault.AltNames,
		}
		// When Vault is the certificate source, set ServerCertificate accordingly
		if tlsConfig.ServerCertificate == nil {
			tlsConfig.ServerCertificate = &tlspkg.CertificateConfig{
				Source: tlspkg.CertificateSourceVault,
			}
		}
		// Default to SIMPLE mode when Vault is enabled and no mode is set
		if tlsConfig.Mode == "" {
			tlsConfig.Mode = tlspkg.TLSModeSimple
		}
	}

	// Configure client validation for mTLS
	if cfg.IsMutual() || cfg.IsOptionalMutual() {
		tlsConfig.ClientValidation = &tlspkg.ClientValidationConfig{
			Enabled:           true,
			CAFile:            cfg.CAFile,
			RequireClientCert: cfg.IsMutual(),
			AllowedCNs:        cfg.AllowedCNs,
			AllowedSANs:       cfg.AllowedSANs,
		}
	}

	// Create manager options
	managerOpts := []tlspkg.ManagerOption{
		tlspkg.WithManagerLogger(l.logger),
	}
	if l.tlsMetrics != nil {
		managerOpts = append(managerOpts, tlspkg.WithManagerMetrics(l.tlsMetrics))
	}
	if l.vaultProviderFactory != nil {
		managerOpts = append(managerOpts, tlspkg.WithVaultProviderFactory(l.vaultProviderFactory))
	}

	return tlspkg.NewManager(tlsConfig, managerOpts...)
}

// buildInterceptors builds the interceptor chains.
// The execution order (outermost executes first):
// Recovery → RequestID → Logging → Metrics → Tracing → Audit → RateLimit → CircuitBreaker
//
// Tracing runs before Audit so that trace context (TraceID/SpanID)
// is available in the request context when audit events are created.
func (l *GRPCListener) buildInterceptors() ([]grpc.UnaryServerInterceptor, []grpc.StreamServerInterceptor) {
	var unaryInterceptors []grpc.UnaryServerInterceptor
	var streamInterceptors []grpc.StreamServerInterceptor

	// Recovery interceptor (first, to catch panics)
	unaryInterceptors = append(unaryInterceptors, grpcmiddleware.UnaryRecoveryInterceptor(l.logger))
	streamInterceptors = append(streamInterceptors, grpcmiddleware.StreamRecoveryInterceptor(l.logger))

	// Request ID interceptor
	unaryInterceptors = append(unaryInterceptors, grpcmiddleware.UnaryRequestIDInterceptor())
	streamInterceptors = append(streamInterceptors, grpcmiddleware.StreamRequestIDInterceptor())

	// Logging interceptor
	unaryInterceptors = append(unaryInterceptors, grpcmiddleware.UnaryLoggingInterceptor(l.logger))
	streamInterceptors = append(streamInterceptors, grpcmiddleware.StreamLoggingInterceptor(l.logger))

	// Metrics interceptor
	if l.metrics != nil {
		unaryInterceptors = append(unaryInterceptors, grpcmiddleware.UnaryMetricsInterceptor(l.metrics))
		streamInterceptors = append(streamInterceptors, grpcmiddleware.StreamMetricsInterceptor(l.metrics))
	}

	// Tracing interceptor
	tracingCfg := grpcmiddleware.DefaultTracingConfig("avapigw")
	unaryInterceptors = append(unaryInterceptors, grpcmiddleware.UnaryTracingInterceptor(tracingCfg))
	streamInterceptors = append(streamInterceptors, grpcmiddleware.StreamTracingInterceptor(tracingCfg))

	// Audit interceptor (after Tracing so trace context is available)
	if l.auditLogger != nil {
		unaryInterceptors = append(unaryInterceptors, grpcmiddleware.UnaryAuditInterceptor(l.auditLogger))
		streamInterceptors = append(streamInterceptors, grpcmiddleware.StreamAuditInterceptor(l.auditLogger))
	}

	// Rate limit interceptor (after Audit)
	if l.rateLimiter != nil {
		unaryInterceptors = append(unaryInterceptors, grpcmiddleware.UnaryRateLimitInterceptor(l.rateLimiter))
		streamInterceptors = append(streamInterceptors, grpcmiddleware.StreamRateLimitInterceptor(l.rateLimiter))
	}

	// Circuit breaker interceptor (after Rate limit)
	if l.circuitBreaker != nil {
		unaryInterceptors = append(unaryInterceptors,
			grpcmiddleware.UnaryCircuitBreakerInterceptor(l.circuitBreaker))
		streamInterceptors = append(streamInterceptors,
			grpcmiddleware.StreamCircuitBreakerInterceptor(l.circuitBreaker))
	}

	return unaryInterceptors, streamInterceptors
}

// Name returns the listener name.
func (l *GRPCListener) Name() string {
	return l.config.Name
}

// Port returns the listener port.
func (l *GRPCListener) Port() int {
	return l.config.Port
}

// Address returns the listener address.
func (l *GRPCListener) Address() string {
	bind := l.config.Bind
	if bind == "" {
		bind = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", bind, l.config.Port)
}

// Start starts the gRPC listener.
func (l *GRPCListener) Start(ctx context.Context) error {
	if l.running.Load() {
		return fmt.Errorf("gRPC listener %s is already running", l.config.Name)
	}

	l.logger.Info("starting gRPC listener",
		observability.String("name", l.config.Name),
		observability.String("address", l.Address()),
	)

	// Start TLS manager if available
	if l.tlsManager != nil {
		if err := l.tlsManager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start TLS manager: %w", err)
		}
		l.logger.Info("TLS manager started",
			observability.String("name", l.config.Name),
			observability.String("mode", string(l.tlsManager.GetMode())),
		)
	}

	if err := l.server.Start(ctx); err != nil {
		// Clean up TLS manager if server fails to start
		if l.tlsManager != nil {
			_ = l.tlsManager.Close()
		}
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}

	l.running.Store(true)

	l.logger.Info("gRPC listener started",
		observability.String("name", l.config.Name),
		observability.String("address", l.Address()),
	)

	return nil
}

// Stop stops the gRPC listener gracefully.
func (l *GRPCListener) Stop(ctx context.Context) error {
	if !l.running.Load() {
		return nil
	}

	l.logger.Info("stopping gRPC listener",
		observability.String("name", l.config.Name),
	)

	// Create timeout context if not already set
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultGracefulStopTimeout)
		defer cancel()
	}

	if err := l.server.GracefulStop(ctx); err != nil {
		l.logger.Error("failed to stop gRPC server gracefully",
			observability.String("name", l.config.Name),
			observability.Error(err),
		)
		return err
	}

	// Close proxy connections
	if err := l.proxy.Close(); err != nil {
		l.logger.Error("failed to close proxy connections",
			observability.String("name", l.config.Name),
			observability.Error(err),
		)
	}

	// Close route TLS manager if we have one
	if l.routeTLSManager != nil {
		if err := l.routeTLSManager.Close(); err != nil {
			l.logger.Error("failed to close route TLS manager",
				observability.String("name", l.config.Name),
				observability.Error(err),
			)
		}
	}

	// Close TLS manager if we created it
	if l.tlsManager != nil {
		if err := l.tlsManager.Close(); err != nil {
			l.logger.Error("failed to close TLS manager",
				observability.String("name", l.config.Name),
				observability.Error(err),
			)
		}
	}

	l.running.Store(false)

	l.logger.Info("gRPC listener stopped",
		observability.String("name", l.config.Name),
	)

	return nil
}

// IsRunning returns true if the listener is running.
func (l *GRPCListener) IsRunning() bool {
	return l.running.Load()
}

// Router returns the gRPC router.
func (l *GRPCListener) Router() *grpcrouter.Router {
	return l.router
}

// Server returns the gRPC server.
func (l *GRPCListener) Server() *grpcserver.Server {
	return l.server
}

// Proxy returns the gRPC proxy.
func (l *GRPCListener) Proxy() *grpcproxy.Proxy {
	return l.proxy
}

// ClearAuthCache clears the gRPC proxy director's authenticator cache.
// This should be called when gRPC route authentication configuration
// changes so that the next request rebuilds authenticators from the
// updated config.
func (l *GRPCListener) ClearAuthCache() {
	if l.proxy != nil {
		l.proxy.ClearAuthCache()
		l.logger.Debug("gRPC listener auth cache cleared",
			observability.String("name", l.config.Name),
		)
	}
}

// ReloadBackends reloads gRPC backend configuration and cleans up stale connections.
// It delegates to the backend registry's ReloadFromConfig for the copy-on-write swap,
// then cleans up connections to removed or changed backends.
func (l *GRPCListener) ReloadBackends(ctx context.Context, backends []config.Backend) error {
	if l.backendRegistry == nil {
		return fmt.Errorf("no backend registry configured for gRPC listener %s", l.config.Name)
	}

	// Collect current backend targets before reload
	oldTargets := l.collectBackendTargets()

	// Reload backends using copy-on-write pattern
	if err := l.backendRegistry.ReloadFromConfig(ctx, backends); err != nil {
		return fmt.Errorf("failed to reload gRPC backends on listener %s: %w", l.config.Name, err)
	}

	// Collect new backend targets after reload
	newTargets := l.collectBackendTargets()

	// Clean up stale connections
	if l.proxy != nil {
		l.proxy.CleanupStaleConnections(newTargets)
	}

	l.logger.Info("gRPC backends reloaded",
		observability.String("listener", l.config.Name),
		observability.Int("old_targets", len(oldTargets)),
		observability.Int("new_targets", len(newTargets)),
	)

	return nil
}

// collectBackendTargets collects all host:port targets from the backend registry.
func (l *GRPCListener) collectBackendTargets() map[string]bool {
	targets := make(map[string]bool)
	if l.backendRegistry == nil {
		return targets
	}
	for _, b := range l.backendRegistry.GetAll() {
		sb, ok := b.(*backend.ServiceBackend)
		if !ok {
			continue
		}
		for _, host := range sb.GetHosts() {
			target := fmt.Sprintf("%s:%d", host.Address, host.Port)
			targets[target] = true
		}
	}
	return targets
}

// LoadRoutes loads gRPC routes from configuration.
func (l *GRPCListener) LoadRoutes(routes []config.GRPCRoute) error {
	return l.router.LoadRoutes(routes)
}

// TLSManager returns the TLS manager if configured.
func (l *GRPCListener) TLSManager() *tlspkg.Manager {
	return l.tlsManager
}

// RouteTLSManager returns the route TLS manager if configured.
func (l *GRPCListener) RouteTLSManager() *tlspkg.RouteTLSManager {
	return l.routeTLSManager
}

// IsRouteTLSEnabled returns true if route-level TLS is enabled.
func (l *GRPCListener) IsRouteTLSEnabled() bool {
	return l.routeTLSManager != nil && l.routeTLSManager.RouteCount() > 0
}

// IsTLSEnabled returns true if TLS is enabled for this listener.
func (l *GRPCListener) IsTLSEnabled() bool {
	if l.tlsManager != nil {
		return l.tlsManager.IsEnabled()
	}
	// Check config
	if l.config.GRPC != nil && l.config.GRPC.TLS != nil {
		return l.config.GRPC.TLS.Enabled && !l.config.GRPC.TLS.IsInsecure()
	}
	return false
}

// IsMTLSEnabled returns true if mutual TLS is enabled for this listener.
func (l *GRPCListener) IsMTLSEnabled() bool {
	if l.tlsManager != nil {
		return l.tlsManager.IsMTLSEnabled()
	}
	// Check config
	if l.config.GRPC != nil && l.config.GRPC.TLS != nil {
		return l.config.GRPC.TLS.IsMutual() || l.config.GRPC.TLS.IsOptionalMutual()
	}
	return false
}

// TLSMode returns the TLS mode for this listener.
func (l *GRPCListener) TLSMode() string {
	if l.tlsManager != nil {
		return string(l.tlsManager.GetMode())
	}
	// Check config
	if l.config.GRPC != nil && l.config.GRPC.TLS != nil {
		return l.config.GRPC.TLS.GetEffectiveMode()
	}
	return config.TLSModeInsecure
}
