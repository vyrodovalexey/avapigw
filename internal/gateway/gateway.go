// Package gateway provides the core API Gateway functionality.
package gateway

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcmiddleware "github.com/vyrodovalexey/avapigw/internal/grpc/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// configField is an atomic pointer for lock-free config access.
// It eliminates the race condition where readers calling Config()
// with RLock could see stale data after Reload() swaps the pointer.
type configField = atomic.Pointer[config.GatewayConfig]

// State represents the gateway state.
type State int32

const (
	// StateStopped indicates the gateway is stopped.
	StateStopped State = iota
	// StateStarting indicates the gateway is starting.
	StateStarting
	// StateRunning indicates the gateway is running.
	StateRunning
	// StateStopping indicates the gateway is stopping.
	StateStopping
)

// String returns the string representation of the state.
func (s State) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	default:
		return "unknown"
	}
}

// Gateway is the main API Gateway struct.
type Gateway struct {
	// config uses atomic.Pointer for lock-free concurrent access.
	// Reload() stores a new pointer atomically; Config() loads it
	// without acquiring a mutex, preventing stale-read races.
	config configField

	logger        observability.Logger
	engine        *gin.Engine
	listeners     []*Listener
	grpcListeners []*GRPCListener
	state         atomic.Int32
	startTime     time.Time

	// Handlers
	routeHandler http.Handler

	// TLS
	vaultProviderFactory tlspkg.VaultProviderFactory

	// Shutdown
	shutdownTimeout time.Duration

	// TLS metrics
	tlsMetrics tlspkg.MetricsRecorder

	// gRPC components
	auditLogger     audit.Logger
	metricsRegistry *prometheus.Registry
	grpcMetrics     *grpcmiddleware.GRPCMetrics
	grpcMetricsOnce sync.Once
	authMetrics     *auth.Metrics
	vaultClient     vault.Client
}

// Option is a functional option for configuring the gateway.
type Option func(*Gateway)

// WithLogger sets the logger for the gateway.
func WithLogger(logger observability.Logger) Option {
	return func(g *Gateway) {
		g.logger = logger
	}
}

// WithShutdownTimeout sets the shutdown timeout.
func WithShutdownTimeout(timeout time.Duration) Option {
	return func(g *Gateway) {
		g.shutdownTimeout = timeout
	}
}

// WithRouteHandler sets the route handler.
func WithRouteHandler(handler http.Handler) Option {
	return func(g *Gateway) {
		g.routeHandler = handler
	}
}

// WithGatewayVaultProviderFactory sets the Vault provider factory for TLS certificate management.
// The factory is propagated to all HTTP and gRPC listeners created by the gateway,
// enabling Vault PKI-based certificate issuance and renewal.
func WithGatewayVaultProviderFactory(factory tlspkg.VaultProviderFactory) Option {
	return func(g *Gateway) {
		g.vaultProviderFactory = factory
	}
}

// WithAuditLogger sets the audit logger for the gateway.
// The audit logger is propagated to gRPC listeners to enable
// audit logging of gRPC requests.
func WithAuditLogger(logger audit.Logger) Option {
	return func(g *Gateway) {
		g.auditLogger = logger
	}
}

// WithMetricsRegistry sets the Prometheus registry for the gateway.
// The registry is used to register gRPC server metrics so they appear
// on the gateway's /metrics endpoint alongside HTTP metrics.
func WithMetricsRegistry(registry *prometheus.Registry) Option {
	return func(g *Gateway) {
		g.metricsRegistry = registry
	}
}

// WithGatewayTLSMetrics sets the TLS metrics recorder for the gateway.
// The metrics recorder is propagated to all HTTP and gRPC listeners,
// enabling TLS connection and handshake metrics to be emitted to Prometheus.
func WithGatewayTLSMetrics(metrics tlspkg.MetricsRecorder) Option {
	return func(g *Gateway) {
		g.tlsMetrics = metrics
	}
}

// WithGatewayAuthMetrics sets the authentication metrics for the gateway.
// The metrics are propagated to gRPC listeners to enable per-route
// authentication metrics in the gRPC proxy director.
func WithGatewayAuthMetrics(metrics *auth.Metrics) Option {
	return func(g *Gateway) {
		g.authMetrics = metrics
	}
}

// WithGatewayVaultClient sets the vault client for the gateway.
// The vault client is propagated to gRPC listeners to enable per-route
// API key authentication using Vault as the key store.
func WithGatewayVaultClient(client vault.Client) Option {
	return func(g *Gateway) {
		g.vaultClient = client
	}
}

// New creates a new Gateway instance.
func New(cfg *config.GatewayConfig, opts ...Option) (*Gateway, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	g := &Gateway{
		logger:          observability.NopLogger(),
		shutdownTimeout: 30 * time.Second,
	}
	g.config.Store(cfg)

	for _, opt := range opts {
		opt(g)
	}

	g.state.Store(int32(StateStopped))

	return g, nil
}

// Start starts the gateway.
func (g *Gateway) Start(ctx context.Context) error {
	if !g.state.CompareAndSwap(int32(StateStopped), int32(StateStarting)) {
		return ErrGatewayNotStopped
	}

	g.logger.Info("starting gateway",
		observability.String("name", g.config.Load().Metadata.Name),
	)

	// Initialize gin engine
	gin.SetMode(gin.ReleaseMode)
	g.engine = gin.New()

	// Setup routes
	g.setupRoutes()

	// Create listeners
	if err := g.createListeners(); err != nil { //nolint:contextcheck // Listener creation doesn't need context
		g.state.Store(int32(StateStopped))
		return fmt.Errorf("failed to create listeners: %w", err)
	}

	// Start HTTP listeners
	for _, listener := range g.listeners {
		if err := listener.Start(ctx); err != nil {
			// Stop already started listeners
			g.stopListeners(ctx)
			g.state.Store(int32(StateStopped))
			return fmt.Errorf("failed to start listener %s: %w", listener.Name(), err)
		}
	}

	// Start gRPC listeners
	for _, listener := range g.grpcListeners {
		if err := listener.Start(ctx); err != nil {
			// Stop already started listeners
			g.stopListeners(ctx)
			g.state.Store(int32(StateStopped))
			return fmt.Errorf("failed to start gRPC listener %s: %w", listener.Name(), err)
		}
	}

	g.startTime = time.Now()
	g.state.Store(int32(StateRunning))

	g.logger.Info("gateway started",
		observability.String("name", g.config.Load().Metadata.Name),
		observability.Int("http_listeners", len(g.listeners)),
		observability.Int("grpc_listeners", len(g.grpcListeners)),
	)

	return nil
}

// Stop stops the gateway gracefully.
func (g *Gateway) Stop(ctx context.Context) error {
	if !g.state.CompareAndSwap(int32(StateRunning), int32(StateStopping)) {
		return ErrGatewayNotRunning
	}

	g.logger.Info("stopping gateway",
		observability.String("name", g.config.Load().Metadata.Name),
	)

	// Create timeout context if not already set
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.shutdownTimeout)
		defer cancel()
	}

	// Stop all listeners
	g.stopListeners(ctx)

	g.state.Store(int32(StateStopped))

	g.logger.Info("gateway stopped",
		observability.String("name", g.config.Load().Metadata.Name),
	)

	return nil
}

// Reload reloads the gateway configuration.
// The new config is validated first, then stored atomically so that
// concurrent readers via Config() never observe a partially-updated
// pointer and never block on a mutex.
func (g *Gateway) Reload(cfg *config.GatewayConfig) error {
	g.logger.Info("reloading gateway configuration",
		observability.String("name", cfg.Metadata.Name),
	)

	// Validate new configuration before swapping
	if err := config.ValidateConfig(cfg); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	// Atomic store ensures concurrent Config() callers see
	// either the old or the new pointer, never a torn read.
	g.config.Store(cfg)

	// Hot-reload of middleware, routes, and backends is handled
	// by the config watcher callback in cmd/gateway/main.go via
	// reloadComponents(), which calls UpdateConfig on each
	// middleware component after this method returns.

	g.logger.Info("gateway configuration reloaded",
		observability.String("name", cfg.Metadata.Name),
	)

	return nil
}

// State returns the current gateway state.
func (g *Gateway) State() State {
	return State(g.state.Load())
}

// IsRunning returns true if the gateway is running.
func (g *Gateway) IsRunning() bool {
	return g.State() == StateRunning
}

// Uptime returns the gateway uptime.
func (g *Gateway) Uptime() time.Duration {
	if g.startTime.IsZero() {
		return 0
	}
	return time.Since(g.startTime)
}

// Config returns the current configuration via an atomic load,
// providing lock-free, race-free access for concurrent readers.
func (g *Gateway) Config() *config.GatewayConfig {
	return g.config.Load()
}

// Engine returns the gin engine.
func (g *Gateway) Engine() *gin.Engine {
	return g.engine
}

// setupRoutes sets up the gin routes.
func (g *Gateway) setupRoutes() {
	// Add recovery middleware
	g.engine.Use(gin.Recovery())

	// If a custom route handler is set, use it for all routes
	if g.routeHandler != nil {
		g.engine.NoRoute(gin.WrapH(g.routeHandler))
	}
}

// createListeners creates listeners from configuration.
// If any listener fails to create, all previously created listeners are cleaned up.
func (g *Gateway) createListeners() error {
	cfg := g.config.Load()
	listeners := make([]*Listener, 0, len(cfg.Spec.Listeners))
	grpcListeners := make([]*GRPCListener, 0)

	for _, listenerCfg := range cfg.Spec.Listeners {
		if listenerCfg.Protocol == config.ProtocolGRPC {
			grpcListener, err := g.createGRPCListener(listenerCfg, cfg.Spec.GRPCRoutes)
			if err != nil {
				g.cleanupListenersOnError(listeners, grpcListeners)
				return err
			}
			grpcListeners = append(grpcListeners, grpcListener)
		} else {
			listener, err := g.createHTTPListener(listenerCfg)
			if err != nil {
				g.cleanupListenersOnError(listeners, grpcListeners)
				return err
			}
			listeners = append(listeners, listener)
		}
	}

	g.listeners = listeners
	g.grpcListeners = grpcListeners

	return nil
}

// createHTTPListener creates a single HTTP listener from configuration.
func (g *Gateway) createHTTPListener(listenerCfg config.Listener) (*Listener, error) {
	httpOpts := []ListenerOption{
		WithListenerLogger(g.logger),
	}
	if g.vaultProviderFactory != nil {
		httpOpts = append(httpOpts, WithVaultProviderFactory(g.vaultProviderFactory))
	}
	if g.tlsMetrics != nil {
		httpOpts = append(httpOpts, WithTLSMetrics(g.tlsMetrics))
	}

	listener, err := NewListener(
		listenerCfg, g.engine,
		httpOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create listener %s: %w",
			listenerCfg.Name, err,
		)
	}

	return listener, nil
}

// createGRPCListener creates a single gRPC listener from configuration and loads its routes.
func (g *Gateway) createGRPCListener(
	listenerCfg config.Listener, grpcRoutes []config.GRPCRoute,
) (*GRPCListener, error) {
	grpcOpts := []GRPCListenerOption{
		WithGRPCListenerLogger(g.logger),
	}
	if g.vaultProviderFactory != nil {
		grpcOpts = append(grpcOpts, WithGRPCVaultProviderFactory(g.vaultProviderFactory))
	}
	if g.tlsMetrics != nil {
		grpcOpts = append(grpcOpts, WithGRPCTLSMetrics(g.tlsMetrics))
	}

	// Create and pass gRPC metrics (once, reused across config reloads).
	// sync.Once ensures MustRegister is called only once, preventing
	// duplicate-registration panics on hot-reload.
	grpcMetrics := g.getOrCreateGRPCMetrics()
	if grpcMetrics != nil {
		grpcOpts = append(grpcOpts, WithGRPCMetrics(grpcMetrics))
	}

	// Pass metrics registry so gRPC proxy metrics (connection pool,
	// direct requests, streaming, etc.) are registered with the
	// gateway's custom registry and appear on /metrics.
	if g.metricsRegistry != nil {
		grpcOpts = append(grpcOpts, WithGRPCMetricsRegistry(g.metricsRegistry))
	}

	// Pass audit logger if available
	if g.auditLogger != nil {
		grpcOpts = append(grpcOpts, WithGRPCAuditLogger(g.auditLogger))
	}

	// Pass auth metrics for per-route authentication observability
	if g.authMetrics != nil {
		grpcOpts = append(grpcOpts, WithGRPCAuthMetrics(g.authMetrics))
	}

	// Pass vault client for per-route API key authentication via Vault
	if g.vaultClient != nil {
		grpcOpts = append(grpcOpts, WithGRPCVaultClient(g.vaultClient))
	}

	grpcListener, err := NewGRPCListener(listenerCfg, grpcOpts...)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to create gRPC listener %s: %w",
			listenerCfg.Name, err,
		)
	}

	if err := grpcListener.LoadRoutes(grpcRoutes); err != nil {
		return nil, fmt.Errorf(
			"failed to load gRPC routes for listener %s: %w",
			listenerCfg.Name, err,
		)
	}

	return grpcListener, nil
}

// getOrCreateGRPCMetrics returns the shared gRPC metrics instance,
// creating it on first call. The sync.Once guarantees that
// NewGRPCMetrics (which calls registry.MustRegister) is invoked
// exactly once, even when createGRPCListener is called multiple
// times during config reloads.
//
// Returns nil when no metrics registry is configured, which causes
// the metrics interceptor to be skipped in buildInterceptors().
func (g *Gateway) getOrCreateGRPCMetrics() *grpcmiddleware.GRPCMetrics {
	g.grpcMetricsOnce.Do(func() {
		if g.metricsRegistry == nil {
			// No registry configured — skip gRPC metrics registration.
			// In production the registry is always provided via
			// WithMetricsRegistry; this path is only hit in tests
			// that omit the option.
			return
		}
		g.grpcMetrics = grpcmiddleware.NewGRPCMetrics("grpc", g.metricsRegistry)
		g.logger.Info("gRPC server metrics registered",
			observability.String("namespace", "grpc"),
		)
	})
	return g.grpcMetrics
}

// cleanupListenersOnError closes all already-created listeners when a subsequent creation fails.
func (g *Gateway) cleanupListenersOnError(listeners []*Listener, grpcListeners []*GRPCListener) {
	for _, l := range listeners {
		if err := l.Stop(context.Background()); err != nil {
			g.logger.Error("failed to cleanup listener during rollback",
				observability.String("name", l.Name()),
				observability.Error(err),
			)
		}
	}
	for _, l := range grpcListeners {
		if err := l.Stop(context.Background()); err != nil {
			g.logger.Error("failed to cleanup gRPC listener during rollback",
				observability.String("name", l.Name()),
				observability.Error(err),
			)
		}
	}
}

// stopListeners stops all listeners.
// It respects context cancellation but ensures all stop operations are initiated.
func (g *Gateway) stopListeners(ctx context.Context) {
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Stop HTTP listeners
	for _, listener := range g.listeners {
		wg.Add(1)
		go func(l *Listener) {
			defer wg.Done()
			if err := l.Stop(ctx); err != nil {
				g.logger.Error("failed to stop listener",
					observability.String("name", l.Name()),
					observability.Error(err),
				)
			}
		}(listener)
	}

	// Stop gRPC listeners
	for _, listener := range g.grpcListeners {
		wg.Add(1)
		go func(l *GRPCListener) {
			defer wg.Done()
			if err := l.Stop(ctx); err != nil {
				g.logger.Error("failed to stop gRPC listener",
					observability.String("name", l.Name()),
					observability.Error(err),
				)
			}
		}(listener)
	}

	// Wait for all listeners to stop or context to be canceled
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All listeners stopped successfully
	case <-ctx.Done():
		g.logger.Warn("context canceled while waiting for listeners to stop",
			observability.Error(ctx.Err()),
		)
		// Wait for remaining listeners to stop (they should respect the context)
		<-done
	}
}

// ClearAllAuthCaches clears the authenticator caches on all gRPC listeners.
// This should be called when gRPC route authentication configuration changes
// (e.g., CRD updates via the operator) so that the next request rebuilds
// authenticators from the updated config.
func (g *Gateway) ClearAllAuthCaches() {
	for _, listener := range g.grpcListeners {
		listener.ClearAuthCache()
	}
	g.logger.Debug("all gRPC auth caches cleared",
		observability.Int("listeners", len(g.grpcListeners)),
	)
}

// GetListeners returns all HTTP listeners.
func (g *Gateway) GetListeners() []*Listener {
	return g.listeners
}

// GetGRPCListeners returns all gRPC listeners.
func (g *Gateway) GetGRPCListeners() []*GRPCListener {
	return g.grpcListeners
}
