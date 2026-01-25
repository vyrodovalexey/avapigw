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

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

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
	config        *config.GatewayConfig
	logger        observability.Logger
	engine        *gin.Engine
	listeners     []*Listener
	grpcListeners []*GRPCListener
	state         atomic.Int32
	startTime     time.Time
	mu            sync.RWMutex

	// Handlers
	routeHandler http.Handler

	// Shutdown
	shutdownTimeout time.Duration
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

// New creates a new Gateway instance.
func New(cfg *config.GatewayConfig, opts ...Option) (*Gateway, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}

	g := &Gateway{
		config:          cfg,
		logger:          observability.NopLogger(),
		shutdownTimeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(g)
	}

	g.state.Store(int32(StateStopped))

	return g, nil
}

// Start starts the gateway.
func (g *Gateway) Start(ctx context.Context) error {
	if !g.state.CompareAndSwap(int32(StateStopped), int32(StateStarting)) {
		return fmt.Errorf("gateway is not in stopped state")
	}

	g.logger.Info("starting gateway",
		observability.String("name", g.config.Metadata.Name),
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
		observability.String("name", g.config.Metadata.Name),
		observability.Int("http_listeners", len(g.listeners)),
		observability.Int("grpc_listeners", len(g.grpcListeners)),
	)

	return nil
}

// Stop stops the gateway gracefully.
func (g *Gateway) Stop(ctx context.Context) error {
	if !g.state.CompareAndSwap(int32(StateRunning), int32(StateStopping)) {
		return fmt.Errorf("gateway is not running")
	}

	g.logger.Info("stopping gateway",
		observability.String("name", g.config.Metadata.Name),
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
		observability.String("name", g.config.Metadata.Name),
	)

	return nil
}

// Reload reloads the gateway configuration.
func (g *Gateway) Reload(cfg *config.GatewayConfig) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.logger.Info("reloading gateway configuration",
		observability.String("name", cfg.Metadata.Name),
	)

	// Validate new configuration
	if err := config.ValidateConfig(cfg); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Update configuration
	g.config = cfg

	// TODO: Implement hot-reload of routes and backends

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

// Config returns the current configuration.
func (g *Gateway) Config() *config.GatewayConfig {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
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
func (g *Gateway) createListeners() error {
	g.listeners = make([]*Listener, 0, len(g.config.Spec.Listeners))
	g.grpcListeners = make([]*GRPCListener, 0)

	for _, listenerCfg := range g.config.Spec.Listeners {
		// Check if this is a gRPC listener
		if listenerCfg.Protocol == config.ProtocolGRPC {
			grpcListener, err := NewGRPCListener(listenerCfg,
				WithGRPCListenerLogger(g.logger),
			)
			if err != nil {
				return fmt.Errorf("failed to create gRPC listener %s: %w", listenerCfg.Name, err)
			}

			// Load gRPC routes
			if err := grpcListener.LoadRoutes(g.config.Spec.GRPCRoutes); err != nil {
				return fmt.Errorf("failed to load gRPC routes for listener %s: %w", listenerCfg.Name, err)
			}

			g.grpcListeners = append(g.grpcListeners, grpcListener)
		} else {
			// HTTP listener
			listener, err := NewListener(listenerCfg, g.engine, WithListenerLogger(g.logger))
			if err != nil {
				return fmt.Errorf("failed to create listener %s: %w", listenerCfg.Name, err)
			}
			g.listeners = append(g.listeners, listener)
		}
	}

	return nil
}

// stopListeners stops all listeners.
func (g *Gateway) stopListeners(ctx context.Context) {
	var wg sync.WaitGroup

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

	wg.Wait()
}

// GetListeners returns all HTTP listeners.
func (g *Gateway) GetListeners() []*Listener {
	return g.listeners
}

// GetGRPCListeners returns all gRPC listeners.
func (g *Gateway) GetGRPCListeners() []*GRPCListener {
	return g.grpcListeners
}
