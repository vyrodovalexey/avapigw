package gateway

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcmiddleware "github.com/vyrodovalexey/avapigw/internal/grpc/middleware"
	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
	grpcserver "github.com/vyrodovalexey/avapigw/internal/grpc/server"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// GRPCListener represents a gRPC listener.
type GRPCListener struct {
	config  config.Listener
	server  *grpcserver.Server
	router  *grpcrouter.Router
	proxy   *grpcproxy.Proxy
	metrics *grpcmiddleware.GRPCMetrics
	logger  observability.Logger
	running atomic.Bool
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

	// Create proxy
	l.proxy = grpcproxy.New(l.router,
		grpcproxy.WithProxyLogger(l.logger),
	)

	// Build interceptors
	unaryInterceptors, streamInterceptors := l.buildInterceptors()

	// Get gRPC config or use defaults
	grpcCfg := cfg.GRPC
	if grpcCfg == nil {
		grpcCfg = config.DefaultGRPCListenerConfig()
	}

	// Create server
	address := l.Address()
	server, err := grpcserver.New(grpcCfg,
		grpcserver.WithLogger(l.logger),
		grpcserver.WithAddress(address),
		grpcserver.WithUnaryInterceptors(unaryInterceptors...),
		grpcserver.WithStreamInterceptors(streamInterceptors...),
		grpcserver.WithUnknownServiceHandler(l.proxy.StreamHandler()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC server: %w", err)
	}

	l.server = server

	return l, nil
}

// buildInterceptors builds the interceptor chains.
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

	if err := l.server.Start(ctx); err != nil {
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
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
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

// LoadRoutes loads gRPC routes from configuration.
func (l *GRPCListener) LoadRoutes(routes []config.GRPCRoute) error {
	return l.router.LoadRoutes(routes)
}
