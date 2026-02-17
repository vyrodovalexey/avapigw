// Package grpc provides gRPC server and client for operator-gateway communication.
package grpc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
	"github.com/vyrodovalexey/avapigw/internal/operator/keys"
	"github.com/vyrodovalexey/avapigw/internal/retry"
)

var (
	defaultMetrics     *serverMetrics
	defaultMetricsOnce sync.Once
)

// RetryConfig contains configuration for retry behavior with exponential backoff.
type RetryConfig struct {
	// MaxAttempts is the maximum number of retry attempts.
	// Default is 3.
	MaxAttempts int

	// InitialBackoff is the initial backoff duration.
	// Default is 100ms.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration.
	// Default is 5s.
	MaxBackoff time.Duration

	// Multiplier is the backoff multiplier (used by the retry package as exponential base).
	// Default is 2.0 (exponential backoff).
	Multiplier float64
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:    3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     5 * time.Second,
		Multiplier:     2.0,
	}
}

// DefaultGracefulShutdownTimeout is the default maximum time to wait for graceful shutdown.
const DefaultGracefulShutdownTimeout = 30 * time.Second

// ServerConfig contains configuration for the gRPC server.
type ServerConfig struct {
	// Port is the port to listen on.
	Port int

	// Certificate is the server certificate.
	Certificate *cert.Certificate

	// CertManager is the certificate manager for client validation.
	CertManager cert.Manager

	// MetricsRegisterer is the Prometheus registerer for server metrics.
	// If nil, metrics are registered with the default registerer.
	MetricsRegisterer prometheus.Registerer

	// MaxConcurrentStreams is the maximum number of concurrent streams.
	MaxConcurrentStreams uint32

	// MaxRecvMsgSize is the maximum message size in bytes.
	MaxRecvMsgSize int

	// MaxSendMsgSize is the maximum message size in bytes.
	MaxSendMsgSize int

	// RetryConfig contains retry configuration for Apply/Delete operations.
	// If nil, default retry configuration is used.
	RetryConfig *RetryConfig

	// GracefulShutdownTimeout is the maximum time to wait for graceful shutdown.
	// If zero, DefaultGracefulShutdownTimeout (30s) is used.
	GracefulShutdownTimeout time.Duration
}

// Server is the gRPC configuration server.
type Server struct {
	config      *ServerConfig
	retryConfig *retry.Config
	grpcServer  *grpc.Server
	logger      observability.Logger
	metrics     *serverMetrics

	// Configuration storage
	mu           sync.RWMutex
	apiRoutes    map[string][]byte
	grpcRoutes   map[string][]byte
	backends     map[string][]byte
	grpcBackends map[string][]byte

	// Configuration change notification.
	// configNotify is closed to broadcast a change to all waiting goroutines,
	// then replaced with a new channel for the next broadcast cycle.
	configNotify chan struct{}

	// Connected gateways
	gateways map[string]*gatewayConnection

	// Lifecycle
	started bool
	closed  bool
}

// gatewayConnection represents a connected gateway.
type gatewayConnection struct {
	name        string
	namespace   string
	connectedAt time.Time
	lastSeen    time.Time
}

// serverMetrics contains Prometheus metrics for the server.
type serverMetrics struct {
	requestsTotal     *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	activeGateways    prometheus.Gauge
	configApplied     *prometheus.CounterVec
	cancelledOps      *prometheus.CounterVec
	operationDuration *prometheus.HistogramVec
	retryAttempts     *prometheus.CounterVec
}

// initServerMetrics initializes the singleton server metrics instance with the
// given Prometheus registerer. If registerer is nil, metrics are registered
// with the default registerer. Must be called before getServerMetrics;
// subsequent calls are no-ops (sync.Once).
func initServerMetrics(registerer prometheus.Registerer) {
	defaultMetricsOnce.Do(func() {
		if registerer == nil {
			registerer = prometheus.DefaultRegisterer
		}
		defaultMetrics = newServerMetricsWithFactory(promauto.With(registerer))
	})
}

// getServerMetrics returns the singleton server metrics instance.
// If initServerMetrics has not been called, metrics are lazily
// initialized with the default registerer.
func getServerMetrics() *serverMetrics {
	initServerMetrics(nil)
	return defaultMetrics
}

// newServerMetricsWithFactory creates server metrics using the given promauto factory.
// This allows tests to supply a custom registry to avoid duplicate registration panics.
func newServerMetricsWithFactory(factory promauto.Factory) *serverMetrics {
	return &serverMetrics{
		requestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc",
				Name:      "requests_total",
				Help:      "Total number of gRPC requests",
			},
			[]string{"method", "status"},
		),
		requestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc",
				Name:      "request_duration_seconds",
				Help:      "gRPC request duration in seconds",
				Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
			},
			[]string{"method"},
		),
		activeGateways: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc",
				Name:      "active_gateways",
				Help:      "Number of active gateway connections",
			},
		),
		configApplied: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc",
				Name:      "config_applied_total",
				Help:      "Total number of configuration applications",
			},
			[]string{"type", "operation"},
		),
		cancelledOps: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc",
				Name:      "canceled_operations_total",
				Help:      "Total number of canceled operations",
			},
			[]string{"operation", "reason"},
		),
		operationDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc",
				Name:      "operation_duration_seconds",
				Help:      "Duration of configuration operations in seconds",
				Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
			},
			[]string{"operation", "type"},
		),
		retryAttempts: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "grpc",
				Name:      "retry_attempts_total",
				Help:      "Total number of retry attempts for configuration operations",
			},
			[]string{"operation", "type", "result"},
		),
	}
}

// NewServer creates a new gRPC server.
func NewServer(config *ServerConfig) (*Server, error) {
	var registerer prometheus.Registerer
	if config != nil {
		registerer = config.MetricsRegisterer
	}
	initServerMetrics(registerer)
	return newServerInternal(config, getServerMetrics())
}

// NewServerWithRegistry creates a new gRPC server using a custom Prometheus registry.
// This is useful for testing to avoid duplicate metric registration panics.
func NewServerWithRegistry(config *ServerConfig, registry *prometheus.Registry) (*Server, error) {
	m := newServerMetricsWithFactory(promauto.With(registry))
	return newServerInternal(config, m)
}

// newServerInternal creates a new gRPC server with the given metrics.
func newServerInternal(config *ServerConfig, metrics *serverMetrics) (*Server, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.Port <= 0 {
		config.Port = DefaultPort
	}

	if config.MaxConcurrentStreams == 0 {
		config.MaxConcurrentStreams = DefaultMaxConcurrentStreams
	}

	if config.MaxRecvMsgSize == 0 {
		config.MaxRecvMsgSize = DefaultMaxMessageSize
	}

	if config.MaxSendMsgSize == 0 {
		config.MaxSendMsgSize = DefaultMaxMessageSize
	}

	// Initialize retry configuration
	retryCfg := config.RetryConfig
	if retryCfg == nil {
		retryCfg = DefaultRetryConfig()
	}

	s := &Server{
		config: config,
		retryConfig: &retry.Config{
			MaxRetries:     retryCfg.MaxAttempts,
			InitialBackoff: retryCfg.InitialBackoff,
			MaxBackoff:     retryCfg.MaxBackoff,
			JitterFactor:   retry.DefaultJitterFactor,
		},
		logger:       observability.GetGlobalLogger().With(observability.String("component", "grpc-server")),
		metrics:      metrics,
		apiRoutes:    make(map[string][]byte),
		grpcRoutes:   make(map[string][]byte),
		backends:     make(map[string][]byte),
		grpcBackends: make(map[string][]byte),
		configNotify: make(chan struct{}),
		gateways:     make(map[string]*gatewayConnection),
	}

	return s, nil
}

// Start starts the gRPC server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("server is closed")
	}
	s.started = true
	s.mu.Unlock()

	// Create listener
	addr := fmt.Sprintf(":%d", s.config.Port)
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	// Create gRPC server options
	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(s.config.MaxConcurrentStreams),
		grpc.MaxRecvMsgSize(s.config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(s.config.MaxSendMsgSize),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     DefaultMaxConnectionIdle,
			MaxConnectionAge:      DefaultMaxConnectionAge,
			MaxConnectionAgeGrace: DefaultMaxConnectionAgeGrace,
			Time:                  DefaultKeepaliveTime,
			Timeout:               DefaultKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             DefaultMinKeepaliveTime,
			PermitWithoutStream: true,
		}),
	}

	// Add TLS if certificate is provided
	if s.config.Certificate != nil {
		tlsCert, err := tls.X509KeyPair(s.config.Certificate.CertificatePEM, s.config.Certificate.PrivateKeyPEM)
		if err != nil {
			return fmt.Errorf("failed to create TLS certificate: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		}

		// Add client CA if available
		if s.config.CertManager != nil {
			caPool, err := s.config.CertManager.GetCA(ctx)
			if err == nil && caPool != nil {
				tlsConfig.ClientCAs = caPool
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}
		}

		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Add gRPC server metrics interceptors for request counting, duration, and stream tracking
	initGRPCServerMetrics(s.config.MetricsRegisterer)
	grpcSrvMetrics := getGRPCServerMetrics()
	opts = append(opts,
		grpc.ChainUnaryInterceptor(grpcSrvMetrics.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(grpcSrvMetrics.StreamServerInterceptor()),
	)

	// Create gRPC server and assign under mutex to prevent data race with Stop()
	grpcSrv := grpc.NewServer(opts...)

	// Register the ConfigurationService with the gRPC server
	registerConfigurationService(grpcSrv, s)

	s.mu.Lock()
	s.grpcServer = grpcSrv
	s.mu.Unlock()

	s.logger.Info("starting gRPC server",
		observability.String("address", addr),
		observability.Bool("tls_enabled", s.config.Certificate != nil),
	)

	// Start serving in a goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		s.logger.Info("shutting down gRPC server")
		s.grpcServer.GracefulStop()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// Stop stops the gRPC server with graceful shutdown timeout.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true

	if s.grpcServer != nil {
		timeout := s.config.GracefulShutdownTimeout
		if timeout == 0 {
			timeout = DefaultGracefulShutdownTimeout
		}

		// Use a channel to signal graceful shutdown completion
		done := make(chan struct{})
		go func() {
			s.grpcServer.GracefulStop()
			close(done)
		}()

		// Wait for graceful shutdown or timeout
		select {
		case <-done:
			s.logger.Info("gRPC server gracefully stopped")
		case <-time.After(timeout):
			s.logger.Warn("graceful shutdown timeout exceeded, forcing stop",
				observability.Duration("timeout", timeout),
			)
			s.grpcServer.Stop() // Force stop
		}
	}

	s.logger.Info("gRPC server stopped")
}

// ApplyAPIRoute applies an API route configuration.
func (s *Server) ApplyAPIRoute(ctx context.Context, name, namespace string, config []byte) error {
	start := time.Now()

	// Check context cancellation at the start
	if err := s.checkContextCancellation(ctx, "ApplyAPIRoute"); err != nil {
		return err
	}

	err := s.executeWithRetry(ctx, "apply", "apiroute", func() error {
		return s.applyAPIRouteInternal(ctx, name, namespace, config)
	})

	if err != nil {
		return err
	}

	s.metrics.configApplied.WithLabelValues("apiroute", "apply").Inc()
	s.metrics.operationDuration.WithLabelValues("apply", "apiroute").Observe(time.Since(start).Seconds())
	s.logger.Info("API route applied",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)

	s.NotifyConfigChanged()

	return nil
}

// applyAPIRouteInternal performs the actual API route application with mutex handling.
func (s *Server) applyAPIRouteInternal(ctx context.Context, name, namespace string, config []byte) error {
	unlock, err := s.withContextLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	key := keys.ResourceKey(namespace, name)
	s.apiRoutes[key] = config

	return nil
}

// DeleteAPIRoute deletes an API route configuration.
func (s *Server) DeleteAPIRoute(ctx context.Context, name, namespace string) error {
	start := time.Now()

	// Check context cancellation at the start
	if err := s.checkContextCancellation(ctx, "DeleteAPIRoute"); err != nil {
		return err
	}

	err := s.executeWithRetry(ctx, "delete", "apiroute", func() error {
		return s.deleteAPIRouteInternal(ctx, name, namespace)
	})

	if err != nil {
		return err
	}

	s.metrics.configApplied.WithLabelValues("apiroute", "delete").Inc()
	s.metrics.operationDuration.WithLabelValues("delete", "apiroute").Observe(time.Since(start).Seconds())
	s.logger.Info("API route deleted",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)

	s.NotifyConfigChanged()

	return nil
}

// deleteAPIRouteInternal performs the actual API route deletion with mutex handling.
func (s *Server) deleteAPIRouteInternal(ctx context.Context, name, namespace string) error {
	unlock, err := s.withContextLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	key := keys.ResourceKey(namespace, name)
	delete(s.apiRoutes, key)

	return nil
}

// ApplyGRPCRoute applies a gRPC route configuration.
func (s *Server) ApplyGRPCRoute(ctx context.Context, name, namespace string, config []byte) error {
	start := time.Now()

	// Check context cancellation at the start
	if err := s.checkContextCancellation(ctx, "ApplyGRPCRoute"); err != nil {
		return err
	}

	err := s.executeWithRetry(ctx, "apply", "grpcroute", func() error {
		return s.applyGRPCRouteInternal(ctx, name, namespace, config)
	})

	if err != nil {
		return err
	}

	s.metrics.configApplied.WithLabelValues("grpcroute", "apply").Inc()
	s.metrics.operationDuration.WithLabelValues("apply", "grpcroute").Observe(time.Since(start).Seconds())
	s.logger.Info("gRPC route applied",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)

	s.NotifyConfigChanged()

	return nil
}

// applyGRPCRouteInternal performs the actual gRPC route application with mutex handling.
func (s *Server) applyGRPCRouteInternal(ctx context.Context, name, namespace string, config []byte) error {
	unlock, err := s.withContextLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	key := keys.ResourceKey(namespace, name)
	s.grpcRoutes[key] = config

	return nil
}

// DeleteGRPCRoute deletes a gRPC route configuration.
func (s *Server) DeleteGRPCRoute(ctx context.Context, name, namespace string) error {
	start := time.Now()

	// Check context cancellation at the start
	if err := s.checkContextCancellation(ctx, "DeleteGRPCRoute"); err != nil {
		return err
	}

	err := s.executeWithRetry(ctx, "delete", "grpcroute", func() error {
		return s.deleteGRPCRouteInternal(ctx, name, namespace)
	})

	if err != nil {
		return err
	}

	s.metrics.configApplied.WithLabelValues("grpcroute", "delete").Inc()
	s.metrics.operationDuration.WithLabelValues("delete", "grpcroute").Observe(time.Since(start).Seconds())
	s.logger.Info("gRPC route deleted",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)

	s.NotifyConfigChanged()

	return nil
}

// deleteGRPCRouteInternal performs the actual gRPC route deletion with mutex handling.
func (s *Server) deleteGRPCRouteInternal(ctx context.Context, name, namespace string) error {
	unlock, err := s.withContextLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	key := keys.ResourceKey(namespace, name)
	delete(s.grpcRoutes, key)

	return nil
}

// ApplyBackend applies a backend configuration.
func (s *Server) ApplyBackend(ctx context.Context, name, namespace string, config []byte) error {
	start := time.Now()

	// Check context cancellation at the start
	if err := s.checkContextCancellation(ctx, "ApplyBackend"); err != nil {
		return err
	}

	err := s.executeWithRetry(ctx, "apply", "backend", func() error {
		return s.applyBackendInternal(ctx, name, namespace, config)
	})

	if err != nil {
		return err
	}

	s.metrics.configApplied.WithLabelValues("backend", "apply").Inc()
	s.metrics.operationDuration.WithLabelValues("apply", "backend").Observe(time.Since(start).Seconds())
	s.logger.Info("backend applied",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)

	s.NotifyConfigChanged()

	return nil
}

// applyBackendInternal performs the actual backend application with mutex handling.
func (s *Server) applyBackendInternal(ctx context.Context, name, namespace string, config []byte) error {
	unlock, err := s.withContextLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	key := keys.ResourceKey(namespace, name)
	s.backends[key] = config

	return nil
}

// DeleteBackend deletes a backend configuration.
func (s *Server) DeleteBackend(ctx context.Context, name, namespace string) error {
	start := time.Now()

	// Check context cancellation at the start
	if err := s.checkContextCancellation(ctx, "DeleteBackend"); err != nil {
		return err
	}

	err := s.executeWithRetry(ctx, "delete", "backend", func() error {
		return s.deleteBackendInternal(ctx, name, namespace)
	})

	if err != nil {
		return err
	}

	s.metrics.configApplied.WithLabelValues("backend", "delete").Inc()
	s.metrics.operationDuration.WithLabelValues("delete", "backend").Observe(time.Since(start).Seconds())
	s.logger.Info("backend deleted",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)

	s.NotifyConfigChanged()

	return nil
}

// deleteBackendInternal performs the actual backend deletion with mutex handling.
func (s *Server) deleteBackendInternal(ctx context.Context, name, namespace string) error {
	unlock, err := s.withContextLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	key := keys.ResourceKey(namespace, name)
	delete(s.backends, key)

	return nil
}

// ApplyGRPCBackend applies a gRPC backend configuration.
func (s *Server) ApplyGRPCBackend(ctx context.Context, name, namespace string, config []byte) error {
	start := time.Now()

	// Check context cancellation at the start
	if err := s.checkContextCancellation(ctx, "ApplyGRPCBackend"); err != nil {
		return err
	}

	err := s.executeWithRetry(ctx, "apply", "grpcbackend", func() error {
		return s.applyGRPCBackendInternal(ctx, name, namespace, config)
	})

	if err != nil {
		return err
	}

	s.metrics.configApplied.WithLabelValues("grpcbackend", "apply").Inc()
	s.metrics.operationDuration.WithLabelValues("apply", "grpcbackend").Observe(time.Since(start).Seconds())
	s.logger.Info("gRPC backend applied",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)

	s.NotifyConfigChanged()

	return nil
}

// applyGRPCBackendInternal performs the actual gRPC backend application with mutex handling.
func (s *Server) applyGRPCBackendInternal(ctx context.Context, name, namespace string, config []byte) error {
	unlock, err := s.withContextLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	key := keys.ResourceKey(namespace, name)
	s.grpcBackends[key] = config

	return nil
}

// DeleteGRPCBackend deletes a gRPC backend configuration.
func (s *Server) DeleteGRPCBackend(ctx context.Context, name, namespace string) error {
	start := time.Now()

	// Check context cancellation at the start
	if err := s.checkContextCancellation(ctx, "DeleteGRPCBackend"); err != nil {
		return err
	}

	err := s.executeWithRetry(ctx, "delete", "grpcbackend", func() error {
		return s.deleteGRPCBackendInternal(ctx, name, namespace)
	})

	if err != nil {
		return err
	}

	s.metrics.configApplied.WithLabelValues("grpcbackend", "delete").Inc()
	s.metrics.operationDuration.WithLabelValues("delete", "grpcbackend").Observe(time.Since(start).Seconds())
	s.logger.Info("gRPC backend deleted",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)

	s.NotifyConfigChanged()

	return nil
}

// deleteGRPCBackendInternal performs the actual gRPC backend deletion with mutex handling.
func (s *Server) deleteGRPCBackendInternal(ctx context.Context, name, namespace string) error {
	unlock, err := s.withContextLock(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	key := keys.ResourceKey(namespace, name)
	delete(s.grpcBackends, key)

	return nil
}

// HasAPIRoute checks if an API route exists in the in-memory configuration map.
// This is used to detect cold start conditions where the resource is marked as Ready
// in Kubernetes but has not been applied to the gRPC server's in-memory state.
func (s *Server) HasAPIRoute(name, namespace string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := keys.ResourceKey(namespace, name)
	_, exists := s.apiRoutes[key]
	return exists
}

// HasGRPCRoute checks if a gRPC route exists in the in-memory configuration map.
// This is used to detect cold start conditions where the resource is marked as Ready
// in Kubernetes but has not been applied to the gRPC server's in-memory state.
func (s *Server) HasGRPCRoute(name, namespace string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := keys.ResourceKey(namespace, name)
	_, exists := s.grpcRoutes[key]
	return exists
}

// HasBackend checks if a backend exists in the in-memory configuration map.
// This is used to detect cold start conditions where the resource is marked as Ready
// in Kubernetes but has not been applied to the gRPC server's in-memory state.
func (s *Server) HasBackend(name, namespace string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := keys.ResourceKey(namespace, name)
	_, exists := s.backends[key]
	return exists
}

// HasGRPCBackend checks if a gRPC backend exists in the in-memory configuration map.
// This is used to detect cold start conditions where the resource is marked as Ready
// in Kubernetes but has not been applied to the gRPC server's in-memory state.
func (s *Server) HasGRPCBackend(name, namespace string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := keys.ResourceKey(namespace, name)
	_, exists := s.grpcBackends[key]
	return exists
}

// GetAllConfigs returns all configurations as JSON.
func (s *Server) GetAllConfigs() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	configs := map[string]interface{}{
		"apiRoutes":    s.apiRoutes,
		"grpcRoutes":   s.grpcRoutes,
		"backends":     s.backends,
		"grpcBackends": s.grpcBackends,
	}

	return json.Marshal(configs)
}

// RegisterGateway registers a gateway connection.
func (s *Server) RegisterGateway(name, namespace string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := keys.ResourceKey(namespace, name)
	s.gateways[key] = &gatewayConnection{
		name:        name,
		namespace:   namespace,
		connectedAt: time.Now(),
		lastSeen:    time.Now(),
	}

	s.metrics.activeGateways.Set(float64(len(s.gateways)))
	s.logger.Info("gateway registered",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)
}

// UnregisterGateway unregisters a gateway connection.
func (s *Server) UnregisterGateway(name, namespace string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := keys.ResourceKey(namespace, name)
	delete(s.gateways, key)

	s.metrics.activeGateways.Set(float64(len(s.gateways)))
	s.logger.Info("gateway unregistered",
		observability.String("name", name),
		observability.String("namespace", namespace),
	)
}

// UpdateGatewayHeartbeat updates the last seen time for a gateway.
func (s *Server) UpdateGatewayHeartbeat(name, namespace string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := keys.ResourceKey(namespace, name)
	if gw, ok := s.gateways[key]; ok {
		gw.lastSeen = time.Now()
	}
}

// GetGatewayCount returns the number of connected gateways.
func (s *Server) GetGatewayCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.gateways)
}

// NotifyConfigChanged broadcasts a configuration change to all waiting streams.
// It closes the current configNotify channel (waking all goroutines blocked on it)
// and replaces it with a fresh channel for the next broadcast cycle.
// This method must be called outside of the data mutex to avoid deadlocks.
func (s *Server) NotifyConfigChanged() {
	s.mu.Lock()
	ch := s.configNotify
	s.configNotify = make(chan struct{})
	s.mu.Unlock()
	close(ch)
}

// WaitForConfigChange returns a channel that will be closed when the configuration changes.
// Callers should select on this channel along with their context's Done channel.
func (s *Server) WaitForConfigChange() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configNotify
}

// checkContextCancellation checks if the context is canceled or deadline exceeded.
// Returns the appropriate error if canceled, nil otherwise.
func (s *Server) checkContextCancellation(ctx context.Context, operation string) error {
	select {
	case <-ctx.Done():
		s.recordCanceledOperation(operation, ctx.Err())
		return ctx.Err()
	default:
		return nil
	}
}

// executeWithRetry executes an operation with retry logic using exponential backoff.
// It records retry metrics and logs retry attempts.
func (s *Server) executeWithRetry(
	ctx context.Context,
	operation, resourceType string,
	fn func() error,
) error {
	retryOpts := &retry.Options{
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			s.metrics.retryAttempts.WithLabelValues(operation, resourceType, "retry").Inc()
			s.logger.Warn("operation failed, retrying",
				observability.String("operation", operation),
				observability.String("type", resourceType),
				observability.Int("attempt", attempt),
				observability.Duration("backoff", backoff),
				observability.Error(err),
			)
		},
	}

	err := retry.Do(ctx, s.retryConfig, fn, retryOpts)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			s.metrics.retryAttempts.WithLabelValues(operation, resourceType, "canceled").Inc()
		} else {
			s.metrics.retryAttempts.WithLabelValues(operation, resourceType, "exhausted").Inc()
		}
		return err
	}

	s.metrics.retryAttempts.WithLabelValues(operation, resourceType, "success").Inc()
	return nil
}

// recordCanceledOperation records a canceled operation metric.
func (s *Server) recordCanceledOperation(operation string, err error) {
	reason := "unknown"
	if errors.Is(err, context.Canceled) {
		reason = "canceled"
	} else if errors.Is(err, context.DeadlineExceeded) {
		reason = "deadline_exceeded"
	}

	s.metrics.cancelledOps.WithLabelValues(operation, reason).Inc()
	s.logger.Warn("operation canceled",
		observability.String("operation", operation),
		observability.String("reason", reason),
		observability.Error(err),
	)
}

// contextLockPollInterval constants for exponential backoff when polling TryLock.
const (
	contextLockInitialInterval = time.Millisecond
	contextLockMaxInterval     = 100 * time.Millisecond
	contextLockBackoffFactor   = 2
)

// withContextLock acquires the mutex with context cancellation support.
// Returns a cleanup function that must be called to release the lock, or an error
// if the context was canceled before or during lock acquisition.
//
// This implementation uses sync.Mutex.TryLock() in a loop with exponential backoff
// (starting at 1ms, doubling up to 100ms) and context checking to avoid spawning
// goroutines that could leak if the context is canceled.
func (s *Server) withContextLock(ctx context.Context) (unlock func(), err error) {
	// Check context first to fail fast
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Try to acquire the lock immediately
	if s.mu.TryLock() {
		// Check context again after acquiring lock
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		return s.mu.Unlock, nil
	}

	// Poll TryLock with exponential backoff and context checking to avoid goroutine leaks
	backoff := contextLockInitialInterval
	for {
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			// Stop the timer and drain the channel to prevent resource leaks
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
			// Timer already fired, no need to stop/drain
			if s.mu.TryLock() {
				// Check context again after acquiring lock
				if err := ctx.Err(); err != nil {
					s.mu.Unlock()
					return nil, err
				}
				return s.mu.Unlock, nil
			}
			// Exponential backoff: double the interval up to the maximum
			backoff *= contextLockBackoffFactor
			if backoff > contextLockMaxInterval {
				backoff = contextLockMaxInterval
			}
		}
	}
}
