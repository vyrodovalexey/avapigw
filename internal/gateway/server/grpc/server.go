// Package grpc provides the gRPC server implementation for the API Gateway.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

// Server represents the gRPC server for the API Gateway.
type Server struct {
	grpcServer         *grpc.Server
	listener           net.Listener
	router             *Router
	proxy              *Proxy
	healthServer       *health.Server
	interceptors       []grpc.UnaryServerInterceptor
	streamInterceptors []grpc.StreamServerInterceptor
	logger             *zap.Logger
	config             *ServerConfig
	backendManager     *backend.Manager
	mu                 sync.RWMutex
	running            bool
}

// ServerConfig holds configuration for the gRPC server.
type ServerConfig struct {
	// Port is the port to listen on.
	Port int

	// Address is the address to bind to.
	Address string

	// MaxRecvMsgSize is the maximum message size in bytes the server can receive.
	MaxRecvMsgSize int

	// MaxSendMsgSize is the maximum message size in bytes the server can send.
	MaxSendMsgSize int

	// MaxConcurrentStreams is the maximum number of concurrent streams per connection.
	MaxConcurrentStreams uint32

	// KeepaliveParams are the keepalive parameters for the server.
	KeepaliveParams keepalive.ServerParameters

	// KeepaliveEnforcementPolicy is the keepalive enforcement policy.
	KeepaliveEnforcementPolicy keepalive.EnforcementPolicy

	// TLS is the TLS configuration for the server.
	TLS *tls.Config

	// EnableReflection enables gRPC reflection for debugging.
	EnableReflection bool

	// EnableHealthCheck enables the gRPC health check service.
	EnableHealthCheck bool

	// ConnectionTimeout is the timeout for establishing connections.
	ConnectionTimeout time.Duration

	// InitialWindowSize is the initial window size for flow control.
	InitialWindowSize int32

	// InitialConnWindowSize is the initial connection window size for flow control.
	InitialConnWindowSize int32
}

// DefaultServerConfig returns a ServerConfig with default values.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:                 9090,
		Address:              "",
		MaxRecvMsgSize:       4 * 1024 * 1024, // 4 MB
		MaxSendMsgSize:       4 * 1024 * 1024, // 4 MB
		MaxConcurrentStreams: 1000,
		KeepaliveParams: keepalive.ServerParameters{
			MaxConnectionIdle:     15 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 5 * time.Minute,
			Time:                  5 * time.Minute,
			Timeout:               1 * time.Minute,
		},
		KeepaliveEnforcementPolicy: keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		},
		EnableReflection:      false,
		EnableHealthCheck:     true,
		ConnectionTimeout:     120 * time.Second,
		InitialWindowSize:     1 << 20, // 1 MB
		InitialConnWindowSize: 1 << 20, // 1 MB
	}
}

// NewServer creates a new gRPC server.
func NewServer(config *ServerConfig, backendManager *backend.Manager, logger *zap.Logger) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}

	s := &Server{
		router:             NewRouter(logger),
		interceptors:       make([]grpc.UnaryServerInterceptor, 0),
		streamInterceptors: make([]grpc.StreamServerInterceptor, 0),
		logger:             logger,
		config:             config,
		backendManager:     backendManager,
	}

	// Create proxy
	s.proxy = NewProxy(backendManager, logger)

	return s
}

// AddUnaryInterceptor adds a unary interceptor to the server.
func (s *Server) AddUnaryInterceptor(interceptor grpc.UnaryServerInterceptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interceptors = append(s.interceptors, interceptor)
}

// AddStreamInterceptor adds a stream interceptor to the server.
func (s *Server) AddStreamInterceptor(interceptor grpc.StreamServerInterceptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamInterceptors = append(s.streamInterceptors, interceptor)
}

// GetRouter returns the router.
func (s *Server) GetRouter() *Router {
	return s.router
}

// GetProxy returns the proxy.
func (s *Server) GetProxy() *Proxy {
	return s.proxy
}

// GetGRPCServer returns the underlying gRPC server.
func (s *Server) GetGRPCServer() *grpc.Server {
	return s.grpcServer
}

// GetHealthServer returns the health server.
func (s *Server) GetHealthServer() *health.Server {
	return s.healthServer
}

// Start starts the gRPC server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)

	// Create listener
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	// Build server options
	opts := s.buildServerOptions()

	// Create gRPC server
	s.grpcServer = grpc.NewServer(opts...)

	// Register health service if enabled
	if s.config.EnableHealthCheck {
		s.healthServer = health.NewServer()
		healthpb.RegisterHealthServer(s.grpcServer, s.healthServer)
		s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	}

	// Enable reflection if configured
	if s.config.EnableReflection {
		reflection.Register(s.grpcServer)
		s.logger.Info("gRPC reflection enabled")
	}

	// Register the transparent proxy handler for unknown services
	s.registerUnknownServiceHandler()

	s.running = true
	s.mu.Unlock()

	s.logger.Info("starting gRPC server",
		zap.String("address", addr),
		zap.Int("maxRecvMsgSize", s.config.MaxRecvMsgSize),
		zap.Int("maxSendMsgSize", s.config.MaxSendMsgSize),
		zap.Uint32("maxConcurrentStreams", s.config.MaxConcurrentStreams),
		zap.Bool("tlsEnabled", s.config.TLS != nil),
		zap.Bool("reflectionEnabled", s.config.EnableReflection),
		zap.Bool("healthCheckEnabled", s.config.EnableHealthCheck),
	)

	// Start serving
	if err := s.grpcServer.Serve(listener); err != nil {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return fmt.Errorf("gRPC server error: %w", err)
	}

	return nil
}

// Stop stops the gRPC server gracefully.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	s.logger.Info("stopping gRPC server")

	// Set health status to not serving
	if s.healthServer != nil {
		s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	}

	// Create a channel to signal when graceful stop is complete
	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	// Wait for graceful stop or context cancellation
	select {
	case <-done:
		s.logger.Info("gRPC server stopped gracefully")
	case <-ctx.Done():
		s.logger.Warn("graceful stop timed out, forcing stop")
		s.grpcServer.Stop()
	}

	// Close proxy connections
	if err := s.proxy.Close(); err != nil {
		s.logger.Error("error closing proxy connections", zap.Error(err))
	}

	s.mu.Lock()
	s.running = false
	s.mu.Unlock()

	s.logger.Info("gRPC server stopped")
	return nil
}

// IsRunning returns whether the server is running.
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// UpdateRoutes updates the routes in the router.
func (s *Server) UpdateRoutes(routes []GRPCRouteConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, route := range routes {
		r := &GRPCRoute{
			Name:      route.Name,
			Hostnames: route.Hostnames,
			Rules:     route.Rules,
		}

		if err := s.router.AddRoute(r); err != nil {
			// Try to update if it already exists
			if err := s.router.UpdateRoute(r); err != nil {
				return fmt.Errorf("failed to add/update route %s: %w", route.Name, err)
			}
		}
	}

	return nil
}

// RemoveRoute removes a route by name.
func (s *Server) RemoveRoute(name string) error {
	return s.router.RemoveRoute(name)
}

// buildServerOptions builds the gRPC server options.
func (s *Server) buildServerOptions() []grpc.ServerOption {
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(s.config.MaxRecvMsgSize),
		grpc.MaxSendMsgSize(s.config.MaxSendMsgSize),
		grpc.MaxConcurrentStreams(s.config.MaxConcurrentStreams),
		grpc.KeepaliveParams(s.config.KeepaliveParams),
		grpc.KeepaliveEnforcementPolicy(s.config.KeepaliveEnforcementPolicy),
		grpc.ConnectionTimeout(s.config.ConnectionTimeout),
		grpc.InitialWindowSize(s.config.InitialWindowSize),
		grpc.InitialConnWindowSize(s.config.InitialConnWindowSize),
	}

	// Add TLS credentials if configured
	if s.config.TLS != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(s.config.TLS)))
	}

	// Chain unary interceptors
	if len(s.interceptors) > 0 {
		opts = append(opts, grpc.ChainUnaryInterceptor(s.interceptors...))
	}

	// Chain stream interceptors
	if len(s.streamInterceptors) > 0 {
		opts = append(opts, grpc.ChainStreamInterceptor(s.streamInterceptors...))
	}

	return opts
}

// registerUnknownServiceHandler registers a handler for unknown services.
func (s *Server) registerUnknownServiceHandler() {
	// The unknown service handler is used for transparent proxying
	// This allows the gateway to forward requests to backends even if
	// the service is not registered on the gateway itself
	s.grpcServer.RegisterService(&grpc.ServiceDesc{
		ServiceName: "",
		HandlerType: nil,
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
		Metadata:    nil,
	}, s)
}

// SetServingStatus sets the serving status for a service.
func (s *Server) SetServingStatus(service string, status healthpb.HealthCheckResponse_ServingStatus) {
	if s.healthServer != nil {
		s.healthServer.SetServingStatus(service, status)
	}
}

// GRPCRouteConfig is a simplified route configuration for external use.
type GRPCRouteConfig struct {
	Name      string
	Hostnames []string
	Rules     []GRPCRouteRule
}
