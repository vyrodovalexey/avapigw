package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// State represents the server state.
type State int32

const (
	// StateStopped indicates the server is stopped.
	StateStopped State = iota
	// StateStarting indicates the server is starting.
	StateStarting
	// StateRunning indicates the server is running.
	StateRunning
	// StateStopping indicates the server is stopping.
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

// Server represents a gRPC server.
type Server struct {
	// Configuration
	config               *config.GRPCListenerConfig
	address              string
	maxConcurrentStreams uint32
	maxRecvMsgSize       int
	maxSendMsgSize       int
	keepaliveParams      *keepalive.ServerParameters
	keepaliveEnforcement *keepalive.EnforcementPolicy
	connectionTimeout    time.Duration
	gracefulStopTimeout  time.Duration

	// TLS
	tlsCertFile string
	tlsKeyFile  string

	// Interceptors
	unaryInterceptors  []grpc.UnaryServerInterceptor
	streamInterceptors []grpc.StreamServerInterceptor

	// Services
	unknownServiceHandler grpc.StreamHandler
	reflectionEnabled     bool
	healthServiceEnabled  bool
	healthServer          *health.Server

	// Runtime
	grpcServer *grpc.Server
	listener   net.Listener
	logger     observability.Logger
	state      atomic.Int32
	startTime  time.Time
}

// New creates a new gRPC server.
func New(cfg *config.GRPCListenerConfig, opts ...Option) (*Server, error) {
	s := &Server{
		config:               cfg,
		logger:               observability.NopLogger(),
		maxConcurrentStreams: 100,
		maxRecvMsgSize:       4 * 1024 * 1024, // 4MB
		maxSendMsgSize:       4 * 1024 * 1024, // 4MB
		connectionTimeout:    120 * time.Second,
		gracefulStopTimeout:  30 * time.Second,
		healthServiceEnabled: true,
	}

	// Apply configuration from config struct
	if cfg != nil {
		if cfg.MaxConcurrentStreams > 0 {
			s.maxConcurrentStreams = cfg.MaxConcurrentStreams
		}
		if cfg.MaxRecvMsgSize > 0 {
			s.maxRecvMsgSize = cfg.MaxRecvMsgSize
		}
		if cfg.MaxSendMsgSize > 0 {
			s.maxSendMsgSize = cfg.MaxSendMsgSize
		}
		s.reflectionEnabled = cfg.Reflection
		s.healthServiceEnabled = cfg.HealthCheck

		if cfg.Keepalive != nil {
			s.keepaliveParams = &keepalive.ServerParameters{
				Time:                  cfg.Keepalive.Time.Duration(),
				Timeout:               cfg.Keepalive.Timeout.Duration(),
				MaxConnectionIdle:     cfg.Keepalive.MaxConnectionIdle.Duration(),
				MaxConnectionAge:      cfg.Keepalive.MaxConnectionAge.Duration(),
				MaxConnectionAgeGrace: cfg.Keepalive.MaxConnectionAgeGrace.Duration(),
			}
			s.keepaliveEnforcement = &keepalive.EnforcementPolicy{
				PermitWithoutStream: cfg.Keepalive.PermitWithoutStream,
			}
		}

		if cfg.TLS != nil && cfg.TLS.Enabled {
			s.tlsCertFile = cfg.TLS.CertFile
			s.tlsKeyFile = cfg.TLS.KeyFile
		}
	}

	// Apply functional options
	for _, opt := range opts {
		opt(s)
	}

	s.state.Store(int32(StateStopped))

	return s, nil
}

// Start starts the gRPC server.
func (s *Server) Start(ctx context.Context) error {
	if !s.state.CompareAndSwap(int32(StateStopped), int32(StateStarting)) {
		return fmt.Errorf("server is not in stopped state, current state: %s", State(s.state.Load()))
	}

	s.logger.Info("starting gRPC server",
		observability.String("address", s.address),
	)

	// Build server options
	serverOpts, err := s.buildServerOptions()
	if err != nil {
		s.state.Store(int32(StateStopped))
		return fmt.Errorf("failed to build server options: %w", err)
	}

	// Create gRPC server
	s.grpcServer = grpc.NewServer(serverOpts...)

	// Register health service
	if s.healthServiceEnabled {
		s.healthServer = health.NewServer()
		healthpb.RegisterHealthServer(s.grpcServer, s.healthServer)
		s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	}

	// Register reflection service
	if s.reflectionEnabled {
		reflection.Register(s.grpcServer)
	}

	// Create listener
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.address)
	if err != nil {
		s.state.Store(int32(StateStopped))
		return fmt.Errorf("failed to listen on %s: %w", s.address, err)
	}
	s.listener = ln

	s.startTime = time.Now()
	s.state.Store(int32(StateRunning))

	s.logger.Info("gRPC server started",
		observability.String("address", s.address),
		observability.Bool("reflection", s.reflectionEnabled),
		observability.Bool("health", s.healthServiceEnabled),
	)

	// Start serving in a goroutine
	go s.serve()

	return nil
}

// serve starts serving gRPC requests.
func (s *Server) serve() {
	if err := s.grpcServer.Serve(s.listener); err != nil {
		if s.state.Load() != int32(StateStopping) && s.state.Load() != int32(StateStopped) {
			s.logger.Error("gRPC server error",
				observability.String("address", s.address),
				observability.Error(err),
			)
		}
	}
	s.state.Store(int32(StateStopped))
}

// Stop stops the gRPC server immediately.
func (s *Server) Stop(_ context.Context) error {
	if !s.state.CompareAndSwap(int32(StateRunning), int32(StateStopping)) {
		return nil
	}

	s.logger.Info("stopping gRPC server",
		observability.String("address", s.address),
	)

	// Set health status to not serving
	if s.healthServer != nil {
		s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	}

	s.grpcServer.Stop()
	s.state.Store(int32(StateStopped))

	s.logger.Info("gRPC server stopped",
		observability.String("address", s.address),
	)

	return nil
}

// GracefulStop stops the gRPC server gracefully.
func (s *Server) GracefulStop(ctx context.Context) error {
	if !s.state.CompareAndSwap(int32(StateRunning), int32(StateStopping)) {
		return nil
	}

	s.logger.Info("gracefully stopping gRPC server",
		observability.String("address", s.address),
	)

	// Set health status to not serving
	if s.healthServer != nil {
		s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	}

	// Create timeout context if not already set
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.gracefulStopTimeout)
		defer cancel()
	}

	// Graceful stop with timeout
	done := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("gRPC server stopped gracefully",
			observability.String("address", s.address),
		)
	case <-ctx.Done():
		s.logger.Warn("graceful stop timeout, forcing stop",
			observability.String("address", s.address),
		)
		s.grpcServer.Stop()
	}

	s.state.Store(int32(StateStopped))
	return nil
}

// RegisterService registers a gRPC service with the server.
// This must be called before Start.
func (s *Server) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	if s.grpcServer != nil {
		s.grpcServer.RegisterService(desc, impl)
	}
}

// GetServiceInfo returns information about registered services.
func (s *Server) GetServiceInfo() map[string]grpc.ServiceInfo {
	if s.grpcServer != nil {
		return s.grpcServer.GetServiceInfo()
	}
	return nil
}

// State returns the current server state.
func (s *Server) State() State {
	return State(s.state.Load())
}

// IsRunning returns true if the server is running.
func (s *Server) IsRunning() bool {
	return s.State() == StateRunning
}

// Uptime returns the server uptime.
func (s *Server) Uptime() time.Duration {
	if s.startTime.IsZero() {
		return 0
	}
	return time.Since(s.startTime)
}

// Address returns the server address.
func (s *Server) Address() string {
	return s.address
}

// GRPCServer returns the underlying gRPC server.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpcServer
}

// HealthServer returns the health server.
func (s *Server) HealthServer() *health.Server {
	return s.healthServer
}

// SetServingStatus sets the serving status for a service.
func (s *Server) SetServingStatus(service string, status healthpb.HealthCheckResponse_ServingStatus) {
	if s.healthServer != nil {
		s.healthServer.SetServingStatus(service, status)
	}
}

// buildServerOptions builds gRPC server options.
func (s *Server) buildServerOptions() ([]grpc.ServerOption, error) {
	opts := make([]grpc.ServerOption, 0, 10)

	// Core server options: max streams, message sizes, connection timeout
	opts = append(opts,
		grpc.MaxConcurrentStreams(s.maxConcurrentStreams),
		grpc.MaxRecvMsgSize(s.maxRecvMsgSize),
		grpc.MaxSendMsgSize(s.maxSendMsgSize),
		grpc.ConnectionTimeout(s.connectionTimeout),
	)

	// Keepalive
	if s.keepaliveParams != nil {
		opts = append(opts, grpc.KeepaliveParams(*s.keepaliveParams))
	}
	if s.keepaliveEnforcement != nil {
		opts = append(opts, grpc.KeepaliveEnforcementPolicy(*s.keepaliveEnforcement))
	}

	// TLS
	if s.tlsCertFile != "" && s.tlsKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Interceptors
	if len(s.unaryInterceptors) > 0 {
		opts = append(opts, grpc.ChainUnaryInterceptor(s.unaryInterceptors...))
	}
	if len(s.streamInterceptors) > 0 {
		opts = append(opts, grpc.ChainStreamInterceptor(s.streamInterceptors...))
	}

	// Unknown service handler for proxying
	if s.unknownServiceHandler != nil {
		opts = append(opts, grpc.UnknownServiceHandler(s.unknownServiceHandler))
	}

	return opts, nil
}
