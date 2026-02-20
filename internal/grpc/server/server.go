package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
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

// Default server configuration constants.
const (
	// DefaultMaxConcurrentStreams is the default maximum number of concurrent streams per connection.
	DefaultMaxConcurrentStreams = 100

	// DefaultMaxMsgSize is the default maximum message size in bytes (4MB).
	DefaultMaxMsgSize = 4 * 1024 * 1024

	// DefaultConnectionTimeout is the default connection timeout.
	DefaultConnectionTimeout = 120 * time.Second

	// DefaultGracefulStopTimeout is the default timeout for graceful server shutdown.
	DefaultGracefulStopTimeout = 30 * time.Second
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

	// TLS - legacy file-based
	tlsCertFile string
	tlsKeyFile  string

	// TLS - enhanced support
	tlsManager                *tlspkg.Manager
	tlsMetrics                tlspkg.MetricsRecorder
	tlsConfig                 *tls.Config
	insecure                  bool
	requireALPN               bool
	extractClientCertMetadata bool

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
		maxConcurrentStreams: DefaultMaxConcurrentStreams,
		maxRecvMsgSize:       DefaultMaxMsgSize,
		maxSendMsgSize:       DefaultMaxMsgSize,
		connectionTimeout:    DefaultConnectionTimeout,
		gracefulStopTimeout:  DefaultGracefulStopTimeout,
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

	// TLS configuration
	tlsOpts, err := s.buildTLSOptions()
	if err != nil {
		return nil, err
	}
	opts = append(opts, tlsOpts...)

	// Add client cert metadata interceptor if enabled
	if s.extractClientCertMetadata && !s.insecure {
		unaryInterceptor := s.clientCertMetadataUnaryInterceptor()
		s.unaryInterceptors = append([]grpc.UnaryServerInterceptor{unaryInterceptor}, s.unaryInterceptors...)

		streamInterceptor := s.clientCertMetadataStreamInterceptor()
		s.streamInterceptors = append([]grpc.StreamServerInterceptor{streamInterceptor}, s.streamInterceptors...)
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

// buildTLSOptions builds TLS-related server options.
func (s *Server) buildTLSOptions() ([]grpc.ServerOption, error) {
	// Check if insecure mode is enabled
	if s.insecure {
		s.logger.Warn("gRPC server running in INSECURE mode (no TLS) - this should only be used in development",
			observability.String("address", s.address),
		)
		return nil, nil
	}

	// Priority 1: Use TLS manager if available
	if s.tlsManager != nil {
		return s.buildTLSOptionsFromManager()
	}

	// Priority 2: Use direct TLS config if provided
	if s.tlsConfig != nil {
		return s.buildTLSOptionsFromConfig()
	}

	// Priority 3: Use legacy file-based TLS
	if s.tlsCertFile != "" && s.tlsKeyFile != "" {
		return s.buildTLSOptionsFromFiles()
	}

	// No TLS configured
	s.logger.Info("no TLS configured for gRPC server, running in plaintext",
		observability.String("address", s.address))
	return nil, nil
}

// buildTLSOptionsFromManager builds TLS options using the TLS manager.
func (s *Server) buildTLSOptionsFromManager() ([]grpc.ServerOption, error) {
	tlsConfig := s.tlsManager.GetTLSConfig()
	if tlsConfig == nil {
		// Manager is in insecure or passthrough mode
		s.logger.Warn("TLS manager returned nil config - running without TLS",
			observability.String("address", s.address),
		)
		return nil, nil
	}

	// Clone the config to avoid modifying the manager's config
	tlsConfig = tlsConfig.Clone()

	// Ensure gRPC-specific settings
	s.configureGRPCTLS(tlsConfig)

	s.logger.Info("gRPC server TLS configured via TLS manager",
		observability.String("address", s.address),
		observability.String("mode", string(s.tlsManager.GetMode())),
		observability.Bool("mtls", s.tlsManager.IsMTLSEnabled()),
	)

	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
}

// buildTLSOptionsFromConfig builds TLS options from a direct tls.Config.
func (s *Server) buildTLSOptionsFromConfig() ([]grpc.ServerOption, error) {
	// Clone the config to avoid modifying the original
	tlsConfig := s.tlsConfig.Clone()

	// Ensure gRPC-specific settings
	s.configureGRPCTLS(tlsConfig)

	s.logger.Info("gRPC server TLS configured via direct config",
		observability.String("address", s.address),
	)

	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
}

// buildTLSOptionsFromFiles builds TLS options from certificate files (legacy).
func (s *Server) buildTLSOptionsFromFiles() ([]grpc.ServerOption, error) {
	cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
	}

	// #nosec G402 -- MinVersion is set below via configureGRPCTLS or applyTLSConfigFromGRPCConfig
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Set secure default immediately
	}

	// Apply config from GRPCListenerConfig if available
	if s.config != nil && s.config.TLS != nil {
		s.applyTLSConfigFromGRPCConfig(tlsConfig, s.config.TLS)
	} else {
		// Apply defaults
		s.configureGRPCTLS(tlsConfig)
	}

	s.logger.Info("gRPC server TLS configured via certificate files",
		observability.String("address", s.address),
		observability.String("certFile", s.tlsCertFile),
	)

	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}, nil
}

// configureGRPCTLS applies gRPC-specific TLS settings.
func (s *Server) configureGRPCTLS(tlsConfig *tls.Config) {
	// Ensure minimum TLS 1.2 for gRPC
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}

	// Set ALPN for HTTP/2 if not already set
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{"h2"}
	}

	// Add ALPN verification callback if required
	if s.requireALPN {
		s.configureALPNVerification(tlsConfig)
	}
}

// configureALPNVerification adds ALPN protocol verification to TLS config.
func (s *Server) configureALPNVerification(tlsConfig *tls.Config) {
	originalVerify := tlsConfig.VerifyConnection
	allowedProtos := tlsConfig.NextProtos

	tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := s.verifyALPNProtocol(cs, allowedProtos); err != nil {
			return err
		}

		// Call original verify if set
		if originalVerify != nil {
			return originalVerify(cs)
		}
		return nil
	}
}

// verifyALPNProtocol verifies that the negotiated ALPN protocol is acceptable.
func (s *Server) verifyALPNProtocol(cs tls.ConnectionState, allowedProtos []string) error {
	// Check ALPN negotiation
	if cs.NegotiatedProtocol == "" {
		s.logger.Warn("connection rejected: no ALPN protocol negotiated",
			observability.String("serverName", cs.ServerName),
		)
		if s.tlsMetrics != nil {
			s.tlsMetrics.RecordHandshakeError("no_alpn")
		}
		return fmt.Errorf("ALPN protocol negotiation required")
	}

	// Check if negotiated protocol is acceptable
	for _, proto := range allowedProtos {
		if cs.NegotiatedProtocol == proto {
			return nil
		}
	}

	s.logger.Warn("connection rejected: invalid ALPN protocol",
		observability.String("negotiated", cs.NegotiatedProtocol),
	)
	if s.tlsMetrics != nil {
		s.tlsMetrics.RecordHandshakeError("invalid_alpn")
	}
	return fmt.Errorf("invalid ALPN protocol: %s", cs.NegotiatedProtocol)
}

// applyTLSConfigFromGRPCConfig applies TLS settings from GRPCListenerConfig.
func (s *Server) applyTLSConfigFromGRPCConfig(tlsConfig *tls.Config, cfg *config.TLSConfig) {
	// Set minimum version
	minVersion := cfg.GetEffectiveMinVersion()
	tlsConfig.MinVersion = parseTLSVersion(minVersion)

	// Set maximum version if specified
	if cfg.MaxVersion != "" {
		tlsConfig.MaxVersion = parseTLSVersion(cfg.MaxVersion)
	}

	// Set ALPN protocols
	tlsConfig.NextProtos = cfg.GetEffectiveALPN()

	// Set cipher suites if specified
	if len(cfg.CipherSuites) > 0 {
		cipherSuites, err := tlspkg.ParseCipherSuites(cfg.CipherSuites)
		if err != nil {
			s.logger.Warn("failed to parse cipher suites, using defaults",
				observability.Error(err),
			)
		} else {
			tlsConfig.CipherSuites = cipherSuites
		}
	}

	// Configure client authentication based on mode
	switch cfg.GetEffectiveMode() {
	case config.TLSModeMutual:
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		if cfg.CAFile != "" {
			if err := s.loadClientCA(tlsConfig, cfg.CAFile); err != nil {
				s.logger.Error("failed to load client CA",
					observability.String("caFile", cfg.CAFile),
					observability.Error(err),
				)
			}
		}
	case config.TLSModeOptionalMutual:
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		if cfg.CAFile != "" {
			if err := s.loadClientCA(tlsConfig, cfg.CAFile); err != nil {
				s.logger.Error("failed to load client CA",
					observability.String("caFile", cfg.CAFile),
					observability.Error(err),
				)
			}
		}
	default:
		tlsConfig.ClientAuth = tls.NoClientCert
	}

	// Set InsecureSkipVerify (for development only)
	if cfg.InsecureSkipVerify {
		s.logger.Warn("InsecureSkipVerify is enabled - certificate verification is disabled")
		tlsConfig.InsecureSkipVerify = true
	}

	// Add client certificate validation if AllowedCNs or AllowedSANs are specified
	if len(cfg.AllowedCNs) > 0 || len(cfg.AllowedSANs) > 0 {
		tlsConfig.VerifyPeerCertificate = s.createClientCertValidator(cfg)
	}
}

// loadClientCA loads the client CA certificate pool.
func (s *Server) loadClientCA(tlsConfig *tls.Config, caFile string) error {
	caCert, err := readFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig.ClientCAs = pool
	return nil
}

// createClientCertValidator creates a VerifyPeerCertificate callback for client cert validation.
func (s *Server) createClientCertValidator(cfg *config.TLSConfig) func([][]byte, [][]*x509.Certificate) error {
	validator := tlspkg.NewValidator(&tlspkg.ClientValidationConfig{
		Enabled:     true,
		AllowedCNs:  cfg.AllowedCNs,
		AllowedSANs: cfg.AllowedSANs,
	})
	requireCert := cfg.IsMutual()

	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return s.validateClientCert(rawCerts, validator, requireCert)
	}
}

// validateClientCert validates a client certificate.
func (s *Server) validateClientCert(
	rawCerts [][]byte,
	validator *tlspkg.Validator,
	requireCert bool,
) error {
	if len(rawCerts) == 0 {
		if requireCert {
			s.recordClientCertMetric(false, "no_certificate")
			return fmt.Errorf("client certificate required")
		}
		return nil
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		s.recordClientCertMetric(false, "parse_error")
		return fmt.Errorf("failed to parse client certificate: %w", err)
	}

	if err := validator.ValidateClientCertificate(cert); err != nil {
		s.recordClientCertMetric(false, "validation_failed")
		s.logger.Warn("client certificate validation failed",
			observability.String("subject", cert.Subject.CommonName),
			observability.Error(err),
		)
		return err
	}

	s.recordClientCertMetric(true, "")
	s.logger.Debug("client certificate validated",
		observability.String("subject", cert.Subject.CommonName),
		observability.String("issuer", cert.Issuer.CommonName),
	)

	return nil
}

// recordClientCertMetric records a client certificate validation metric.
func (s *Server) recordClientCertMetric(success bool, reason string) {
	if s.tlsMetrics != nil {
		s.tlsMetrics.RecordClientCertValidation(success, reason)
	}
}

// clientCertMetadataUnaryInterceptor extracts client certificate identity to metadata.
func (s *Server) clientCertMetadataUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		ctx = s.extractClientCertToContext(ctx)
		return handler(ctx, req)
	}
}

// clientCertMetadataStreamInterceptor extracts client certificate identity to metadata.
func (s *Server) clientCertMetadataStreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		_ *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := s.extractClientCertToContext(ss.Context())
		wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

// extractClientCertToContext extracts client certificate identity and adds it to context.
func (s *Server) extractClientCertToContext(ctx context.Context) context.Context {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ctx
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ctx
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return ctx
	}

	cert := tlsInfo.State.PeerCertificates[0]
	identity := tlspkg.ExtractClientIdentity(cert)
	if identity == nil {
		return ctx
	}

	// Add identity to metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}

	// Create a copy of metadata to avoid modifying the original
	md = md.Copy()

	// Add client certificate identity fields
	if identity.CommonName != "" {
		md.Set("x-client-cert-cn", identity.CommonName)
	}
	if identity.SerialNumber != "" {
		md.Set("x-client-cert-serial", identity.SerialNumber)
	}
	if len(identity.Organization) > 0 {
		md.Set("x-client-cert-org", identity.Organization...)
	}
	if len(identity.DNSNames) > 0 {
		md.Set("x-client-cert-dns", identity.DNSNames...)
	}
	if identity.Issuer != "" {
		md.Set("x-client-cert-issuer", identity.Issuer)
	}

	return metadata.NewIncomingContext(ctx, md)
}

// wrappedServerStream wraps a grpc.ServerStream with a custom context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// parseTLSVersion parses a TLS version string to uint16.
func parseTLSVersion(version string) uint16 {
	switch version {
	case "TLS10":
		return tls.VersionTLS10
	case "TLS11":
		return tls.VersionTLS11
	case "TLS12":
		return tls.VersionTLS12
	case "TLS13":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12 // Safe default for gRPC
	}
}

// readFile reads a file and returns its contents.
// #nosec G304 -- File path is from configuration, validated by caller
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
