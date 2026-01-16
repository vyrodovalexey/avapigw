// Package tls provides the TLS server implementation for the API Gateway.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
	"github.com/vyrodovalexey/avapigw/internal/gateway/server/tcp"
)

// TLSMode defines the TLS handling mode.
type TLSMode string

const (
	// TLSModeTerminate terminates TLS at the gateway.
	TLSModeTerminate TLSMode = "Terminate"
	// TLSModePassthrough passes TLS connections through to backends.
	TLSModePassthrough TLSMode = "Passthrough"
)

// Default configuration values for context cancellation handling.
const (
	// DefaultTLSAcceptDeadline is the default deadline for accept operations
	// to allow periodic context checks.
	DefaultTLSAcceptDeadline = 500 * time.Millisecond

	// DefaultTLSShutdownTimeout is the default timeout for graceful shutdown.
	DefaultTLSShutdownTimeout = 30 * time.Second
)

// Server represents the TLS server for the API Gateway.
type Server struct {
	listener    net.Listener
	router      *Router
	proxy       *PassthroughProxy
	certManager *CertificateManager
	logger      *zap.Logger
	config      *ServerConfig
	connections *tcp.ConnectionTracker
	wg          sync.WaitGroup
	mu          sync.RWMutex
	running     bool
	stopCh      chan struct{}
	cancelFunc  context.CancelFunc // Cancel function for server context
}

// ServerConfig holds configuration for the TLS server.
type ServerConfig struct {
	// Port is the port to listen on.
	Port int

	// Address is the address to bind to.
	Address string

	// Mode is the TLS handling mode (Terminate or Passthrough).
	Mode TLSMode

	// DefaultCert is the default certificate to use.
	DefaultCert *tls.Certificate

	// MinVersion is the minimum TLS version.
	MinVersion uint16

	// MaxVersion is the maximum TLS version.
	MaxVersion uint16

	// CipherSuites is the list of allowed cipher suites.
	CipherSuites []uint16

	// ClientAuth is the client authentication type.
	ClientAuth tls.ClientAuthType

	// ReadTimeout is the maximum duration for reading from a connection.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration for writing to a connection.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum duration a connection may be idle.
	IdleTimeout time.Duration

	// MaxConnections is the maximum number of concurrent connections.
	MaxConnections int

	// ConnectTimeout is the timeout for connecting to backends.
	ConnectTimeout time.Duration

	// ShutdownTimeout is the timeout for graceful shutdown.
	// If not set, DefaultTLSShutdownTimeout is used.
	ShutdownTimeout time.Duration

	// AcceptDeadline is the deadline for accept operations to allow
	// periodic context checks. If not set, DefaultTLSAcceptDeadline is used.
	AcceptDeadline time.Duration
}

// DefaultServerConfig returns a ServerConfig with default values.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:       8443,
		Address:    "",
		Mode:       TLSModePassthrough,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		ClientAuth:      tls.NoClientCert,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     5 * time.Minute,
		MaxConnections:  10000,
		ConnectTimeout:  30 * time.Second,
		ShutdownTimeout: DefaultTLSShutdownTimeout,
		AcceptDeadline:  DefaultTLSAcceptDeadline,
	}
}

// NewServer creates a new TLS server.
func NewServer(config *ServerConfig, logger *zap.Logger) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}

	return &Server{
		router:      NewRouter(logger),
		certManager: NewCertificateManager(logger),
		logger:      logger,
		config:      config,
		connections: tcp.NewConnectionTracker(config.MaxConnections, logger),
		stopCh:      make(chan struct{}),
	}
}

// NewServerWithBackend creates a new TLS server with a backend manager.
func NewServerWithBackend(config *ServerConfig, backendManager *backend.Manager, logger *zap.Logger) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}

	return &Server{
		router:      NewRouter(logger),
		proxy:       NewPassthroughProxy(backendManager, logger),
		certManager: NewCertificateManager(logger),
		logger:      logger,
		config:      config,
		connections: tcp.NewConnectionTracker(config.MaxConnections, logger),
		stopCh:      make(chan struct{}),
	}
}

// SetProxy sets the passthrough proxy.
func (s *Server) SetProxy(proxy *PassthroughProxy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proxy = proxy
}

// GetRouter returns the router.
func (s *Server) GetRouter() *Router {
	return s.router
}

// GetProxy returns the passthrough proxy.
func (s *Server) GetProxy() *PassthroughProxy {
	return s.proxy
}

// GetCertificateManager returns the certificate manager.
func (s *Server) GetCertificateManager() *CertificateManager {
	return s.certManager
}

// GetConnectionTracker returns the connection tracker.
func (s *Server) GetConnectionTracker() *tcp.ConnectionTracker {
	return s.connections
}

// createListener creates the appropriate listener based on the TLS mode.
func (s *Server) createListener(addr string) (net.Listener, error) {
	if s.config.Mode == TLSModeTerminate {
		tlsConfig := s.buildTLSConfig()
		return tls.Listen("tcp", addr, tlsConfig)
	}
	lc := &net.ListenConfig{}
	return lc.Listen(context.Background(), "tcp", addr)
}

// initializeServerState initializes the server state for starting.
func (s *Server) initializeServerState(ctx context.Context, listener net.Listener) context.Context {
	serverCtx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel
	s.listener = listener
	s.running = true
	s.stopCh = make(chan struct{})
	return serverCtx
}

// logServerStart logs the server start information.
func (s *Server) logServerStart(addr string, acceptDeadline time.Duration) {
	s.logger.Info("starting TLS server",
		zap.String("address", addr),
		zap.String("mode", string(s.config.Mode)),
		zap.Duration("readTimeout", s.config.ReadTimeout),
		zap.Duration("writeTimeout", s.config.WriteTimeout),
		zap.Duration("idleTimeout", s.config.IdleTimeout),
		zap.Int("maxConnections", s.config.MaxConnections),
		zap.Duration("acceptDeadline", acceptDeadline),
		zap.Duration("shutdownTimeout", s.config.ShutdownTimeout),
	)
}

// acceptLoop runs the main accept loop for incoming connections.
func (s *Server) acceptLoop(serverCtx context.Context, acceptDeadline time.Duration) error {
	for {
		select {
		case <-serverCtx.Done():
			s.logger.Debug("server context cancelled, stopping accept loop")
			return serverCtx.Err()
		case <-s.stopCh:
			s.logger.Debug("stop signal received, stopping accept loop")
			return nil
		default:
		}

		if err := s.setAcceptDeadline(acceptDeadline); err != nil {
			s.logger.Warn("failed to set accept deadline", zap.Error(err))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if s.handleAcceptError(err, serverCtx) {
				continue
			}
			return nil
		}

		s.spawnConnectionHandler(serverCtx, conn)
	}
}

// handleAcceptError handles errors from Accept(). Returns true if the loop should continue.
func (s *Server) handleAcceptError(err error, serverCtx context.Context) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	select {
	case <-serverCtx.Done():
		return false
	case <-s.stopCh:
		return false
	default:
		s.logger.Error("accept error", zap.Error(err))
		return true
	}
}

// spawnConnectionHandler spawns a goroutine to handle a connection.
func (s *Server) spawnConnectionHandler(serverCtx context.Context, conn net.Conn) {
	connCtx, connCancel := context.WithCancel(serverCtx)
	s.wg.Add(1)
	go func(ctx context.Context, cancel context.CancelFunc, c net.Conn) {
		defer s.wg.Done()
		defer cancel()
		s.handleConnection(ctx, c)
	}(connCtx, connCancel, conn)
}

// Start starts the TLS server.
// The server will gracefully shut down when the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	listener, err := s.createListener(addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	serverCtx := s.initializeServerState(ctx, listener)
	s.mu.Unlock()

	acceptDeadline := s.config.AcceptDeadline
	if acceptDeadline <= 0 {
		acceptDeadline = DefaultTLSAcceptDeadline
	}

	s.logServerStart(addr, acceptDeadline)
	return s.acceptLoop(serverCtx, acceptDeadline)
}

// setAcceptDeadline sets the accept deadline on the listener.
// Returns nil if the listener doesn't support deadlines.
func (s *Server) setAcceptDeadline(deadline time.Duration) error {
	switch l := s.listener.(type) {
	case *net.TCPListener:
		return l.SetDeadline(time.Now().Add(deadline))
	case interface{ SetDeadline(time.Time) error }:
		return l.SetDeadline(time.Now().Add(deadline))
	default:
		// Listener doesn't support deadlines, which is fine
		return nil
	}
}

// getShutdownTimeout returns the shutdown timeout from config or default.
func (s *Server) getShutdownTimeout() time.Duration {
	shutdownTimeout := s.config.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = DefaultTLSShutdownTimeout
	}
	return shutdownTimeout
}

// signalShutdown cancels the server context and closes the stop channel.
func (s *Server) signalShutdown() {
	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	s.mu.Lock()
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	s.mu.Unlock()

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.logger.Debug("error closing listener", zap.Error(err))
		}
	}
}

// waitForConnectionsWithTimeout waits for connections to close with a timeout.
func (s *Server) waitForConnectionsWithTimeout(shutdownCtx context.Context) {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("all connections closed gracefully",
			zap.Int("remainingConnections", s.connections.Count()),
		)
	case <-shutdownCtx.Done():
		s.handleShutdownTimeout()
	}
}

// handleShutdownTimeout handles the case when graceful shutdown times out.
func (s *Server) handleShutdownTimeout() {
	remainingConns := s.connections.Count()
	s.logger.Warn("graceful shutdown timed out, force closing remaining connections",
		zap.Int("remainingConnections", remainingConns),
	)
	s.connections.CloseAll()

	forceCloseWait := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(forceCloseWait)
	}()

	select {
	case <-forceCloseWait:
		s.logger.Debug("all connection handlers exited after force close")
	case <-time.After(1 * time.Second):
		s.logger.Warn("some connection handlers may still be running")
	}
}

// cleanupServerState cleans up the server state after shutdown.
func (s *Server) cleanupServerState() {
	if s.certManager != nil {
		_ = s.certManager.Close()
	}

	s.mu.Lock()
	s.running = false
	s.cancelFunc = nil
	s.mu.Unlock()

	s.logger.Info("TLS server stopped")
}

// Stop stops the TLS server gracefully.
// It will wait for active connections to complete up to the shutdown timeout.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	shutdownTimeout := s.getShutdownTimeout()
	s.mu.Unlock()

	s.logger.Info("stopping TLS server",
		zap.Duration("shutdownTimeout", shutdownTimeout),
		zap.Int("activeConnections", s.connections.Count()),
	)

	s.signalShutdown()

	var shutdownCtx context.Context
	var cancel context.CancelFunc
	if ctx == nil {
		shutdownCtx, cancel = context.WithTimeout(context.Background(), shutdownTimeout)
	} else {
		shutdownCtx, cancel = context.WithTimeout(ctx, shutdownTimeout)
	}
	defer cancel()

	s.waitForConnectionsWithTimeout(shutdownCtx)
	s.cleanupServerState()
	return nil
}

// IsRunning returns whether the server is running.
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// handleConnection handles a single connection.
// The connection will be closed when the context is cancelled.
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	// Check context before doing any work
	select {
	case <-ctx.Done():
		s.logger.Debug("context cancelled before handling connection",
			zap.String("remoteAddr", conn.RemoteAddr().String()),
		)
		_ = conn.Close() // Ignore error on cleanup
		return
	default:
	}

	// Track the connection
	tracked, err := s.connections.Add(conn)
	if err != nil {
		s.logger.Warn("connection rejected",
			zap.String("remoteAddr", conn.RemoteAddr().String()),
			zap.Error(err),
		)
		_ = conn.Close() // Ignore error on cleanup
		return
	}
	defer s.connections.Remove(tracked.ID)
	defer func() { _ = conn.Close() }() // Ignore error on cleanup

	// Set up a goroutine to close the connection when context is cancelled
	// This ensures the connection is closed promptly on shutdown
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			s.logger.Debug("context cancelled, closing connection",
				zap.String("id", tracked.ID),
			)
			_ = conn.Close() // Ignore error on cleanup
		case <-done:
			// Handler completed normally
		}
	}()

	if s.config.Mode == TLSModePassthrough {
		s.handlePassthroughConnection(ctx, conn, tracked)
	} else {
		s.handleTerminateConnection(ctx, conn, tracked)
	}
}

// extractSNIAndValidate extracts SNI from the connection and validates context.
// Returns the SNI, clientHello bytes, and whether to continue processing.
func (s *Server) extractSNIAndValidate(
	ctx context.Context,
	conn net.Conn,
	tracked *tcp.TrackedConnection,
) (sni string, clientHello []byte, ok bool) {
	sni, clientHello, err := ExtractSNI(conn)
	if err != nil {
		s.logger.Debug("failed to extract SNI",
			zap.String("id", tracked.ID),
			zap.Error(err),
		)
		return "", nil, false
	}

	s.logger.Debug("SNI extracted",
		zap.String("id", tracked.ID),
		zap.String("sni", sni),
	)

	select {
	case <-ctx.Done():
		s.logger.Debug("context cancelled after SNI extraction",
			zap.String("id", tracked.ID),
		)
		return "", nil, false
	default:
		return sni, clientHello, true
	}
}

// resolveBackendForRoute resolves the backend service for a route.
func (s *Server) resolveBackendForRoute(route *TLSRoute, tracked *tcp.TrackedConnection) *backend.Backend {
	if s.proxy == nil {
		s.logger.Error("proxy not configured",
			zap.String("id", tracked.ID),
			zap.String("route", route.Name),
		)
		return nil
	}

	if len(route.BackendRefs) == 0 {
		s.logger.Error("no backends configured for route",
			zap.String("id", tracked.ID),
			zap.String("route", route.Name),
		)
		return nil
	}

	backendRef := route.BackendRefs[0]
	backendKey := backendRef.Name
	if backendRef.Namespace != "" {
		backendKey = fmt.Sprintf("%s/%s", backendRef.Namespace, backendRef.Name)
	}

	backendSvc := s.proxy.backendManager.GetBackend(backendKey)
	if backendSvc == nil {
		s.logger.Error("backend not found",
			zap.String("id", tracked.ID),
			zap.String("backend", backendKey),
		)
	}
	return backendSvc
}

// proxyPassthroughConnection proxies the connection to the backend.
func (s *Server) proxyPassthroughConnection(
	ctx context.Context,
	conn net.Conn,
	clientHello []byte,
	backendSvc *backend.Backend,
	route *TLSRoute,
	sni string,
	tracked *tcp.TrackedConnection,
) {
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	err := s.proxy.ProxyWithIdleTimeout(
		proxyCtx, conn, clientHello, backendSvc, s.config.ConnectTimeout, s.config.IdleTimeout,
	)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Debug("proxy error",
				zap.String("id", tracked.ID),
				zap.String("route", route.Name),
				zap.String("sni", sni),
				zap.Error(err),
			)
		}
	}

	bytesIn, bytesOut, duration := tracked.GetStats()
	s.logger.Debug("TLS passthrough connection closed",
		zap.String("id", tracked.ID),
		zap.String("route", route.Name),
		zap.String("sni", sni),
		zap.Int64("bytesIn", bytesIn),
		zap.Int64("bytesOut", bytesOut),
		zap.Duration("duration", duration),
	)
}

// handlePassthroughConnection handles a TLS passthrough connection.
func (s *Server) handlePassthroughConnection(ctx context.Context, conn net.Conn, tracked *tcp.TrackedConnection) {
	select {
	case <-ctx.Done():
		s.logger.Debug("context cancelled before handling passthrough connection",
			zap.String("id", tracked.ID),
		)
		return
	default:
	}

	s.logger.Debug("handling TLS passthrough connection",
		zap.String("id", tracked.ID),
		zap.String("remoteAddr", tracked.RemoteAddr),
	)

	sni, clientHello, ok := s.extractSNIAndValidate(ctx, conn, tracked)
	if !ok {
		return
	}

	route, err := s.router.Match(sni)
	if err != nil {
		s.logger.Debug("no matching route for SNI",
			zap.String("id", tracked.ID),
			zap.String("sni", sni),
			zap.Error(err),
		)
		return
	}

	backendSvc := s.resolveBackendForRoute(route, tracked)
	if backendSvc == nil {
		return
	}

	s.proxyPassthroughConnection(ctx, conn, clientHello, backendSvc, route, sni, tracked)
}

// performTLSHandshake performs the TLS handshake and returns the connection state.
// Returns nil if the handshake failed or context was cancelled.
func (s *Server) performTLSHandshake(
	ctx context.Context,
	tlsConn *tls.Conn,
	tracked *tcp.TrackedConnection,
) *tls.ConnectionState {
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			s.logger.Debug("context cancelled during TLS handshake",
				zap.String("id", tracked.ID),
			)
		} else {
			s.logger.Debug("TLS handshake failed",
				zap.String("id", tracked.ID),
				zap.Error(err),
			)
		}
		return nil
	}

	state := tlsConn.ConnectionState()
	s.logger.Debug("TLS handshake completed",
		zap.String("id", tracked.ID),
		zap.String("sni", state.ServerName),
		zap.String("protocol", state.NegotiatedProtocol),
		zap.Uint16("version", state.Version),
	)
	return &state
}

// handleTerminateConnection handles a TLS termination connection.
func (s *Server) handleTerminateConnection(ctx context.Context, conn net.Conn, tracked *tcp.TrackedConnection) {
	select {
	case <-ctx.Done():
		s.logger.Debug("context cancelled before handling terminate connection",
			zap.String("id", tracked.ID),
		)
		return
	default:
	}

	s.logger.Debug("handling TLS termination connection",
		zap.String("id", tracked.ID),
		zap.String("remoteAddr", tracked.RemoteAddr),
	)

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		s.logger.Error("expected TLS connection for termination mode",
			zap.String("id", tracked.ID),
		)
		return
	}

	state := s.performTLSHandshake(ctx, tlsConn, tracked)
	if state == nil {
		return
	}

	select {
	case <-ctx.Done():
		s.logger.Debug("context cancelled after TLS handshake",
			zap.String("id", tracked.ID),
		)
		return
	default:
	}

	route, err := s.router.Match(state.ServerName)
	if err != nil {
		s.logger.Debug("no matching route for SNI",
			zap.String("id", tracked.ID),
			zap.String("sni", state.ServerName),
			zap.Error(err),
		)
		return
	}

	s.logger.Debug("route matched for TLS termination",
		zap.String("id", tracked.ID),
		zap.String("route", route.Name),
		zap.String("sni", state.ServerName),
	)

	// TODO: Hand off to HTTP/gRPC handler based on ALPN
}

// buildTLSConfig builds the TLS configuration for termination mode.
func (s *Server) buildTLSConfig() *tls.Config {
	// G402: MinVersion is configurable by the user for flexibility
	config := &tls.Config{ //nolint:gosec // MinVersion is user-configurable
		GetCertificate: s.certManager.GetCertificate,
		MinVersion:     s.config.MinVersion,
		MaxVersion:     s.config.MaxVersion,
		ClientAuth:     s.config.ClientAuth,
	}

	if len(s.config.CipherSuites) > 0 {
		config.CipherSuites = s.config.CipherSuites
	}

	// Set default certificate if available
	if s.config.DefaultCert != nil {
		config.Certificates = []tls.Certificate{*s.config.DefaultCert}
	}

	return config
}

// UpdateRoutes updates the routes in the router.
func (s *Server) UpdateRoutes(routes []TLSRouteConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, routeConfig := range routes {
		route := &TLSRoute{
			Name:        routeConfig.Name,
			Hostnames:   routeConfig.Hostnames,
			BackendRefs: routeConfig.BackendRefs,
			Priority:    routeConfig.Priority,
		}

		if err := s.router.AddRoute(route); err != nil {
			// Try to update if it already exists
			if err := s.router.UpdateRoute(route); err != nil {
				return fmt.Errorf("failed to add/update route %s: %w", routeConfig.Name, err)
			}
		}
	}

	return nil
}

// RemoveRoute removes a route by name.
func (s *Server) RemoveRoute(name string) error {
	return s.router.RemoveRoute(name)
}

// TLSRouteConfig is a simplified route configuration for external use.
type TLSRouteConfig struct {
	Name        string
	Hostnames   []string
	BackendRefs []TLSBackendRef
	Priority    int
}

// GetActiveConnections returns the number of active connections.
func (s *Server) GetActiveConnections() int {
	return s.connections.Count()
}

// ListActiveConnections returns all active connections.
func (s *Server) ListActiveConnections() []*tcp.TrackedConnection {
	return s.connections.List()
}

// LoadCertificate loads a certificate for a hostname.
func (s *Server) LoadCertificate(hostname, certFile, keyFile string) error {
	return s.certManager.LoadCertificate(hostname, certFile, keyFile)
}

// LoadCertificateFromSecret loads a certificate from secret data.
func (s *Server) LoadCertificateFromSecret(hostname string, certData, keyData []byte) error {
	return s.certManager.LoadCertificateFromSecret(hostname, certData, keyData)
}

// SetDefaultCertificate sets the default certificate.
func (s *Server) SetDefaultCertificate(certFile, keyFile string) error {
	return s.certManager.SetDefaultCertificateFromFiles(certFile, keyFile)
}
