// Package tcp provides the TCP server implementation for the API Gateway.
package tcp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

// Default configuration values for context cancellation handling.
const (
	// DefaultAcceptDeadline is the default deadline for accept operations
	// to allow periodic context checks.
	DefaultAcceptDeadline = 500 * time.Millisecond

	// DefaultShutdownTimeout is the default timeout for graceful shutdown.
	DefaultShutdownTimeout = 30 * time.Second

	// DefaultContextCheckInterval is the interval for checking context cancellation.
	DefaultContextCheckInterval = 100 * time.Millisecond
)

// Server represents the TCP server for the API Gateway.
type Server struct {
	listener    net.Listener
	router      *Router
	proxy       *Proxy
	logger      *zap.Logger
	config      *ServerConfig
	connections *ConnectionTracker
	wg          sync.WaitGroup
	mu          sync.RWMutex
	running     bool
	stopCh      chan struct{}
	cancelFunc  context.CancelFunc // Cancel function for server context
}

// ServerConfig holds configuration for the TCP server.
type ServerConfig struct {
	// Port is the port to listen on.
	Port int

	// Address is the address to bind to.
	Address string

	// ReadTimeout is the maximum duration for reading from a connection.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration for writing to a connection.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum duration a connection may be idle.
	IdleTimeout time.Duration

	// MaxConnections is the maximum number of concurrent connections.
	MaxConnections int

	// TLS is the TLS configuration for the server.
	TLS *tls.Config

	// ShutdownTimeout is the timeout for graceful shutdown.
	// If not set, DefaultShutdownTimeout is used.
	ShutdownTimeout time.Duration

	// AcceptDeadline is the deadline for accept operations to allow
	// periodic context checks. If not set, DefaultAcceptDeadline is used.
	AcceptDeadline time.Duration
}

// DefaultServerConfig returns a ServerConfig with default values.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:            8443,
		Address:         "",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     5 * time.Minute,
		MaxConnections:  10000,
		ShutdownTimeout: DefaultShutdownTimeout,
		AcceptDeadline:  DefaultAcceptDeadline,
	}
}

// NewServer creates a new TCP server.
func NewServer(config *ServerConfig, logger *zap.Logger) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}

	return &Server{
		router:      NewRouter(logger),
		logger:      logger,
		config:      config,
		connections: NewConnectionTracker(config.MaxConnections, logger),
		stopCh:      make(chan struct{}),
	}
}

// NewServerWithBackend creates a new TCP server with a backend manager.
func NewServerWithBackend(config *ServerConfig, backendManager *backend.Manager, logger *zap.Logger) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}

	return &Server{
		router:      NewRouter(logger),
		proxy:       NewProxy(backendManager, logger),
		logger:      logger,
		config:      config,
		connections: NewConnectionTracker(config.MaxConnections, logger),
		stopCh:      make(chan struct{}),
	}
}

// SetProxy sets the proxy for the server.
func (s *Server) SetProxy(proxy *Proxy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proxy = proxy
}

// GetRouter returns the router.
func (s *Server) GetRouter() *Router {
	return s.router
}

// GetProxy returns the proxy.
func (s *Server) GetProxy() *Proxy {
	return s.proxy
}

// GetConnectionTracker returns the connection tracker.
func (s *Server) GetConnectionTracker() *ConnectionTracker {
	return s.connections
}

// Start starts the TCP server.
// The server will gracefully shut down when the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if err := s.initializeServer(ctx); err != nil {
		return err
	}

	serverCtx, acceptDeadline := s.getServerContext(ctx)
	s.logServerStart(acceptDeadline)

	return s.acceptLoop(serverCtx, acceptDeadline)
}

// initializeServer initializes the server listener and state.
func (s *Server) initializeServer(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	listener, err := s.createListener(ctx, addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	_, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel
	s.listener = listener
	s.running = true
	s.stopCh = make(chan struct{})

	return nil
}

// createListener creates a TCP listener with optional TLS.
func (s *Server) createListener(ctx context.Context, addr string) (net.Listener, error) {
	if s.config.TLS != nil {
		return tls.Listen("tcp", addr, s.config.TLS)
	}
	lc := &net.ListenConfig{}
	return lc.Listen(ctx, "tcp", addr)
}

// getServerContext returns the server context and accept deadline.
func (s *Server) getServerContext(ctx context.Context) (context.Context, time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	acceptDeadline := s.config.AcceptDeadline
	if acceptDeadline <= 0 {
		acceptDeadline = DefaultAcceptDeadline
	}
	return ctx, acceptDeadline
}

// logServerStart logs the server startup information.
func (s *Server) logServerStart(acceptDeadline time.Duration) {
	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)
	s.logger.Info("starting TCP server",
		zap.String("address", addr),
		zap.Duration("readTimeout", s.config.ReadTimeout),
		zap.Duration("writeTimeout", s.config.WriteTimeout),
		zap.Duration("idleTimeout", s.config.IdleTimeout),
		zap.Int("maxConnections", s.config.MaxConnections),
		zap.Bool("tlsEnabled", s.config.TLS != nil),
		zap.Duration("acceptDeadline", acceptDeadline),
		zap.Duration("shutdownTimeout", s.config.ShutdownTimeout),
	)
}

// acceptLoop runs the main connection accept loop.
func (s *Server) acceptLoop(serverCtx context.Context, acceptDeadline time.Duration) error {
	for {
		if err := s.checkShutdown(serverCtx); err != nil {
			return err
		}

		if err := s.setAcceptDeadline(acceptDeadline); err != nil {
			s.logger.Warn("failed to set accept deadline", zap.Error(err))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if shouldContinueOnError(err, serverCtx, s.stopCh, s.logger) {
				continue
			}
			return s.handleAcceptShutdown(serverCtx)
		}

		s.spawnConnectionHandler(serverCtx, conn)
	}
}

// checkShutdown checks if the server should stop accepting connections.
func (s *Server) checkShutdown(serverCtx context.Context) error {
	select {
	case <-serverCtx.Done():
		s.logger.Debug("server context cancelled, stopping accept loop")
		return serverCtx.Err()
	case <-s.stopCh:
		s.logger.Debug("stop signal received, stopping accept loop")
		return nil
	default:
		return nil
	}
}

// shouldContinueOnError determines if the accept loop should continue after an error.
func shouldContinueOnError(err error, serverCtx context.Context, stopCh chan struct{}, logger *zap.Logger) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	select {
	case <-serverCtx.Done():
		return false
	case <-stopCh:
		return false
	default:
		logger.Error("accept error", zap.Error(err))
		return true
	}
}

// handleAcceptShutdown handles shutdown during accept.
func (s *Server) handleAcceptShutdown(serverCtx context.Context) error {
	select {
	case <-serverCtx.Done():
		return serverCtx.Err()
	case <-s.stopCh:
		return nil
	default:
		return nil
	}
}

// spawnConnectionHandler spawns a goroutine to handle a new connection.
func (s *Server) spawnConnectionHandler(serverCtx context.Context, conn net.Conn) {
	connCtx, connCancel := context.WithCancel(serverCtx)

	s.wg.Add(1)
	go func(ctx context.Context, cancel context.CancelFunc, c net.Conn) {
		defer s.wg.Done()
		defer cancel()
		s.handleConnection(ctx, c)
	}(connCtx, connCancel, conn)
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

// Stop stops the TCP server gracefully.
// It will wait for active connections to complete up to the shutdown timeout.
func (s *Server) Stop(ctx context.Context) error {
	shutdownTimeout, shouldStop := s.prepareShutdown()
	if !shouldStop {
		return nil
	}

	s.signalShutdown()
	s.closeListener()

	shutdownCtx, cancel := s.createShutdownContext(ctx, shutdownTimeout)
	defer cancel()

	s.waitForConnectionsOrTimeout(shutdownCtx)
	s.finalizeShutdown()

	s.logger.Info("TCP server stopped")
	return nil
}

// prepareShutdown prepares for server shutdown and returns the timeout and whether to proceed.
func (s *Server) prepareShutdown() (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return 0, false
	}

	shutdownTimeout := s.config.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = DefaultShutdownTimeout
	}

	s.logger.Info("stopping TCP server",
		zap.Duration("shutdownTimeout", shutdownTimeout),
		zap.Int("activeConnections", s.connections.Count()),
	)

	return shutdownTimeout, true
}

// signalShutdown signals all handlers to stop.
func (s *Server) signalShutdown() {
	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	s.mu.Lock()
	select {
	case <-s.stopCh:
		// Already closed
	default:
		close(s.stopCh)
	}
	s.mu.Unlock()
}

// closeListener closes the server listener.
func (s *Server) closeListener() {
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.logger.Debug("error closing listener", zap.Error(err))
		}
	}
}

// createShutdownContext creates a context with the shutdown timeout.
func (s *Server) createShutdownContext(
	ctx context.Context,
	shutdownTimeout time.Duration,
) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), shutdownTimeout)
	}
	return context.WithTimeout(ctx, shutdownTimeout)
}

// waitForConnectionsOrTimeout waits for connections to close or times out.
func (s *Server) waitForConnectionsOrTimeout(shutdownCtx context.Context) {
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
	s.waitForForceClose()
}

// waitForForceClose waits briefly for handlers to exit after force close.
func (s *Server) waitForForceClose() {
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

// finalizeShutdown finalizes the server shutdown state.
func (s *Server) finalizeShutdown() {
	s.mu.Lock()
	s.running = false
	s.cancelFunc = nil
	s.mu.Unlock()
}

// IsRunning returns whether the server is running.
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// handleConnection handles a single TCP connection.
// The connection will be closed when the context is cancelled.
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	if s.isContextCancelled(ctx, conn) {
		return
	}

	tracked, ok := s.trackConnection(conn)
	if !ok {
		return
	}
	defer s.connections.Remove(tracked.ID)
	defer func() { _ = conn.Close() }()

	done := s.setupContextCancellation(ctx, conn, tracked.ID)
	defer close(done)

	route := s.matchRoute(ctx, conn, tracked.ID)
	if route == nil {
		return
	}

	backendSvc := s.getBackendService(tracked.ID, route)
	if backendSvc == nil {
		return
	}

	s.proxyConnection(ctx, conn, tracked, route, backendSvc)
}

// isContextCancelled checks if context is cancelled before handling connection.
func (s *Server) isContextCancelled(ctx context.Context, conn net.Conn) bool {
	select {
	case <-ctx.Done():
		s.logger.Debug("context cancelled before handling connection",
			zap.String("remoteAddr", conn.RemoteAddr().String()),
		)
		_ = conn.Close()
		return true
	default:
		return false
	}
}

// trackConnection adds the connection to the tracker.
func (s *Server) trackConnection(conn net.Conn) (*TrackedConnection, bool) {
	tracked, err := s.connections.Add(conn)
	if err != nil {
		s.logger.Warn("connection rejected",
			zap.String("remoteAddr", conn.RemoteAddr().String()),
			zap.Error(err),
		)
		_ = conn.Close()
		return nil, false
	}

	s.logger.Debug("handling connection",
		zap.String("id", tracked.ID),
		zap.String("remoteAddr", tracked.RemoteAddr),
	)
	return tracked, true
}

// setupContextCancellation sets up a goroutine to close connection on context cancellation.
func (s *Server) setupContextCancellation(ctx context.Context, conn net.Conn, connID string) chan struct{} {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.logger.Debug("context cancelled, closing connection", zap.String("id", connID))
			_ = conn.Close()
		case <-done:
		}
	}()
	return done
}

// matchRoute finds a matching route for the connection.
func (s *Server) matchRoute(ctx context.Context, conn net.Conn, connID string) *TCPRoute {
	route, err := s.router.Match(conn)
	if err != nil {
		s.logger.Debug("no matching route", zap.String("id", connID), zap.Error(err))
		return nil
	}

	select {
	case <-ctx.Done():
		s.logger.Debug("context cancelled after route matching", zap.String("id", connID))
		return nil
	default:
		return route
	}
}

// getBackendService retrieves the backend service for the route.
func (s *Server) getBackendService(connID string, route *TCPRoute) *backend.Backend {
	if s.proxy == nil {
		s.logger.Error("proxy not configured", zap.String("id", connID), zap.String("route", route.Name))
		return nil
	}

	if len(route.BackendRefs) == 0 {
		s.logger.Error("no backends configured for route", zap.String("id", connID), zap.String("route", route.Name))
		return nil
	}

	backendRef := route.BackendRefs[0]
	backendKey := backendRef.Name
	if backendRef.Namespace != "" {
		backendKey = fmt.Sprintf("%s/%s", backendRef.Namespace, backendRef.Name)
	}

	backendSvc := s.proxy.backendManager.GetBackend(backendKey)
	if backendSvc == nil {
		s.logger.Error("backend not found", zap.String("id", connID), zap.String("backend", backendKey))
		return nil
	}
	return backendSvc
}

// proxyConnection proxies the connection to the backend and logs stats.
func (s *Server) proxyConnection(
	ctx context.Context,
	conn net.Conn,
	tracked *TrackedConnection,
	route *TCPRoute,
	backendSvc *backend.Backend,
) {
	countingConn := NewCountingConn(conn, tracked)

	err := s.proxy.ProxyWithIdleTimeout(
		ctx,
		countingConn,
		backendSvc,
		route.ConnectTimeout,
		route.IdleTimeout,
	)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Debug("proxy error",
				zap.String("id", tracked.ID),
				zap.String("route", route.Name),
				zap.Error(err),
			)
		}
	}

	bytesIn, bytesOut, duration := tracked.GetStats()
	s.logger.Debug("connection closed",
		zap.String("id", tracked.ID),
		zap.String("route", route.Name),
		zap.Int64("bytesIn", bytesIn),
		zap.Int64("bytesOut", bytesOut),
		zap.Duration("duration", duration),
	)
}

// UpdateRoutes updates the routes in the router.
func (s *Server) UpdateRoutes(routes []TCPRouteConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, routeConfig := range routes {
		route := &TCPRoute{
			Name:           routeConfig.Name,
			BackendRefs:    routeConfig.BackendRefs,
			IdleTimeout:    routeConfig.IdleTimeout,
			ConnectTimeout: routeConfig.ConnectTimeout,
			Priority:       routeConfig.Priority,
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

// TCPRouteConfig is a simplified route configuration for external use.
type TCPRouteConfig struct {
	Name           string
	BackendRefs    []BackendRef
	IdleTimeout    time.Duration
	ConnectTimeout time.Duration
	Priority       int
}

// GetActiveConnections returns the number of active connections.
func (s *Server) GetActiveConnections() int {
	return s.connections.Count()
}

// ListActiveConnections returns all active connections.
func (s *Server) ListActiveConnections() []*TrackedConnection {
	return s.connections.List()
}
