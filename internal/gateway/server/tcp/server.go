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
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)

	// Create listener
	var listener net.Listener
	var err error

	if s.config.TLS != nil {
		listener, err = tls.Listen("tcp", addr, s.config.TLS)
	} else {
		lc := &net.ListenConfig{}
		listener, err = lc.Listen(context.Background(), "tcp", addr)
	}

	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	// Create a cancellable context for the server
	serverCtx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel

	s.listener = listener
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	// Get accept deadline from config or use default
	acceptDeadline := s.config.AcceptDeadline
	if acceptDeadline <= 0 {
		acceptDeadline = DefaultAcceptDeadline
	}

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

	// Accept connections loop with proper context cancellation handling
	for {
		// Check for context cancellation or stop signal first
		select {
		case <-serverCtx.Done():
			s.logger.Debug("server context cancelled, stopping accept loop")
			return serverCtx.Err()
		case <-s.stopCh:
			s.logger.Debug("stop signal received, stopping accept loop")
			return nil
		default:
			// Continue to accept
		}

		// Set accept deadline to allow periodic context checks
		// This ensures we respond to context cancellation within acceptDeadline
		if err := s.setAcceptDeadline(acceptDeadline); err != nil {
			s.logger.Warn("failed to set accept deadline", zap.Error(err))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			// Check if it's a timeout - this is expected for context checking
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout, loop back to check context
			}

			// Check if we're shutting down
			select {
			case <-serverCtx.Done():
				return serverCtx.Err()
			case <-s.stopCh:
				return nil
			default:
				// Log unexpected errors but continue accepting
				s.logger.Error("accept error", zap.Error(err))
				continue
			}
		}

		// Create a connection-scoped context that will be cancelled when
		// the server context is cancelled
		connCtx, connCancel := context.WithCancel(serverCtx)

		// Handle connection in a goroutine
		s.wg.Add(1)
		go func(ctx context.Context, cancel context.CancelFunc, c net.Conn) {
			defer s.wg.Done()
			defer cancel() // Ensure connection context is cancelled when handler exits
			s.handleConnection(ctx, c)
		}(connCtx, connCancel, conn)
	}
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
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}

	// Get shutdown timeout from config
	shutdownTimeout := s.config.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = DefaultShutdownTimeout
	}
	s.mu.Unlock()

	s.logger.Info("stopping TCP server",
		zap.Duration("shutdownTimeout", shutdownTimeout),
		zap.Int("activeConnections", s.connections.Count()),
	)

	// Cancel the server context to signal all connection handlers
	if s.cancelFunc != nil {
		s.cancelFunc()
	}

	// Signal to stop accepting new connections
	s.mu.Lock()
	select {
	case <-s.stopCh:
		// Already closed
	default:
		close(s.stopCh)
	}
	s.mu.Unlock()

	// Close the listener to unblock Accept()
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.logger.Debug("error closing listener", zap.Error(err))
		}
	}

	// Create a timeout context for shutdown if not provided
	var shutdownCtx context.Context
	var cancel context.CancelFunc
	if ctx == nil {
		shutdownCtx, cancel = context.WithTimeout(context.Background(), shutdownTimeout)
	} else {
		// Use the shorter of the provided context or shutdown timeout
		shutdownCtx, cancel = context.WithTimeout(ctx, shutdownTimeout)
	}
	defer cancel()

	// Wait for all connections to finish with timeout
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
		remainingConns := s.connections.Count()
		s.logger.Warn("graceful shutdown timed out, force closing remaining connections",
			zap.Int("remainingConnections", remainingConns),
		)
		// Force close all remaining connections
		s.connections.CloseAll()

		// Wait a short time for goroutines to exit after force close
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

	s.mu.Lock()
	s.running = false
	s.cancelFunc = nil
	s.mu.Unlock()

	s.logger.Info("TCP server stopped")
	return nil
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

	s.logger.Debug("handling connection",
		zap.String("id", tracked.ID),
		zap.String("remoteAddr", tracked.RemoteAddr),
	)

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

	// Find matching route
	route, err := s.router.Match(conn)
	if err != nil {
		s.logger.Debug("no matching route",
			zap.String("id", tracked.ID),
			zap.Error(err),
		)
		return
	}

	// Check context again after route matching
	select {
	case <-ctx.Done():
		s.logger.Debug("context cancelled after route matching",
			zap.String("id", tracked.ID),
		)
		return
	default:
	}

	// Check if proxy is available
	if s.proxy == nil {
		s.logger.Error("proxy not configured",
			zap.String("id", tracked.ID),
			zap.String("route", route.Name),
		)
		return
	}

	// Get backend from route
	if len(route.BackendRefs) == 0 {
		s.logger.Error("no backends configured for route",
			zap.String("id", tracked.ID),
			zap.String("route", route.Name),
		)
		return
	}

	// Use the first backend (load balancing is handled by the backend manager)
	backendRef := route.BackendRefs[0]
	backendKey := backendRef.Name
	if backendRef.Namespace != "" {
		backendKey = fmt.Sprintf("%s/%s", backendRef.Namespace, backendRef.Name)
	}

	// Get backend from manager
	backendSvc := s.proxy.backendManager.GetBackend(backendKey)
	if backendSvc == nil {
		s.logger.Error("backend not found",
			zap.String("id", tracked.ID),
			zap.String("backend", backendKey),
		)
		return
	}

	// Wrap connection for byte counting
	countingConn := NewCountingConn(conn, tracked)

	// Proxy the connection - the context will handle cancellation
	if err := s.proxy.ProxyWithIdleTimeout(ctx, countingConn, backendSvc, route.ConnectTimeout, route.IdleTimeout); err != nil {
		// Don't log context cancellation as an error - it's expected during shutdown
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
