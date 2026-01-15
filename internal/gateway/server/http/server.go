// Package http provides the HTTP server implementation for the API Gateway.
package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ginModeOnce ensures gin.SetMode is only called once to avoid race conditions
var ginModeOnce sync.Once

// Server represents the HTTP server for the API Gateway.
type Server struct {
	engine      *gin.Engine
	httpServer  *http.Server
	router      *Router
	middlewares []gin.HandlerFunc
	logger      *zap.Logger
	config      *ServerConfig
	mu          sync.RWMutex
	running     bool
}

// ServerConfig holds configuration for the HTTP server.
type ServerConfig struct {
	Port           int
	Address        string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxHeaderBytes int
	TLS            *tls.Config
	// MaxRequestBodySize is the maximum allowed request body size in bytes.
	// Default is 10MB. Set to 0 to disable the limit.
	MaxRequestBodySize int64
}

// DefaultServerConfig returns a ServerConfig with default values.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:               8080,
		Address:            "",
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       30 * time.Second,
		IdleTimeout:        120 * time.Second,
		MaxHeaderBytes:     1 << 20,  // 1 MB
		MaxRequestBodySize: 10 << 20, // 10 MB default request body limit
	}
}

// NewServer creates a new HTTP server.
func NewServer(config *ServerConfig, logger *zap.Logger) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}

	// Set Gin mode based on environment (only once to avoid race conditions)
	ginModeOnce.Do(func() {
		gin.SetMode(gin.ReleaseMode)
	})

	engine := gin.New()

	s := &Server{
		engine:      engine,
		router:      NewRouter(logger),
		middlewares: make([]gin.HandlerFunc, 0),
		logger:      logger,
		config:      config,
	}

	// Add request body size limit middleware if configured
	if config.MaxRequestBodySize > 0 {
		s.Use(s.maxRequestBodySizeMiddleware())
	}

	return s
}

// maxRequestBodySizeMiddleware returns a middleware that limits request body size.
func (s *Server) maxRequestBodySizeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Wrap the request body with MaxBytesReader to enforce size limit
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, s.config.MaxRequestBodySize)
		c.Next()
	}
}

// Use adds middleware to the server.
func (s *Server) Use(middleware ...gin.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.middlewares = append(s.middlewares, middleware...)
	for _, m := range middleware {
		s.engine.Use(m)
	}
}

// GetEngine returns the underlying Gin engine.
func (s *Server) GetEngine() *gin.Engine {
	return s.engine
}

// GetRouter returns the router.
func (s *Server) GetRouter() *Router {
	return s.router
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	addr := fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)

	s.httpServer = &http.Server{
		Addr:           addr,
		Handler:        s.engine,
		ReadTimeout:    s.config.ReadTimeout,
		WriteTimeout:   s.config.WriteTimeout,
		IdleTimeout:    s.config.IdleTimeout,
		MaxHeaderBytes: s.config.MaxHeaderBytes,
		TLSConfig:      s.config.TLS,
	}

	s.running = true
	s.mu.Unlock()

	s.logger.Info("starting HTTP server",
		zap.String("address", addr),
		zap.Duration("readTimeout", s.config.ReadTimeout),
		zap.Duration("writeTimeout", s.config.WriteTimeout),
	)

	// Setup the catch-all route handler
	s.setupRouteHandler()

	var err error
	if s.config.TLS != nil {
		err = s.httpServer.ListenAndServeTLS("", "")
	} else {
		err = s.httpServer.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// Stop stops the HTTP server gracefully.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	s.logger.Info("stopping HTTP server")

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	s.mu.Lock()
	s.running = false
	s.mu.Unlock()

	s.logger.Info("HTTP server stopped")
	return nil
}

// IsRunning returns whether the server is running.
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// UpdateRoutes updates the routes in the router.
func (s *Server) UpdateRoutes(routes []RouteConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, route := range routes {
		r := &Route{
			Name:      route.Name,
			Hostnames: route.Hostnames,
			Rules:     route.Rules,
			Backends:  route.Backends,
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

// setupRouteHandler sets up the catch-all route handler.
func (s *Server) setupRouteHandler() {
	s.engine.NoRoute(func(c *gin.Context) {
		s.handleRequest(c)
	})

	// Also handle all methods on all paths
	s.engine.Any("/*path", func(c *gin.Context) {
		s.handleRequest(c)
	})
}

// handleRequest handles incoming HTTP requests by matching them to routes.
func (s *Server) handleRequest(c *gin.Context) {
	route, rule := s.router.Match(c.Request)
	if route == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "No route matched the request",
		})
		return
	}

	// Store route info in context for downstream handlers
	c.Set("route", route)
	if rule != nil {
		c.Set("rule", rule)
	}

	// The actual proxying will be handled by the backend proxy middleware
	// For now, we just acknowledge the match
	s.logger.Debug("route matched",
		zap.String("route", route.Name),
		zap.String("path", c.Request.URL.Path),
		zap.String("method", c.Request.Method),
	)
}

// RouteConfig is a simplified route configuration for external use.
type RouteConfig struct {
	Name      string
	Hostnames []string
	Rules     []RouteRule
	Backends  []BackendRef
}
