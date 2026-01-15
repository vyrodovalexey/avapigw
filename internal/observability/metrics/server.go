// Package metrics provides Prometheus metrics for the API Gateway.
package metrics

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// ServerConfig holds configuration for the metrics server.
type ServerConfig struct {
	// Port is the port to listen on.
	Port int

	// Path is the path to serve metrics on.
	Path string

	// ReadTimeout is the read timeout for the server.
	ReadTimeout time.Duration

	// WriteTimeout is the write timeout for the server.
	WriteTimeout time.Duration

	// EnableRuntimeMetrics enables Go runtime metrics collection.
	EnableRuntimeMetrics bool

	// EnableProcessMetrics enables process metrics collection.
	EnableProcessMetrics bool

	// Registry is the Prometheus registry to use. If nil, uses the default registry.
	Registry *prometheus.Registry
}

// DefaultServerConfig returns a ServerConfig with default values.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:                 9091,
		Path:                 "/metrics",
		ReadTimeout:          5 * time.Second,
		WriteTimeout:         10 * time.Second,
		EnableRuntimeMetrics: true,
		EnableProcessMetrics: true,
	}
}

// Server is a Prometheus metrics server.
type Server struct {
	config        *ServerConfig
	server        *http.Server
	logger        *zap.Logger
	collector     *GatewayCollector
	runtime       *RuntimeCollector
	registry      *prometheus.Registry
	stopCh        chan struct{}
	collectTicker *time.Ticker
	stopOnce      sync.Once
}

// NewServer creates a new metrics server.
func NewServer(config *ServerConfig, logger *zap.Logger) *Server {
	if config == nil {
		config = DefaultServerConfig()
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	registry := config.Registry
	if registry == nil {
		if reg, ok := prometheus.DefaultRegisterer.(*prometheus.Registry); ok {
			registry = reg
		} else {
			// Create a new registry if default is not available
			registry = prometheus.NewRegistry()
		}
	}

	return &Server{
		config:   config,
		logger:   logger,
		registry: registry,
		stopCh:   make(chan struct{}),
	}
}

// WithGatewayCollector sets the gateway collector.
func (s *Server) WithGatewayCollector(collector *GatewayCollector) *Server {
	s.collector = collector
	return s
}

// WithRuntimeCollector sets the runtime collector.
func (s *Server) WithRuntimeCollector(collector *RuntimeCollector) *Server {
	s.runtime = collector
	return s
}

// Start starts the metrics server.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Create handler options
	handlerOpts := promhttp.HandlerOpts{
		ErrorLog:            &zapErrorLogger{logger: s.logger},
		ErrorHandling:       promhttp.ContinueOnError,
		Registry:            s.registry,
		DisableCompression:  false,
		MaxRequestsInFlight: 10,
		Timeout:             s.config.WriteTimeout,
		EnableOpenMetrics:   true,
	}

	// Register metrics handler
	mux.Handle(s.config.Path, promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		handlerOpts,
	))

	// Register health endpoint for the metrics server itself
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			// Log but don't fail - this is a health check
			s.logger.Debug("failed to write health response", zap.Error(err))
		}
	})

	// Register ready endpoint
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("Ready")); err != nil {
			s.logger.Debug("failed to write ready response", zap.Error(err))
		}
	})

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Port),
		Handler:      mux,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	// Start periodic collection if collectors are set
	if s.collector != nil || s.runtime != nil {
		s.collectTicker = time.NewTicker(10 * time.Second)
		go s.collectLoop()
	}

	s.logger.Info("starting metrics server",
		zap.Int("port", s.config.Port),
		zap.String("path", s.config.Path),
	)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return s.Stop(context.Background())
	case err := <-errCh:
		return err
	}
}

// Stop stops the metrics server.
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("stopping metrics server")

	var stopErr error
	s.stopOnce.Do(func() {
		// Stop collection ticker
		if s.collectTicker != nil {
			s.collectTicker.Stop()
		}

		// Signal stop
		close(s.stopCh)

		// Shutdown server
		if s.server != nil {
			stopErr = s.server.Shutdown(ctx)
		}
	})

	return stopErr
}

// collectLoop periodically collects metrics.
func (s *Server) collectLoop() {
	for {
		select {
		case <-s.stopCh:
			return
		case <-s.collectTicker.C:
			// Create a context with timeout for collection
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = ctx // Context available for future use in collectors
			if s.collector != nil {
				s.collector.Collect()
			}
			if s.runtime != nil {
				s.runtime.Collect()
			}
			cancel()
		}
	}
}

// GetHandler returns the Prometheus HTTP handler.
func (s *Server) GetHandler() http.Handler {
	return promhttp.Handler()
}

// GetHandlerFor returns a Prometheus HTTP handler for a specific gatherer.
func (s *Server) GetHandlerFor(gatherer prometheus.Gatherer) http.Handler {
	return promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{
		ErrorLog:            &zapErrorLogger{logger: s.logger},
		ErrorHandling:       promhttp.ContinueOnError,
		DisableCompression:  false,
		MaxRequestsInFlight: 10,
		EnableOpenMetrics:   true,
	})
}

// zapErrorLogger adapts zap.Logger to promhttp.Logger interface.
type zapErrorLogger struct {
	logger *zap.Logger
}

// Println implements promhttp.Logger.
func (l *zapErrorLogger) Println(v ...interface{}) {
	l.logger.Error(fmt.Sprint(v...))
}

// MetricsMiddleware returns an HTTP middleware that records metrics.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code and size
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		// Increment in-flight requests
		IncrementHTTPInFlight(r.Method)
		defer DecrementHTTPInFlight(r.Method)

		// Process request
		next.ServeHTTP(wrapped, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		statusCode := fmt.Sprintf("%d", wrapped.statusCode)
		path := r.URL.Path

		RecordHTTPRequest(
			r.Method,
			path,
			statusCode,
			duration,
			r.ContentLength,
			int64(wrapped.size),
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code and size.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

// WriteHeader captures the status code.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the response size.
func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// Flush implements http.Flusher.
func (rw *responseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("response writer does not support hijacking")
}
