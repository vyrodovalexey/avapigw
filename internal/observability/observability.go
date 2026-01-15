// Package observability provides comprehensive observability for the API Gateway.
// It includes metrics, tracing, and logging functionality.
package observability

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/observability/logging"
	"github.com/vyrodovalexey/avapigw/internal/observability/metrics"
	"github.com/vyrodovalexey/avapigw/internal/observability/tracing"
)

// Config holds configuration for observability.
type Config struct {
	// Service information
	ServiceName    string
	ServiceVersion string
	Environment    string

	// Logging configuration
	LogLevel         logging.Level
	LogFormat        logging.Format
	LogOutput        string
	AccessLogEnabled bool

	// Tracing configuration
	TracingEnabled    bool
	TracingExporter   tracing.ExporterType
	OTLPEndpoint      string
	TracingSampleRate float64
	TracingInsecure   bool
	TracingHeaders    map[string]string

	// Metrics configuration
	MetricsEnabled bool
	MetricsPort    int
	MetricsPath    string
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		ServiceName:       "avapigw",
		ServiceVersion:    "1.0.0",
		Environment:       "development",
		LogLevel:          logging.LevelInfo,
		LogFormat:         logging.FormatJSON,
		LogOutput:         "stdout",
		AccessLogEnabled:  true,
		TracingEnabled:    false,
		TracingExporter:   tracing.ExporterOTLPGRPC,
		OTLPEndpoint:      "localhost:4317",
		TracingSampleRate: 1.0,
		TracingInsecure:   true,
		MetricsEnabled:    true,
		MetricsPort:       9091,
		MetricsPath:       "/metrics",
	}
}

// Observability manages all observability components.
type Observability struct {
	config           *Config
	logger           *logging.Logger
	tracingProvider  *tracing.Provider
	metricsServer    *metrics.Server
	collector        *metrics.GatewayCollector
	runtimeCollector *metrics.RuntimeCollector
	metricsErrCh     chan error    // Channel to capture metrics server startup errors
	metricsReady     chan struct{} // Channel to signal metrics server is ready
}

// New creates a new Observability instance.
func New(config *Config) (*Observability, error) {
	if config == nil {
		config = DefaultConfig()
	}

	return &Observability{
		config: config,
	}, nil
}

// Start initializes and starts all observability components.
func (o *Observability) Start(ctx context.Context) error {
	// Initialize logging
	if err := o.initLogging(); err != nil {
		return fmt.Errorf("failed to initialize logging: %w", err)
	}

	o.logger.Info("initializing observability",
		zap.String("service", o.config.ServiceName),
		zap.String("version", o.config.ServiceVersion),
		zap.String("environment", o.config.Environment),
	)

	// Initialize tracing
	if o.config.TracingEnabled {
		if err := o.initTracing(ctx); err != nil {
			return fmt.Errorf("failed to initialize tracing: %w", err)
		}
	}

	// Initialize metrics
	if o.config.MetricsEnabled {
		if err := o.initMetrics(ctx); err != nil {
			return fmt.Errorf("failed to initialize metrics: %w", err)
		}
	}

	// Setup propagators
	tracing.SetupPropagators(&tracing.PropagatorConfig{
		Types:         []tracing.PropagatorType{tracing.PropagatorW3C},
		EnableBaggage: true,
	})

	o.logger.Info("observability initialized successfully")
	return nil
}

// Stop shuts down all observability components.
func (o *Observability) Stop(ctx context.Context) error {
	o.logger.Info("stopping observability")

	var errs []error

	// Stop metrics server
	if o.metricsServer != nil {
		if err := o.metricsServer.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop metrics server: %w", err))
		}
	}

	// Stop tracing provider
	if o.tracingProvider != nil {
		if err := o.tracingProvider.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop tracing provider: %w", err))
		}
	}

	// Sync logger
	if o.logger != nil {
		if err := o.logger.Sync(); err != nil {
			// Ignore sync errors for stdout/stderr
			if o.config.LogOutput != "stdout" && o.config.LogOutput != "stderr" {
				errs = append(errs, fmt.Errorf("failed to sync logger: %w", err))
			}
		}
	}

	if len(errs) > 0 {
		// Use errors.Join for proper error wrapping (Go 1.20+)
		return errors.Join(errs...)
	}

	return nil
}

// initLogging initializes the logging component.
func (o *Observability) initLogging() error {
	logConfig := &logging.Config{
		Level:       o.config.LogLevel,
		Format:      o.config.LogFormat,
		Output:      o.config.LogOutput,
		Development: o.config.Environment == "development",
		InitialFields: map[string]interface{}{
			"service":     o.config.ServiceName,
			"version":     o.config.ServiceVersion,
			"environment": o.config.Environment,
		},
	}

	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		return err
	}

	o.logger = logger
	logging.SetGlobalLogger(logger)

	return nil
}

// initTracing initializes the tracing component.
func (o *Observability) initTracing(ctx context.Context) error {
	tracingConfig := &tracing.Config{
		ServiceName:    o.config.ServiceName,
		ServiceVersion: o.config.ServiceVersion,
		Environment:    o.config.Environment,
		ExporterType:   o.config.TracingExporter,
		Endpoint:       o.config.OTLPEndpoint,
		Insecure:       o.config.TracingInsecure,
		Headers:        o.config.TracingHeaders,
		SampleRate:     o.config.TracingSampleRate,
		BatchTimeout:   5 * time.Second,
	}

	provider, err := tracing.NewProvider(tracingConfig, o.logger.Logger)
	if err != nil {
		return err
	}

	if err := provider.Start(ctx); err != nil {
		return err
	}

	o.tracingProvider = provider
	return nil
}

// initMetrics initializes the metrics component.
func (o *Observability) initMetrics(ctx context.Context) error {
	// Create collectors
	o.collector = metrics.NewGatewayCollector(o.config.ServiceName, o.config.ServiceVersion)
	o.runtimeCollector = metrics.NewRuntimeCollector()

	// Create metrics server
	serverConfig := &metrics.ServerConfig{
		Port:                 o.config.MetricsPort,
		Path:                 o.config.MetricsPath,
		ReadTimeout:          5 * time.Second,
		WriteTimeout:         10 * time.Second,
		EnableRuntimeMetrics: true,
		EnableProcessMetrics: true,
	}

	o.metricsServer = metrics.NewServer(serverConfig, o.logger.Logger).
		WithGatewayCollector(o.collector).
		WithRuntimeCollector(o.runtimeCollector)

	// Initialize error and ready channels
	o.metricsErrCh = make(chan error, 1)
	o.metricsReady = make(chan struct{})

	// Start metrics server in background
	go func() {
		// Signal ready after a short delay to allow server to start
		go func() {
			// Give the server a moment to start listening
			time.Sleep(100 * time.Millisecond)
			close(o.metricsReady)
		}()

		if err := o.metricsServer.Start(ctx); err != nil {
			o.logger.Error("metrics server error", zap.Error(err))
			select {
			case o.metricsErrCh <- err:
			default:
				// Channel full, error already reported
			}
		}
	}()

	// Wait for server to be ready or error with timeout
	select {
	case <-o.metricsReady:
		o.logger.Info("metrics server started successfully", zap.Int("port", o.config.MetricsPort))
		return nil
	case err := <-o.metricsErrCh:
		return fmt.Errorf("metrics server failed to start: %w", err)
	case <-time.After(5 * time.Second):
		return fmt.Errorf("metrics server startup timed out")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Logger returns the logger.
func (o *Observability) Logger() *logging.Logger {
	return o.logger
}

// TracingProvider returns the tracing provider.
func (o *Observability) TracingProvider() *tracing.Provider {
	return o.tracingProvider
}

// MetricsServer returns the metrics server.
func (o *Observability) MetricsServer() *metrics.Server {
	return o.metricsServer
}

// GatewayCollector returns the gateway collector.
func (o *Observability) GatewayCollector() *metrics.GatewayCollector {
	return o.collector
}

// RuntimeCollector returns the runtime collector.
func (o *Observability) RuntimeCollector() *metrics.RuntimeCollector {
	return o.runtimeCollector
}

// RecordHTTPRequest records an HTTP request metric.
func (o *Observability) RecordHTTPRequest(method, path, statusCode string, duration float64, requestSize, responseSize int64) {
	metrics.RecordHTTPRequest(method, path, statusCode, duration, requestSize, responseSize)
}

// RecordGRPCRequest records a gRPC request metric.
func (o *Observability) RecordGRPCRequest(service, method, code string, duration float64) {
	metrics.RecordGRPCRequest(service, method, code, duration)
}

// RecordBackendRequest records a backend request metric.
func (o *Observability) RecordBackendRequest(backend, method, status string, duration float64) {
	metrics.RecordBackendRequest(backend, method, status, duration)
}

// RecordRateLimitCheck records a rate limit check.
func (o *Observability) RecordRateLimitCheck(key string, allowed bool, remaining int) {
	metrics.RecordRateLimitCheck(key, allowed, remaining)
}

// RecordCircuitBreakerRequest records a circuit breaker request.
func (o *Observability) RecordCircuitBreakerRequest(name string, allowed bool) {
	metrics.RecordCircuitBreakerRequest(name, allowed)
}

// RecordAuthRequest records an authentication request.
func (o *Observability) RecordAuthRequest(authType, result string, duration float64) {
	metrics.RecordAuthRequest(authType, result, duration)
}

// IsMetricsServerHealthy checks if the metrics server is healthy.
// Returns true if the server is running and accepting connections.
func (o *Observability) IsMetricsServerHealthy() bool {
	if o.metricsServer == nil {
		return false
	}

	// Check if there's an error in the error channel (non-blocking)
	select {
	case err := <-o.metricsErrCh:
		// Put the error back for other readers
		select {
		case o.metricsErrCh <- err:
		default:
		}
		return false
	default:
		// No error, server is healthy
		return true
	}
}

// GetMetricsServerError returns any error from the metrics server startup.
// Returns nil if no error occurred.
func (o *Observability) GetMetricsServerError() error {
	select {
	case err := <-o.metricsErrCh:
		// Put the error back for other readers
		select {
		case o.metricsErrCh <- err:
		default:
		}
		return err
	default:
		return nil
	}
}
