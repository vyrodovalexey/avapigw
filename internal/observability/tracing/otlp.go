// Package tracing provides OpenTelemetry tracing for the API Gateway.
package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ExporterType defines the type of trace exporter.
type ExporterType string

const (
	// ExporterOTLPGRPC exports traces via OTLP over gRPC.
	ExporterOTLPGRPC ExporterType = "otlp-grpc"
	// ExporterOTLPHTTP exports traces via OTLP over HTTP.
	ExporterOTLPHTTP ExporterType = "otlp-http"
	// ExporterNone disables trace export.
	ExporterNone ExporterType = "none"
)

// Config holds configuration for the tracing provider.
type Config struct {
	// ServiceName is the name of the service.
	ServiceName string

	// ServiceVersion is the version of the service.
	ServiceVersion string

	// Environment is the deployment environment (e.g., production, staging).
	Environment string

	// ExporterType is the type of exporter to use.
	ExporterType ExporterType

	// Endpoint is the OTLP collector endpoint.
	Endpoint string

	// Insecure disables TLS for the exporter connection.
	Insecure bool

	// Headers are additional headers to send with traces.
	Headers map[string]string

	// SampleRate is the sampling rate (0.0 to 1.0).
	SampleRate float64

	// BatchTimeout is the maximum time to wait before exporting a batch.
	BatchTimeout time.Duration

	// MaxExportBatchSize is the maximum number of spans to export in a batch.
	MaxExportBatchSize int

	// MaxQueueSize is the maximum number of spans to queue before dropping.
	MaxQueueSize int

	// Attributes are additional attributes to add to all spans.
	Attributes map[string]string
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		ServiceName:        "avapigw",
		ServiceVersion:     "1.0.0",
		Environment:        "development",
		ExporterType:       ExporterOTLPGRPC,
		Endpoint:           "localhost:4317",
		Insecure:           true,
		SampleRate:         1.0,
		BatchTimeout:       5 * time.Second,
		MaxExportBatchSize: 512,
		MaxQueueSize:       2048,
	}
}

// Provider manages the OpenTelemetry trace provider.
type Provider struct {
	config         *Config
	tracerProvider *sdktrace.TracerProvider
	logger         *zap.Logger
}

// NewProvider creates a new tracing provider.
func NewProvider(config *Config, logger *zap.Logger) (*Provider, error) {
	if config == nil {
		config = DefaultConfig()
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Provider{
		config: config,
		logger: logger,
	}, nil
}

// Start initializes and starts the tracing provider.
func (p *Provider) Start(ctx context.Context) error {
	// Create resource
	res, err := p.createResource(ctx)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporter
	exporter, err := p.createExporter(ctx)
	if err != nil {
		return fmt.Errorf("failed to create exporter: %w", err)
	}

	// Create sampler
	sampler := p.createSampler()

	// Create batch span processor
	bsp := sdktrace.NewBatchSpanProcessor(
		exporter,
		sdktrace.WithBatchTimeout(p.config.BatchTimeout),
		sdktrace.WithMaxExportBatchSize(p.config.MaxExportBatchSize),
		sdktrace.WithMaxQueueSize(p.config.MaxQueueSize),
	)

	// Create tracer provider
	p.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithSampler(sampler),
	)

	// Set global tracer provider
	otel.SetTracerProvider(p.tracerProvider)

	p.logger.Info("tracing provider started",
		zap.String("service", p.config.ServiceName),
		zap.String("exporter", string(p.config.ExporterType)),
		zap.String("endpoint", p.config.Endpoint),
		zap.Float64("sampleRate", p.config.SampleRate),
	)

	return nil
}

// Stop shuts down the tracing provider.
func (p *Provider) Stop(ctx context.Context) error {
	if p.tracerProvider == nil {
		return nil
	}

	p.logger.Info("stopping tracing provider")
	return p.tracerProvider.Shutdown(ctx)
}

// Tracer returns a tracer with the given name.
func (p *Provider) Tracer(name string) trace.Tracer {
	if p.tracerProvider == nil {
		return otel.GetTracerProvider().Tracer(name)
	}
	return p.tracerProvider.Tracer(name)
}

// createResource creates the OpenTelemetry resource.
func (p *Provider) createResource(ctx context.Context) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(p.config.ServiceName),
		semconv.ServiceVersion(p.config.ServiceVersion),
		semconv.DeploymentEnvironment(p.config.Environment),
	}

	// Add custom attributes
	for k, v := range p.config.Attributes {
		attrs = append(attrs, attribute.String(k, v))
	}

	return resource.New(ctx,
		resource.WithAttributes(attrs...),
		resource.WithHost(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
	)
}

// createExporter creates the trace exporter.
func (p *Provider) createExporter(ctx context.Context) (*otlptrace.Exporter, error) {
	switch p.config.ExporterType {
	case ExporterOTLPGRPC:
		return p.createGRPCExporter(ctx)
	case ExporterOTLPHTTP:
		return p.createHTTPExporter(ctx)
	case ExporterNone:
		return nil, fmt.Errorf("no exporter configured")
	default:
		return p.createGRPCExporter(ctx)
	}
}

// createGRPCExporter creates an OTLP gRPC exporter.
func (p *Provider) createGRPCExporter(ctx context.Context) (*otlptrace.Exporter, error) {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(p.config.Endpoint),
	}

	if p.config.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	if len(p.config.Headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(p.config.Headers))
	}

	return otlptracegrpc.New(ctx, opts...)
}

// createHTTPExporter creates an OTLP HTTP exporter.
func (p *Provider) createHTTPExporter(ctx context.Context) (*otlptrace.Exporter, error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(p.config.Endpoint),
	}

	if p.config.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	if len(p.config.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(p.config.Headers))
	}

	return otlptracehttp.New(ctx, opts...)
}

// createSampler creates the trace sampler.
func (p *Provider) createSampler() sdktrace.Sampler {
	if p.config.SampleRate <= 0 {
		return sdktrace.NeverSample()
	}
	if p.config.SampleRate >= 1.0 {
		return sdktrace.AlwaysSample()
	}
	return sdktrace.TraceIDRatioBased(p.config.SampleRate)
}

// GetTracerProvider returns the tracer provider.
func (p *Provider) GetTracerProvider() trace.TracerProvider {
	if p.tracerProvider == nil {
		return otel.GetTracerProvider()
	}
	return p.tracerProvider
}

// InitGlobalTracer initializes the global tracer with the given configuration.
func InitGlobalTracer(ctx context.Context, config *Config, logger *zap.Logger) (*Provider, error) {
	provider, err := NewProvider(config, logger)
	if err != nil {
		return nil, err
	}

	if err := provider.Start(ctx); err != nil {
		return nil, err
	}

	return provider, nil
}
