package observability

import (
	"context"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.39.0"
	"go.opentelemetry.io/otel/trace"
)

// OTLP exporter retry configuration defaults.
const (
	// DefaultOTLPRetryInitialInterval is the initial backoff interval for OTLP exporter retries.
	DefaultOTLPRetryInitialInterval = 1 * time.Second

	// DefaultOTLPRetryMaxInterval is the maximum backoff interval for OTLP exporter retries.
	DefaultOTLPRetryMaxInterval = 30 * time.Second

	// DefaultOTLPRetryMaxElapsedTime is the maximum total time for OTLP exporter retries.
	DefaultOTLPRetryMaxElapsedTime = 1 * time.Minute

	// DefaultOTLPTimeout is the default timeout for OTLP exporter operations.
	DefaultOTLPTimeout = 10 * time.Second

	// DefaultOTLPReconnectionPeriod is the default reconnection period for OTLP gRPC connection.
	DefaultOTLPReconnectionPeriod = 10 * time.Second
)

// TracerConfig contains tracing configuration.
type TracerConfig struct {
	ServiceName  string
	OTLPEndpoint string
	SamplingRate float64
	Enabled      bool

	// Retry configuration for OTLP exporter.
	// If nil, defaults will be used.
	RetryConfig *OTLPRetryConfig
}

// OTLPRetryConfig contains retry configuration for OTLP exporter.
type OTLPRetryConfig struct {
	// Enabled indicates whether retry is enabled.
	Enabled bool

	// InitialInterval is the initial backoff interval.
	InitialInterval time.Duration

	// MaxInterval is the maximum backoff interval.
	MaxInterval time.Duration

	// MaxElapsedTime is the maximum total time for retries.
	MaxElapsedTime time.Duration
}

// Tracer wraps OpenTelemetry tracing functionality.
type Tracer struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
	config   TracerConfig
}

// NewTracer creates a new tracer.
func NewTracer(cfg TracerConfig) (*Tracer, error) {
	if !cfg.Enabled {
		return &Tracer{
			config: cfg,
			tracer: otel.Tracer(cfg.ServiceName),
		}, nil
	}

	ctx := context.Background()

	var exporter *otlptrace.Exporter
	var err error

	if cfg.OTLPEndpoint != "" {
		// Build OTLP exporter options with retry configuration
		opts := buildOTLPExporterOptions(cfg)

		exporter, err = otlptracegrpc.New(ctx, opts...)
		if err != nil {
			return nil, err
		}
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, err
	}

	sampler := createSampler(cfg.SamplingRate)

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	}

	if exporter != nil {
		opts = append(opts, sdktrace.WithBatcher(exporter))
	}

	provider := sdktrace.NewTracerProvider(opts...)

	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Tracer{
		provider: provider,
		tracer:   provider.Tracer(cfg.ServiceName),
		config:   cfg,
	}, nil
}

// createSampler creates a sampler based on the sampling rate.
func createSampler(rate float64) sdktrace.Sampler {
	switch {
	case rate >= 1.0:
		return sdktrace.AlwaysSample()
	case rate <= 0:
		return sdktrace.NeverSample()
	default:
		return sdktrace.TraceIDRatioBased(rate)
	}
}

// buildOTLPExporterOptions builds OTLP gRPC exporter options with retry configuration.
func buildOTLPExporterOptions(cfg TracerConfig) []otlptracegrpc.Option {
	// Preallocate with capacity for all options (4 base + 1 retry)
	opts := make([]otlptracegrpc.Option, 0, 5)
	opts = append(opts,
		otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithTimeout(DefaultOTLPTimeout),
		otlptracegrpc.WithReconnectionPeriod(DefaultOTLPReconnectionPeriod),
	)

	// Configure retry with exponential backoff
	retryConfig := buildRetryConfig(cfg.RetryConfig)
	opts = append(opts, otlptracegrpc.WithRetry(retryConfig))

	return opts
}

// buildRetryConfig builds the retry configuration for OTLP exporter.
func buildRetryConfig(cfg *OTLPRetryConfig) otlptracegrpc.RetryConfig {
	// Use defaults if no custom config provided
	if cfg == nil {
		return otlptracegrpc.RetryConfig{
			Enabled:         true,
			InitialInterval: DefaultOTLPRetryInitialInterval,
			MaxInterval:     DefaultOTLPRetryMaxInterval,
			MaxElapsedTime:  DefaultOTLPRetryMaxElapsedTime,
		}
	}

	// Build config from provided values, using defaults for zero values
	retryConfig := otlptracegrpc.RetryConfig{
		Enabled: cfg.Enabled,
	}

	if cfg.InitialInterval > 0 {
		retryConfig.InitialInterval = cfg.InitialInterval
	} else {
		retryConfig.InitialInterval = DefaultOTLPRetryInitialInterval
	}

	if cfg.MaxInterval > 0 {
		retryConfig.MaxInterval = cfg.MaxInterval
	} else {
		retryConfig.MaxInterval = DefaultOTLPRetryMaxInterval
	}

	if cfg.MaxElapsedTime > 0 {
		retryConfig.MaxElapsedTime = cfg.MaxElapsedTime
	} else {
		retryConfig.MaxElapsedTime = DefaultOTLPRetryMaxElapsedTime
	}

	return retryConfig
}

// Shutdown shuts down the tracer.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t.provider != nil {
		return t.provider.Shutdown(ctx)
	}
	return nil
}

// StartSpan starts a new span.
func (t *Tracer) StartSpan(
	ctx context.Context,
	name string,
	opts ...trace.SpanStartOption,
) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, opts...)
}

// SpanFromContext returns the span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// TracingMiddleware returns a middleware that adds tracing to requests.
func TracingMiddleware(tracer *Tracer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			ctx, span := tracer.StartSpan(ctx, r.URL.Path,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String("http.request.method", r.Method),
					attribute.String("url.full", r.URL.String()),
					attribute.String("user_agent.original", r.UserAgent()),
					attribute.String("server.address", r.Host),
				),
			)
			defer span.End()

			ctx = addTraceContextToContext(ctx, span)

			rw := &tracingResponseWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			next.ServeHTTP(rw, r.WithContext(ctx))

			span.SetAttributes(attribute.Int("http.response.status_code", rw.status))

			if rw.status >= 400 {
				span.SetAttributes(attribute.Bool("error", true))
			}
		})
	}
}

// addTraceContextToContext adds trace and span IDs to context for logging.
func addTraceContextToContext(ctx context.Context, span trace.Span) context.Context {
	if span.SpanContext().HasTraceID() {
		ctx = ContextWithTraceID(ctx, span.SpanContext().TraceID().String())
	}
	if span.SpanContext().HasSpanID() {
		ctx = ContextWithSpanID(ctx, span.SpanContext().SpanID().String())
	}
	return ctx
}

// tracingResponseWriter wraps http.ResponseWriter to capture status.
type tracingResponseWriter struct {
	http.ResponseWriter
	status int
}

// WriteHeader captures the status code.
func (rw *tracingResponseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush implements http.Flusher interface for streaming support.
func (rw *tracingResponseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// InjectTraceContext injects trace context into outgoing request headers.
func InjectTraceContext(ctx context.Context, r *http.Request) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(r.Header))
}
