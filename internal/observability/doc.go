// Package observability provides logging, metrics, and tracing
// functionality for the API Gateway.
//
// This package implements the three pillars of observability:
// structured logging via zap, Prometheus metrics collection, and
// distributed tracing via OpenTelemetry with OTLP export.
//
// # Logging
//
// The Logger interface provides structured logging:
//
//	logger, err := observability.NewLogger("info", "json")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer logger.Sync()
//
//	logger.Info("request processed",
//	    observability.String("method", "GET"),
//	    observability.Int("status", 200),
//	)
//
// # Metrics
//
// Prometheus metrics for HTTP requests, backends, and rate limiting:
//
//	metrics := observability.NewMetrics("gateway")
//	handler := metrics.Handler()
//
// # Tracing
//
// OpenTelemetry distributed tracing with OTLP export:
//
//	tp, err := observability.NewTracerProvider(ctx, cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tp.Shutdown(ctx)
//
// The tracing implementation supports B3 and Jaeger propagation
// formats for cross-service trace context propagation.
package observability
