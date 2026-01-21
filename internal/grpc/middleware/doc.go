// Package middleware provides gRPC interceptors for the API Gateway.
//
// The middleware package implements gRPC interceptors for:
//   - Logging (structured logging with gRPC status codes)
//   - Metrics (Prometheus metrics for gRPC requests)
//   - Tracing (OpenTelemetry distributed tracing)
//   - Rate limiting (per-client and global rate limiting)
//   - Circuit breaker (failure protection)
//   - Retry (automatic retry with backoff)
//   - Timeout (request timeout enforcement)
//   - Recovery (panic recovery)
//   - Request ID (request correlation)
//
// Interceptors can be chained using grpc.ChainUnaryInterceptor and
// grpc.ChainStreamInterceptor.
//
// Example usage:
//
//	srv := grpc.NewServer(
//	    grpc.ChainUnaryInterceptor(
//	        middleware.UnaryRecoveryInterceptor(logger),
//	        middleware.UnaryRequestIDInterceptor(),
//	        middleware.UnaryLoggingInterceptor(logger),
//	        middleware.UnaryMetricsInterceptor(metrics),
//	    ),
//	    grpc.ChainStreamInterceptor(
//	        middleware.StreamRecoveryInterceptor(logger),
//	        middleware.StreamRequestIDInterceptor(),
//	        middleware.StreamLoggingInterceptor(logger),
//	        middleware.StreamMetricsInterceptor(metrics),
//	    ),
//	)
package middleware
