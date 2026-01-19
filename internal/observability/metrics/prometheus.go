// Package metrics provides Prometheus metrics for the API Gateway.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// Namespace is the metrics namespace for all gateway metrics.
	Namespace = "avapigw"

	// Subsystem names for different components.
	SubsystemHTTP           = "http"
	SubsystemGRPC           = "grpc"
	SubsystemBackend        = "backend"
	SubsystemRateLimit      = "ratelimit"
	SubsystemCircuitBreaker = "circuitbreaker"
	SubsystemAuth           = "auth"
)

var (
	// HTTP Request Metrics

	// HTTPRequestsTotal counts total HTTP requests.
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemHTTP,
			Name:      "requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status_code"},
	)

	// HTTPRequestDuration measures HTTP request duration.
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: SubsystemHTTP,
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path", "status_code"},
	)

	// HTTPRequestSize measures HTTP request body size.
	HTTPRequestSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: SubsystemHTTP,
			Name:      "request_size_bytes",
			Help:      "HTTP request body size in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 8), // 100B to 1GB
		},
		[]string{"method", "path"},
	)

	// HTTPResponseSize measures HTTP response body size.
	HTTPResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: SubsystemHTTP,
			Name:      "response_size_bytes",
			Help:      "HTTP response body size in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 8), // 100B to 1GB
		},
		[]string{"method", "path", "status_code"},
	)

	// HTTPRequestsInFlight tracks current in-flight requests.
	HTTPRequestsInFlight = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemHTTP,
			Name:      "requests_in_flight",
			Help:      "Current number of HTTP requests being processed",
		},
		[]string{"method"},
	)

	// HTTPErrorsTotal counts HTTP errors by type.
	HTTPErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemHTTP,
			Name:      "errors_total",
			Help:      "Total number of HTTP errors",
		},
		[]string{"method", "path", "error_type"},
	)

	// gRPC Request Metrics

	// GRPCRequestsTotal counts total gRPC requests.
	GRPCRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemGRPC,
			Name:      "requests_total",
			Help:      "Total number of gRPC requests",
		},
		[]string{"service", "method", "code"},
	)

	// GRPCRequestDuration measures gRPC request duration.
	GRPCRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: SubsystemGRPC,
			Name:      "request_duration_seconds",
			Help:      "gRPC request duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"service", "method", "code"},
	)

	// GRPCStreamMessagesReceived counts received stream messages.
	GRPCStreamMessagesReceived = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemGRPC,
			Name:      "stream_messages_received_total",
			Help:      "Total number of gRPC stream messages received",
		},
		[]string{"service", "method"},
	)

	// GRPCStreamMessagesSent counts sent stream messages.
	GRPCStreamMessagesSent = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemGRPC,
			Name:      "stream_messages_sent_total",
			Help:      "Total number of gRPC stream messages sent",
		},
		[]string{"service", "method"},
	)

	// Backend Metrics

	// BackendRequestsTotal counts total backend requests.
	BackendRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemBackend,
			Name:      "requests_total",
			Help:      "Total number of backend requests",
		},
		[]string{"backend", "method", "status"},
	)

	// BackendRequestDuration measures backend request duration.
	BackendRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: SubsystemBackend,
			Name:      "request_duration_seconds",
			Help:      "Backend request duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"backend", "method"},
	)

	// BackendConnectionsActive tracks active backend connections.
	BackendConnectionsActive = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemBackend,
			Name:      "connections_active",
			Help:      "Current number of active backend connections",
		},
		[]string{"backend"},
	)

	// BackendConnectionsTotal counts total backend connections.
	BackendConnectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemBackend,
			Name:      "connections_total",
			Help:      "Total number of backend connections established",
		},
		[]string{"backend", "status"},
	)

	// BackendHealthStatus tracks backend health status.
	BackendHealthStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemBackend,
			Name:      "health_status",
			Help:      "Backend health status (1=healthy, 0=unhealthy)",
		},
		[]string{"backend"},
	)

	// BackendLatencyP50 tracks backend latency percentiles.
	BackendLatencyP50 = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemBackend,
			Name:      "latency_p50_seconds",
			Help:      "Backend latency 50th percentile in seconds",
		},
		[]string{"backend"},
	)

	// BackendLatencyP95 tracks backend latency 95th percentile.
	BackendLatencyP95 = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemBackend,
			Name:      "latency_p95_seconds",
			Help:      "Backend latency 95th percentile in seconds",
		},
		[]string{"backend"},
	)

	// BackendLatencyP99 tracks backend latency 99th percentile.
	BackendLatencyP99 = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemBackend,
			Name:      "latency_p99_seconds",
			Help:      "Backend latency 99th percentile in seconds",
		},
		[]string{"backend"},
	)

	// Rate Limit Metrics

	// RateLimitRequestsTotal counts rate limit checks.
	RateLimitRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemRateLimit,
			Name:      "requests_total",
			Help:      "Total number of rate limit checks",
		},
		[]string{"key", "result"},
	)

	// RateLimitRejectedTotal counts rejected requests.
	RateLimitRejectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemRateLimit,
			Name:      "rejected_total",
			Help:      "Total number of requests rejected due to rate limiting",
		},
		[]string{"key"},
	)

	// RateLimitRemaining shows remaining requests in window.
	RateLimitRemaining = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemRateLimit,
			Name:      "remaining",
			Help:      "Remaining requests in the current rate limit window",
		},
		[]string{"key"},
	)

	// RateLimitCheckDuration measures rate limit check duration.
	RateLimitCheckDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: SubsystemRateLimit,
			Name:      "check_duration_seconds",
			Help:      "Rate limit check duration in seconds",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1},
		},
		[]string{"algorithm"},
	)

	// Circuit Breaker Metrics

	// CircuitBreakerState shows circuit breaker state.
	CircuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: SubsystemCircuitBreaker,
			Name:      "state",
			Help:      "Current state of the circuit breaker (0=closed, 1=open, 2=half-open)",
		},
		[]string{"name"},
	)

	// CircuitBreakerRequestsTotal counts circuit breaker requests.
	CircuitBreakerRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemCircuitBreaker,
			Name:      "requests_total",
			Help:      "Total number of requests through circuit breakers",
		},
		[]string{"name", "result"},
	)

	// CircuitBreakerStateChangesTotal counts state changes.
	CircuitBreakerStateChangesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemCircuitBreaker,
			Name:      "state_changes_total",
			Help:      "Total number of circuit breaker state changes",
		},
		[]string{"name", "from", "to"},
	)

	// Authentication Metrics

	// AuthRequestsTotal counts authentication requests.
	AuthRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: SubsystemAuth,
			Name:      "requests_total",
			Help:      "Total number of authentication requests",
		},
		[]string{"type", "result"},
	)

	// AuthDuration measures authentication duration.
	AuthDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Subsystem: SubsystemAuth,
			Name:      "duration_seconds",
			Help:      "Authentication duration in seconds",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		},
		[]string{"type"},
	)
)

// RecordHTTPRequest records an HTTP request metric.
func RecordHTTPRequest(method, path, statusCode string, duration float64, requestSize, responseSize int64) {
	HTTPRequestsTotal.WithLabelValues(method, path, statusCode).Inc()
	HTTPRequestDuration.WithLabelValues(method, path, statusCode).Observe(duration)
	if requestSize > 0 {
		HTTPRequestSize.WithLabelValues(method, path).Observe(float64(requestSize))
	}
	if responseSize > 0 {
		HTTPResponseSize.WithLabelValues(method, path, statusCode).Observe(float64(responseSize))
	}
}

// RecordHTTPError records an HTTP error.
func RecordHTTPError(method, path, errorType string) {
	HTTPErrorsTotal.WithLabelValues(method, path, errorType).Inc()
}

// IncrementHTTPInFlight increments in-flight requests.
func IncrementHTTPInFlight(method string) {
	HTTPRequestsInFlight.WithLabelValues(method).Inc()
}

// DecrementHTTPInFlight decrements in-flight requests.
func DecrementHTTPInFlight(method string) {
	HTTPRequestsInFlight.WithLabelValues(method).Dec()
}

// RecordGRPCRequest records a gRPC request metric.
func RecordGRPCRequest(service, method, code string, duration float64) {
	GRPCRequestsTotal.WithLabelValues(service, method, code).Inc()
	GRPCRequestDuration.WithLabelValues(service, method, code).Observe(duration)
}

// RecordGRPCStreamMessage records gRPC stream messages.
func RecordGRPCStreamMessage(service, method string, sent bool) {
	if sent {
		GRPCStreamMessagesSent.WithLabelValues(service, method).Inc()
	} else {
		GRPCStreamMessagesReceived.WithLabelValues(service, method).Inc()
	}
}

// RecordBackendRequest records a backend request metric.
func RecordBackendRequest(backend, method, status string, duration float64) {
	BackendRequestsTotal.WithLabelValues(backend, method, status).Inc()
	BackendRequestDuration.WithLabelValues(backend, method).Observe(duration)
}

// SetBackendConnectionsActive sets active backend connections.
func SetBackendConnectionsActive(backend string, count int) {
	BackendConnectionsActive.WithLabelValues(backend).Set(float64(count))
}

// RecordBackendConnection records a backend connection.
func RecordBackendConnection(backend, status string) {
	BackendConnectionsTotal.WithLabelValues(backend, status).Inc()
}

// SetBackendHealthStatus sets backend health status.
func SetBackendHealthStatus(backend string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	BackendHealthStatus.WithLabelValues(backend).Set(value)
}

// SetBackendLatencyPercentiles sets backend latency percentiles.
func SetBackendLatencyPercentiles(backend string, p50, p95, p99 float64) {
	BackendLatencyP50.WithLabelValues(backend).Set(p50)
	BackendLatencyP95.WithLabelValues(backend).Set(p95)
	BackendLatencyP99.WithLabelValues(backend).Set(p99)
}

// RecordRateLimitCheck records a rate limit check.
func RecordRateLimitCheck(key string, allowed bool, remaining int) {
	result := "allowed"
	if !allowed {
		result = "rejected"
		RateLimitRejectedTotal.WithLabelValues(key).Inc()
	}
	RateLimitRequestsTotal.WithLabelValues(key, result).Inc()
	RateLimitRemaining.WithLabelValues(key).Set(float64(remaining))
}

// RecordRateLimitCheckDuration records rate limit check duration.
func RecordRateLimitCheckDuration(algorithm string, duration float64) {
	RateLimitCheckDuration.WithLabelValues(algorithm).Observe(duration)
}

// SetCircuitBreakerState sets circuit breaker state.
func SetCircuitBreakerState(name string, state int) {
	CircuitBreakerState.WithLabelValues(name).Set(float64(state))
}

// RecordCircuitBreakerRequest records a circuit breaker request.
func RecordCircuitBreakerRequest(name string, allowed bool) {
	result := "allowed"
	if !allowed {
		result = "rejected"
	}
	CircuitBreakerRequestsTotal.WithLabelValues(name, result).Inc()
}

// RecordCircuitBreakerStateChange records a circuit breaker state change.
func RecordCircuitBreakerStateChange(name, from, to string) {
	CircuitBreakerStateChangesTotal.WithLabelValues(name, from, to).Inc()
}

// RecordAuthRequest records an authentication request.
func RecordAuthRequest(authType, result string, duration float64) {
	AuthRequestsTotal.WithLabelValues(authType, result).Inc()
	AuthDuration.WithLabelValues(authType).Observe(duration)
}
