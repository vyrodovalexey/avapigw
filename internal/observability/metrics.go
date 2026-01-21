package observability

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the gateway.
type Metrics struct {
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	requestSize     *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
	activeRequests  *prometheus.GaugeVec
	backendHealth   *prometheus.GaugeVec
	circuitBreaker  *prometheus.GaugeVec
	rateLimitHits   *prometheus.CounterVec
	registry        *prometheus.Registry
}

// NewMetrics creates a new Metrics instance.
func NewMetrics(namespace string) *Metrics {
	if namespace == "" {
		namespace = "gateway"
	}

	m := &Metrics{
		registry: prometheus.NewRegistry(),
	}

	m.requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status", "route"},
	)

	m.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path", "status", "route"},
	)

	m.requestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_size_bytes",
			Help:      "HTTP request size in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path"},
	)

	m.responseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "response_size_bytes",
			Help:      "HTTP response size in bytes",
			Buckets:   prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path", "status"},
	)

	m.activeRequests = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_requests",
			Help:      "Number of active HTTP requests",
		},
		[]string{"method", "path"},
	)

	m.backendHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "backend_health",
			Help:      "Backend health status (1=healthy, 0=unhealthy)",
		},
		[]string{"backend", "host"},
	)

	m.circuitBreaker = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "circuit_breaker_state",
			Help:      "Circuit breaker state (0=closed, 1=half-open, 2=open)",
		},
		[]string{"name"},
	)

	m.rateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rate_limit_hits_total",
			Help:      "Total number of rate limit hits",
		},
		[]string{"client_ip", "path"},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.requestSize,
		m.responseSize,
		m.activeRequests,
		m.backendHealth,
		m.circuitBreaker,
		m.rateLimitHits,
	)

	// Register default Go metrics using the new collectors package
	m.registry.MustRegister(collectors.NewGoCollector())
	m.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return m
}

// RecordRequest records a completed HTTP request.
func (m *Metrics) RecordRequest(
	method, path, route string,
	status int,
	duration time.Duration,
	reqSize, respSize int64,
) {
	statusStr := strconv.Itoa(status)

	m.requestsTotal.WithLabelValues(method, path, statusStr, route).Inc()
	m.requestDuration.WithLabelValues(method, path, statusStr, route).Observe(duration.Seconds())
	m.requestSize.WithLabelValues(method, path).Observe(float64(reqSize))
	m.responseSize.WithLabelValues(method, path, statusStr).Observe(float64(respSize))
}

// IncrementActiveRequests increments the active requests gauge.
func (m *Metrics) IncrementActiveRequests(method, path string) {
	m.activeRequests.WithLabelValues(method, path).Inc()
}

// DecrementActiveRequests decrements the active requests gauge.
func (m *Metrics) DecrementActiveRequests(method, path string) {
	m.activeRequests.WithLabelValues(method, path).Dec()
}

// SetBackendHealth sets the backend health status.
func (m *Metrics) SetBackendHealth(backend, host string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	m.backendHealth.WithLabelValues(backend, host).Set(value)
}

// SetCircuitBreakerState sets the circuit breaker state.
func (m *Metrics) SetCircuitBreakerState(name string, state int) {
	m.circuitBreaker.WithLabelValues(name).Set(float64(state))
}

// RecordRateLimitHit records a rate limit hit.
func (m *Metrics) RecordRateLimitHit(clientIP, path string) {
	m.rateLimitHits.WithLabelValues(clientIP, path).Inc()
}

// Handler returns an HTTP handler for the metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// MetricsMiddleware returns a middleware that records metrics.
func MetricsMiddleware(metrics *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			path := r.URL.Path
			method := r.Method

			metrics.IncrementActiveRequests(method, path)
			defer metrics.DecrementActiveRequests(method, path)

			rw := &metricsResponseWriter{
				ResponseWriter: w,
				status:         http.StatusOK,
			}

			next.ServeHTTP(rw, r)

			duration := time.Since(start)
			route := "" // Route is set by proxy

			metrics.RecordRequest(method, path, route, rw.status, duration, r.ContentLength, int64(rw.size))
		})
	}
}

// metricsResponseWriter wraps http.ResponseWriter to capture metrics.
type metricsResponseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

// WriteHeader captures the status code.
func (rw *metricsResponseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the response size.
func (rw *metricsResponseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}
