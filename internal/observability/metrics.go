package observability

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// unmatchedRoute is the label value used for requests that do not
// match any configured route, ensuring bounded cardinality.
const unmatchedRoute = "unmatched"

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
		[]string{"method", "route", "status"},
	)

	m.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration in seconds",
			Buckets: []float64{
				.001, .005, .01, .025, .05,
				.1, .25, .5, 1, 2.5, 5, 10,
			},
		},
		[]string{"method", "route", "status"},
	)

	m.requestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_size_bytes",
			Help:      "HTTP request size in bytes",
			Buckets: prometheus.ExponentialBuckets(
				100, 10, 8,
			),
		},
		[]string{"method", "route"},
	)

	m.responseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "response_size_bytes",
			Help:      "HTTP response size in bytes",
			Buckets: prometheus.ExponentialBuckets(
				100, 10, 8,
			),
		},
		[]string{"method", "route", "status"},
	)

	m.activeRequests = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "active_requests",
			Help: "Number of active HTTP " +
				"requests",
		},
		[]string{"method", "route"},
	)

	m.backendHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "backend_health",
			Help: "Backend health status " +
				"(1=healthy, 0=unhealthy)",
		},
		[]string{"backend", "host"},
	)

	m.circuitBreaker = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "circuit_breaker_state",
			Help: "Circuit breaker state " +
				"(0=closed, 1=half-open, 2=open)",
		},
		[]string{"name"},
	)

	m.rateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "rate_limit_hits_total",
			Help: "Total number of rate " +
				"limit hits",
		},
		[]string{"route"},
	)

	m.registerCollectors()

	return m
}

// registerCollectors registers all metric collectors with the
// Prometheus registry.
func (m *Metrics) registerCollectors() {
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

	m.registry.MustRegister(collectors.NewGoCollector())
	m.registry.MustRegister(
		collectors.NewProcessCollector(
			collectors.ProcessCollectorOpts{},
		),
	)
}

// RecordRequest records a completed HTTP request.
// The route parameter should be the matched route name/pattern,
// not the raw request path, to prevent cardinality explosion.
func (m *Metrics) RecordRequest(
	method, route string,
	status int,
	duration time.Duration,
	reqSize, respSize int64,
) {
	statusStr := strconv.Itoa(status)

	m.requestsTotal.WithLabelValues(
		method, route, statusStr,
	).Inc()
	m.requestDuration.WithLabelValues(
		method, route, statusStr,
	).Observe(duration.Seconds())
	m.requestSize.WithLabelValues(
		method, route,
	).Observe(float64(reqSize))
	m.responseSize.WithLabelValues(
		method, route, statusStr,
	).Observe(float64(respSize))
}

// IncrementActiveRequests increments the active requests gauge.
func (m *Metrics) IncrementActiveRequests(
	method, route string,
) {
	m.activeRequests.WithLabelValues(method, route).Inc()
}

// DecrementActiveRequests decrements the active requests gauge.
func (m *Metrics) DecrementActiveRequests(
	method, route string,
) {
	m.activeRequests.WithLabelValues(method, route).Dec()
}

// SetBackendHealth sets the backend health status.
func (m *Metrics) SetBackendHealth(
	backend, host string, healthy bool,
) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	m.backendHealth.WithLabelValues(backend, host).Set(value)
}

// SetCircuitBreakerState sets the circuit breaker state.
func (m *Metrics) SetCircuitBreakerState(
	name string, state int,
) {
	m.circuitBreaker.WithLabelValues(name).Set(float64(state))
}

// RecordRateLimitHit records a rate limit hit.
// Uses route label instead of client_ip to prevent unbounded
// cardinality. Client IP tracking should be done via logs.
func (m *Metrics) RecordRateLimitHit(route string) {
	m.rateLimitHits.WithLabelValues(route).Inc()
}

// Handler returns an HTTP handler for the metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(
		m.registry,
		promhttp.HandlerOpts{EnableOpenMetrics: true},
	)
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// MetricsMiddleware returns a middleware that records metrics.
// It extracts the route name from context (set by the proxy/router)
// instead of using the raw request path, preventing metrics
// cardinality explosion from dynamic path segments.
func MetricsMiddleware(
	metrics *Metrics,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()
				method := r.Method

				rw := &metricsResponseWriter{
					ResponseWriter: w,
					status:         http.StatusOK,
				}

				next.ServeHTTP(rw, r)

				route := routeFromRequest(r)
				duration := time.Since(start)

				metrics.IncrementActiveRequests(method, route)
				defer metrics.DecrementActiveRequests(
					method, route,
				)

				metrics.RecordRequest(
					method, route, rw.status,
					duration,
					r.ContentLength, int64(rw.size),
				)
			},
		)
	}
}

// routeFromRequest extracts the route name from the request
// context. Returns unmatchedRoute if no route is set.
func routeFromRequest(r *http.Request) string {
	route := util.RouteFromContext(r.Context())
	if route == "" {
		return unmatchedRoute
	}
	return route
}

// metricsResponseWriter wraps http.ResponseWriter to capture
// metrics.
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

// Flush implements http.Flusher interface for streaming support.
func (rw *metricsResponseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
