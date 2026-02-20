package observability

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	routepkg "github.com/vyrodovalexey/avapigw/internal/metrics/route"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

// unmatchedRoute is the label value used for requests that do not
// match any configured route, ensuring bounded cardinality.
const unmatchedRoute = "unmatched"

// inFlightRoute is the label value used for tracking in-flight
// requests before the route is known.
const inFlightRoute = "in_flight"

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
	buildInfo       *prometheus.GaugeVec
	startTime       prometheus.Gauge
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

	m.buildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "build_info",
			Help:      "Build information for the gateway",
		},
		[]string{"version", "commit", "build_time"},
	)

	m.startTime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "start_time_seconds",
			Help: "Start time of the gateway " +
				"in unix seconds",
		},
	)

	m.registerCollectors()

	m.startTime.SetToCurrentTime()

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
		m.buildInfo,
		m.startTime,
	)

	m.registry.MustRegister(collectors.NewGoCollector())
	m.registry.MustRegister(
		collectors.NewProcessCollector(
			collectors.ProcessCollectorOpts{},
		),
	)
}

// InitVecMetrics pre-populates common label combinations with zero
// values so that Vec metrics appear in /metrics output immediately
// after startup. Prometheus *Vec types only emit metric lines after
// WithLabelValues() is called at least once. This method is idempotent.
func (m *Metrics) InitVecMetrics() {
	m.circuitBreaker.WithLabelValues("default")
	m.rateLimitHits.WithLabelValues("default")
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

// SetBuildInfo sets the build information metric.
func (m *Metrics) SetBuildInfo(
	version, commit, buildTime string,
) {
	m.buildInfo.WithLabelValues(
		version, commit, buildTime,
	).Set(1)
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

// RegisterCollector registers an additional collector with the custom
// registry. It returns an error if the collector is already registered
// or conflicts with an existing one. This allows external packages
// (e.g. reload metrics, audit metrics) to share the same registry
// that backs the /metrics endpoint.
func (m *Metrics) RegisterCollector(c prometheus.Collector) error {
	return m.registry.Register(c)
}

// MustRegisterCollector registers an additional collector with the
// custom registry, panicking on error.
func (m *Metrics) MustRegisterCollector(c prometheus.Collector) {
	m.registry.MustRegister(c)
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

				// Track active requests (route not yet known)
				metrics.activeRequests.WithLabelValues(
					method, inFlightRoute,
				).Inc()

				next.ServeHTTP(rw, r)

				metrics.activeRequests.WithLabelValues(
					method, inFlightRoute,
				).Dec()

				route := routeFromRequest(r)
				duration := time.Since(start)

				metrics.RecordRequest(
					method, route, rw.status,
					duration,
					r.ContentLength, int64(rw.size),
				)

				// Record route-level metrics in parallel
				routeMetrics := routepkg.GetRouteMetrics()
				routeMetrics.RecordRequest(
					route, method, rw.status,
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

// Hijack implements http.Hijacker interface for WebSocket support.
func (rw *metricsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
