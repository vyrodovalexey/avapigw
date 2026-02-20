// Package route provides standardized Prometheus metrics for
// route-level observability in the API Gateway.
package route

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	namespace    = "gateway"
	subsystem    = "route"
	defaultLabel = "default"
)

// RouteMetrics holds all route-level Prometheus metrics.
type RouteMetrics struct {
	RequestsTotal            *prometheus.CounterVec
	RequestSizeBytes         *prometheus.HistogramVec
	ResponseSizeBytes        *prometheus.HistogramVec
	RequestDurationSeconds   *prometheus.HistogramVec
	UpstreamDurationSeconds  *prometheus.HistogramVec
	ErrorsTotal              *prometheus.CounterVec
	TimeoutsTotal            *prometheus.CounterVec
	RateLimitHitsTotal       *prometheus.CounterVec
	AuthFailuresTotal        *prometheus.CounterVec
	AuthSuccessesTotal       *prometheus.CounterVec
	CircuitBreakerState      *prometheus.GaugeVec
	CircuitBreakerTripsTotal *prometheus.CounterVec
	CacheHitsTotal           *prometheus.CounterVec
	CacheMissesTotal         *prometheus.CounterVec
	CacheBypassTotal         *prometheus.CounterVec
	RetriesTotal             *prometheus.CounterVec
	RetryExhaustedTotal      *prometheus.CounterVec
	CertExpirySeconds        *prometheus.GaugeVec
}

var (
	routeMetricsInstance *RouteMetrics
	routeMetricsOnce     sync.Once
)

// sizeBuckets defines histogram buckets for request/response sizes:
// 100, 1K, 10K, 100K, 1M, 10M, 100M.
var sizeBuckets = prometheus.ExponentialBuckets(100, 10, 7)

// NewRouteMetrics creates a new RouteMetrics instance with all
// metrics registered via promauto (default global registry).
func NewRouteMetrics() *RouteMetrics {
	return &RouteMetrics{
		RequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "requests_total",
				Help:      "Total number of requests processed by route",
			},
			[]string{"route", "method", "status_code"},
		),
		RequestSizeBytes: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "request_size_bytes",
				Help:      "Request body size in bytes",
				Buckets:   sizeBuckets,
			},
			[]string{"route", "method"},
		),
		ResponseSizeBytes: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "response_size_bytes",
				Help:      "Response body size in bytes",
				Buckets:   sizeBuckets,
			},
			[]string{"route", "method", "status_code"},
		),
		RequestDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "request_duration_seconds",
				Help: "Total request duration " +
					"including upstream",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"route", "method", "status_code"},
		),
		UpstreamDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "upstream_duration_seconds",
				Help: "Duration of upstream " +
					"(backend) request only",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"route", "method", "status_code"},
		),
		ErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "errors_total",
				Help:      "Total number of errors by type",
			},
			[]string{"route", "method", "error_type"},
		),
		TimeoutsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "timeouts_total",
				Help:      "Total number of timeouts by stage",
			},
			[]string{"route", "method", "timeout_stage"},
		),
		RateLimitHitsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "ratelimit_hits_total",
				Help:      "Total number of rate limit hits",
			},
			[]string{"route", "method", "consumer"},
		),
		AuthFailuresTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "auth_failures_total",
				Help: "Total number of " +
					"authentication failures",
			},
			[]string{"route", "method", "auth_type", "reason"},
		),
		AuthSuccessesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "auth_successes_total",
				Help: "Total number of " +
					"authentication successes",
			},
			[]string{"route", "method", "auth_type"},
		),
		CircuitBreakerState: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "circuit_breaker_state",
				Help: "Circuit breaker state " +
					"(0=closed, 1=half-open, 2=open)",
			},
			[]string{"route"},
		),
		CircuitBreakerTripsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "circuit_breaker_trips_total",
				Help: "Total number of " +
					"circuit breaker trips",
			},
			[]string{"route"},
		),
		CacheHitsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_hits_total",
				Help:      "Total number of cache hits",
			},
			[]string{"route", "method"},
		),
		CacheMissesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_misses_total",
				Help:      "Total number of cache misses",
			},
			[]string{"route", "method"},
		),
		CacheBypassTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_bypass_total",
				Help:      "Total number of cache bypasses",
			},
			[]string{"route", "method", "reason"},
		),
		RetriesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "retries_total",
				Help:      "Total number of retry attempts",
			},
			[]string{"route", "method"},
		),
		RetryExhaustedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "retry_exhausted_total",
				Help:      "Total number of exhausted retries",
			},
			[]string{"route", "method"},
		),
		CertExpirySeconds: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cert_expiry_seconds",
				Help: "Time until TLS certificate " +
					"expiry in seconds",
			},
			[]string{"route"},
		),
	}
}

// GetRouteMetrics returns the singleton route metrics instance.
func GetRouteMetrics() *RouteMetrics {
	routeMetricsOnce.Do(func() {
		routeMetricsInstance = NewRouteMetrics()
	})
	return routeMetricsInstance
}

// MustRegister registers all route metric collectors with the given
// Prometheus registry. It uses Register (not MustRegister) to
// gracefully handle duplicate registration that can occur when
// providers are recreated on config reload.
// AlreadyRegisteredError is silently ignored.
func (m *RouteMetrics) MustRegister(registry *prometheus.Registry) {
	for _, c := range m.collectors() {
		if err := registry.Register(c); err != nil {
			if !isAlreadyRegistered(err) {
				panic(err)
			}
		}
	}
}

// Init pre-initializes common label combinations with zero values so
// that metrics appear in /metrics output immediately after startup.
// Prometheus *Vec types only emit metric lines after
// WithLabelValues() is called at least once. This method is
// idempotent and safe to call multiple times.
//
//nolint:funlen // pre-populating many label combinations requires many statements
func (m *RouteMetrics) Init() {
	statusCodes := []string{
		"200", "201", "204", "301", "302",
		"400", "401", "403", "404", "429",
		"500", "502", "503", "504",
	}
	methods := []string{
		"GET", "POST", "PUT", "DELETE",
		"PATCH", "OPTIONS", "HEAD",
	}
	errorTypes := []string{
		"proxy_error", "timeout", "connection_refused",
		"bad_gateway", "service_unavailable",
	}
	timeoutStages := []string{
		"upstream", "middleware", "total",
	}
	authTypes := []string{
		"jwt", "apikey", "basic", "mtls", "oidc",
	}
	authFailReasons := []string{
		"invalid_token", "expired",
		"no_credentials", "forbidden",
	}
	cacheBypassReasons := []string{
		"no_cache_header", "method_not_cacheable",
		"cache_disabled",
	}

	rt := defaultLabel
	consumer := defaultLabel

	for _, method := range methods {
		for _, sc := range statusCodes {
			m.RequestsTotal.WithLabelValues(rt, method, sc)
			m.ResponseSizeBytes.WithLabelValues(rt, method, sc)
			m.RequestDurationSeconds.WithLabelValues(rt, method, sc)
			m.UpstreamDurationSeconds.WithLabelValues(rt, method, sc)
		}
		m.RequestSizeBytes.WithLabelValues(rt, method)
		for _, et := range errorTypes {
			m.ErrorsTotal.WithLabelValues(rt, method, et)
		}
		for _, ts := range timeoutStages {
			m.TimeoutsTotal.WithLabelValues(rt, method, ts)
		}
		m.RateLimitHitsTotal.WithLabelValues(rt, method, consumer)
		for _, at := range authTypes {
			m.AuthSuccessesTotal.WithLabelValues(rt, method, at)
			for _, reason := range authFailReasons {
				m.AuthFailuresTotal.WithLabelValues(
					rt, method, at, reason,
				)
			}
		}
		m.CacheHitsTotal.WithLabelValues(rt, method)
		m.CacheMissesTotal.WithLabelValues(rt, method)
		for _, reason := range cacheBypassReasons {
			m.CacheBypassTotal.WithLabelValues(rt, method, reason)
		}
		m.RetriesTotal.WithLabelValues(rt, method)
		m.RetryExhaustedTotal.WithLabelValues(rt, method)
	}

	m.CircuitBreakerState.WithLabelValues(rt)
	m.CircuitBreakerTripsTotal.WithLabelValues(rt)
	m.CertExpirySeconds.WithLabelValues(rt)
}

// RecordRequest records a completed HTTP request with all relevant
// route-level metrics in a single call.
func (m *RouteMetrics) RecordRequest(
	route, method string,
	statusCode int,
	duration time.Duration,
	reqSize, respSize int64,
) {
	sc := strconv.Itoa(statusCode)
	m.RequestsTotal.WithLabelValues(route, method, sc).Inc()
	m.RequestSizeBytes.WithLabelValues(route, method).Observe(
		float64(reqSize),
	)
	m.ResponseSizeBytes.WithLabelValues(route, method, sc).Observe(
		float64(respSize),
	)
	m.RequestDurationSeconds.WithLabelValues(route, method, sc).Observe(
		duration.Seconds(),
	)
}

// RecordUpstreamDuration records the duration of the upstream
// (backend) request only.
func (m *RouteMetrics) RecordUpstreamDuration(
	route, method string,
	statusCode int,
	duration time.Duration,
) {
	sc := strconv.Itoa(statusCode)
	m.UpstreamDurationSeconds.WithLabelValues(
		route, method, sc,
	).Observe(duration.Seconds())
}

// RecordError records a route-level error by type.
func (m *RouteMetrics) RecordError(
	route, method, errorType string,
) {
	m.ErrorsTotal.WithLabelValues(route, method, errorType).Inc()
}

// RecordTimeout records a route-level timeout by stage.
func (m *RouteMetrics) RecordTimeout(
	route, method, timeoutStage string,
) {
	m.TimeoutsTotal.WithLabelValues(
		route, method, timeoutStage,
	).Inc()
}

// RecordRateLimitHit records a rate limit hit for a route.
func (m *RouteMetrics) RecordRateLimitHit(
	route, method, consumer string,
) {
	m.RateLimitHitsTotal.WithLabelValues(
		route, method, consumer,
	).Inc()
}

// RecordAuthFailure records an authentication failure.
func (m *RouteMetrics) RecordAuthFailure(
	route, method, authType, reason string,
) {
	m.AuthFailuresTotal.WithLabelValues(
		route, method, authType, reason,
	).Inc()
}

// RecordAuthSuccess records an authentication success.
func (m *RouteMetrics) RecordAuthSuccess(
	route, method, authType string,
) {
	m.AuthSuccessesTotal.WithLabelValues(
		route, method, authType,
	).Inc()
}

// RecordCacheHit records a cache hit for a route.
func (m *RouteMetrics) RecordCacheHit(route, method string) {
	m.CacheHitsTotal.WithLabelValues(route, method).Inc()
}

// RecordCacheMiss records a cache miss for a route.
func (m *RouteMetrics) RecordCacheMiss(route, method string) {
	m.CacheMissesTotal.WithLabelValues(route, method).Inc()
}

// RecordCacheBypass records a cache bypass for a route.
func (m *RouteMetrics) RecordCacheBypass(
	route, method, reason string,
) {
	m.CacheBypassTotal.WithLabelValues(
		route, method, reason,
	).Inc()
}

// RecordRetry records a retry attempt for a route.
func (m *RouteMetrics) RecordRetry(route, method string) {
	m.RetriesTotal.WithLabelValues(route, method).Inc()
}

// RecordRetryExhausted records an exhausted retry for a route.
func (m *RouteMetrics) RecordRetryExhausted(route, method string) {
	m.RetryExhaustedTotal.WithLabelValues(route, method).Inc()
}

// collectors returns all metric collectors for registration.
func (m *RouteMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.RequestsTotal,
		m.RequestSizeBytes,
		m.ResponseSizeBytes,
		m.RequestDurationSeconds,
		m.UpstreamDurationSeconds,
		m.ErrorsTotal,
		m.TimeoutsTotal,
		m.RateLimitHitsTotal,
		m.AuthFailuresTotal,
		m.AuthSuccessesTotal,
		m.CircuitBreakerState,
		m.CircuitBreakerTripsTotal,
		m.CacheHitsTotal,
		m.CacheMissesTotal,
		m.CacheBypassTotal,
		m.RetriesTotal,
		m.RetryExhaustedTotal,
		m.CertExpirySeconds,
	}
}

// isAlreadyRegistered returns true if the error indicates the
// collector was already registered with the registry.
func isAlreadyRegistered(err error) bool {
	var are prometheus.AlreadyRegisteredError
	return errors.As(err, &are)
}
