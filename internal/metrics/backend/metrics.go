// Package backend provides standardized Prometheus metrics for
// backend-level observability in the API Gateway.
package backend

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
	subsystem    = "backend"
	defaultLabel = "default"
)

// BackendMetrics holds all backend-level Prometheus metrics.
type BackendMetrics struct {
	RequestsTotal                 *prometheus.CounterVec
	ConnectionsTotal              *prometheus.CounterVec
	ConnectionErrorsTotal         *prometheus.CounterVec
	ResponseDurationSeconds       *prometheus.HistogramVec
	ConnectDurationSeconds        *prometheus.HistogramVec
	HealthCheckStatus             *prometheus.GaugeVec
	HealthChecksTotal             *prometheus.CounterVec
	HealthCheckDurationSeconds    *prometheus.HistogramVec
	ConsecutiveFailures           *prometheus.GaugeVec
	LBSelectionsTotal             *prometheus.CounterVec
	LBWeight                      *prometheus.GaugeVec
	PoolSize                      *prometheus.GaugeVec
	CircuitBreakerState           *prometheus.GaugeVec
	CircuitBreakerTripsTotal      *prometheus.CounterVec
	CircuitBreakerRejectionsTotal *prometheus.CounterVec
	PoolIdleConnections           *prometheus.GaugeVec
	PoolActiveConnections         *prometheus.GaugeVec
	PoolWaitTotal                 *prometheus.CounterVec
	PoolWaitDurationSeconds       *prometheus.HistogramVec
	PoolExhaustedTotal            *prometheus.CounterVec
	CacheHitsTotal                *prometheus.CounterVec
	CacheMissesTotal              *prometheus.CounterVec
	CacheBypassTotal              *prometheus.CounterVec
	RateLimitHitsTotal            *prometheus.CounterVec
	AuthFailuresTotal             *prometheus.CounterVec
	AuthSuccessesTotal            *prometheus.CounterVec
	TLSHandshakeDurationSeconds   *prometheus.HistogramVec
	TLSErrorsTotal                *prometheus.CounterVec
	CertExpirySeconds             *prometheus.GaugeVec
}

var (
	backendMetricsInstance *BackendMetrics
	backendMetricsOnce     sync.Once
)

// NewBackendMetrics creates a new BackendMetrics instance with all
// metrics registered via promauto (default global registry).
//
//nolint:funlen // many metrics require many statements
func NewBackendMetrics() *BackendMetrics {
	return &BackendMetrics{
		RequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "requests_total",
				Help: "Total number of requests " +
					"sent to backend",
			},
			[]string{"backend", "method", "status_code"},
		),
		ConnectionsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "connections_total",
				Help: "Total number of connections " +
					"established to backend",
			},
			[]string{"backend"},
		),
		ConnectionErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "connection_errors_total",
				Help: "Total number of connection " +
					"errors by type",
			},
			[]string{"backend", "error_type"},
		),
		ResponseDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "response_duration_seconds",
				Help: "Duration of backend " +
					"response in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"backend", "method", "status_code"},
		),
		ConnectDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "connect_duration_seconds",
				Help: "Duration of backend " +
					"connection establishment",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"backend"},
		),
		HealthCheckStatus: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "health_check_status",
				Help: "Backend health check status " +
					"(1=healthy, 0=unhealthy)",
			},
			[]string{"backend"},
		),
		HealthChecksTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "health_checks_total",
				Help: "Total number of health " +
					"checks by result",
			},
			[]string{"backend", "result"},
		),
		HealthCheckDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name: "health_check_duration" +
					"_seconds",
				Help: "Duration of health check " +
					"execution",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"backend"},
		),
		ConsecutiveFailures: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "consecutive_failures",
				Help: "Number of consecutive " +
					"failures for backend",
			},
			[]string{"backend"},
		),
		LBSelectionsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "lb_selections_total",
				Help: "Total number of load balancer " +
					"selections by algorithm",
			},
			[]string{"backend", "lb_algorithm"},
		),
		LBWeight: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "lb_weight",
				Help: "Current load balancer weight " +
					"for backend",
			},
			[]string{"backend"},
		),
		PoolSize: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "pool_size",
				Help: "Connection pool size " +
					"by state",
			},
			[]string{"pool", "state"},
		),
		CircuitBreakerState: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "circuit_breaker_state",
				Help: "Circuit breaker state " +
					"(0=closed, 1=half-open, 2=open)",
			},
			[]string{"backend"},
		),
		CircuitBreakerTripsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "circuit_breaker_trips_total",
				Help: "Total number of circuit " +
					"breaker trips",
			},
			[]string{"backend"},
		),
		CircuitBreakerRejectionsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name: "circuit_breaker_rejections" +
					"_total",
				Help: "Total number of requests " +
					"rejected by circuit breaker",
			},
			[]string{"backend"},
		),
		PoolIdleConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "pool_idle_connections",
				Help: "Number of idle connections " +
					"in pool",
			},
			[]string{"backend"},
		),
		PoolActiveConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "pool_active_connections",
				Help: "Number of active connections " +
					"in pool",
			},
			[]string{"backend"},
		),
		PoolWaitTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "pool_wait_total",
				Help: "Total number of pool " +
					"wait events",
			},
			[]string{"backend"},
		),
		PoolWaitDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "pool_wait_duration_seconds",
				Help: "Duration of pool wait " +
					"in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"backend"},
		),
		PoolExhaustedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "pool_exhausted_total",
				Help: "Total number of pool " +
					"exhaustion events",
			},
			[]string{"backend"},
		),
		CacheHitsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_hits_total",
				Help:      "Total number of cache hits",
			},
			[]string{"backend", "method"},
		),
		CacheMissesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_misses_total",
				Help:      "Total number of cache misses",
			},
			[]string{"backend", "method"},
		),
		CacheBypassTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cache_bypass_total",
				Help:      "Total number of cache bypasses",
			},
			[]string{"backend", "method", "reason"},
		),
		RateLimitHitsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "ratelimit_hits_total",
				Help:      "Total number of rate limit hits",
			},
			[]string{"backend", "method", "consumer"},
		),
		AuthFailuresTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "auth_failures_total",
				Help: "Total number of " +
					"authentication failures",
			},
			[]string{"backend", "method", "auth_type", "reason"},
		),
		AuthSuccessesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "auth_successes_total",
				Help: "Total number of " +
					"authentication successes",
			},
			[]string{"backend", "method", "auth_type"},
		),
		TLSHandshakeDurationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name: "tls_handshake_duration" +
					"_seconds",
				Help: "Duration of TLS handshake " +
					"by version",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"backend", "tls_version"},
		),
		TLSErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "tls_errors_total",
				Help:      "Total number of TLS errors",
			},
			[]string{"backend", "error_type"},
		),
		CertExpirySeconds: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "cert_expiry_seconds",
				Help: "Time until TLS certificate " +
					"expiry in seconds",
			},
			[]string{"backend"},
		),
	}
}

// GetBackendMetrics returns the singleton backend metrics instance.
func GetBackendMetrics() *BackendMetrics {
	backendMetricsOnce.Do(func() {
		backendMetricsInstance = NewBackendMetrics()
	})
	return backendMetricsInstance
}

// MustRegister registers all backend metric collectors with the given
// Prometheus registry. It uses Register (not MustRegister) to
// gracefully handle duplicate registration that can occur when
// providers are recreated on config reload.
// AlreadyRegisteredError is silently ignored.
func (m *BackendMetrics) MustRegister(registry *prometheus.Registry) {
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
func (m *BackendMetrics) Init() {
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
		"connection_refused", "timeout",
		"tls_error", "dns_error", "reset",
	}
	healthResults := []string{
		"success", "failure", "timeout",
	}
	lbAlgorithms := []string{
		"round_robin", "random",
		"least_connections", "weighted",
	}
	poolStates := []string{
		"idle", "active", "connecting",
	}
	authTypes := []string{
		"oidc", "basic", "mtls", "apikey",
	}
	authFailReasons := []string{
		"token_error", "connection_error",
		"auth_failed", "expired",
	}
	cacheBypassReasons := []string{
		"no_cache_header", "method_not_cacheable",
		"cache_disabled",
	}
	tlsVersions := []string{"1.2", "1.3"}

	be := defaultLabel
	pool := defaultLabel
	consumer := defaultLabel

	for _, method := range methods {
		for _, sc := range statusCodes {
			m.RequestsTotal.WithLabelValues(be, method, sc)
			m.ResponseDurationSeconds.WithLabelValues(
				be, method, sc,
			)
		}
		m.CacheHitsTotal.WithLabelValues(be, method)
		m.CacheMissesTotal.WithLabelValues(be, method)
		for _, reason := range cacheBypassReasons {
			m.CacheBypassTotal.WithLabelValues(
				be, method, reason,
			)
		}
		m.RateLimitHitsTotal.WithLabelValues(be, method, consumer)
		for _, at := range authTypes {
			m.AuthSuccessesTotal.WithLabelValues(be, method, at)
			for _, reason := range authFailReasons {
				m.AuthFailuresTotal.WithLabelValues(
					be, method, at, reason,
				)
			}
		}
	}

	m.ConnectionsTotal.WithLabelValues(be)
	for _, et := range errorTypes {
		m.ConnectionErrorsTotal.WithLabelValues(be, et)
	}
	m.ConnectDurationSeconds.WithLabelValues(be)
	m.HealthCheckStatus.WithLabelValues(be)
	for _, result := range healthResults {
		m.HealthChecksTotal.WithLabelValues(be, result)
	}
	m.HealthCheckDurationSeconds.WithLabelValues(be)
	m.ConsecutiveFailures.WithLabelValues(be)
	for _, alg := range lbAlgorithms {
		m.LBSelectionsTotal.WithLabelValues(be, alg)
	}
	m.LBWeight.WithLabelValues(be)
	for _, state := range poolStates {
		m.PoolSize.WithLabelValues(pool, state)
	}
	m.CircuitBreakerState.WithLabelValues(be)
	m.CircuitBreakerTripsTotal.WithLabelValues(be)
	m.CircuitBreakerRejectionsTotal.WithLabelValues(be)
	m.PoolIdleConnections.WithLabelValues(be)
	m.PoolActiveConnections.WithLabelValues(be)
	m.PoolWaitTotal.WithLabelValues(be)
	m.PoolWaitDurationSeconds.WithLabelValues(be)
	m.PoolExhaustedTotal.WithLabelValues(be)
	for _, ver := range tlsVersions {
		m.TLSHandshakeDurationSeconds.WithLabelValues(be, ver)
	}
	for _, et := range errorTypes {
		m.TLSErrorsTotal.WithLabelValues(be, et)
	}
	m.CertExpirySeconds.WithLabelValues(be)
}

// RecordRequest records a completed backend request.
func (m *BackendMetrics) RecordRequest(
	backend, method string,
	statusCode int,
	duration time.Duration,
) {
	sc := strconv.Itoa(statusCode)
	m.RequestsTotal.WithLabelValues(backend, method, sc).Inc()
	m.ResponseDurationSeconds.WithLabelValues(
		backend, method, sc,
	).Observe(duration.Seconds())
}

// RecordConnection records a new backend connection.
func (m *BackendMetrics) RecordConnection(backend string) {
	m.ConnectionsTotal.WithLabelValues(backend).Inc()
}

// RecordConnectionError records a backend connection error.
func (m *BackendMetrics) RecordConnectionError(
	backend, errorType string,
) {
	m.ConnectionErrorsTotal.WithLabelValues(
		backend, errorType,
	).Inc()
}

// RecordConnectDuration records the duration of a backend connection
// establishment.
func (m *BackendMetrics) RecordConnectDuration(
	backend string, duration time.Duration,
) {
	m.ConnectDurationSeconds.WithLabelValues(backend).Observe(
		duration.Seconds(),
	)
}

// RecordHealthCheck records a health check result and duration.
func (m *BackendMetrics) RecordHealthCheck(
	backend, result string, duration time.Duration,
) {
	m.HealthChecksTotal.WithLabelValues(backend, result).Inc()
	m.HealthCheckDurationSeconds.WithLabelValues(backend).Observe(
		duration.Seconds(),
	)
}

// RecordLBSelection records a load balancer selection.
func (m *BackendMetrics) RecordLBSelection(
	backend, lbAlgorithm string,
) {
	m.LBSelectionsTotal.WithLabelValues(
		backend, lbAlgorithm,
	).Inc()
}

// RecordPoolWait records a pool wait event and its duration.
func (m *BackendMetrics) RecordPoolWait(
	backend string, duration time.Duration,
) {
	m.PoolWaitTotal.WithLabelValues(backend).Inc()
	m.PoolWaitDurationSeconds.WithLabelValues(backend).Observe(
		duration.Seconds(),
	)
}

// RecordPoolExhausted records a pool exhaustion event.
func (m *BackendMetrics) RecordPoolExhausted(backend string) {
	m.PoolExhaustedTotal.WithLabelValues(backend).Inc()
}

// RecordCacheHit records a cache hit for a backend.
func (m *BackendMetrics) RecordCacheHit(backend, method string) {
	m.CacheHitsTotal.WithLabelValues(backend, method).Inc()
}

// RecordCacheMiss records a cache miss for a backend.
func (m *BackendMetrics) RecordCacheMiss(backend, method string) {
	m.CacheMissesTotal.WithLabelValues(backend, method).Inc()
}

// RecordCacheBypass records a cache bypass for a backend.
func (m *BackendMetrics) RecordCacheBypass(
	backend, method, reason string,
) {
	m.CacheBypassTotal.WithLabelValues(
		backend, method, reason,
	).Inc()
}

// RecordRateLimitHit records a rate limit hit for a backend.
func (m *BackendMetrics) RecordRateLimitHit(
	backend, method, consumer string,
) {
	m.RateLimitHitsTotal.WithLabelValues(
		backend, method, consumer,
	).Inc()
}

// RecordAuthFailure records an authentication failure for a backend.
func (m *BackendMetrics) RecordAuthFailure(
	backend, method, authType, reason string,
) {
	m.AuthFailuresTotal.WithLabelValues(
		backend, method, authType, reason,
	).Inc()
}

// RecordAuthSuccess records an authentication success for a backend.
func (m *BackendMetrics) RecordAuthSuccess(
	backend, method, authType string,
) {
	m.AuthSuccessesTotal.WithLabelValues(
		backend, method, authType,
	).Inc()
}

// RecordTLSHandshake records a TLS handshake duration.
func (m *BackendMetrics) RecordTLSHandshake(
	backend, tlsVersion string, duration time.Duration,
) {
	m.TLSHandshakeDurationSeconds.WithLabelValues(
		backend, tlsVersion,
	).Observe(duration.Seconds())
}

// RecordTLSError records a TLS error.
func (m *BackendMetrics) RecordTLSError(
	backend, errorType string,
) {
	m.TLSErrorsTotal.WithLabelValues(backend, errorType).Inc()
}

// RecordCircuitBreakerTrip records a circuit breaker trip.
func (m *BackendMetrics) RecordCircuitBreakerTrip(backend string) {
	m.CircuitBreakerTripsTotal.WithLabelValues(backend).Inc()
}

// RecordCircuitBreakerRejection records a circuit breaker rejection.
func (m *BackendMetrics) RecordCircuitBreakerRejection(
	backend string,
) {
	m.CircuitBreakerRejectionsTotal.WithLabelValues(backend).Inc()
}

// collectors returns all metric collectors for registration.
//
//nolint:funlen // many collectors require many statements
func (m *BackendMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.RequestsTotal,
		m.ConnectionsTotal,
		m.ConnectionErrorsTotal,
		m.ResponseDurationSeconds,
		m.ConnectDurationSeconds,
		m.HealthCheckStatus,
		m.HealthChecksTotal,
		m.HealthCheckDurationSeconds,
		m.ConsecutiveFailures,
		m.LBSelectionsTotal,
		m.LBWeight,
		m.PoolSize,
		m.CircuitBreakerState,
		m.CircuitBreakerTripsTotal,
		m.CircuitBreakerRejectionsTotal,
		m.PoolIdleConnections,
		m.PoolActiveConnections,
		m.PoolWaitTotal,
		m.PoolWaitDurationSeconds,
		m.PoolExhaustedTotal,
		m.CacheHitsTotal,
		m.CacheMissesTotal,
		m.CacheBypassTotal,
		m.RateLimitHitsTotal,
		m.AuthFailuresTotal,
		m.AuthSuccessesTotal,
		m.TLSHandshakeDurationSeconds,
		m.TLSErrorsTotal,
		m.CertExpirySeconds,
	}
}

// isAlreadyRegistered returns true if the error indicates the
// collector was already registered with the registry.
func isAlreadyRegistered(err error) bool {
	var are prometheus.AlreadyRegisteredError
	return errors.As(err, &are)
}
