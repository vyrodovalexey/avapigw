package auth

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	sharedMetricsInstance *Metrics
	sharedMetricsOnce     sync.Once
)

// GetSharedMetrics returns the singleton backend auth metrics instance.
// This shared instance should be used by all backend auth providers
// and registered with the gateway's custom Prometheus registry.
func GetSharedMetrics() *Metrics {
	sharedMetricsOnce.Do(func() {
		sharedMetricsInstance = NewMetrics("gateway")
	})
	return sharedMetricsInstance
}

// Metrics holds Prometheus metrics for backend authentication operations.
type Metrics struct {
	requestsTotal       *prometheus.CounterVec
	requestDuration     *prometheus.HistogramVec
	tokenRefreshTotal   *prometheus.CounterVec
	errorsTotal         *prometheus.CounterVec
	credentialCacheHits prometheus.Counter
	credentialCacheMiss prometheus.Counter
	tokenExpiryGauge    *prometheus.GaugeVec
	registry            *prometheus.Registry
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
			Subsystem: "backend_auth",
			Name:      "requests_total",
			Help:      "Total number of backend authentication requests",
		},
		[]string{"provider", "auth_type", "status"},
	)

	m.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "backend_auth",
			Name:      "request_duration_seconds",
			Help:      "Backend authentication request duration in seconds",
			Buckets:   []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"provider", "auth_type", "operation"},
	)

	m.tokenRefreshTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "backend_auth",
			Name:      "token_refresh_total",
			Help:      "Total number of token refresh operations",
		},
		[]string{"provider", "auth_type", "status"},
	)

	m.errorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "backend_auth",
			Name:      "errors_total",
			Help:      "Total number of backend authentication errors",
		},
		[]string{"provider", "auth_type", "error_type"},
	)

	m.credentialCacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "backend_auth",
			Name:      "credential_cache_hits_total",
			Help:      "Total number of credential cache hits",
		},
	)

	m.credentialCacheMiss = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "backend_auth",
			Name:      "credential_cache_misses_total",
			Help:      "Total number of credential cache misses",
		},
	)

	m.tokenExpiryGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "backend_auth",
			Name:      "token_expiry_seconds",
			Help:      "Token expiry timestamp in seconds since epoch",
		},
		[]string{"provider", "auth_type"},
	)

	// Register all metrics
	m.registry.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.tokenRefreshTotal,
		m.errorsTotal,
		m.credentialCacheHits,
		m.credentialCacheMiss,
		m.tokenExpiryGauge,
	)

	return m
}

// Init pre-populates common label combinations with zero values so
// that backend auth Vec metrics appear in /metrics output immediately
// after startup. Prometheus *Vec types only emit metric lines after
// WithLabelValues() is called at least once. This method is
// idempotent and safe to call multiple times.
func (m *Metrics) Init() {
	authTypes := []string{"oidc", "basic", "mtls"}
	errorTypes := []string{
		"token_error",
		"connection_error",
		"auth_failed",
	}
	statuses := []string{"success", "error"}

	for _, at := range authTypes {
		for _, et := range errorTypes {
			m.errorsTotal.WithLabelValues("default", at, et)
		}
		for _, s := range statuses {
			m.tokenRefreshTotal.WithLabelValues("default", at, s)
		}
	}
}

// RecordRequest records a backend authentication request.
func (m *Metrics) RecordRequest(provider, authType, status string, duration time.Duration) {
	m.requestsTotal.WithLabelValues(provider, authType, status).Inc()
	m.requestDuration.WithLabelValues(provider, authType, "apply").Observe(duration.Seconds())
}

// RecordRefresh records a token refresh operation.
func (m *Metrics) RecordRefresh(provider, authType, status string, duration time.Duration) {
	m.tokenRefreshTotal.WithLabelValues(provider, authType, status).Inc()
	m.requestDuration.WithLabelValues(provider, authType, "refresh").Observe(duration.Seconds())
}

// RecordError records an authentication error.
func (m *Metrics) RecordError(provider, authType, errorType string) {
	m.errorsTotal.WithLabelValues(provider, authType, errorType).Inc()
}

// RecordCacheHit records a credential cache hit.
func (m *Metrics) RecordCacheHit() {
	m.credentialCacheHits.Inc()
}

// RecordCacheMiss records a credential cache miss.
func (m *Metrics) RecordCacheMiss() {
	m.credentialCacheMiss.Inc()
}

// SetTokenExpiry sets the token expiry timestamp.
func (m *Metrics) SetTokenExpiry(provider, authType string, expiry time.Time) {
	m.tokenExpiryGauge.WithLabelValues(provider, authType).Set(float64(expiry.Unix()))
}

// Registry returns the Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// MustRegister registers the metrics with the given registry.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.tokenRefreshTotal,
		m.errorsTotal,
		m.credentialCacheHits,
		m.credentialCacheMiss,
		m.tokenExpiryGauge,
	)
}

// NopMetrics returns a no-op metrics instance for testing.
func NopMetrics() *Metrics {
	return NewMetrics("test")
}
