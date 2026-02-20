package security

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// defaultSecurityMetrics holds the singleton Metrics instance registered with the default global registry.
var (
	defaultSecurityMetrics     *Metrics
	defaultSecurityMetricsOnce sync.Once
)

// GetSecurityMetrics returns the singleton security metrics instance.
// It initializes the metrics on first call (singleton pattern).
func GetSecurityMetrics() *Metrics {
	defaultSecurityMetricsOnce.Do(func() {
		defaultSecurityMetrics = NewMetrics("gateway")
	})
	return defaultSecurityMetrics
}

// Metrics contains security metrics.
type Metrics struct {
	// headersApplied counts the number of times security headers were applied.
	headersApplied *prometheus.CounterVec

	// hstsApplied counts the number of times HSTS header was applied.
	hstsApplied prometheus.Counter

	// cspApplied counts the number of times CSP header was applied.
	cspApplied prometheus.Counter

	// cspViolations counts CSP violations reported.
	cspViolations *prometheus.CounterVec
}

// NewMetrics creates new security metrics.
func NewMetrics(namespace string) *Metrics {
	return &Metrics{
		headersApplied: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "security",
				Name:      "headers_applied_total",
				Help:      "Total number of times security headers were applied",
			},
			[]string{"header"},
		),
		hstsApplied: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "security",
				Name:      "hsts_applied_total",
				Help:      "Total number of times HSTS header was applied",
			},
		),
		cspApplied: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "security",
				Name:      "csp_applied_total",
				Help:      "Total number of times CSP header was applied",
			},
		),
		cspViolations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: "security",
				Name:      "csp_violations_total",
				Help:      "Total number of CSP violations reported",
			},
			[]string{"directive", "blocked_uri"},
		),
	}
}

// MustRegister registers all security metric collectors with the
// given Prometheus registry. This is needed because promauto registers
// metrics with the default global registry, but the gateway serves
// /metrics from a custom registry. Calling MustRegister bridges the
// two so security metrics appear on the gateway's metrics endpoint.
func (m *Metrics) MustRegister(registry *prometheus.Registry) {
	registry.MustRegister(
		m.headersApplied,
		m.hstsApplied,
		m.cspApplied,
		m.cspViolations,
	)
}

// Init pre-initializes common label combinations with zero values so
// that metrics appear in /metrics output immediately after startup.
// Prometheus *Vec types only emit metric lines after WithLabelValues()
// is called at least once. This method is idempotent and safe to call
// multiple times.
func (m *Metrics) Init() {
	for _, header := range []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
	} {
		m.headersApplied.WithLabelValues(header)
	}

	// Pre-populate CSP violation directives with common values.
	cspDirectives := []string{
		"script-src",
		"style-src",
		"img-src",
		"connect-src",
		"default-src",
	}
	for _, directive := range cspDirectives {
		m.cspViolations.WithLabelValues(directive, "unknown")
	}
}

// RecordHeaderApplied records that a security header was applied.
func (m *Metrics) RecordHeaderApplied(header string) {
	m.headersApplied.WithLabelValues(header).Inc()
}

// RecordHSTSApplied records that HSTS header was applied.
func (m *Metrics) RecordHSTSApplied() {
	m.hstsApplied.Inc()
}

// RecordCSPApplied records that CSP header was applied.
func (m *Metrics) RecordCSPApplied() {
	m.cspApplied.Inc()
}

// RecordCSPViolation records a CSP violation.
func (m *Metrics) RecordCSPViolation(directive, blockedURI string) {
	m.cspViolations.WithLabelValues(directive, blockedURI).Inc()
}
