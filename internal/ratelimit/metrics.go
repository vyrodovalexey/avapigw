package ratelimit

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RateLimitRequestsTotal counts total rate limit checks.
	RateLimitRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ratelimit_requests_total",
			Help: "Total number of rate limit checks",
		},
		[]string{"key", "allowed"},
	)

	// RateLimitRejectedTotal counts rejected requests.
	RateLimitRejectedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ratelimit_rejected_total",
			Help: "Total number of rejected requests due to rate limiting",
		},
		[]string{"key"},
	)

	// RateLimitRemaining shows remaining requests in the current window.
	RateLimitRemaining = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ratelimit_remaining",
			Help: "Remaining requests in the current rate limit window",
		},
		[]string{"key"},
	)

	// RateLimitLatency measures rate limit check latency.
	RateLimitLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ratelimit_check_duration_seconds",
			Help:    "Rate limit check duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"algorithm"},
	)
)

// RecordRateLimitCheck records a rate limit check.
func RecordRateLimitCheck(key string, allowed bool) {
	allowedStr := "true"
	if !allowed {
		allowedStr = "false"
		RateLimitRejectedTotal.WithLabelValues(key).Inc()
	}
	RateLimitRequestsTotal.WithLabelValues(key, allowedStr).Inc()
}

// RecordRateLimitRemaining records the remaining requests.
func RecordRateLimitRemaining(key string, remaining int) {
	RateLimitRemaining.WithLabelValues(key).Set(float64(remaining))
}
