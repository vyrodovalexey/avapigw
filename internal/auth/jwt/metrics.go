package jwt

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Additional metrics for JWT operations.
var (
	// JWKSRefreshTotal counts JWKS refresh attempts.
	JWKSRefreshTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_jwks_refresh_total",
			Help: "Total number of JWKS refresh attempts",
		},
		[]string{"url", "result"},
	)

	// JWKSRefreshDuration measures JWKS refresh duration.
	JWKSRefreshDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "avapigw_jwks_refresh_duration_seconds",
			Help:    "Duration of JWKS refresh in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"url"},
	)

	// JWKSCacheHits counts JWKS cache hits.
	JWKSCacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_jwks_cache_hits_total",
			Help: "Total number of JWKS cache hits",
		},
		[]string{"url"},
	)

	// JWKSCacheMisses counts JWKS cache misses.
	JWKSCacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_jwks_cache_misses_total",
			Help: "Total number of JWKS cache misses",
		},
		[]string{"url"},
	)

	// TokenExtractionTotal counts token extraction attempts.
	TokenExtractionTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_token_extraction_total",
			Help: "Total number of token extraction attempts",
		},
		[]string{"source", "result"},
	)
)

// RecordJWKSRefresh records a JWKS refresh attempt.
func RecordJWKSRefresh(url, result string, duration float64) {
	JWKSRefreshTotal.WithLabelValues(url, result).Inc()
	JWKSRefreshDuration.WithLabelValues(url).Observe(duration)
}

// RecordJWKSCacheHit records a JWKS cache hit.
func RecordJWKSCacheHit(url string) {
	JWKSCacheHits.WithLabelValues(url).Inc()
}

// RecordJWKSCacheMiss records a JWKS cache miss.
func RecordJWKSCacheMiss(url string) {
	JWKSCacheMisses.WithLabelValues(url).Inc()
}

// RecordTokenExtraction records a token extraction attempt.
func RecordTokenExtraction(source, result string) {
	TokenExtractionTotal.WithLabelValues(source, result).Inc()
}
