package vault

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// vaultRequestsTotal counts total Vault requests.
	vaultRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vault_requests_total",
			Help: "Total number of Vault requests",
		},
		[]string{"operation", "status"},
	)

	// vaultRequestDuration measures Vault request duration.
	vaultRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "vault_request_duration_seconds",
			Help:    "Duration of Vault requests in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"operation"},
	)

	// vaultAuthenticationsTotal counts total Vault authentications.
	vaultAuthenticationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vault_authentications_total",
			Help: "Total number of Vault authentication attempts",
		},
		[]string{"method", "status"},
	)

	// vaultSecretsWatched tracks the number of secrets being watched.
	vaultSecretsWatched = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "vault_secrets_watched",
			Help: "Number of secrets currently being watched",
		},
	)

	// vaultSecretRefreshTotal counts secret refresh operations.
	vaultSecretRefreshTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vault_secret_refresh_total",
			Help: "Total number of secret refresh operations",
		},
		[]string{"path", "status"},
	)

	// vaultCacheHits counts cache hits.
	vaultCacheHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "vault_cache_hits_total",
			Help: "Total number of Vault cache hits",
		},
	)

	// vaultCacheMisses counts cache misses.
	vaultCacheMisses = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "vault_cache_misses_total",
			Help: "Total number of Vault cache misses",
		},
	)

	// vaultTokenExpiryTime tracks token expiry time.
	vaultTokenExpiryTime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "vault_token_expiry_timestamp_seconds",
			Help: "Unix timestamp when the Vault token expires",
		},
	)

	// vaultRetryTotal counts retry attempts.
	vaultRetryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "vault_retry_total",
			Help: "Total number of Vault retry attempts",
		},
		[]string{"operation", "attempt"},
	)

	// vaultConnectionErrors counts connection errors.
	vaultConnectionErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "vault_connection_errors_total",
			Help: "Total number of Vault connection errors",
		},
	)

	// vaultCacheSize tracks the current size of the secret cache.
	vaultCacheSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "vault_cache_size",
			Help: "Current number of entries in the Vault secret cache",
		},
	)

	// vaultCacheEvictions counts cache evictions.
	vaultCacheEvictions = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "vault_cache_evictions_total",
			Help: "Total number of Vault cache evictions due to LRU policy",
		},
	)

	// vaultClientCacheSize tracks the current size of the Vault client cache.
	vaultClientCacheSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "vault_client_cache_size",
			Help: "Current number of Vault clients in the cache",
		},
	)

	// vaultClientCacheHits counts Vault client cache hits.
	vaultClientCacheHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "vault_client_cache_hits_total",
			Help: "Total number of Vault client cache hits",
		},
	)

	// vaultClientCacheMisses counts Vault client cache misses.
	vaultClientCacheMisses = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "vault_client_cache_misses_total",
			Help: "Total number of Vault client cache misses",
		},
	)

	// vaultClientCacheEvictions counts Vault client cache evictions.
	vaultClientCacheEvictions = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "vault_client_cache_evictions_total",
			Help: "Total number of Vault client cache evictions",
		},
	)
)

const (
	statusSuccess = "success"
	statusError   = "error"
)

// RecordRequest records a Vault request metric.
// Includes nil checks and panic recovery for safety.
func RecordRequest(operation string, duration time.Duration, success bool) {
	defer func() {
		// Silently recover from any panic in metrics recording
		// This ensures metrics issues don't crash the application
		_ = recover()
	}()

	if vaultRequestsTotal == nil || vaultRequestDuration == nil {
		return
	}

	status := statusSuccess
	if !success {
		status = statusError
	}
	vaultRequestsTotal.WithLabelValues(operation, status).Inc()
	vaultRequestDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordAuthentication records a Vault authentication metric.
// Includes nil checks and panic recovery for safety.
func RecordAuthentication(method string, success bool) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultAuthenticationsTotal == nil {
		return
	}

	status := statusSuccess
	if !success {
		status = statusError
	}
	vaultAuthenticationsTotal.WithLabelValues(method, status).Inc()
}

// UpdateSecretsWatched updates the number of secrets being watched.
// Includes nil checks and panic recovery for safety.
func UpdateSecretsWatched(count int) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultSecretsWatched == nil {
		return
	}

	vaultSecretsWatched.Set(float64(count))
}

// RecordSecretRefresh records a secret refresh operation.
// Includes nil checks and panic recovery for safety.
func RecordSecretRefresh(path string, success bool) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultSecretRefreshTotal == nil {
		return
	}

	status := statusSuccess
	if !success {
		status = statusError
	}
	vaultSecretRefreshTotal.WithLabelValues(path, status).Inc()
}

// RecordCacheHit records a cache hit.
// Includes nil checks and panic recovery for safety.
func RecordCacheHit() {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultCacheHits == nil {
		return
	}

	vaultCacheHits.Inc()
}

// RecordCacheMiss records a cache miss.
// Includes nil checks and panic recovery for safety.
func RecordCacheMiss() {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultCacheMisses == nil {
		return
	}

	vaultCacheMisses.Inc()
}

// UpdateTokenExpiry updates the token expiry timestamp.
// Includes nil checks and panic recovery for safety.
func UpdateTokenExpiry(expiry time.Time) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultTokenExpiryTime == nil {
		return
	}

	if expiry.IsZero() {
		vaultTokenExpiryTime.Set(0)
	} else {
		vaultTokenExpiryTime.Set(float64(expiry.Unix()))
	}
}

// RecordRetry records a retry attempt.
// Includes nil checks and panic recovery for safety.
func RecordRetry(operation string, attempt int) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultRetryTotal == nil {
		return
	}

	vaultRetryTotal.WithLabelValues(operation, string(rune('0'+attempt))).Inc()
}

// RecordConnectionError records a connection error.
// Includes nil checks and panic recovery for safety.
func RecordConnectionError() {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultConnectionErrors == nil {
		return
	}

	vaultConnectionErrors.Inc()
}

// UpdateCacheSize updates the current cache size metric.
// Includes nil checks and panic recovery for safety.
func UpdateCacheSize(size int) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultCacheSize == nil {
		return
	}

	vaultCacheSize.Set(float64(size))
}

// RecordCacheEviction records a cache eviction due to LRU policy.
// Includes nil checks and panic recovery for safety.
func RecordCacheEviction() {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultCacheEvictions == nil {
		return
	}

	vaultCacheEvictions.Inc()
}

// UpdateVaultClientCacheSize updates the current Vault client cache size metric.
// Includes nil checks and panic recovery for safety.
func UpdateVaultClientCacheSize(size int) {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultClientCacheSize == nil {
		return
	}

	vaultClientCacheSize.Set(float64(size))
}

// RecordVaultClientCacheHit records a Vault client cache hit.
// Includes nil checks and panic recovery for safety.
func RecordVaultClientCacheHit() {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultClientCacheHits == nil {
		return
	}

	vaultClientCacheHits.Inc()
}

// RecordVaultClientCacheMiss records a Vault client cache miss.
// Includes nil checks and panic recovery for safety.
func RecordVaultClientCacheMiss() {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultClientCacheMisses == nil {
		return
	}

	vaultClientCacheMisses.Inc()
}

// RecordVaultClientCacheEviction records a Vault client cache eviction.
// Includes nil checks and panic recovery for safety.
func RecordVaultClientCacheEviction() {
	defer func() {
		// Silently recover from any panic in metrics recording
		_ = recover()
	}()

	if vaultClientCacheEvictions == nil {
		return
	}

	vaultClientCacheEvictions.Inc()
}
