package auth

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	t.Parallel()

	t.Run("creates metrics with default namespace", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("")
		require.NotNil(t, metrics)
		assert.NotNil(t, metrics.requestsTotal)
		assert.NotNil(t, metrics.requestDuration)
		assert.NotNil(t, metrics.tokenRefreshTotal)
		assert.NotNil(t, metrics.errorsTotal)
		assert.NotNil(t, metrics.credentialCacheHits)
		assert.NotNil(t, metrics.credentialCacheMiss)
		assert.NotNil(t, metrics.tokenExpiryGauge)
		assert.NotNil(t, metrics.registry)

		// Verify metrics can be gathered from internal registry
		metrics.RecordRequest("test", "jwt", "success", time.Millisecond)
		families, err := metrics.Registry().Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, families)
	})

	t.Run("creates metrics with custom namespace", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("custom")
		require.NotNil(t, metrics)
		assert.NotNil(t, metrics.registry)

		// Verify custom namespace is used
		metrics.RecordRequest("test", "jwt", "success", time.Millisecond)
		families, err := metrics.Registry().Gather()
		require.NoError(t, err)

		// Check that at least one metric has the custom namespace
		found := false
		for _, family := range families {
			if family.GetName() == "custom_backend_auth_requests_total" {
				found = true
				break
			}
		}
		assert.True(t, found, "metric with custom namespace should be present")
	})
}

func TestMetrics_RecordRequest(t *testing.T) {
	t.Parallel()

	t.Run("records request metrics", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("test_request")

		// Should not panic
		metrics.RecordRequest("test-provider", "jwt", "success", 100*time.Millisecond)
		metrics.RecordRequest("test-provider", "jwt", "error", 50*time.Millisecond)
		metrics.RecordRequest("test-provider", "basic", "success", 10*time.Millisecond)
	})
}

func TestMetrics_RecordRefresh(t *testing.T) {
	t.Parallel()

	t.Run("records refresh metrics", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("test_refresh")

		// Should not panic
		metrics.RecordRefresh("test-provider", "jwt", "success", 200*time.Millisecond)
		metrics.RecordRefresh("test-provider", "jwt", "error", 100*time.Millisecond)
	})
}

func TestMetrics_RecordError(t *testing.T) {
	t.Parallel()

	t.Run("records error metrics", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("test_error")

		// Should not panic
		metrics.RecordError("test-provider", "jwt", "token_expired")
		metrics.RecordError("test-provider", "basic", "credential_acquisition")
		metrics.RecordError("test-provider", "mtls", "certificate_load")
	})
}

func TestMetrics_RecordCacheHit(t *testing.T) {
	t.Parallel()

	t.Run("records cache hit", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("test_cache_hit")

		// Should not panic
		metrics.RecordCacheHit()
		metrics.RecordCacheHit()
	})
}

func TestMetrics_RecordCacheMiss(t *testing.T) {
	t.Parallel()

	t.Run("records cache miss", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("test_cache_miss")

		// Should not panic
		metrics.RecordCacheMiss()
		metrics.RecordCacheMiss()
	})
}

func TestMetrics_SetTokenExpiry(t *testing.T) {
	t.Parallel()

	t.Run("sets token expiry", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("test_expiry")
		expiry := time.Now().Add(1 * time.Hour)

		// Should not panic
		metrics.SetTokenExpiry("test-provider", "jwt", expiry)
	})
}

func TestMetrics_Registry(t *testing.T) {
	t.Parallel()

	t.Run("returns the prometheus registry", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("test_registry")
		registry := metrics.Registry()

		assert.NotNil(t, registry)
		assert.IsType(t, &prometheus.Registry{}, registry)
	})
}

func TestMetrics_MustRegister(t *testing.T) {
	t.Parallel()

	t.Run("registers metrics with external registry", func(t *testing.T) {
		t.Parallel()

		// Create a new registry to register metrics with
		externalRegistry := prometheus.NewRegistry()

		// Create metrics (they are already registered with their internal registry)
		metrics := NewMetrics("test_must_register")

		// Register with external registry
		// This should not panic
		metrics.MustRegister(externalRegistry)

		// Record some metrics to ensure they appear in the gathered output
		metrics.RecordRequest("test-provider", "jwt", "success", 100*time.Millisecond)
		metrics.RecordRefresh("test-provider", "jwt", "success", 50*time.Millisecond)
		metrics.RecordError("test-provider", "jwt", "token_expired")
		metrics.RecordCacheHit()
		metrics.RecordCacheMiss()
		metrics.SetTokenExpiry("test-provider", "jwt", time.Now().Add(1*time.Hour))

		// Verify metrics are registered by gathering them
		families, err := externalRegistry.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, families)

		// Check that expected metric families are present
		metricNames := make(map[string]bool)
		for _, family := range families {
			metricNames[family.GetName()] = true
		}

		// Verify all expected metrics are present
		assert.True(t, metricNames["test_must_register_backend_auth_requests_total"],
			"requests_total metric should be present")
		assert.True(t, metricNames["test_must_register_backend_auth_request_duration_seconds"],
			"request_duration_seconds metric should be present")
		assert.True(t, metricNames["test_must_register_backend_auth_token_refresh_total"],
			"token_refresh_total metric should be present")
		assert.True(t, metricNames["test_must_register_backend_auth_errors_total"],
			"errors_total metric should be present")
		assert.True(t, metricNames["test_must_register_backend_auth_credential_cache_hits_total"],
			"credential_cache_hits_total metric should be present")
		assert.True(t, metricNames["test_must_register_backend_auth_credential_cache_misses_total"],
			"credential_cache_misses_total metric should be present")
		assert.True(t, metricNames["test_must_register_backend_auth_token_expiry_seconds"],
			"token_expiry_seconds metric should be present")
	})
}

func TestNopMetrics(t *testing.T) {
	t.Parallel()

	t.Run("returns a valid metrics instance", func(t *testing.T) {
		t.Parallel()

		metrics := NopMetrics()
		require.NotNil(t, metrics)

		// All operations should work without panic
		metrics.RecordRequest("test", "jwt", "success", time.Millisecond)
		metrics.RecordRefresh("test", "jwt", "success", time.Millisecond)
		metrics.RecordError("test", "jwt", "error")
		metrics.RecordCacheHit()
		metrics.RecordCacheMiss()
		metrics.SetTokenExpiry("test", "jwt", time.Now())
	})
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	t.Run("handles concurrent access safely", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("test_concurrent")

		// Run multiple goroutines accessing metrics concurrently
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					metrics.RecordRequest("provider", "jwt", "success", time.Millisecond)
					metrics.RecordRefresh("provider", "jwt", "success", time.Millisecond)
					metrics.RecordError("provider", "jwt", "error")
					metrics.RecordCacheHit()
					metrics.RecordCacheMiss()
					metrics.SetTokenExpiry("provider", "jwt", time.Now())
				}
				done <- true
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

func TestMetrics_Init(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_init")

	// Init should not panic
	assert.NotPanics(t, func() {
		metrics.Init()
	})

	// Verify metrics are pre-populated by gathering from registry
	mfs, err := metrics.Registry().Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)

	// Init should be idempotent
	assert.NotPanics(t, func() {
		metrics.Init()
	})
}
