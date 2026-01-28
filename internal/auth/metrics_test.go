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

	tests := []struct {
		name      string
		namespace string
	}{
		{
			name:      "with namespace",
			namespace: "test",
		},
		{
			name:      "empty namespace defaults to gateway",
			namespace: "",
		},
		{
			name:      "custom namespace",
			namespace: "myapp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := NewMetrics(tt.namespace)
			require.NotNil(t, m)
			assert.NotNil(t, m.requestsTotal)
			assert.NotNil(t, m.requestDuration)
			assert.NotNil(t, m.authSuccessTotal)
			assert.NotNil(t, m.authFailureTotal)
			assert.NotNil(t, m.cacheHits)
			assert.NotNil(t, m.cacheMisses)
			assert.NotNil(t, m.registry)
		})
	}
}

func TestMetrics_RecordRequest(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	tests := []struct {
		name     string
		method   string
		authType string
		status   string
		duration time.Duration
	}{
		{
			name:     "HTTP JWT success",
			method:   "http",
			authType: "jwt",
			status:   "success",
			duration: 10 * time.Millisecond,
		},
		{
			name:     "HTTP API key failure",
			method:   "http",
			authType: "apikey",
			status:   "failure",
			duration: 5 * time.Millisecond,
		},
		{
			name:     "gRPC JWT success",
			method:   "grpc",
			authType: "jwt",
			status:   "success",
			duration: 15 * time.Millisecond,
		},
		{
			name:     "HTTP mTLS success",
			method:   "http",
			authType: "mtls",
			status:   "success",
			duration: 20 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record request - should not panic
			assert.NotPanics(t, func() {
				m.RecordRequest(tt.method, tt.authType, tt.status, tt.duration)
			})
		})
	}
}

func TestMetrics_RecordSuccess(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	authTypes := []string{"jwt", "apikey", "mtls", "oidc"}

	for _, authType := range authTypes {
		t.Run(authType, func(t *testing.T) {
			// Record success - should not panic
			assert.NotPanics(t, func() {
				m.RecordSuccess(authType)
			})
		})
	}
}

func TestMetrics_RecordFailure(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	tests := []struct {
		name     string
		authType string
		reason   string
	}{
		{
			name:     "JWT expired",
			authType: "jwt",
			reason:   "token_expired",
		},
		{
			name:     "API key invalid",
			authType: "apikey",
			reason:   "invalid_key",
		},
		{
			name:     "mTLS untrusted",
			authType: "mtls",
			reason:   "untrusted_certificate",
		},
		{
			name:     "no credentials",
			authType: "unknown",
			reason:   "no_credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record failure - should not panic
			assert.NotPanics(t, func() {
				m.RecordFailure(tt.authType, tt.reason)
			})
		})
	}
}

func TestMetrics_RecordCacheHit(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	// Record multiple cache hits - should not panic
	for i := 0; i < 10; i++ {
		assert.NotPanics(t, func() {
			m.RecordCacheHit()
		})
	}
}

func TestMetrics_RecordCacheMiss(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	// Record multiple cache misses - should not panic
	for i := 0; i < 10; i++ {
		assert.NotPanics(t, func() {
			m.RecordCacheMiss()
		})
	}
}

func TestMetrics_Registry(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	registry := m.Registry()
	assert.NotNil(t, registry)

	// Record some metrics first so they appear in gather
	m.RecordRequest("http", "jwt", "success", time.Millisecond)
	m.RecordSuccess("jwt")
	m.RecordFailure("apikey", "invalid")
	m.RecordCacheHit()
	m.RecordCacheMiss()

	// Verify metrics are registered
	mfs, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)

	// Check that expected metrics exist
	metricNames := make(map[string]bool)
	for _, mf := range mfs {
		metricNames[mf.GetName()] = true
	}

	assert.True(t, metricNames["test_auth_requests_total"])
	assert.True(t, metricNames["test_auth_request_duration_seconds"])
	assert.True(t, metricNames["test_auth_success_total"])
	assert.True(t, metricNames["test_auth_failure_total"])
	assert.True(t, metricNames["test_auth_cache_hits_total"])
	assert.True(t, metricNames["test_auth_cache_misses_total"])
}

func TestMetrics_MustRegister(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test_register")

	// Create a new registry
	registry := prometheus.NewRegistry()

	// Should not panic
	assert.NotPanics(t, func() {
		m.MustRegister(registry)
	})

	// Record some metrics
	m.RecordRequest("http", "jwt", "success", time.Millisecond)

	// Verify metrics are registered in the new registry
	mfs, err := registry.Gather()
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, mf := range mfs {
		metricNames[mf.GetName()] = true
	}

	assert.True(t, metricNames["test_register_auth_requests_total"])
}

func TestMetrics_MultipleRecords(t *testing.T) {
	t.Parallel()

	m := NewMetrics("multi")

	// Record multiple operations
	for i := 0; i < 100; i++ {
		m.RecordRequest("http", "jwt", "success", time.Duration(i)*time.Microsecond)
		m.RecordSuccess("jwt")
	}

	for i := 0; i < 50; i++ {
		m.RecordRequest("grpc", "apikey", "failure", time.Duration(i)*time.Microsecond)
		m.RecordFailure("apikey", "invalid")
	}

	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			m.RecordCacheHit()
		} else {
			m.RecordCacheMiss()
		}
	}

	// Gather and verify
	mfs, err := m.Registry().Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)
}
