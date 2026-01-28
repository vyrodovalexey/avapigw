package oidc

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
			assert.NotNil(t, m.discoveryTotal)
			assert.NotNil(t, m.tokenValidationTotal)
			assert.NotNil(t, m.tokenValidationDuration)
			assert.NotNil(t, m.introspectionTotal)
			assert.NotNil(t, m.introspectionDuration)
			assert.NotNil(t, m.userinfoTotal)
			assert.NotNil(t, m.registry)
		})
	}
}

func TestMetrics_RecordDiscovery(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	tests := []struct {
		name     string
		status   string
		provider string
	}{
		{
			name:     "success",
			status:   "success",
			provider: "keycloak",
		},
		{
			name:     "cache hit",
			status:   "cache_hit",
			provider: "auth0",
		},
		{
			name:     "error",
			status:   "error",
			provider: "okta",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record discovery - should not panic
			assert.NotPanics(t, func() {
				m.RecordDiscovery(tt.status, tt.provider)
			})
		})
	}
}

func TestMetrics_RecordTokenValidation(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	tests := []struct {
		name     string
		status   string
		provider string
		duration time.Duration
	}{
		{
			name:     "success",
			status:   "success",
			provider: "keycloak",
			duration: 10 * time.Millisecond,
		},
		{
			name:     "error",
			status:   "error",
			provider: "auth0",
			duration: 5 * time.Millisecond,
		},
		{
			name:     "expired",
			status:   "expired",
			provider: "okta",
			duration: 1 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record token validation - should not panic
			assert.NotPanics(t, func() {
				m.RecordTokenValidation(tt.status, tt.provider, tt.duration)
			})
		})
	}
}

func TestMetrics_RecordIntrospection(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	tests := []struct {
		name     string
		status   string
		provider string
		duration time.Duration
	}{
		{
			name:     "active",
			status:   "active",
			provider: "keycloak",
			duration: 50 * time.Millisecond,
		},
		{
			name:     "inactive",
			status:   "inactive",
			provider: "auth0",
			duration: 30 * time.Millisecond,
		},
		{
			name:     "error",
			status:   "error",
			provider: "okta",
			duration: 100 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record introspection - should not panic
			assert.NotPanics(t, func() {
				m.RecordIntrospection(tt.status, tt.provider, tt.duration)
			})
		})
	}
}

func TestMetrics_RecordUserinfo(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	tests := []struct {
		name     string
		status   string
		provider string
	}{
		{
			name:     "success",
			status:   "success",
			provider: "keycloak",
		},
		{
			name:     "error",
			status:   "error",
			provider: "auth0",
		},
		{
			name:     "unauthorized",
			status:   "unauthorized",
			provider: "okta",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Record userinfo - should not panic
			assert.NotPanics(t, func() {
				m.RecordUserinfo(tt.status, tt.provider)
			})
		})
	}
}

func TestMetrics_Registry(t *testing.T) {
	t.Parallel()

	m := NewMetrics("test")

	registry := m.Registry()
	assert.NotNil(t, registry)

	// Record some metrics first so they appear in gather
	m.RecordDiscovery("success", "test")
	m.RecordTokenValidation("success", "test", time.Millisecond)
	m.RecordIntrospection("active", "test", time.Millisecond)
	m.RecordUserinfo("success", "test")

	// Verify metrics are registered
	mfs, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)

	// Check that expected metrics exist
	metricNames := make(map[string]bool)
	for _, mf := range mfs {
		metricNames[mf.GetName()] = true
	}

	assert.True(t, metricNames["test_oidc_discovery_total"])
	assert.True(t, metricNames["test_oidc_token_validation_total"])
	assert.True(t, metricNames["test_oidc_token_validation_duration_seconds"])
	assert.True(t, metricNames["test_oidc_introspection_total"])
	assert.True(t, metricNames["test_oidc_introspection_duration_seconds"])
	assert.True(t, metricNames["test_oidc_userinfo_total"])
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
	m.RecordDiscovery("success", "test")

	// Verify metrics are registered in the new registry
	mfs, err := registry.Gather()
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, mf := range mfs {
		metricNames[mf.GetName()] = true
	}

	assert.True(t, metricNames["test_register_oidc_discovery_total"])
}

func TestMetrics_MultipleRecords(t *testing.T) {
	t.Parallel()

	m := NewMetrics("multi")

	// Record multiple operations
	for i := 0; i < 10; i++ {
		m.RecordDiscovery("success", "provider1")
		m.RecordTokenValidation("success", "provider1", time.Duration(i)*time.Millisecond)
	}

	for i := 0; i < 5; i++ {
		m.RecordDiscovery("error", "provider2")
		m.RecordIntrospection("error", "provider2", time.Duration(i)*time.Millisecond)
	}

	for i := 0; i < 3; i++ {
		m.RecordUserinfo("success", "provider1")
		m.RecordUserinfo("error", "provider2")
	}

	// Gather and verify
	mfs, err := m.Registry().Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, mfs)
}
