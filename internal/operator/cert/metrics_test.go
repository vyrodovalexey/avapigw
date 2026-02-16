package cert

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCertMetrics_Singleton(t *testing.T) {
	m1 := GetCertMetrics()
	m2 := GetCertMetrics()

	require.NotNil(t, m1)
	assert.Same(t, m1, m2, "should return same instance")
}

func TestGetCertMetrics_AllFieldsInitialized(t *testing.T) {
	m := GetCertMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.issuedTotal, "issuedTotal should be initialized")
	assert.NotNil(t, m.rotationsTotal, "rotationsTotal should be initialized")
	assert.NotNil(t, m.errorsTotal, "errorsTotal should be initialized")
	assert.NotNil(t, m.expirySeconds, "expirySeconds should be initialized")
}

func TestCertMetrics_RecordIssued(t *testing.T) {
	m := GetCertMetrics()

	tests := []struct {
		name     string
		provider string
	}{
		{name: "selfsigned provider", provider: "metrics-test-selfsigned"},
		{name: "vault provider", provider: "metrics-test-vault"},
		{name: "acme provider", provider: "metrics-test-acme"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.issuedTotal.WithLabelValues(tt.provider),
			)
			m.issuedTotal.WithLabelValues(tt.provider).Inc()
			after := testutil.ToFloat64(
				m.issuedTotal.WithLabelValues(tt.provider),
			)

			assert.Equal(t, before+1, after, "issuedTotal should increment by 1")
		})
	}
}

func TestCertMetrics_RecordRotation(t *testing.T) {
	m := GetCertMetrics()

	before := testutil.ToFloat64(
		m.rotationsTotal.WithLabelValues("metrics-test-rotation"),
	)
	m.rotationsTotal.WithLabelValues("metrics-test-rotation").Inc()
	after := testutil.ToFloat64(
		m.rotationsTotal.WithLabelValues("metrics-test-rotation"),
	)

	assert.Equal(t, before+1, after, "rotationsTotal should increment by 1")
}

func TestCertMetrics_RecordError(t *testing.T) {
	m := GetCertMetrics()

	tests := []struct {
		name      string
		provider  string
		operation string
	}{
		{name: "issue error", provider: "metrics-test-err", operation: "issue"},
		{name: "rotate error", provider: "metrics-test-err", operation: "rotate"},
		{name: "renew error", provider: "metrics-test-err", operation: "renew"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.provider, tt.operation),
			)
			m.errorsTotal.WithLabelValues(tt.provider, tt.operation).Inc()
			after := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.provider, tt.operation),
			)

			assert.Equal(t, before+1, after, "errorsTotal should increment by 1")
		})
	}
}

func TestCertMetrics_SetExpiry(t *testing.T) {
	m := GetCertMetrics()

	tests := []struct {
		name       string
		commonName string
		seconds    float64
	}{
		{name: "long expiry", commonName: "metrics-test-long.example.com", seconds: 86400},
		{name: "short expiry", commonName: "metrics-test-short.example.com", seconds: 3600},
		{name: "expired", commonName: "metrics-test-expired.example.com", seconds: -100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.expirySeconds.WithLabelValues(tt.commonName).Set(tt.seconds)
			val := testutil.ToFloat64(
				m.expirySeconds.WithLabelValues(tt.commonName),
			)

			assert.Equal(t, tt.seconds, val, "expirySeconds should be set correctly")
		})
	}
}

func TestCertMetrics_ConcurrentAccess(t *testing.T) {
	m := GetCertMetrics()

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.issuedTotal.WithLabelValues("concurrent-provider").Inc()
				m.rotationsTotal.WithLabelValues("concurrent-provider").Inc()
				m.errorsTotal.WithLabelValues("concurrent-provider", "issue").Inc()
				m.expirySeconds.WithLabelValues("concurrent.example.com").Set(float64(j))
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}
