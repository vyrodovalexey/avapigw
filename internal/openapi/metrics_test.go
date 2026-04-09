package openapi

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		registerer prometheus.Registerer
	}{
		{
			name:       "with custom registerer",
			registerer: prometheus.NewRegistry(),
		},
		{
			name:       "with nil registerer uses default",
			registerer: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Not parallel because nil registerer uses DefaultRegisterer
			// which can conflict with other tests.
			if tt.registerer != nil {
				t.Parallel()
			}

			m := NewMetrics(tt.registerer)
			require.NotNil(t, m)
			assert.NotNil(t, m.requestsTotal)
			assert.NotNil(t, m.duration)
			assert.NotNil(t, m.errorsTotal)
			assert.True(t, m.registeredOnce)
		})
	}
}

func TestMetrics_RecordSuccess(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.RecordSuccess("/api/v1/items", 0.005)
	m.RecordSuccess("/api/v1/items", 0.010)
	m.RecordSuccess("/api/v1/users", 0.003)

	// Verify requests_total counter
	families, err := reg.Gather()
	require.NoError(t, err)

	var requestsTotal *dto.MetricFamily
	var durationHist *dto.MetricFamily
	for _, f := range families {
		switch f.GetName() {
		case "gateway_openapi_validation_requests_total":
			requestsTotal = f
		case "gateway_openapi_validation_duration_seconds":
			durationHist = f
		}
	}

	require.NotNil(t, requestsTotal, "requests_total metric should exist")
	assert.NotEmpty(t, requestsTotal.GetMetric())

	// Check that we have success metrics
	found := false
	for _, metric := range requestsTotal.GetMetric() {
		for _, label := range metric.GetLabel() {
			if label.GetName() == "result" && label.GetValue() == "success" {
				found = true
				break
			}
		}
	}
	assert.True(t, found, "should have success result label")

	require.NotNil(t, durationHist, "duration metric should exist")
	assert.NotEmpty(t, durationHist.GetMetric())
}

func TestMetrics_RecordFailure(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.RecordFailure("/api/v1/items", "body", 0.002)
	m.RecordFailure("/api/v1/items", "params", 0.001)

	families, err := reg.Gather()
	require.NoError(t, err)

	var requestsTotal *dto.MetricFamily
	var errorsTotal *dto.MetricFamily
	var durationHist *dto.MetricFamily
	for _, f := range families {
		switch f.GetName() {
		case "gateway_openapi_validation_requests_total":
			requestsTotal = f
		case "gateway_openapi_validation_errors_total":
			errorsTotal = f
		case "gateway_openapi_validation_duration_seconds":
			durationHist = f
		}
	}

	require.NotNil(t, requestsTotal, "requests_total metric should exist")
	require.NotNil(t, errorsTotal, "errors_total metric should exist")
	require.NotNil(t, durationHist, "duration metric should exist")

	// Check failure result label
	foundFailure := false
	for _, metric := range requestsTotal.GetMetric() {
		for _, label := range metric.GetLabel() {
			if label.GetName() == "result" && label.GetValue() == "failure" {
				foundFailure = true
				break
			}
		}
	}
	assert.True(t, foundFailure, "should have failure result label")

	// Check error type labels
	errorTypes := make(map[string]bool)
	for _, metric := range errorsTotal.GetMetric() {
		for _, label := range metric.GetLabel() {
			if label.GetName() == "error_type" {
				errorTypes[label.GetValue()] = true
			}
		}
	}
	assert.True(t, errorTypes["body"], "should have body error type")
	assert.True(t, errorTypes["params"], "should have params error type")
}

func TestMetrics_Labels(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.RecordSuccess("/api/v1/items", 0.001)
	m.RecordFailure("/api/v1/users", "security", 0.002)

	families, err := reg.Gather()
	require.NoError(t, err)

	// Verify route labels exist
	routeLabels := make(map[string]bool)
	for _, f := range families {
		for _, metric := range f.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "route" {
					routeLabels[label.GetValue()] = true
				}
			}
		}
	}

	assert.True(t, routeLabels["/api/v1/items"], "should have /api/v1/items route label")
	assert.True(t, routeLabels["/api/v1/users"], "should have /api/v1/users route label")
}

func TestMetrics_RegisterOnce(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Calling register again should be a no-op
	assert.True(t, m.registeredOnce)
	m.register() // Should not panic
}

func TestMetrics_MetricNames(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Record some data to ensure metrics are populated
	m.RecordSuccess("/test", 0.001)
	m.RecordFailure("/test", "body", 0.002)

	families, err := reg.Gather()
	require.NoError(t, err)

	metricNames := make(map[string]bool)
	for _, f := range families {
		metricNames[f.GetName()] = true
	}

	assert.True(t, metricNames["gateway_openapi_validation_requests_total"],
		"should have requests_total metric")
	assert.True(t, metricNames["gateway_openapi_validation_duration_seconds"],
		"should have duration_seconds metric")
	assert.True(t, metricNames["gateway_openapi_validation_errors_total"],
		"should have errors_total metric")
}
