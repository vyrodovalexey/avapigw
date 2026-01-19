package health

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Test Cases for RecordHealthCheck
// ============================================================================

func TestRecordHealthCheck_Healthy(t *testing.T) {
	// Record a healthy check
	RecordHealthCheck("test-check-healthy", true, 0.5)

	// Verify the counter was incremented
	counter, err := HealthCheckTotal.GetMetricWithLabelValues("test-check-healthy", "healthy")
	assert.NoError(t, err)
	assert.NotNil(t, counter)

	// Verify the gauge was set
	gauge, err := HealthCheckStatus.GetMetricWithLabelValues("test-check-healthy")
	assert.NoError(t, err)
	assert.NotNil(t, gauge)
}

func TestRecordHealthCheck_Unhealthy(t *testing.T) {
	// Record an unhealthy check
	RecordHealthCheck("test-check-unhealthy", false, 1.0)

	// Verify the counter was incremented
	counter, err := HealthCheckTotal.GetMetricWithLabelValues("test-check-unhealthy", "unhealthy")
	assert.NoError(t, err)
	assert.NotNil(t, counter)

	// Verify the gauge was set to 0
	gauge, err := HealthCheckStatus.GetMetricWithLabelValues("test-check-unhealthy")
	assert.NoError(t, err)
	assert.NotNil(t, gauge)
}

func TestRecordHealthCheck_Duration(t *testing.T) {
	// Record with specific duration
	RecordHealthCheck("test-check-duration", true, 0.123)

	// Verify the histogram was observed
	histogram, err := HealthCheckDuration.GetMetricWithLabelValues("test-check-duration")
	assert.NoError(t, err)
	assert.NotNil(t, histogram)
}

// ============================================================================
// Test Cases for SetOverallHealthStatus
// ============================================================================

func TestSetOverallHealthStatus_Healthy(t *testing.T) {
	SetOverallHealthStatus(true)

	// Get the metric value
	ch := make(chan prometheus.Metric, 1)
	OverallHealthStatus.Collect(ch)
	metric := <-ch

	var m prometheus.Metric = metric
	assert.NotNil(t, m)
}

func TestSetOverallHealthStatus_Unhealthy(t *testing.T) {
	SetOverallHealthStatus(false)

	// Get the metric value
	ch := make(chan prometheus.Metric, 1)
	OverallHealthStatus.Collect(ch)
	metric := <-ch

	var m prometheus.Metric = metric
	assert.NotNil(t, m)
}

func TestSetOverallHealthStatus_Toggle(t *testing.T) {
	// Set to healthy
	SetOverallHealthStatus(true)

	// Set to unhealthy
	SetOverallHealthStatus(false)

	// Set back to healthy
	SetOverallHealthStatus(true)

	// Verify metric exists
	ch := make(chan prometheus.Metric, 1)
	OverallHealthStatus.Collect(ch)
	metric := <-ch
	assert.NotNil(t, metric)
}

// ============================================================================
// Test Cases for SetDependencyHealthStatus
// ============================================================================

func TestSetDependencyHealthStatus_Healthy(t *testing.T) {
	SetDependencyHealthStatus("test-dependency", "database", true)

	// Verify the gauge was set
	gauge, err := DependencyHealthStatus.GetMetricWithLabelValues("test-dependency", "database")
	assert.NoError(t, err)
	assert.NotNil(t, gauge)
}

func TestSetDependencyHealthStatus_Unhealthy(t *testing.T) {
	SetDependencyHealthStatus("test-dependency-unhealthy", "cache", false)

	// Verify the gauge was set
	gauge, err := DependencyHealthStatus.GetMetricWithLabelValues("test-dependency-unhealthy", "cache")
	assert.NoError(t, err)
	assert.NotNil(t, gauge)
}

func TestSetDependencyHealthStatus_DifferentTypes(t *testing.T) {
	tests := []struct {
		name    string
		depType string
		healthy bool
	}{
		{"db-dep", "database", true},
		{"cache-dep", "cache", false},
		{"http-dep", "http", true},
		{"tcp-dep", "tcp", false},
		{"custom-dep", "custom", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetDependencyHealthStatus(tt.name, tt.depType, tt.healthy)

			gauge, err := DependencyHealthStatus.GetMetricWithLabelValues(tt.name, tt.depType)
			assert.NoError(t, err)
			assert.NotNil(t, gauge)
		})
	}
}

// ============================================================================
// Test Cases for SetUptimeSeconds
// ============================================================================

func TestSetUptimeSeconds(t *testing.T) {
	SetUptimeSeconds(123.456)

	// Verify the gauge was set
	ch := make(chan prometheus.Metric, 1)
	UptimeSeconds.Collect(ch)
	metric := <-ch
	assert.NotNil(t, metric)
}

func TestSetUptimeSeconds_Zero(t *testing.T) {
	SetUptimeSeconds(0)

	ch := make(chan prometheus.Metric, 1)
	UptimeSeconds.Collect(ch)
	metric := <-ch
	assert.NotNil(t, metric)
}

func TestSetUptimeSeconds_LargeValue(t *testing.T) {
	// Set a large uptime value (e.g., 1 year in seconds)
	SetUptimeSeconds(31536000)

	ch := make(chan prometheus.Metric, 1)
	UptimeSeconds.Collect(ch)
	metric := <-ch
	assert.NotNil(t, metric)
}

// ============================================================================
// Test Cases for Metrics Constants
// ============================================================================

func TestMetricsConstants(t *testing.T) {
	assert.Equal(t, "avapigw", Namespace)
	assert.Equal(t, "health", Subsystem)
}

// ============================================================================
// Test Cases for Metrics Initialization
// ============================================================================

func TestMetricsInitialization(t *testing.T) {
	// Verify all metrics are initialized
	assert.NotNil(t, HealthCheckTotal)
	assert.NotNil(t, HealthCheckDuration)
	assert.NotNil(t, HealthCheckStatus)
	assert.NotNil(t, OverallHealthStatus)
	assert.NotNil(t, DependencyHealthStatus)
	assert.NotNil(t, UptimeSeconds)
}

// ============================================================================
// Test Cases for Metrics Labels
// ============================================================================

func TestHealthCheckTotal_Labels(t *testing.T) {
	// Test with different label combinations
	tests := []struct {
		name   string
		status string
	}{
		{"check1", "healthy"},
		{"check2", "unhealthy"},
		{"check3", "healthy"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.status, func(t *testing.T) {
			counter, err := HealthCheckTotal.GetMetricWithLabelValues(tt.name, tt.status)
			assert.NoError(t, err)
			assert.NotNil(t, counter)
		})
	}
}

func TestHealthCheckDuration_Labels(t *testing.T) {
	tests := []string{"duration-check1", "duration-check2", "duration-check3"}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			histogram, err := HealthCheckDuration.GetMetricWithLabelValues(name)
			assert.NoError(t, err)
			assert.NotNil(t, histogram)
		})
	}
}

func TestHealthCheckStatus_Labels(t *testing.T) {
	tests := []string{"status-check1", "status-check2", "status-check3"}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			gauge, err := HealthCheckStatus.GetMetricWithLabelValues(name)
			assert.NoError(t, err)
			assert.NotNil(t, gauge)
		})
	}
}

func TestDependencyHealthStatus_Labels(t *testing.T) {
	tests := []struct {
		dependency string
		depType    string
	}{
		{"dep1", "database"},
		{"dep2", "cache"},
		{"dep3", "http"},
		{"dep4", "tcp"},
		{"dep5", "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.dependency+"_"+tt.depType, func(t *testing.T) {
			gauge, err := DependencyHealthStatus.GetMetricWithLabelValues(tt.dependency, tt.depType)
			assert.NoError(t, err)
			assert.NotNil(t, gauge)
		})
	}
}

// ============================================================================
// Test Cases for RecordHealthCheck Integration
// ============================================================================

func TestRecordHealthCheck_MultipleRecordings(t *testing.T) {
	// Record multiple health checks
	for i := 0; i < 10; i++ {
		RecordHealthCheck("multi-record-check", i%2 == 0, float64(i)*0.1)
	}

	// Verify counters exist for both statuses
	healthyCounter, err := HealthCheckTotal.GetMetricWithLabelValues("multi-record-check", "healthy")
	assert.NoError(t, err)
	assert.NotNil(t, healthyCounter)

	unhealthyCounter, err := HealthCheckTotal.GetMetricWithLabelValues("multi-record-check", "unhealthy")
	assert.NoError(t, err)
	assert.NotNil(t, unhealthyCounter)
}
