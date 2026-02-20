// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testMetricsRegistry is a shared registry for tests to avoid duplicate metrics registration.
var (
	testMetrics     *clientMetrics
	testMetricsOnce sync.Once
)

func getTestMetrics(t *testing.T) *clientMetrics {
	testMetricsOnce.Do(func() {
		testMetrics = newClientMetrics(nil)
	})
	return testMetrics
}

func TestNewClientMetrics_WithNilRegistry(t *testing.T) {
	// Should not panic with nil registry
	m := newClientMetrics(nil)
	require.NotNil(t, m)
	assert.NotNil(t, m.connected)
	assert.NotNil(t, m.reconnectsTotal)
	assert.NotNil(t, m.configUpdatesTotal)
	assert.NotNil(t, m.configApplyDuration)
	assert.NotNil(t, m.heartbeatLatency)
	assert.NotNil(t, m.streamErrors)
	assert.NotNil(t, m.registrationErrors)
	assert.NotNil(t, m.lastConfigVersion)
	assert.NotNil(t, m.lastConfigTimestamp)
}

func TestNewClientMetrics_WithRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newClientMetrics(registry)
	require.NotNil(t, m)

	// Trigger some metrics to ensure they appear in the registry
	m.setConnected(true)
	m.incReconnects()
	m.incConfigUpdates("test", "success")
	m.observeConfigApplyDuration(0.1)
	m.observeHeartbeatLatency(0.01)
	m.incStreamErrors()
	m.incRegistrationErrors()
	m.setLastConfigVersion(1)
	m.setLastConfigTimestamp(1234567890)

	// Verify metrics are registered
	families, err := registry.Gather()
	require.NoError(t, err)

	// Check that we have metrics registered
	metricNames := make(map[string]bool)
	for _, family := range families {
		metricNames[family.GetName()] = true
	}

	// Verify expected metrics are present
	expectedMetrics := []string{
		"gateway_operator_client_connected",
		"gateway_operator_client_reconnects_total",
		"gateway_operator_client_config_updates_total",
		"gateway_operator_client_config_apply_duration_seconds",
		"gateway_operator_client_heartbeat_latency_seconds",
		"gateway_operator_client_stream_errors_total",
		"gateway_operator_client_registration_errors_total",
		"gateway_operator_client_last_config_version",
		"gateway_operator_client_last_config_timestamp_seconds",
	}

	for _, name := range expectedMetrics {
		assert.True(t, metricNames[name], "metric %s should be registered", name)
	}
}

func TestClientMetrics_SetConnected(t *testing.T) {
	m := getTestMetrics(t)

	tests := []struct {
		name      string
		connected bool
		expected  float64
	}{
		{
			name:      "set connected",
			connected: true,
			expected:  1,
		},
		{
			name:      "set disconnected",
			connected: false,
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.setConnected(tt.connected)
			// Verify by collecting the metric
			ch := make(chan prometheus.Metric, 1)
			m.connected.Collect(ch)
			metric := <-ch

			dto := &io_prometheus_client.Metric{}
			err := metric.Write(dto)
			require.NoError(t, err)
			value := dto.GetGauge().GetValue()
			assert.Equal(t, tt.expected, value)
		})
	}
}

func TestClientMetrics_SetConnected_NilReceiver(t *testing.T) {
	var m *clientMetrics
	// Should not panic
	m.setConnected(true)
}

func TestClientMetrics_IncReconnects(t *testing.T) {
	m := getTestMetrics(t)

	// Get initial value
	ch := make(chan prometheus.Metric, 1)
	m.reconnectsTotal.Collect(ch)
	metric := <-ch
	dto := &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	initialValue := dto.GetCounter().GetValue()

	// Increment
	m.incReconnects()

	// Verify increment
	ch = make(chan prometheus.Metric, 1)
	m.reconnectsTotal.Collect(ch)
	metric = <-ch
	dto = &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	newValue := dto.GetCounter().GetValue()

	assert.Equal(t, initialValue+1, newValue)
}

func TestClientMetrics_IncReconnects_NilReceiver(t *testing.T) {
	var m *clientMetrics
	// Should not panic
	m.incReconnects()
}

func TestClientMetrics_IncConfigUpdates(t *testing.T) {
	m := getTestMetrics(t)

	// Increment with different labels
	m.incConfigUpdates("UPDATE_TYPE_ADDED", "success")
	m.incConfigUpdates("UPDATE_TYPE_MODIFIED", "error")
	m.incConfigUpdates("UPDATE_TYPE_DELETED", "success")

	// Verify by collecting metrics
	ch := make(chan prometheus.Metric, 10)
	m.configUpdatesTotal.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	assert.Greater(t, count, 0, "should have collected some metrics")
}

func TestClientMetrics_IncConfigUpdates_NilReceiver(t *testing.T) {
	var m *clientMetrics
	// Should not panic
	m.incConfigUpdates("UPDATE_TYPE_ADDED", "success")
}

func TestClientMetrics_ObserveConfigApplyDuration(t *testing.T) {
	m := getTestMetrics(t)

	// Observe some durations
	m.observeConfigApplyDuration(0.001)
	m.observeConfigApplyDuration(0.01)
	m.observeConfigApplyDuration(0.1)
	m.observeConfigApplyDuration(1.0)

	// Verify by collecting metrics
	ch := make(chan prometheus.Metric, 1)
	m.configApplyDuration.Collect(ch)
	metric := <-ch

	dto := &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	assert.Greater(t, dto.GetHistogram().GetSampleCount(), uint64(0))
}

func TestClientMetrics_ObserveConfigApplyDuration_NilReceiver(t *testing.T) {
	var m *clientMetrics
	// Should not panic
	m.observeConfigApplyDuration(0.1)
}

func TestClientMetrics_ObserveHeartbeatLatency(t *testing.T) {
	m := getTestMetrics(t)

	// Observe some latencies
	m.observeHeartbeatLatency(0.001)
	m.observeHeartbeatLatency(0.005)
	m.observeHeartbeatLatency(0.01)

	// Verify by collecting metrics
	ch := make(chan prometheus.Metric, 1)
	m.heartbeatLatency.Collect(ch)
	metric := <-ch

	dto := &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	assert.Greater(t, dto.GetHistogram().GetSampleCount(), uint64(0))
}

func TestClientMetrics_ObserveHeartbeatLatency_NilReceiver(t *testing.T) {
	var m *clientMetrics
	// Should not panic
	m.observeHeartbeatLatency(0.01)
}

func TestClientMetrics_IncStreamErrors(t *testing.T) {
	m := getTestMetrics(t)

	// Get initial value
	ch := make(chan prometheus.Metric, 1)
	m.streamErrors.Collect(ch)
	metric := <-ch
	dto := &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	initialValue := dto.GetCounter().GetValue()

	// Increment
	m.incStreamErrors()

	// Verify increment
	ch = make(chan prometheus.Metric, 1)
	m.streamErrors.Collect(ch)
	metric = <-ch
	dto = &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	newValue := dto.GetCounter().GetValue()

	assert.Equal(t, initialValue+1, newValue)
}

func TestClientMetrics_IncStreamErrors_NilReceiver(t *testing.T) {
	var m *clientMetrics
	// Should not panic
	m.incStreamErrors()
}

func TestClientMetrics_IncRegistrationErrors(t *testing.T) {
	m := getTestMetrics(t)

	// Get initial value
	ch := make(chan prometheus.Metric, 1)
	m.registrationErrors.Collect(ch)
	metric := <-ch
	dto := &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	initialValue := dto.GetCounter().GetValue()

	// Increment
	m.incRegistrationErrors()

	// Verify increment
	ch = make(chan prometheus.Metric, 1)
	m.registrationErrors.Collect(ch)
	metric = <-ch
	dto = &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	newValue := dto.GetCounter().GetValue()

	assert.Equal(t, initialValue+1, newValue)
}

func TestClientMetrics_IncRegistrationErrors_NilReceiver(t *testing.T) {
	var m *clientMetrics
	// Should not panic
	m.incRegistrationErrors()
}

func TestClientMetrics_SetLastConfigVersion(t *testing.T) {
	m := getTestMetrics(t)

	m.setLastConfigVersion(42)

	// Verify by collecting the metric
	ch := make(chan prometheus.Metric, 1)
	m.lastConfigVersion.Collect(ch)
	metric := <-ch

	dto := &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	assert.Equal(t, float64(42), dto.GetGauge().GetValue())
}

func TestClientMetrics_SetLastConfigVersion_NilReceiver(t *testing.T) {
	var m *clientMetrics
	// Should not panic
	m.setLastConfigVersion(42)
}

func TestClientMetrics_SetLastConfigTimestamp(t *testing.T) {
	m := getTestMetrics(t)

	timestamp := float64(1704067200) // 2024-01-01 00:00:00 UTC
	m.setLastConfigTimestamp(timestamp)

	// Verify by collecting the metric
	ch := make(chan prometheus.Metric, 1)
	m.lastConfigTimestamp.Collect(ch)
	metric := <-ch

	dto := &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	assert.Equal(t, timestamp, dto.GetGauge().GetValue())
}

func TestClientMetrics_SetLastConfigTimestamp_NilReceiver(t *testing.T) {
	var m *clientMetrics
	// Should not panic
	m.setLastConfigTimestamp(1704067200)
}
