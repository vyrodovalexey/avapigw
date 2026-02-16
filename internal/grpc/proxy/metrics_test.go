package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetGRPCProxyMetrics_Singleton(t *testing.T) {
	// Get the metrics instance twice
	m1 := getGRPCProxyMetrics()
	m2 := getGRPCProxyMetrics()

	// Should return the same instance (singleton)
	require.NotNil(t, m1)
	require.NotNil(t, m2)
	assert.Same(t, m1, m2)
}

func TestGetGRPCProxyMetrics_FieldsInitialized(t *testing.T) {
	m := getGRPCProxyMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.poolSize)
	assert.NotNil(t, m.connectionCreated)
	assert.NotNil(t, m.connectionErrors)
	assert.NotNil(t, m.connectionClosed)
	assert.NotNil(t, m.directRequests)
	assert.NotNil(t, m.directDuration)
}

func TestGRPCProxyMetrics_RecordPoolSize(t *testing.T) {
	m := getGRPCProxyMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.poolSize.Set(5)
		m.poolSize.Inc()
		m.poolSize.Dec()
	})
}

func TestGRPCProxyMetrics_RecordConnectionCreated(t *testing.T) {
	m := getGRPCProxyMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.connectionCreated.WithLabelValues("localhost:50051").Inc()
	})
}

func TestGRPCProxyMetrics_RecordConnectionErrors(t *testing.T) {
	m := getGRPCProxyMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.connectionErrors.WithLabelValues("localhost:50051", "dial_error").Inc()
	})
}

func TestGRPCProxyMetrics_RecordConnectionClosed(t *testing.T) {
	m := getGRPCProxyMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.connectionClosed.WithLabelValues("localhost:50051").Inc()
	})
}

func TestGRPCProxyMetrics_RecordDirectRequests(t *testing.T) {
	m := getGRPCProxyMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.directRequests.WithLabelValues("/service/Method", "success").Inc()
		m.directRequests.WithLabelValues("/service/Method", "error").Inc()
	})
}

func TestGRPCProxyMetrics_RecordDirectDuration(t *testing.T) {
	m := getGRPCProxyMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.directDuration.WithLabelValues("/service/Method").Observe(0.5)
	})
}
