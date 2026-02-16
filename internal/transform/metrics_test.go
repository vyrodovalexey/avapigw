package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetTransformMetrics_Singleton(t *testing.T) {
	// Get the metrics instance twice
	m1 := GetTransformMetrics()
	m2 := GetTransformMetrics()

	// Should return the same instance (singleton)
	require.NotNil(t, m1)
	require.NotNil(t, m2)
	assert.Same(t, m1, m2)
}

func TestGetTransformMetrics_FieldsInitialized(t *testing.T) {
	m := GetTransformMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.operationsTotal)
	assert.NotNil(t, m.operationDuration)
	assert.NotNil(t, m.errorsTotal)
}

func TestTransformMetrics_RecordOperation(t *testing.T) {
	m := GetTransformMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.RecordOperation("request", "success")
		m.RecordOperation("response", "success")
		m.RecordOperation("request", "error")
	})
}

func TestTransformMetrics_RecordError(t *testing.T) {
	m := GetTransformMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.RecordError("request", "parse_error")
		m.RecordError("response", "transform_error")
	})
}
