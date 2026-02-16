package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEncodingMetrics_Singleton(t *testing.T) {
	// Get the metrics instance twice
	m1 := GetEncodingMetrics()
	m2 := GetEncodingMetrics()

	// Should return the same instance (singleton)
	require.NotNil(t, m1)
	require.NotNil(t, m2)
	assert.Same(t, m1, m2)
}

func TestGetEncodingMetrics_FieldsInitialized(t *testing.T) {
	m := GetEncodingMetrics()

	require.NotNil(t, m)
	assert.NotNil(t, m.negotiationsTotal)
	assert.NotNil(t, m.encodeTotal)
	assert.NotNil(t, m.decodeTotal)
	assert.NotNil(t, m.errorsTotal)
}

func TestEncodingMetrics_RecordNegotiation(t *testing.T) {
	m := GetEncodingMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.RecordNegotiation("application/json", "success")
		m.RecordNegotiation("application/xml", "unsupported")
	})
}

func TestEncodingMetrics_RecordEncode(t *testing.T) {
	m := GetEncodingMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.RecordEncode("application/json", "success")
		m.RecordEncode("application/json", "error")
	})
}

func TestEncodingMetrics_RecordDecode(t *testing.T) {
	m := GetEncodingMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.RecordDecode("application/json", "success")
		m.RecordDecode("application/json", "error")
	})
}

func TestEncodingMetrics_RecordError(t *testing.T) {
	m := GetEncodingMetrics()

	// Should not panic
	assert.NotPanics(t, func() {
		m.RecordError("application/json", "encode")
		m.RecordError("application/json", "decode")
	})
}
