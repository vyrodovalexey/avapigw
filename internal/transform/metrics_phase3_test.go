package transform

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTransformMetrics_RecordDuration asserts that RecordDuration records a
// histogram observation for the given direction. The transform metrics
// instance is a process-global singleton, so the test reads the histogram
// sample count and sum for the specific direction series before and after the
// call and asserts the delta rather than an absolute value. This keeps the
// test deterministic under -race even if other tests touch the same singleton.
func TestTransformMetrics_RecordDuration(t *testing.T) {
	m := GetTransformMetrics()

	tests := []struct {
		name      string
		direction string
		d         time.Duration
	}{
		{
			name:      "request direction records observation",
			direction: "request",
			d:         5 * time.Millisecond,
		},
		{
			name:      "response direction records observation",
			direction: "response",
			d:         12 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange: read the current sample count and sum for this
			// direction's histogram series.
			beforeCount, beforeSum := histogramSnapshot(t, m, tt.direction)

			// Act
			m.RecordDuration(tt.direction, tt.d)

			// Assert: exactly one new sample recorded for this direction and
			// the observed sum increased by the duration in seconds.
			afterCount, afterSum := histogramSnapshot(t, m, tt.direction)
			assert.Equal(t, beforeCount+1, afterCount,
				"RecordDuration must record exactly one histogram sample for %q", tt.direction)
			assert.InDelta(t, beforeSum+tt.d.Seconds(), afterSum, 1e-9,
				"RecordDuration must add the observed duration to the histogram sum for %q", tt.direction)
		})
	}
}

// histogramSnapshot returns the current sample count and sum for the
// operation_duration_seconds histogram series identified by the given
// direction label. It writes the specific observer to a dto.Metric so the
// read is scoped to exactly one series (deterministic under concurrent tests).
func histogramSnapshot(t *testing.T, m *TransformMetrics, direction string) (uint64, float64) {
	t.Helper()

	observer, err := m.operationDuration.GetMetricWithLabelValues(direction)
	require.NoError(t, err)

	collector, ok := observer.(prometheus.Metric)
	require.True(t, ok, "histogram observer must implement prometheus.Metric")

	var metric dto.Metric
	require.NoError(t, collector.Write(&metric))
	require.NotNil(t, metric.GetHistogram())

	return metric.GetHistogram().GetSampleCount(), metric.GetHistogram().GetSampleSum()
}
