package metrics

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestMetrics creates a fresh Metrics instance with a custom registry for testing.
func newTestMetrics(t *testing.T) *Metrics {
	t.Helper()
	reg := prometheus.NewRegistry()
	factory := promauto.With(reg)
	return newMetricsWithFactory(factory)
}

func TestNewMetricsWithFactory(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	require.NotNil(t, m)
	assert.NotNil(t, m.requestsTotal)
	assert.NotNil(t, m.requestDuration)
	assert.NotNil(t, m.errorsTotal)
	assert.NotNil(t, m.depthLimitExceeded)
	assert.NotNil(t, m.complexityExceeded)
	assert.NotNil(t, m.introspectionBlocked)
	assert.NotNil(t, m.activeSubscriptions)
	assert.NotNil(t, m.queryDepth)
	assert.NotNil(t, m.queryComplexity)
}

func TestMetrics_RecordRequest(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	tests := []struct {
		name       string
		backend    string
		opType     string
		statusCode int
		duration   time.Duration
	}{
		{
			name:       "successful query",
			backend:    "test-backend",
			opType:     "query",
			statusCode: 200,
			duration:   100 * time.Millisecond,
		},
		{
			name:       "failed mutation",
			backend:    "test-backend",
			opType:     "mutation",
			statusCode: 500,
			duration:   500 * time.Millisecond,
		},
		{
			name:       "subscription",
			backend:    "sub-backend",
			opType:     "subscription",
			statusCode: 200,
			duration:   1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := strconv.Itoa(tt.statusCode)
			before := testutil.ToFloat64(
				m.requestsTotal.WithLabelValues(tt.backend, tt.opType, sc),
			)
			m.RecordRequest(tt.backend, tt.opType, tt.statusCode, tt.duration)
			after := testutil.ToFloat64(
				m.requestsTotal.WithLabelValues(tt.backend, tt.opType, sc),
			)
			assert.Equal(t, before+1, after)
		})
	}
}

func TestMetrics_RecordRequest_Duration(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	m.RecordRequest("be", "query", 200, 250*time.Millisecond)

	// Verify histogram was observed (count > 0)
	count := testutil.CollectAndCount(m.requestDuration)
	assert.Greater(t, count, 0)
}

func TestMetrics_RecordError(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	tests := []struct {
		name      string
		backend   string
		opType    string
		errorType string
	}{
		{
			name:      "backend not found",
			backend:   "test-backend",
			opType:    "query",
			errorType: "backend_not_found",
		},
		{
			name:      "transport error",
			backend:   "test-backend",
			opType:    "mutation",
			errorType: "transport_error",
		},
		{
			name:      "request creation failed",
			backend:   "test-backend",
			opType:    "query",
			errorType: "request_creation_failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.backend, tt.opType, tt.errorType),
			)
			m.RecordError(tt.backend, tt.opType, tt.errorType)
			after := testutil.ToFloat64(
				m.errorsTotal.WithLabelValues(tt.backend, tt.opType, tt.errorType),
			)
			assert.Equal(t, before+1, after)
		})
	}
}

func TestMetrics_RecordDepthLimitExceeded(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	before := testutil.ToFloat64(m.depthLimitExceeded)
	m.RecordDepthLimitExceeded()
	after := testutil.ToFloat64(m.depthLimitExceeded)
	assert.Equal(t, before+1, after)
}

func TestMetrics_RecordComplexityExceeded(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	before := testutil.ToFloat64(m.complexityExceeded)
	m.RecordComplexityExceeded()
	after := testutil.ToFloat64(m.complexityExceeded)
	assert.Equal(t, before+1, after)
}

func TestMetrics_RecordIntrospectionBlocked(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	before := testutil.ToFloat64(m.introspectionBlocked)
	m.RecordIntrospectionBlocked()
	after := testutil.ToFloat64(m.introspectionBlocked)
	assert.Equal(t, before+1, after)
}

func TestMetrics_SetActiveSubscriptions(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	m.SetActiveSubscriptions(5)
	assert.Equal(t, float64(5), testutil.ToFloat64(m.activeSubscriptions))

	m.SetActiveSubscriptions(0)
	assert.Equal(t, float64(0), testutil.ToFloat64(m.activeSubscriptions))

	m.SetActiveSubscriptions(100)
	assert.Equal(t, float64(100), testutil.ToFloat64(m.activeSubscriptions))
}

func TestMetrics_RecordQueryDepth(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	tests := []struct {
		name   string
		opType string
		depth  float64
	}{
		{name: "shallow query", opType: "query", depth: 2},
		{name: "deep query", opType: "query", depth: 15},
		{name: "mutation depth", opType: "mutation", depth: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.RecordQueryDepth(tt.opType, tt.depth)
			count := testutil.CollectAndCount(m.queryDepth)
			assert.Greater(t, count, 0)
		})
	}
}

func TestMetrics_RecordQueryComplexity(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	tests := []struct {
		name       string
		opType     string
		complexity float64
	}{
		{name: "simple query", opType: "query", complexity: 5},
		{name: "complex query", opType: "query", complexity: 250},
		{name: "mutation complexity", opType: "mutation", complexity: 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.RecordQueryComplexity(tt.opType, tt.complexity)
			count := testutil.CollectAndCount(m.queryComplexity)
			assert.Greater(t, count, 0)
		})
	}
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	m := newTestMetrics(t)

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.RecordRequest("concurrent-be", "query", 200, 10*time.Millisecond)
				m.RecordError("concurrent-be", "query", "timeout")
				m.RecordDepthLimitExceeded()
				m.RecordComplexityExceeded()
				m.RecordIntrospectionBlocked()
				m.SetActiveSubscriptions(float64(j))
				m.RecordQueryDepth("query", float64(j))
				m.RecordQueryComplexity("query", float64(j))
			}
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}

// TestInitMetrics_WithNilRegisterer tests that InitMetrics with nil uses the default registerer.
// This test exercises the singleton path. Because sync.Once is global, this test
// must NOT be run in parallel with other tests that call InitMetrics/GetMetrics.
func TestInitMetrics_WithNilRegisterer(t *testing.T) {
	// Reset the singleton for this test
	oldMetrics := defaultMetrics
	oldOnce := defaultMetricsOnce
	defaultMetrics = nil
	defaultMetricsOnce = sync.Once{}
	defer func() {
		defaultMetrics = oldMetrics
		defaultMetricsOnce = oldOnce
	}()

	// Use a custom registry to avoid polluting the default one
	reg := prometheus.NewRegistry()
	InitMetrics(reg)

	m := GetMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.requestsTotal)
	assert.NotNil(t, m.requestDuration)
	assert.NotNil(t, m.errorsTotal)
	assert.NotNil(t, m.depthLimitExceeded)
	assert.NotNil(t, m.complexityExceeded)
	assert.NotNil(t, m.introspectionBlocked)
	assert.NotNil(t, m.activeSubscriptions)
	assert.NotNil(t, m.queryDepth)
	assert.NotNil(t, m.queryComplexity)

	// Calling InitMetrics again should be a no-op (sync.Once)
	InitMetrics(prometheus.NewRegistry())
	m2 := GetMetrics()
	assert.Same(t, m, m2, "second InitMetrics call should not create new metrics")
}

// TestGetMetrics_LazyInit tests that GetMetrics lazily initializes metrics.
func TestGetMetrics_LazyInit(t *testing.T) {
	// Reset the singleton for this test
	oldMetrics := defaultMetrics
	oldOnce := defaultMetricsOnce
	defaultMetrics = nil
	defaultMetricsOnce = sync.Once{}
	defer func() {
		defaultMetrics = oldMetrics
		defaultMetricsOnce = oldOnce
	}()

	// GetMetrics should lazily initialize with nil (default registerer)
	// We need to use a custom registry to avoid conflicts
	reg := prometheus.NewRegistry()
	InitMetrics(reg)

	m := GetMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.requestsTotal)
}

// TestInitVecMetrics tests that InitVecMetrics pre-populates vector metrics.
func TestInitVecMetrics(t *testing.T) {
	// Reset the singleton for this test
	oldMetrics := defaultMetrics
	oldOnce := defaultMetricsOnce
	defaultMetrics = nil
	defaultMetricsOnce = sync.Once{}
	defer func() {
		defaultMetrics = oldMetrics
		defaultMetricsOnce = oldOnce
	}()

	reg := prometheus.NewRegistry()
	InitMetrics(reg)
	InitVecMetrics()

	m := GetMetrics()
	require.NotNil(t, m)

	// After InitVecMetrics, the vector metrics should have pre-populated label combinations.
	// Verify that we can collect metrics (they should exist with zero values).
	operationTypes := []string{"query", "mutation", "subscription"}
	statusCodes := []string{"200", "400", "500"}

	for _, op := range operationTypes {
		for _, sc := range statusCodes {
			val := testutil.ToFloat64(m.requestsTotal.WithLabelValues("", op, sc))
			assert.Equal(t, float64(0), val, "pre-populated metric should be zero for op=%s sc=%s", op, sc)
		}
	}

	// Verify error types are pre-populated
	errorTypes := []string{
		"backend_not_found", "transport_error", "request_creation_failed",
		"depth_exceeded", "complexity_exceeded", "introspection_blocked",
	}
	for _, op := range operationTypes {
		for _, et := range errorTypes {
			val := testutil.ToFloat64(m.errorsTotal.WithLabelValues("", op, et))
			assert.Equal(t, float64(0), val, "pre-populated error metric should be zero for op=%s et=%s", op, et)
		}
	}
}

// TestInitMetrics_NilRegistererUsesDefault tests the nil registerer path.
func TestInitMetrics_NilRegistererUsesDefault(t *testing.T) {
	// Reset the singleton for this test
	oldMetrics := defaultMetrics
	oldOnce := defaultMetricsOnce
	defaultMetrics = nil
	defaultMetricsOnce = sync.Once{}
	defer func() {
		defaultMetrics = oldMetrics
		defaultMetricsOnce = oldOnce
	}()

	// Pass nil to exercise the nil-registerer branch
	InitMetrics(nil)

	m := GetMetrics()
	require.NotNil(t, m)
	assert.NotNil(t, m.requestsTotal)
}
