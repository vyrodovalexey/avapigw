package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Test Cases for Metrics Recording - RecordSuccess
// ============================================================================

func TestRecordSuccess_MetricsCall(t *testing.T) {
	// Reset metrics registry for this test
	originalCounter := CircuitBreakerSuccessesTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_successes_total",
			Help: "Total number of successes recorded by circuit breakers",
		},
		[]string{"name"},
	)
	CircuitBreakerSuccessesTotal = testCounter
	defer func() {
		CircuitBreakerSuccessesTotal = originalCounter
	}()

	testName := "test-success-metrics"
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker(testName, DefaultConfig(), logger)

	// Record success - this should call RecordSuccess which increments the metric
	cb.RecordSuccess()

	// Verify the metric was incremented
	metric, err := testCounter.GetMetricWithLabelValues(testName)
	require.NoError(t, err)

	counterMetric := &dto.Metric{}
	err = metric.Write(counterMetric)
	require.NoError(t, err)
	require.NotNil(t, counterMetric.Counter)
	assert.Equal(t, float64(1), *counterMetric.Counter.Value)
}

func TestRecordSuccess_MultipleSuccesses(t *testing.T) {
	// Reset metrics registry for this test
	originalCounter := CircuitBreakerSuccessesTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_successes_total_multi",
			Help: "Total number of successes recorded by circuit breakers",
		},
		[]string{"name"},
	)
	CircuitBreakerSuccessesTotal = testCounter
	defer func() {
		CircuitBreakerSuccessesTotal = originalCounter
	}()

	testName := "test-multi-success"
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker(testName, DefaultConfig(), logger)

	// Record multiple successes
	for i := 0; i < 5; i++ {
		cb.RecordSuccess()
	}

	// Verify the metric shows 5 successes
	metric, err := testCounter.GetMetricWithLabelValues(testName)
	require.NoError(t, err)

	counterMetric := &dto.Metric{}
	err = metric.Write(counterMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(5), *counterMetric.Counter.Value)
}

// ============================================================================
// Test Cases for Metrics Recording - RecordFailure
// ============================================================================

func TestRecordFailure_MetricsCall(t *testing.T) {
	// Reset metrics registry for this test
	originalCounter := CircuitBreakerFailuresTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_failures_total",
			Help: "Total number of failures recorded by circuit breakers",
		},
		[]string{"name"},
	)
	CircuitBreakerFailuresTotal = testCounter
	defer func() {
		CircuitBreakerFailuresTotal = originalCounter
	}()

	testName := "test-failure-metrics"
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker(testName, DefaultConfig(), logger)

	// Record failure - this should call RecordFailure which increments the metric
	cb.RecordFailure()

	// Verify the metric was incremented
	metric, err := testCounter.GetMetricWithLabelValues(testName)
	require.NoError(t, err)

	counterMetric := &dto.Metric{}
	err = metric.Write(counterMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *counterMetric.Counter.Value)
}

func TestRecordFailure_MultipleFailures(t *testing.T) {
	// Reset metrics registry for this test
	originalCounter := CircuitBreakerFailuresTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_failures_total_multi",
			Help: "Total number of failures recorded by circuit breakers",
		},
		[]string{"name"},
	)
	CircuitBreakerFailuresTotal = testCounter
	defer func() {
		CircuitBreakerFailuresTotal = originalCounter
	}()

	testName := "test-multi-failure"
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker(testName, DefaultConfig(), logger)

	// Record multiple failures
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}

	// Verify the metric shows 3 failures
	metric, err := testCounter.GetMetricWithLabelValues(testName)
	require.NoError(t, err)

	counterMetric := &dto.Metric{}
	err = metric.Write(counterMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(3), *counterMetric.Counter.Value)
}

// ============================================================================
// Test Cases for Metrics Recording - RecordStateChange
// ============================================================================

func TestRecordStateChange_MetricsCall(t *testing.T) {
	// Reset metrics registry for this test
	originalCounter := CircuitBreakerStateChangesTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_state_changes_total",
			Help: "Total number of circuit breaker state changes",
		},
		[]string{"name", "from", "to"},
	)
	CircuitBreakerStateChangesTotal = testCounter
	defer func() {
		CircuitBreakerStateChangesTotal = originalCounter
	}()

	testName := "test-state-change-metrics"
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1

	cb := NewCircuitBreaker(testName, config, logger)

	// Initial state is closed
	assert.Equal(t, StateClosed, cb.State())

	// Record failure - this should trigger state change to open
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.State())

	// Verify state change metrics were recorded
	metric, err := testCounter.GetMetricWithLabelValues(testName, "closed", "open")
	require.NoError(t, err)

	counterMetric := &dto.Metric{}
	err = metric.Write(counterMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *counterMetric.Counter.Value)
}

func TestRecordStateChange_MultipleChanges(t *testing.T) {
	// Reset metrics registry for this test
	originalCounter := CircuitBreakerStateChangesTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_state_changes_total_multi",
			Help: "Total number of circuit breaker state changes",
		},
		[]string{"name", "from", "to"},
	)
	CircuitBreakerStateChangesTotal = testCounter
	defer func() {
		CircuitBreakerStateChangesTotal = originalCounter
	}()

	testName := "test-multi-state-change"
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1
	config.Timeout = 10 * time.Millisecond
	config.SuccessThreshold = 1

	cb := NewCircuitBreaker(testName, config, logger)

	// State: Closed -> Open (on failure)
	cb.RecordFailure()
	assert.Equal(t, StateOpen, cb.State())

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// State: Open -> HalfOpen (on Allow)
	cb.Allow()
	assert.Equal(t, StateHalfOpen, cb.State())

	// State: HalfOpen -> Closed (on success)
	cb.RecordSuccess()
	assert.Equal(t, StateClosed, cb.State())

	// Verify all state changes were recorded
	metric1, err := testCounter.GetMetricWithLabelValues(testName, "closed", "open")
	require.NoError(t, err)
	counterMetric1 := &dto.Metric{}
	err = metric1.Write(counterMetric1)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *counterMetric1.Counter.Value)

	metric2, err := testCounter.GetMetricWithLabelValues(testName, "open", "half-open")
	require.NoError(t, err)
	counterMetric2 := &dto.Metric{}
	err = metric2.Write(counterMetric2)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *counterMetric2.Counter.Value)

	metric3, err := testCounter.GetMetricWithLabelValues(testName, "half-open", "closed")
	require.NoError(t, err)
	counterMetric3 := &dto.Metric{}
	err = metric3.Write(counterMetric3)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *counterMetric3.Counter.Value)
}

// ============================================================================
// Test Cases for Metrics Recording - RecordRequest
// ============================================================================

func TestRecordRequest_MetricsCall_Allowed(t *testing.T) {
	// Reset metrics registry for this test
	originalCounter := CircuitBreakerRequestsTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_requests_total",
			Help: "Total number of requests through circuit breakers",
		},
		[]string{"name", "result"},
	)
	CircuitBreakerRequestsTotal = testCounter
	defer func() {
		CircuitBreakerRequestsTotal = originalCounter
	}()

	testName := "test-request-allowed"
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker(testName, DefaultConfig(), logger)

	// Allow a request - this should call RecordRequest with allowed=true
	cb.Allow()

	// Verify "allowed" metric was incremented
	metric, err := testCounter.GetMetricWithLabelValues(testName, "allowed")
	require.NoError(t, err)

	counterMetric := &dto.Metric{}
	err = metric.Write(counterMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *counterMetric.Counter.Value)

	// Verify "rejected" metric is 0
	metricRejected, err := testCounter.GetMetricWithLabelValues(testName, "rejected")
	require.NoError(t, err)
	counterMetricRejected := &dto.Metric{}
	err = metricRejected.Write(counterMetricRejected)
	require.NoError(t, err)
	assert.Equal(t, float64(0), *counterMetricRejected.Counter.Value)
}

func TestRecordRequest_MetricsCall_Rejected(t *testing.T) {
	// Reset metrics registry for this test
	originalCounter := CircuitBreakerRequestsTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_requests_total_rejected",
			Help: "Total number of requests through circuit breakers",
		},
		[]string{"name", "result"},
	)
	CircuitBreakerRequestsTotal = testCounter
	defer func() {
		CircuitBreakerRequestsTotal = originalCounter
	}()

	testName := "test-request-rejected"
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1

	cb := NewCircuitBreaker(testName, config, logger)

	// Open the circuit
	cb.RecordFailure()

	// Try to allow a request - should be rejected
	cb.Allow()

	// Verify "rejected" metric was incremented
	metric, err := testCounter.GetMetricWithLabelValues(testName, "rejected")
	require.NoError(t, err)

	counterMetric := &dto.Metric{}
	err = metric.Write(counterMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *counterMetric.Counter.Value)
}

func TestRecordRequest_RejectedCounterIncremented(t *testing.T) {
	// Reset metrics registry for this test
	originalRejectedCounter := CircuitBreakerRejectedTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_rejected_total",
			Help: "Total number of requests rejected due to open circuit",
		},
		[]string{"name"},
	)
	CircuitBreakerRejectedTotal = testCounter
	defer func() {
		CircuitBreakerRejectedTotal = originalRejectedCounter
	}()

	testName := "test-rejected-counter"
	logger, _ := zap.NewDevelopment()

	config := DefaultConfig()
	config.MaxFailures = 1

	cb := NewCircuitBreaker(testName, config, logger)

	// Open the circuit
	cb.RecordFailure()

	// Try to allow multiple requests - all should be rejected
	cb.Allow()
	cb.Allow()
	cb.Allow()

	// Verify rejected counter was incremented for each rejection
	metric, err := testCounter.GetMetricWithLabelValues(testName)
	require.NoError(t, err)

	counterMetric := &dto.Metric{}
	err = metric.Write(counterMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(3), *counterMetric.Counter.Value)
}

// ============================================================================
// Test Cases for Metrics Integration via Execute
// ============================================================================

func TestCircuitBreaker_Execute_RecordsMetrics(t *testing.T) {
	// Reset metrics registry for this test
	originalSuccess := CircuitBreakerSuccessesTotal
	originalFailure := CircuitBreakerFailuresTotal
	originalRequests := CircuitBreakerRequestsTotal

	testSuccessCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_exec_successes_total",
			Help: "Total number of successes recorded by circuit breakers",
		},
		[]string{"name"},
	)
	testFailureCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_exec_failures_total",
			Help: "Total number of failures recorded by circuit breakers",
		},
		[]string{"name"},
	)
	testRequestsCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_exec_requests_total",
			Help: "Total number of requests through circuit breakers",
		},
		[]string{"name", "result"},
	)

	CircuitBreakerSuccessesTotal = testSuccessCounter
	CircuitBreakerFailuresTotal = testFailureCounter
	CircuitBreakerRequestsTotal = testRequestsCounter

	defer func() {
		CircuitBreakerSuccessesTotal = originalSuccess
		CircuitBreakerFailuresTotal = originalFailure
		CircuitBreakerRequestsTotal = originalRequests
	}()

	testName := "test-exec-metrics"
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker(testName, DefaultConfig(), logger)

	// Execute a successful function
	err := cb.Execute(context.Background(), func() error {
		return nil
	})
	require.NoError(t, err)

	// Verify success metrics were recorded
	successMetric, err := testSuccessCounter.GetMetricWithLabelValues(testName)
	require.NoError(t, err)
	successCounter := &dto.Metric{}
	err = successMetric.Write(successCounter)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *successCounter.Counter.Value)

	// Verify request was recorded as allowed
	requestMetric, err := testRequestsCounter.GetMetricWithLabelValues(testName, "allowed")
	require.NoError(t, err)
	requestCounter := &dto.Metric{}
	err = requestMetric.Write(requestCounter)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *requestCounter.Counter.Value)
}

func TestCircuitBreaker_ExecuteWithError_RecordsFailureMetrics(t *testing.T) {
	// Reset metrics registry for this test
	originalFailure := CircuitBreakerFailuresTotal
	originalRequests := CircuitBreakerRequestsTotal

	testFailureCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_exec_failures_total_err",
			Help: "Total number of failures recorded by circuit breakers",
		},
		[]string{"name"},
	)
	testRequestsCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_exec_requests_total_err",
			Help: "Total number of requests through circuit breakers",
		},
		[]string{"name", "result"},
	)

	CircuitBreakerFailuresTotal = testFailureCounter
	CircuitBreakerRequestsTotal = testRequestsCounter

	defer func() {
		CircuitBreakerFailuresTotal = originalFailure
		CircuitBreakerRequestsTotal = originalRequests
	}()

	testName := "test-exec-error-metrics"
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker(testName, DefaultConfig(), logger)

	testErr := errors.New("test error")

	// Execute a failing function
	err := cb.Execute(context.Background(), func() error {
		return testErr
	})
	assert.Equal(t, testErr, err)

	// Verify failure metrics were recorded
	failureMetric, err := testFailureCounter.GetMetricWithLabelValues(testName)
	require.NoError(t, err)
	failureCounter := &dto.Metric{}
	err = failureMetric.Write(failureCounter)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *failureCounter.Counter.Value)

	// Verify request was recorded as allowed (the request itself was allowed)
	requestMetric, err := testRequestsCounter.GetMetricWithLabelValues(testName, "allowed")
	require.NoError(t, err)
	requestCounter := &dto.Metric{}
	err = requestMetric.Write(requestCounter)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *requestCounter.Counter.Value)
}

// ============================================================================
// Test Cases for Metrics State Recording
// ============================================================================

func TestRecordState_MetricsCall(t *testing.T) {
	// Reset metrics registry for this test
	originalGauge := CircuitBreakerState
	testGauge := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "test_circuit_breaker_state",
			Help: "Current state of the circuit breaker (0=closed, 1=open, 2=half-open)",
		},
		[]string{"name"},
	)
	CircuitBreakerState = testGauge
	defer func() {
		CircuitBreakerState = originalGauge
	}()

	testName := "test-state-gauge"
	logger, _ := zap.NewDevelopment()
	_ = NewCircuitBreaker(testName, DefaultConfig(), logger)

	// Initial state should be closed (0)
	RecordState(testName, StateClosed)
	metric, err := testGauge.GetMetricWithLabelValues(testName)
	require.NoError(t, err)
	gaugeMetric := &dto.Metric{}
	err = metric.Write(gaugeMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(StateClosed), *gaugeMetric.Gauge.Value)

	// Change to open state (1)
	RecordState(testName, StateOpen)
	metric, err = testGauge.GetMetricWithLabelValues(testName)
	require.NoError(t, err)
	gaugeMetric = &dto.Metric{}
	err = metric.Write(gaugeMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(StateOpen), *gaugeMetric.Gauge.Value)

	// Change to half-open state (2)
	RecordState(testName, StateHalfOpen)
	metric, err = testGauge.GetMetricWithLabelValues(testName)
	require.NoError(t, err)
	gaugeMetric = &dto.Metric{}
	err = metric.Write(gaugeMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(StateHalfOpen), *gaugeMetric.Gauge.Value)
}

// ============================================================================
// Test Cases for Metrics Callbacks
// ============================================================================

func TestMetricsOnStateChange_ReturnsCallback(t *testing.T) {
	// Reset metrics registry for this test
	originalCounter := CircuitBreakerStateChangesTotal
	testCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_circuit_breaker_state_changes_total_callback",
			Help: "Total number of circuit breaker state changes",
		},
		[]string{"name", "from", "to"},
	)
	CircuitBreakerStateChangesTotal = testCounter
	defer func() {
		CircuitBreakerStateChangesTotal = originalCounter
	}()

	// Get the callback
	callback := MetricsOnStateChange()
	assert.NotNil(t, callback)

	// Call the callback
	callback("test-callback", StateClosed, StateOpen)

	// Verify state change was recorded
	metric, err := testCounter.GetMetricWithLabelValues("test-callback", "closed", "open")
	require.NoError(t, err)
	counterMetric := &dto.Metric{}
	err = metric.Write(counterMetric)
	require.NoError(t, err)
	assert.Equal(t, float64(1), *counterMetric.Counter.Value)
}

// ============================================================================
// Test Cases for Concurrent Metrics Access
// ============================================================================

func TestCircuitBreaker_Metrics_ConcurrentAccess(t *testing.T) {
	// Reset metrics registry for this test
	originalSuccess := CircuitBreakerSuccessesTotal
	originalFailure := CircuitBreakerFailuresTotal
	originalRequests := CircuitBreakerRequestsTotal
	originalChanges := CircuitBreakerStateChangesTotal

	testSuccessCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_concurrent_successes",
			Help: "Total number of successes recorded by circuit breakers",
		},
		[]string{"name"},
	)
	testFailureCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_concurrent_failures",
			Help: "Total number of failures recorded by circuit breakers",
		},
		[]string{"name"},
	)
	testRequestsCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_concurrent_requests",
			Help: "Total number of requests through circuit breakers",
		},
		[]string{"name", "result"},
	)
	testChangesCounter := promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_concurrent_changes",
			Help: "Total number of circuit breaker state changes",
		},
		[]string{"name", "from", "to"},
	)

	CircuitBreakerSuccessesTotal = testSuccessCounter
	CircuitBreakerFailuresTotal = testFailureCounter
	CircuitBreakerRequestsTotal = testRequestsCounter
	CircuitBreakerStateChangesTotal = testChangesCounter

	defer func() {
		CircuitBreakerSuccessesTotal = originalSuccess
		CircuitBreakerFailuresTotal = originalFailure
		CircuitBreakerRequestsTotal = originalRequests
		CircuitBreakerStateChangesTotal = originalChanges
	}()

	testName := "test-concurrent-metrics"
	logger, _ := zap.NewDevelopment()
	cb := NewCircuitBreaker(testName, DefaultConfig(), logger)

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent Allow calls (which record requests)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				cb.Allow()
			}
		}()
	}

	// Concurrent RecordSuccess calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				cb.RecordSuccess()
			}
		}()
	}

	wg.Wait()

	// Verify no panics and metrics are accessible
	stats := cb.Stats()
	// Note: TotalRequests is only incremented by RecordSuccess() and RecordFailure(),
	// not by Allow(). So we expect 250 total requests (50 goroutines * 5 successes each).
	assert.Equal(t, 250, stats.TotalRequests) // 50 goroutines * 5 successes each
	assert.Equal(t, 250, stats.Successes)     // 50 goroutines * 5 successes each
}
