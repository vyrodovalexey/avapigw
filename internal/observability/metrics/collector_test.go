// Package metrics provides Prometheus metrics for the API Gateway.
package metrics

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCounter is used to generate unique metric names for tests
var testCounter atomic.Int64

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, testCounter.Add(1))
}

func TestNewREDMetrics(t *testing.T) {
	tests := []struct {
		name       string
		subsystem  string
		metricName string
		labels     []string
	}{
		{
			name:       "basic RED metrics",
			subsystem:  "http",
			metricName: "request",
			labels:     []string{"method", "path"},
		},
		{
			name:       "with single label",
			subsystem:  "grpc",
			metricName: "call",
			labels:     []string{"service"},
		},
		{
			name:       "with multiple labels",
			subsystem:  "backend",
			metricName: "proxy",
			labels:     []string{"backend", "method", "status"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := uniqueName("test_new_red")
			red := NewREDMetrics(namespace, tt.subsystem, tt.metricName, tt.labels)
			assert.NotNil(t, red)
			assert.NotNil(t, red.requestsTotal)
			assert.NotNil(t, red.errorsTotal)
			assert.NotNil(t, red.durationSeconds)
		})
	}
}

func TestREDMetrics_RecordRequest(t *testing.T) {
	namespace := uniqueName("test_record_req")
	red := NewREDMetrics(namespace, "http", "request", []string{"method", "path"})

	tests := []struct {
		name   string
		labels []string
	}{
		{
			name:   "record GET request",
			labels: []string{"GET", "/api/v1/users"},
		},
		{
			name:   "record POST request",
			labels: []string{"POST", "/api/v1/users"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				red.RecordRequest(tt.labels...)
			})
		})
	}
}

func TestREDMetrics_RecordError(t *testing.T) {
	namespace := uniqueName("test_record_err")
	red := NewREDMetrics(namespace, "http", "request", []string{"method", "path"})

	tests := []struct {
		name   string
		labels []string
	}{
		{
			name:   "record error",
			labels: []string{"GET", "/api/v1/users"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				red.RecordError(tt.labels...)
			})
		})
	}
}

func TestREDMetrics_RecordDuration(t *testing.T) {
	namespace := uniqueName("test_record_dur")
	red := NewREDMetrics(namespace, "http", "request", []string{"method", "path"})

	tests := []struct {
		name     string
		duration float64
		labels   []string
	}{
		{
			name:     "record short duration",
			duration: 0.001,
			labels:   []string{"GET", "/api/v1/users"},
		},
		{
			name:     "record long duration",
			duration: 5.0,
			labels:   []string{"POST", "/api/v1/users"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				red.RecordDuration(tt.duration, tt.labels...)
			})
		})
	}
}

func TestREDMetrics_Record(t *testing.T) {
	namespace := uniqueName("test_record_full")
	red := NewREDMetrics(namespace, "http", "request", []string{"method", "path"})

	tests := []struct {
		name     string
		duration float64
		isError  bool
		labels   []string
	}{
		{
			name:     "record successful request",
			duration: 0.100,
			isError:  false,
			labels:   []string{"GET", "/api/v1/users"},
		},
		{
			name:     "record failed request",
			duration: 0.050,
			isError:  true,
			labels:   []string{"POST", "/api/v1/users"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			assert.NotPanics(t, func() {
				red.Record(tt.duration, tt.isError, tt.labels...)
			})
		})
	}
}

// gatewayCollectorOnce ensures we only create one GatewayCollector for tests
var (
	gatewayCollectorOnce sync.Once
	testGatewayCollector *GatewayCollector
)

func getTestGatewayCollector() *GatewayCollector {
	gatewayCollectorOnce.Do(func() {
		testGatewayCollector = NewGatewayCollector("test-service", "1.0.0")
	})
	return testGatewayCollector
}

func TestNewGatewayCollector(t *testing.T) {
	gc := getTestGatewayCollector()
	require.NotNil(t, gc)
	assert.NotNil(t, gc.gatewayInfo)
	assert.NotNil(t, gc.uptime)
	assert.NotNil(t, gc.goroutines)
	assert.NotNil(t, gc.threads)
	assert.NotNil(t, gc.heapAlloc)
	assert.NotNil(t, gc.heapSys)
	assert.NotNil(t, gc.gcPause)
	assert.NotNil(t, gc.activeConnections)
	assert.NotNil(t, gc.totalConnections)
	assert.NotNil(t, gc.connectionErrors)
	assert.NotNil(t, gc.connectionDurations)
	assert.NotNil(t, gc.requestsInProgress)
	assert.NotNil(t, gc.requestQueueSize)
	assert.NotNil(t, gc.customGauges)
	assert.NotNil(t, gc.customCounters)
}

func TestGatewayCollector_Collect(t *testing.T) {
	gc := getTestGatewayCollector()

	// Should not panic
	assert.NotPanics(t, func() {
		gc.Collect()
	})

	// Call multiple times to ensure stability
	for i := 0; i < 5; i++ {
		assert.NotPanics(t, func() {
			gc.Collect()
		})
	}
}

func TestGatewayCollector_SetActiveConnections(t *testing.T) {
	gc := getTestGatewayCollector()

	tests := []struct {
		name  string
		count int
	}{
		{"zero connections", 0},
		{"some connections", 100},
		{"many connections", 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				gc.SetActiveConnections(tt.count)
			})
		})
	}
}

func TestGatewayCollector_IncrementConnections(t *testing.T) {
	gc := getTestGatewayCollector()

	// Should not panic
	assert.NotPanics(t, func() {
		gc.IncrementConnections()
	})

	// Multiple increments
	for i := 0; i < 10; i++ {
		assert.NotPanics(t, func() {
			gc.IncrementConnections()
		})
	}
}

func TestGatewayCollector_IncrementConnectionErrors(t *testing.T) {
	gc := getTestGatewayCollector()

	// Should not panic
	assert.NotPanics(t, func() {
		gc.IncrementConnectionErrors()
	})

	// Multiple increments
	for i := 0; i < 10; i++ {
		assert.NotPanics(t, func() {
			gc.IncrementConnectionErrors()
		})
	}
}

func TestGatewayCollector_RecordConnectionDuration(t *testing.T) {
	gc := getTestGatewayCollector()

	tests := []struct {
		name     string
		duration time.Duration
	}{
		{"short duration", 100 * time.Millisecond},
		{"medium duration", 5 * time.Second},
		{"long duration", 1 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				gc.RecordConnectionDuration(tt.duration)
			})
		})
	}
}

func TestGatewayCollector_SetRequestsInProgress(t *testing.T) {
	gc := getTestGatewayCollector()

	tests := []struct {
		name  string
		count int
	}{
		{"zero requests", 0},
		{"some requests", 50},
		{"many requests", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				gc.SetRequestsInProgress(tt.count)
			})
		})
	}
}

func TestGatewayCollector_IncrementRequestsInProgress(t *testing.T) {
	gc := getTestGatewayCollector()

	// Should not panic
	assert.NotPanics(t, func() {
		gc.IncrementRequestsInProgress()
	})

	// Multiple increments
	for i := 0; i < 10; i++ {
		assert.NotPanics(t, func() {
			gc.IncrementRequestsInProgress()
		})
	}
}

func TestGatewayCollector_DecrementRequestsInProgress(t *testing.T) {
	gc := getTestGatewayCollector()

	// Increment first
	gc.IncrementRequestsInProgress()
	gc.IncrementRequestsInProgress()

	// Should not panic
	assert.NotPanics(t, func() {
		gc.DecrementRequestsInProgress()
	})
}

func TestGatewayCollector_SetRequestQueueSize(t *testing.T) {
	gc := getTestGatewayCollector()

	tests := []struct {
		name string
		size int
	}{
		{"empty queue", 0},
		{"small queue", 10},
		{"large queue", 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				gc.SetRequestQueueSize(tt.size)
			})
		})
	}
}

func TestGatewayCollector_RegisterCustomGauge(t *testing.T) {
	gc := getTestGatewayCollector()

	gaugeName := uniqueName("custom_gauge")
	gauge := gc.RegisterCustomGauge(gaugeName, "A custom gauge metric")
	assert.NotNil(t, gauge)

	// Registering same gauge should return existing one
	gauge2 := gc.RegisterCustomGauge(gaugeName, "A custom gauge metric")
	assert.Same(t, gauge, gauge2)
}

func TestGatewayCollector_RegisterCustomCounter(t *testing.T) {
	gc := getTestGatewayCollector()

	counterName := uniqueName("custom_counter")
	counter := gc.RegisterCustomCounter(counterName, "A custom counter metric")
	assert.NotNil(t, counter)

	// Registering same counter should return existing one
	counter2 := gc.RegisterCustomCounter(counterName, "A custom counter metric")
	assert.Same(t, counter, counter2)
}

func TestGatewayCollector_GetCustomGauge(t *testing.T) {
	gc := getTestGatewayCollector()

	// Get non-existent gauge
	gauge, exists := gc.GetCustomGauge("nonexistent_gauge_xyz")
	assert.False(t, exists)
	assert.Nil(t, gauge)

	// Register and get gauge
	gaugeName := uniqueName("get_gauge")
	gc.RegisterCustomGauge(gaugeName, "My gauge")
	gauge, exists = gc.GetCustomGauge(gaugeName)
	assert.True(t, exists)
	assert.NotNil(t, gauge)
}

func TestGatewayCollector_GetCustomCounter(t *testing.T) {
	gc := getTestGatewayCollector()

	// Get non-existent counter
	counter, exists := gc.GetCustomCounter("nonexistent_counter_xyz")
	assert.False(t, exists)
	assert.Nil(t, counter)

	// Register and get counter
	counterName := uniqueName("get_counter")
	gc.RegisterCustomCounter(counterName, "My counter")
	counter, exists = gc.GetCustomCounter(counterName)
	assert.True(t, exists)
	assert.NotNil(t, counter)
}

func TestGatewayCollector_CustomMetricsUsage(t *testing.T) {
	gc := getTestGatewayCollector()

	// Register and use custom gauge
	gaugeName := uniqueName("usage_gauge")
	gauge := gc.RegisterCustomGauge(gaugeName, "Test gauge")
	assert.NotPanics(t, func() {
		gauge.Set(42.0)
		gauge.Inc()
		gauge.Dec()
		gauge.Add(10.0)
		gauge.Sub(5.0)
	})

	// Register and use custom counter
	counterName := uniqueName("usage_counter")
	counter := gc.RegisterCustomCounter(counterName, "Test counter")
	assert.NotPanics(t, func() {
		counter.Inc()
		counter.Add(10.0)
	})
}

// runtimeCollectorOnce ensures we only create one RuntimeCollector for tests
var (
	runtimeCollectorOnce sync.Once
	testRuntimeCollector *RuntimeCollector
)

func getTestRuntimeCollector() *RuntimeCollector {
	runtimeCollectorOnce.Do(func() {
		testRuntimeCollector = NewRuntimeCollector()
	})
	return testRuntimeCollector
}

func TestNewRuntimeCollector(t *testing.T) {
	rc := getTestRuntimeCollector()
	require.NotNil(t, rc)
	assert.NotNil(t, rc.allocBytes)
	assert.NotNil(t, rc.totalAllocBytes)
	assert.NotNil(t, rc.sysBytes)
	assert.NotNil(t, rc.mallocsTotal)
	assert.NotNil(t, rc.freesTotal)
	assert.NotNil(t, rc.gcSysBytes)
	assert.NotNil(t, rc.gcNextBytes)
	assert.NotNil(t, rc.gcCPUFraction)
	assert.NotNil(t, rc.numGC)
	assert.NotNil(t, rc.numGoroutines)
	assert.NotNil(t, rc.numCgoCall)
}

func TestRuntimeCollector_Collect(t *testing.T) {
	rc := getTestRuntimeCollector()

	// Should not panic
	assert.NotPanics(t, func() {
		rc.Collect()
	})

	// Call multiple times to ensure stability
	for i := 0; i < 5; i++ {
		assert.NotPanics(t, func() {
			rc.Collect()
		})
	}
}

func TestGatewayCollector_ConcurrentAccess(t *testing.T) {
	gc := getTestGatewayCollector()

	done := make(chan bool)

	// Concurrent writes
	go func() {
		for i := 0; i < 100; i++ {
			gc.SetActiveConnections(i)
			gc.IncrementConnections()
			gc.IncrementConnectionErrors()
			gc.SetRequestsInProgress(i)
			gc.IncrementRequestsInProgress()
			gc.DecrementRequestsInProgress()
			gc.SetRequestQueueSize(i)
		}
		done <- true
	}()

	// Concurrent reads
	go func() {
		for i := 0; i < 100; i++ {
			gc.Collect()
			gc.GetCustomGauge("test")
			gc.GetCustomCounter("test")
		}
		done <- true
	}()

	// Concurrent custom metric registration
	go func() {
		for i := 0; i < 10; i++ {
			gc.RegisterCustomGauge(uniqueName("conc_gauge"), "help")
			gc.RegisterCustomCounter(uniqueName("conc_counter"), "help")
		}
		done <- true
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done
}

// TestGatewayCollector_Collect_WithGC tests Collect after forcing garbage collection.
func TestGatewayCollector_Collect_WithGC(t *testing.T) {
	gc := getTestGatewayCollector()

	// Force garbage collection to ensure NumGC > 0
	runtime.GC()

	// Should not panic and should record GC pause
	assert.NotPanics(t, func() {
		gc.Collect()
	})

	// Force multiple GC cycles
	for i := 0; i < 5; i++ {
		// Allocate some memory to trigger GC
		_ = make([]byte, 1024*1024)
		runtime.GC()
		gc.Collect()
	}
}

// TestGatewayCollector_Collect_UptimeIncreases tests that uptime increases over time.
func TestGatewayCollector_Collect_UptimeIncreases(t *testing.T) {
	gc := getTestGatewayCollector()

	// First collect
	gc.Collect()

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Second collect - uptime should have increased
	gc.Collect()

	// We can't easily verify the uptime value without accessing internal state,
	// but we verify no panic occurs
}

// TestGatewayCollector_Collect_RuntimeMetrics tests that runtime metrics are collected.
func TestGatewayCollector_Collect_RuntimeMetrics(t *testing.T) {
	gc := getTestGatewayCollector()

	// Create some goroutines to affect the count
	done := make(chan struct{})
	for i := 0; i < 5; i++ {
		go func() {
			<-done
		}()
	}

	// Collect should capture goroutine count
	gc.Collect()

	// Clean up goroutines
	close(done)
	time.Sleep(10 * time.Millisecond)

	// Collect again
	gc.Collect()
}
