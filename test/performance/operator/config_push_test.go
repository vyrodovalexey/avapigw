// Package operator provides performance tests for the apigw-operator.
//
//go:build performance
// +build performance

package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

// ConfigPushMetrics holds performance metrics for configuration push tests.
type ConfigPushMetrics struct {
	TotalPushes      int64
	SuccessfulPushes int64
	FailedPushes     int64
	TotalDuration    time.Duration
	MinLatency       time.Duration
	MaxLatency       time.Duration
	AvgLatency       time.Duration
	P50Latency       time.Duration
	P95Latency       time.Duration
	P99Latency       time.Duration
	Throughput       float64 // pushes per second
	ConfigSizeBytes  int
	BatchSize        int
}

// ConfigPushResult holds the result of a configuration push test.
type ConfigPushResult struct {
	TestName   string
	Duration   time.Duration
	Metrics    ConfigPushMetrics
	PassedSLO  bool
	SLODetails string
}

// ConfigPushSLO defines Service Level Objectives for configuration push.
type ConfigPushSLO struct {
	MaxP99LatencyMs     float64
	MinThroughputRPS    float64
	MaxErrorRatePercent float64
}

// DefaultConfigPushSLO returns the default SLO for configuration push.
func DefaultConfigPushSLO() ConfigPushSLO {
	return ConfigPushSLO{
		MaxP99LatencyMs:     50.0,  // < 50ms
		MinThroughputRPS:    500.0, // > 500 pushes/second
		MaxErrorRatePercent: 0.1,   // < 0.1% error rate
	}
}

// TestConfigPushLatency measures configuration push latency.
func TestConfigPushLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	server := createTestServer(t)
	defer server.Stop()

	// Test with different config sizes
	configSizes := []int{1024, 4096, 16384, 65536} // 1KB, 4KB, 16KB, 64KB

	for _, size := range configSizes {
		t.Run(fmt.Sprintf("ConfigSize_%dB", size), func(t *testing.T) {
			result := runConfigPushLatencyTest(t, ctx, server, size, 30*time.Second)

			slo := DefaultConfigPushSLO()
			result.PassedSLO = checkConfigPushSLO(result.Metrics, slo)

			logConfigPushResult(t, result)

			if !result.PassedSLO {
				t.Errorf("Config push SLO not met: %s", result.SLODetails)
			}
		})
	}
}

// TestConfigPushThroughput measures configuration push throughput.
func TestConfigPushThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	server := createTestServer(t)
	defer server.Stop()

	result := runConfigPushThroughputTest(t, ctx, server, 4096, 60*time.Second, 10)

	slo := DefaultConfigPushSLO()
	result.PassedSLO = checkConfigPushSLO(result.Metrics, slo)

	logConfigPushResult(t, result)

	if result.Metrics.Throughput < slo.MinThroughputRPS {
		t.Errorf("Config push throughput SLO not met: got %.2f RPS, want >= %.2f RPS",
			result.Metrics.Throughput, slo.MinThroughputRPS)
	}
}

// TestBatchConfigUpdate tests batch configuration update performance.
func TestBatchConfigUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	server := createTestServer(t)
	defer server.Stop()

	batchSizes := []int{1, 10, 50, 100}

	for _, batchSize := range batchSizes {
		t.Run(fmt.Sprintf("BatchSize_%d", batchSize), func(t *testing.T) {
			result := runBatchConfigUpdateTest(t, ctx, server, batchSize, 4096, 30*time.Second)

			logConfigPushResult(t, result)

			// Verify batch processing is efficient
			expectedMinThroughput := float64(batchSize) * 10 // At least 10 batches per second
			if result.Metrics.Throughput < expectedMinThroughput {
				t.Logf("WARNING: Batch throughput may not be optimal: %.2f RPS", result.Metrics.Throughput)
			}
		})
	}
}

// TestConfigPushWithVaryingSizes tests configuration push with varying sizes.
func TestConfigPushWithVaryingSizes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	server := createTestServer(t)
	defer server.Stop()

	// Test with sizes from 256B to 1MB
	configSizes := []int{256, 1024, 4096, 16384, 65536, 262144, 1048576}
	var results []ConfigPushResult

	for _, size := range configSizes {
		result := runConfigPushLatencyTest(t, ctx, server, size, 10*time.Second)
		results = append(results, result)
	}

	// Analyze scaling behavior
	t.Log("Config Size Scaling Analysis:")
	t.Log("==============================")
	for i, result := range results {
		t.Logf("Config Size: %d bytes, P99 Latency: %.2fms, Throughput: %.2f RPS",
			result.Metrics.ConfigSizeBytes,
			float64(result.Metrics.P99Latency.Microseconds())/1000.0,
			result.Metrics.Throughput)

		// Check for linear scaling
		if i > 0 {
			prevLatency := float64(results[i-1].Metrics.P99Latency.Microseconds())
			currLatency := float64(result.Metrics.P99Latency.Microseconds())
			sizeRatio := float64(result.Metrics.ConfigSizeBytes) / float64(results[i-1].Metrics.ConfigSizeBytes)
			latencyRatio := currLatency / prevLatency

			if latencyRatio > sizeRatio*2 {
				t.Logf("WARNING: Non-linear scaling detected. Size ratio: %.2f, Latency ratio: %.2f",
					sizeRatio, latencyRatio)
			}
		}
	}
}

// TestConcurrentConfigPush tests concurrent configuration push performance.
func TestConcurrentConfigPush(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	server := createTestServer(t)
	defer server.Stop()

	concurrencyLevels := []int{1, 5, 10, 20, 50}

	for _, concurrency := range concurrencyLevels {
		t.Run(fmt.Sprintf("Concurrency_%d", concurrency), func(t *testing.T) {
			result := runConcurrentConfigPushTest(t, ctx, server, concurrency, 4096, 20*time.Second)

			logConfigPushResult(t, result)

			// Verify no errors under concurrent load
			errorRate := float64(result.Metrics.FailedPushes) / float64(result.Metrics.TotalPushes) * 100
			if errorRate > 0.1 {
				t.Errorf("Error rate too high under concurrent load: %.2f%%", errorRate)
			}
		})
	}
}

// TestConfigPushAllTypes tests pushing all configuration types.
func TestConfigPushAllTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	server := createTestServer(t)
	defer server.Stop()

	configTypes := []string{"apiroute", "grpcroute", "backend", "grpcbackend"}

	for _, configType := range configTypes {
		t.Run(fmt.Sprintf("Type_%s", configType), func(t *testing.T) {
			result := runConfigTypePushTest(t, ctx, server, configType, 4096, 20*time.Second)

			logConfigPushResult(t, result)

			slo := DefaultConfigPushSLO()
			if !checkConfigPushSLO(result.Metrics, slo) {
				t.Errorf("Config push SLO not met for type %s", configType)
			}
		})
	}
}

// createTestServer creates a test gRPC server.
func createTestServer(t *testing.T) *operatorgrpc.Server {
	t.Helper()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{
		Port:                 0,
		MaxConcurrentStreams: 1000,
		MaxRecvMsgSize:       4 * 1024 * 1024,
		MaxSendMsgSize:       4 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("Failed to create gRPC server: %v", err)
	}

	return server
}

// generateTestConfig generates a test configuration of the specified size.
func generateTestConfig(size int) []byte {
	config := make([]byte, size)
	for i := range config {
		config[i] = byte('a' + (i % 26))
	}
	return config
}

// runConfigPushLatencyTest runs a configuration push latency test.
func runConfigPushLatencyTest(t *testing.T, ctx context.Context, server *operatorgrpc.Server, configSize int, duration time.Duration) ConfigPushResult {
	t.Helper()

	config := generateTestConfig(configSize)
	var latencies []time.Duration
	var mu sync.Mutex
	var successCount, failCount int64

	startTime := time.Now()
	endTime := startTime.Add(duration)

	routeNum := 0
	for time.Now().Before(endTime) {
		name := fmt.Sprintf("test-route-%d", routeNum)
		routeNum++

		start := time.Now()
		err := server.ApplyAPIRoute(ctx, name, "default", config)
		elapsed := time.Since(start)

		mu.Lock()
		latencies = append(latencies, elapsed)
		mu.Unlock()

		if err != nil {
			atomic.AddInt64(&failCount, 1)
		} else {
			atomic.AddInt64(&successCount, 1)
		}
	}

	totalDuration := time.Since(startTime)
	metrics := calculateConfigPushMetrics(latencies, successCount, failCount, totalDuration, configSize, 1)

	return ConfigPushResult{
		TestName: fmt.Sprintf("ConfigPushLatency_%dB", configSize),
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runConfigPushThroughputTest runs a configuration push throughput test.
func runConfigPushThroughputTest(t *testing.T, ctx context.Context, server *operatorgrpc.Server, configSize int, duration time.Duration, concurrency int) ConfigPushResult {
	t.Helper()

	config := generateTestConfig(configSize)
	var totalPushes int64
	var successCount, failCount int64
	var latencies []time.Duration
	var mu sync.Mutex

	startTime := time.Now()
	endTime := startTime.Add(duration)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			routeNum := 0
			for time.Now().Before(endTime) {
				name := fmt.Sprintf("worker-%d-route-%d", workerID, routeNum)
				routeNum++

				start := time.Now()
				err := server.ApplyAPIRoute(ctx, name, "default", config)
				elapsed := time.Since(start)

				mu.Lock()
				latencies = append(latencies, elapsed)
				mu.Unlock()

				atomic.AddInt64(&totalPushes, 1)

				if err != nil {
					atomic.AddInt64(&failCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	totalDuration := time.Since(startTime)
	metrics := calculateConfigPushMetrics(latencies, successCount, failCount, totalDuration, configSize, 1)

	return ConfigPushResult{
		TestName: "ConfigPushThroughput",
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runBatchConfigUpdateTest runs a batch configuration update test.
func runBatchConfigUpdateTest(t *testing.T, ctx context.Context, server *operatorgrpc.Server, batchSize, configSize int, duration time.Duration) ConfigPushResult {
	t.Helper()

	config := generateTestConfig(configSize)
	var latencies []time.Duration
	var mu sync.Mutex
	var successCount, failCount int64

	startTime := time.Now()
	endTime := startTime.Add(duration)

	batchNum := 0
	for time.Now().Before(endTime) {
		start := time.Now()

		// Push a batch of configurations
		for i := 0; i < batchSize; i++ {
			name := fmt.Sprintf("batch-%d-route-%d", batchNum, i)
			err := server.ApplyAPIRoute(ctx, name, "default", config)
			if err != nil {
				atomic.AddInt64(&failCount, 1)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}

		elapsed := time.Since(start)
		batchNum++

		mu.Lock()
		latencies = append(latencies, elapsed)
		mu.Unlock()
	}

	totalDuration := time.Since(startTime)
	metrics := calculateConfigPushMetrics(latencies, successCount, failCount, totalDuration, configSize, batchSize)

	return ConfigPushResult{
		TestName: fmt.Sprintf("BatchConfigUpdate_%d", batchSize),
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runConcurrentConfigPushTest runs a concurrent configuration push test.
func runConcurrentConfigPushTest(t *testing.T, ctx context.Context, server *operatorgrpc.Server, concurrency, configSize int, duration time.Duration) ConfigPushResult {
	t.Helper()

	config := generateTestConfig(configSize)
	var totalPushes int64
	var successCount, failCount int64
	var latencies []time.Duration
	var mu sync.Mutex

	startTime := time.Now()
	endTime := startTime.Add(duration)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			routeNum := 0
			for time.Now().Before(endTime) {
				name := fmt.Sprintf("concurrent-%d-route-%d", workerID, routeNum)
				routeNum++

				start := time.Now()
				err := server.ApplyAPIRoute(ctx, name, "default", config)
				elapsed := time.Since(start)

				mu.Lock()
				latencies = append(latencies, elapsed)
				mu.Unlock()

				atomic.AddInt64(&totalPushes, 1)

				if err != nil {
					atomic.AddInt64(&failCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()
	totalDuration := time.Since(startTime)
	metrics := calculateConfigPushMetrics(latencies, successCount, failCount, totalDuration, configSize, 1)

	return ConfigPushResult{
		TestName: fmt.Sprintf("ConcurrentConfigPush_%d", concurrency),
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runConfigTypePushTest runs a configuration push test for a specific type.
func runConfigTypePushTest(t *testing.T, ctx context.Context, server *operatorgrpc.Server, configType string, configSize int, duration time.Duration) ConfigPushResult {
	t.Helper()

	config := generateTestConfig(configSize)
	var latencies []time.Duration
	var mu sync.Mutex
	var successCount, failCount int64

	startTime := time.Now()
	endTime := startTime.Add(duration)

	routeNum := 0
	for time.Now().Before(endTime) {
		name := fmt.Sprintf("test-%s-%d", configType, routeNum)
		routeNum++

		start := time.Now()
		var err error

		switch configType {
		case "apiroute":
			err = server.ApplyAPIRoute(ctx, name, "default", config)
		case "grpcroute":
			err = server.ApplyGRPCRoute(ctx, name, "default", config)
		case "backend":
			err = server.ApplyBackend(ctx, name, "default", config)
		case "grpcbackend":
			err = server.ApplyGRPCBackend(ctx, name, "default", config)
		}

		elapsed := time.Since(start)

		mu.Lock()
		latencies = append(latencies, elapsed)
		mu.Unlock()

		if err != nil {
			atomic.AddInt64(&failCount, 1)
		} else {
			atomic.AddInt64(&successCount, 1)
		}
	}

	totalDuration := time.Since(startTime)
	metrics := calculateConfigPushMetrics(latencies, successCount, failCount, totalDuration, configSize, 1)

	return ConfigPushResult{
		TestName: fmt.Sprintf("ConfigTypePush_%s", configType),
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// calculateConfigPushMetrics calculates configuration push metrics.
func calculateConfigPushMetrics(latencies []time.Duration, successCount, failCount int64, totalDuration time.Duration, configSize, batchSize int) ConfigPushMetrics {
	if len(latencies) == 0 {
		return ConfigPushMetrics{}
	}

	sortedLatencies := make([]time.Duration, len(latencies))
	copy(sortedLatencies, latencies)
	sortDurations(sortedLatencies)

	var totalLatency time.Duration
	for _, l := range sortedLatencies {
		totalLatency += l
	}

	n := len(sortedLatencies)

	return ConfigPushMetrics{
		TotalPushes:      successCount + failCount,
		SuccessfulPushes: successCount,
		FailedPushes:     failCount,
		TotalDuration:    totalDuration,
		MinLatency:       sortedLatencies[0],
		MaxLatency:       sortedLatencies[n-1],
		AvgLatency:       totalLatency / time.Duration(n),
		P50Latency:       sortedLatencies[n*50/100],
		P95Latency:       sortedLatencies[n*95/100],
		P99Latency:       sortedLatencies[n*99/100],
		Throughput:       float64(successCount+failCount) / totalDuration.Seconds(),
		ConfigSizeBytes:  configSize,
		BatchSize:        batchSize,
	}
}

// checkConfigPushSLO checks if metrics meet the configuration push SLO.
func checkConfigPushSLO(metrics ConfigPushMetrics, slo ConfigPushSLO) bool {
	p99Ms := float64(metrics.P99Latency.Microseconds()) / 1000.0
	errorRate := float64(metrics.FailedPushes) / float64(metrics.TotalPushes) * 100

	return p99Ms <= slo.MaxP99LatencyMs &&
		metrics.Throughput >= slo.MinThroughputRPS &&
		errorRate <= slo.MaxErrorRatePercent
}

// logConfigPushResult logs the configuration push result.
func logConfigPushResult(t *testing.T, result ConfigPushResult) {
	t.Helper()

	t.Logf("Config Push Test: %s", result.TestName)
	t.Logf("  Duration: %v", result.Duration)
	t.Logf("  Total Pushes: %d", result.Metrics.TotalPushes)
	t.Logf("  Successful: %d", result.Metrics.SuccessfulPushes)
	t.Logf("  Failed: %d", result.Metrics.FailedPushes)
	t.Logf("  Throughput: %.2f pushes/sec", result.Metrics.Throughput)
	t.Logf("  Config Size: %d bytes", result.Metrics.ConfigSizeBytes)

	if result.Metrics.BatchSize > 1 {
		t.Logf("  Batch Size: %d", result.Metrics.BatchSize)
	}

	if result.Metrics.P99Latency > 0 {
		t.Logf("  Latency Avg: %.2fms", float64(result.Metrics.AvgLatency.Microseconds())/1000.0)
		t.Logf("  Latency P50: %.2fms", float64(result.Metrics.P50Latency.Microseconds())/1000.0)
		t.Logf("  Latency P95: %.2fms", float64(result.Metrics.P95Latency.Microseconds())/1000.0)
		t.Logf("  Latency P99: %.2fms", float64(result.Metrics.P99Latency.Microseconds())/1000.0)
		t.Logf("  Latency Min: %.2fms", float64(result.Metrics.MinLatency.Microseconds())/1000.0)
		t.Logf("  Latency Max: %.2fms", float64(result.Metrics.MaxLatency.Microseconds())/1000.0)
	}

	jsonResult, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("JSON Result:\n%s", string(jsonResult))
}

// BenchmarkConfigPush provides Go benchmark for configuration push.
func BenchmarkConfigPush(b *testing.B) {
	ctx := context.Background()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	config := generateTestConfig(4096)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("bench-route-%d", i)
		_ = server.ApplyAPIRoute(ctx, name, "default", config)
	}
}

// BenchmarkConfigPushParallel provides parallel benchmark for configuration push.
func BenchmarkConfigPushParallel(b *testing.B) {
	ctx := context.Background()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	config := generateTestConfig(4096)

	b.ResetTimer()
	b.ReportAllocs()

	var counter int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddInt64(&counter, 1)
			name := fmt.Sprintf("bench-route-%d", idx)
			_ = server.ApplyAPIRoute(ctx, name, "default", config)
		}
	})
}

// BenchmarkConfigPushVaryingSizes benchmarks config push with varying sizes.
func BenchmarkConfigPushVaryingSizes(b *testing.B) {
	ctx := context.Background()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	sizes := []int{1024, 4096, 16384, 65536}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			config := generateTestConfig(size)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				name := fmt.Sprintf("bench-route-%d", i)
				_ = server.ApplyAPIRoute(ctx, name, "default", config)
			}
		})
	}
}
