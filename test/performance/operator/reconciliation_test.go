// Package operator provides performance tests for the apigw-operator.
//
//go:build performance
// +build performance

package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/operator/controller"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

func init() {
	_ = avapigwv1alpha1.AddToScheme(scheme.Scheme)
}

// ReconciliationMetrics holds performance metrics for reconciliation tests.
type ReconciliationMetrics struct {
	TotalReconciliations int64
	SuccessfulReconciles int64
	FailedReconciles     int64
	TotalDuration        time.Duration
	MinLatency           time.Duration
	MaxLatency           time.Duration
	P50Latency           time.Duration
	P95Latency           time.Duration
	P99Latency           time.Duration
	Throughput           float64 // reconciles per second
	MemoryUsageMB        float64
	GoroutineCount       int
}

// PerformanceResult holds the result of a performance test.
type PerformanceResult struct {
	TestName   string
	CRDCount   int
	Duration   time.Duration
	Metrics    ReconciliationMetrics
	PassedSLO  bool
	SLODetails string
}

// SLO defines Service Level Objectives for operator performance.
type SLO struct {
	MaxP99LatencyMs     float64
	MinThroughputRPS    float64
	MaxMemoryUsageMB    float64
	MaxErrorRatePercent float64
}

// DefaultSLO returns the default SLO for operator performance.
func DefaultSLO() SLO {
	return SLO{
		MaxP99LatencyMs:     100.0,  // < 100ms
		MinThroughputRPS:    1000.0, // > 1000 reconciles/second
		MaxMemoryUsageMB:    256.0,  // < 256MB
		MaxErrorRatePercent: 0.1,    // < 0.1% error rate
	}
}

// TestReconciliationLatency measures reconciliation latency for varying CRD counts.
func TestReconciliationLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	crdCounts := []int{10, 50, 100, 500}
	slo := DefaultSLO()

	for _, count := range crdCounts {
		t.Run(fmt.Sprintf("CRDCount_%d", count), func(t *testing.T) {
			result := runReconciliationLatencyTest(t, count, 30*time.Second)

			// Check SLO
			result.PassedSLO = checkSLO(result.Metrics, slo)

			// Log results
			logPerformanceResult(t, result)

			// Assert SLO
			if !result.PassedSLO {
				t.Errorf("SLO not met: %s", result.SLODetails)
			}
		})
	}
}

// TestReconciliationThroughput measures maximum reconciliation throughput.
func TestReconciliationThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Test with 100 CRDs for 60 seconds
	result := runReconciliationThroughputTest(t, 100, 60*time.Second)

	slo := DefaultSLO()
	result.PassedSLO = checkSLO(result.Metrics, slo)

	logPerformanceResult(t, result)

	if result.Metrics.Throughput < slo.MinThroughputRPS {
		t.Errorf("Throughput SLO not met: got %.2f RPS, want >= %.2f RPS",
			result.Metrics.Throughput, slo.MinThroughputRPS)
	}
}

// TestConcurrentReconciliation tests concurrent reconciliation performance.
func TestConcurrentReconciliation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	concurrencyLevels := []int{1, 5, 10, 20}
	crdCount := 100

	for _, concurrency := range concurrencyLevels {
		t.Run(fmt.Sprintf("Concurrency_%d", concurrency), func(t *testing.T) {
			result := runConcurrentReconciliationTest(t, crdCount, concurrency, 30*time.Second)

			logPerformanceResult(t, result)

			// Verify no errors under concurrent load
			errorRate := float64(result.Metrics.FailedReconciles) / float64(result.Metrics.TotalReconciliations) * 100
			if errorRate > 0.1 {
				t.Errorf("Error rate too high under concurrent load: %.2f%%", errorRate)
			}
		})
	}
}

// TestMemoryUsageDuringReconciliation measures memory usage during reconciliation.
func TestMemoryUsageDuringReconciliation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	crdCounts := []int{10, 50, 100, 500}
	slo := DefaultSLO()

	for _, count := range crdCounts {
		t.Run(fmt.Sprintf("CRDCount_%d", count), func(t *testing.T) {
			result := runMemoryUsageTest(t, count, 30*time.Second)

			logPerformanceResult(t, result)

			if result.Metrics.MemoryUsageMB > slo.MaxMemoryUsageMB {
				t.Errorf("Memory usage SLO not met: got %.2f MB, want <= %.2f MB",
					result.Metrics.MemoryUsageMB, slo.MaxMemoryUsageMB)
			}
		})
	}
}

// TestReconciliationScaling tests how reconciliation performance scales with CRD count.
func TestReconciliationScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	crdCounts := []int{10, 50, 100, 200, 500}
	var results []PerformanceResult

	for _, count := range crdCounts {
		result := runReconciliationLatencyTest(t, count, 20*time.Second)
		results = append(results, result)
	}

	// Analyze scaling behavior
	t.Log("Scaling Analysis:")
	t.Log("================")
	for i, result := range results {
		t.Logf("CRD Count: %d, P99 Latency: %.2fms, Throughput: %.2f RPS",
			result.CRDCount,
			float64(result.Metrics.P99Latency.Microseconds())/1000.0,
			result.Metrics.Throughput)

		// Check for linear scaling (latency should not increase more than 2x when CRD count doubles)
		if i > 0 {
			prevLatency := float64(results[i-1].Metrics.P99Latency.Microseconds())
			currLatency := float64(result.Metrics.P99Latency.Microseconds())
			crdRatio := float64(result.CRDCount) / float64(results[i-1].CRDCount)
			latencyRatio := currLatency / prevLatency

			if latencyRatio > crdRatio*2 {
				t.Logf("WARNING: Non-linear scaling detected. CRD ratio: %.2f, Latency ratio: %.2f",
					crdRatio, latencyRatio)
			}
		}
	}
}

// runReconciliationLatencyTest runs a reconciliation latency test.
func runReconciliationLatencyTest(t *testing.T, crdCount int, duration time.Duration) PerformanceResult {
	ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
	defer cancel()

	// Create fake client and reconciler
	kit := setupTestReconciler(t, crdCount)

	// Create CRDs
	crds := createTestAPIRoutes(crdCount)
	for _, crd := range crds {
		if err := kit.FakeClient.Create(ctx, crd); err != nil {
			t.Fatalf("Failed to create CRD: %v", err)
		}
	}

	// Collect latencies
	var latencies []time.Duration
	var mu sync.Mutex
	var successCount, failCount int64

	startTime := time.Now()
	endTime := startTime.Add(duration)

	for time.Now().Before(endTime) {
		for _, crd := range crds {
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      crd.Name,
					Namespace: crd.Namespace,
				},
			}

			start := time.Now()
			_, err := kit.Reconciler.Reconcile(ctx, req)
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
	}

	totalDuration := time.Since(startTime)

	// Calculate metrics
	metrics := calculateMetrics(latencies, successCount, failCount, totalDuration)

	return PerformanceResult{
		TestName: "ReconciliationLatency",
		CRDCount: crdCount,
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runReconciliationThroughputTest runs a throughput test.
func runReconciliationThroughputTest(t *testing.T, crdCount int, duration time.Duration) PerformanceResult {
	ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
	defer cancel()

	kit := setupTestReconciler(t, crdCount)

	crds := createTestAPIRoutes(crdCount)
	for _, crd := range crds {
		if err := kit.FakeClient.Create(ctx, crd); err != nil {
			t.Fatalf("Failed to create CRD: %v", err)
		}
	}

	var totalReconciles int64
	var successCount, failCount int64

	startTime := time.Now()
	endTime := startTime.Add(duration)

	// Run reconciliations as fast as possible
	for time.Now().Before(endTime) {
		for _, crd := range crds {
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      crd.Name,
					Namespace: crd.Namespace,
				},
			}

			_, err := kit.Reconciler.Reconcile(ctx, req)
			atomic.AddInt64(&totalReconciles, 1)

			if err != nil {
				atomic.AddInt64(&failCount, 1)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}
	}

	totalDuration := time.Since(startTime)
	throughput := float64(totalReconciles) / totalDuration.Seconds()

	return PerformanceResult{
		TestName: "ReconciliationThroughput",
		CRDCount: crdCount,
		Duration: totalDuration,
		Metrics: ReconciliationMetrics{
			TotalReconciliations: totalReconciles,
			SuccessfulReconciles: successCount,
			FailedReconciles:     failCount,
			Throughput:           throughput,
		},
	}
}

// runConcurrentReconciliationTest runs a concurrent reconciliation test.
func runConcurrentReconciliationTest(t *testing.T, crdCount, concurrency int, duration time.Duration) PerformanceResult {
	ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
	defer cancel()

	kit := setupTestReconciler(t, crdCount)

	crds := createTestAPIRoutes(crdCount)
	for _, crd := range crds {
		if err := kit.FakeClient.Create(ctx, crd); err != nil {
			t.Fatalf("Failed to create CRD: %v", err)
		}
	}

	var totalReconciles int64
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

			for time.Now().Before(endTime) {
				// Each worker processes a subset of CRDs
				for j := workerID; j < len(crds); j += concurrency {
					crd := crds[j]
					req := reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      crd.Name,
							Namespace: crd.Namespace,
						},
					}

					start := time.Now()
					_, err := kit.Reconciler.Reconcile(ctx, req)
					elapsed := time.Since(start)

					mu.Lock()
					latencies = append(latencies, elapsed)
					mu.Unlock()

					atomic.AddInt64(&totalReconciles, 1)

					if err != nil {
						atomic.AddInt64(&failCount, 1)
					} else {
						atomic.AddInt64(&successCount, 1)
					}
				}
			}
		}(i)
	}

	wg.Wait()
	totalDuration := time.Since(startTime)

	metrics := calculateMetrics(latencies, successCount, failCount, totalDuration)

	return PerformanceResult{
		TestName: fmt.Sprintf("ConcurrentReconciliation_%d", concurrency),
		CRDCount: crdCount,
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runMemoryUsageTest runs a memory usage test.
func runMemoryUsageTest(t *testing.T, crdCount int, duration time.Duration) PerformanceResult {
	ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
	defer cancel()

	// Force GC before test
	runtime.GC()
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	kit := setupTestReconciler(t, crdCount)

	crds := createTestAPIRoutes(crdCount)
	for _, crd := range crds {
		if err := kit.FakeClient.Create(ctx, crd); err != nil {
			t.Fatalf("Failed to create CRD: %v", err)
		}
	}

	var totalReconciles int64
	var maxMemory uint64
	var maxGoroutines int

	startTime := time.Now()
	endTime := startTime.Add(duration)

	for time.Now().Before(endTime) {
		for _, crd := range crds {
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      crd.Name,
					Namespace: crd.Namespace,
				},
			}

			_, _ = kit.Reconciler.Reconcile(ctx, req)
			atomic.AddInt64(&totalReconciles, 1)
		}

		// Sample memory usage
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		if memStats.Alloc > maxMemory {
			maxMemory = memStats.Alloc
		}

		goroutines := runtime.NumGoroutine()
		if goroutines > maxGoroutines {
			maxGoroutines = goroutines
		}
	}

	totalDuration := time.Since(startTime)

	return PerformanceResult{
		TestName: "MemoryUsage",
		CRDCount: crdCount,
		Duration: totalDuration,
		Metrics: ReconciliationMetrics{
			TotalReconciliations: totalReconciles,
			MemoryUsageMB:        float64(maxMemory) / 1024 / 1024,
			GoroutineCount:       maxGoroutines,
			Throughput:           float64(totalReconciles) / totalDuration.Seconds(),
		},
	}
}

// reconcilerTestKit holds the fake client and reconciler for performance tests.
type reconcilerTestKit struct {
	FakeClient ctrlclient.Client
	Reconciler *controller.APIRouteReconciler
}

// setupTestReconciler creates a test reconciler with fake client.
func setupTestReconciler(t *testing.T, _ int) reconcilerTestKit {
	t.Helper()

	// Create gRPC server for testing
	grpcServer, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{
		Port: 0, // Don't actually listen
	})
	if err != nil {
		t.Fatalf("Failed to create gRPC server: %v", err)
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()

	reconciler := &controller.APIRouteReconciler{
		Client:     fakeClient,
		Scheme:     scheme.Scheme,
		GRPCServer: grpcServer,
	}

	return reconcilerTestKit{
		FakeClient: fakeClient,
		Reconciler: reconciler,
	}
}

// createTestAPIRoutes creates test APIRoute CRDs.
func createTestAPIRoutes(count int) []*avapigwv1alpha1.APIRoute {
	routes := make([]*avapigwv1alpha1.APIRoute, count)

	for i := 0; i < count; i++ {
		routes[i] = &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       fmt.Sprintf("test-route-%d", i),
				Namespace:  "default",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{
							Prefix: fmt.Sprintf("/api/v1/route-%d", i),
						},
						Methods: []string{"GET", "POST"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{
							Host: "backend-service",
							Port: 8080,
						},
						Weight: 100,
					},
				},
				Timeout: avapigwv1alpha1.Duration("30s"),
			},
		}
	}

	return routes
}

// calculateMetrics calculates performance metrics from latencies.
func calculateMetrics(latencies []time.Duration, successCount, failCount int64, totalDuration time.Duration) ReconciliationMetrics {
	if len(latencies) == 0 {
		return ReconciliationMetrics{}
	}

	// Sort latencies for percentile calculation
	sortedLatencies := make([]time.Duration, len(latencies))
	copy(sortedLatencies, latencies)
	sortDurations(sortedLatencies)

	var totalLatency time.Duration
	minLatency := sortedLatencies[0]
	maxLatency := sortedLatencies[len(sortedLatencies)-1]

	for _, l := range sortedLatencies {
		totalLatency += l
	}

	n := len(sortedLatencies)
	p50 := sortedLatencies[n*50/100]
	p95 := sortedLatencies[n*95/100]
	p99 := sortedLatencies[n*99/100]

	return ReconciliationMetrics{
		TotalReconciliations: successCount + failCount,
		SuccessfulReconciles: successCount,
		FailedReconciles:     failCount,
		TotalDuration:        totalDuration,
		MinLatency:           minLatency,
		MaxLatency:           maxLatency,
		P50Latency:           p50,
		P95Latency:           p95,
		P99Latency:           p99,
		Throughput:           float64(successCount+failCount) / totalDuration.Seconds(),
	}
}

// sortDurations sorts a slice of durations in ascending order.
func sortDurations(durations []time.Duration) {
	for i := 0; i < len(durations); i++ {
		for j := i + 1; j < len(durations); j++ {
			if durations[j] < durations[i] {
				durations[i], durations[j] = durations[j], durations[i]
			}
		}
	}
}

// checkSLO checks if metrics meet the SLO.
func checkSLO(metrics ReconciliationMetrics, slo SLO) bool {
	p99Ms := float64(metrics.P99Latency.Microseconds()) / 1000.0
	errorRate := float64(metrics.FailedReconciles) / float64(metrics.TotalReconciliations) * 100

	return p99Ms <= slo.MaxP99LatencyMs &&
		metrics.Throughput >= slo.MinThroughputRPS &&
		metrics.MemoryUsageMB <= slo.MaxMemoryUsageMB &&
		errorRate <= slo.MaxErrorRatePercent
}

// logPerformanceResult logs the performance result.
func logPerformanceResult(t *testing.T, result PerformanceResult) {
	t.Helper()

	t.Logf("Performance Test: %s", result.TestName)
	t.Logf("  CRD Count: %d", result.CRDCount)
	t.Logf("  Duration: %v", result.Duration)
	t.Logf("  Total Reconciliations: %d", result.Metrics.TotalReconciliations)
	t.Logf("  Successful: %d", result.Metrics.SuccessfulReconciles)
	t.Logf("  Failed: %d", result.Metrics.FailedReconciles)
	t.Logf("  Throughput: %.2f reconciles/sec", result.Metrics.Throughput)

	if result.Metrics.P99Latency > 0 {
		t.Logf("  Latency P50: %.2fms", float64(result.Metrics.P50Latency.Microseconds())/1000.0)
		t.Logf("  Latency P95: %.2fms", float64(result.Metrics.P95Latency.Microseconds())/1000.0)
		t.Logf("  Latency P99: %.2fms", float64(result.Metrics.P99Latency.Microseconds())/1000.0)
		t.Logf("  Latency Min: %.2fms", float64(result.Metrics.MinLatency.Microseconds())/1000.0)
		t.Logf("  Latency Max: %.2fms", float64(result.Metrics.MaxLatency.Microseconds())/1000.0)
	}

	if result.Metrics.MemoryUsageMB > 0 {
		t.Logf("  Memory Usage: %.2f MB", result.Metrics.MemoryUsageMB)
	}

	if result.Metrics.GoroutineCount > 0 {
		t.Logf("  Goroutine Count: %d", result.Metrics.GoroutineCount)
	}

	// Export as JSON for analysis
	jsonResult, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("JSON Result:\n%s", string(jsonResult))
}

// BenchmarkReconciliation provides Go benchmark for reconciliation.
func BenchmarkReconciliation(b *testing.B) {
	ctx := context.Background()

	// Create fake client and reconciler
	grpcServer, _ := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	clientBuilder := fake.NewClientBuilder().WithScheme(scheme.Scheme)
	fakeClient := clientBuilder.Build()

	reconciler := &controller.APIRouteReconciler{
		Client:     fakeClient,
		Scheme:     scheme.Scheme,
		GRPCServer: grpcServer,
	}

	// Create a test CRD
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "bench-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{
					URI: &avapigwv1alpha1.URIMatch{
						Prefix: "/api/v1/bench",
					},
				},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{
					Destination: avapigwv1alpha1.Destination{
						Host: "backend",
						Port: 8080,
					},
					Weight: 100,
				},
			},
		},
	}

	if err := fakeClient.Create(ctx, route); err != nil {
		b.Fatalf("Failed to create CRD: %v", err)
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      route.Name,
			Namespace: route.Namespace,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = reconciler.Reconcile(ctx, req)
	}
}

// BenchmarkReconciliationParallel provides parallel benchmark for reconciliation.
func BenchmarkReconciliationParallel(b *testing.B) {
	ctx := context.Background()

	grpcServer, _ := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	clientBuilder := fake.NewClientBuilder().WithScheme(scheme.Scheme)
	fakeClient := clientBuilder.Build()

	reconciler := &controller.APIRouteReconciler{
		Client:     fakeClient,
		Scheme:     scheme.Scheme,
		GRPCServer: grpcServer,
	}

	// Create test CRDs
	for i := 0; i < 100; i++ {
		route := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:       fmt.Sprintf("bench-route-%d", i),
				Namespace:  "default",
				Generation: 1,
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{
							Prefix: fmt.Sprintf("/api/v1/bench-%d", i),
						},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{
							Host: "backend",
							Port: 8080,
						},
						Weight: 100,
					},
				},
			},
		}
		if err := fakeClient.Create(ctx, route); err != nil {
			b.Fatalf("Failed to create CRD: %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	var counter int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddInt64(&counter, 1) % 100
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      fmt.Sprintf("bench-route-%d", idx),
					Namespace: "default",
				},
			}
			_, _ = reconciler.Reconcile(ctx, req)
		}
	})
}
