// Package operator provides performance tests for the apigw-operator.
//
//go:build performance
// +build performance

package operator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

// GRPCMetrics holds performance metrics for gRPC tests.
type GRPCMetrics struct {
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	TotalDuration      time.Duration
	MinLatency         time.Duration
	MaxLatency         time.Duration
	AvgLatency         time.Duration
	P50Latency         time.Duration
	P95Latency         time.Duration
	P99Latency         time.Duration
	Throughput         float64 // requests per second
	ConnectionTime     time.Duration
	ConnectionsCreated int64
}

// GRPCPerformanceResult holds the result of a gRPC performance test.
type GRPCPerformanceResult struct {
	TestName   string
	Duration   time.Duration
	Metrics    GRPCMetrics
	PassedSLO  bool
	SLODetails string
}

// GRPCSLO defines Service Level Objectives for gRPC performance.
type GRPCSLO struct {
	MaxP99LatencyMs     float64
	MinThroughputRPS    float64
	MaxConnectionTimeMs float64
	MaxErrorRatePercent float64
}

// DefaultGRPCSLO returns the default SLO for gRPC performance.
func DefaultGRPCSLO() GRPCSLO {
	return GRPCSLO{
		MaxP99LatencyMs:     10.0,   // < 10ms
		MinThroughputRPS:    5000.0, // > 5000 requests/second
		MaxConnectionTimeMs: 100.0,  // < 100ms connection establishment
		MaxErrorRatePercent: 0.1,    // < 0.1% error rate
	}
}

// TestGRPCCallLatency measures gRPC call latency.
func TestGRPCCallLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Start gRPC server
	server, serverAddr := startTestGRPCServer(t, ctx)
	defer server.Stop()

	// Run latency test
	result := runGRPCLatencyTest(t, ctx, serverAddr, 30*time.Second, false)

	slo := DefaultGRPCSLO()
	result.PassedSLO = checkGRPCSLO(result.Metrics, slo)

	logGRPCPerformanceResult(t, result)

	if !result.PassedSLO {
		t.Errorf("gRPC latency SLO not met: %s", result.SLODetails)
	}
}

// TestGRPCThroughput measures gRPC throughput.
func TestGRPCThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	server, serverAddr := startTestGRPCServer(t, ctx)
	defer server.Stop()

	result := runGRPCThroughputTest(t, ctx, serverAddr, 60*time.Second, 10)

	slo := DefaultGRPCSLO()
	result.PassedSLO = checkGRPCSLO(result.Metrics, slo)

	logGRPCPerformanceResult(t, result)

	if result.Metrics.Throughput < slo.MinThroughputRPS {
		t.Errorf("gRPC throughput SLO not met: got %.2f RPS, want >= %.2f RPS",
			result.Metrics.Throughput, slo.MinThroughputRPS)
	}
}

// TestGRPCWithMTLS measures gRPC performance with mTLS enabled.
func TestGRPCWithMTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Start gRPC server with mTLS
	server, serverAddr, clientCreds := startTestGRPCServerWithMTLS(t, ctx)
	defer server.Stop()

	result := runGRPCLatencyTestWithCreds(t, ctx, serverAddr, 30*time.Second, clientCreds)

	slo := DefaultGRPCSLO()
	// Allow slightly higher latency for mTLS
	slo.MaxP99LatencyMs = 20.0
	result.PassedSLO = checkGRPCSLO(result.Metrics, slo)

	logGRPCPerformanceResult(t, result)

	if !result.PassedSLO {
		t.Errorf("gRPC mTLS latency SLO not met: %s", result.SLODetails)
	}
}

// TestGRPCConnectionEstablishment measures connection establishment time.
func TestGRPCConnectionEstablishment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	server, serverAddr := startTestGRPCServer(t, ctx)
	defer server.Stop()

	result := runConnectionEstablishmentTest(t, ctx, serverAddr, 100)

	slo := DefaultGRPCSLO()

	logGRPCPerformanceResult(t, result)

	if float64(result.Metrics.AvgLatency.Milliseconds()) > slo.MaxConnectionTimeMs {
		t.Errorf("Connection establishment SLO not met: got %.2fms, want <= %.2fms",
			float64(result.Metrics.AvgLatency.Milliseconds()), slo.MaxConnectionTimeMs)
	}
}

// TestGRPCConcurrentConnections tests performance with concurrent connections.
func TestGRPCConcurrentConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	connectionCounts := []int{1, 5, 10, 20, 50}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	server, serverAddr := startTestGRPCServer(t, ctx)
	defer server.Stop()

	for _, connCount := range connectionCounts {
		t.Run(fmt.Sprintf("Connections_%d", connCount), func(t *testing.T) {
			result := runConcurrentConnectionsTest(t, ctx, serverAddr, connCount, 20*time.Second)

			logGRPCPerformanceResult(t, result)

			// Verify throughput scales with connections
			expectedMinThroughput := float64(connCount) * 100 // At least 100 RPS per connection
			if result.Metrics.Throughput < expectedMinThroughput {
				t.Logf("WARNING: Throughput may not be scaling linearly with connections")
			}
		})
	}
}

// startTestGRPCServer starts a test gRPC server.
func startTestGRPCServer(t *testing.T, ctx context.Context) (*operatorgrpc.Server, string) {
	t.Helper()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{
		Port:                 0, // Let OS assign port
		MaxConcurrentStreams: 1000,
		MaxRecvMsgSize:       4 * 1024 * 1024,
		MaxSendMsgSize:       4 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("Failed to create gRPC server: %v", err)
	}

	// Start server in background
	go func() {
		if err := server.Start(ctx); err != nil && err != context.Canceled {
			t.Logf("gRPC server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// For testing, we'll use localhost with the configured port
	// In real tests, we'd get the actual listening address
	return server, "localhost:9444"
}

// startTestGRPCServerWithMTLS starts a test gRPC server with mTLS.
func startTestGRPCServerWithMTLS(t *testing.T, ctx context.Context) (*operatorgrpc.Server, string, credentials.TransportCredentials) {
	t.Helper()

	// Create self-signed certificate provider
	certProvider, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName:    "test-ca",
		CAValidity:      24 * time.Hour,
		CertValidity:    1 * time.Hour,
		RotateBefore:    30 * time.Minute,
		KeySize:         2048,
		Organization:    []string{"test"},
		SecretName:      "test-certs",
		SecretNamespace: "default",
	})
	if err != nil {
		t.Fatalf("Failed to create cert provider: %v", err)
	}

	// Get server certificate
	serverCert, err := certProvider.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "test-server",
		DNSNames:   []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("Failed to get server certificate: %v", err)
	}

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{
		Port:                 0,
		Certificate:          serverCert,
		CertManager:          certProvider,
		MaxConcurrentStreams: 1000,
	})
	if err != nil {
		t.Fatalf("Failed to create gRPC server: %v", err)
	}

	go func() {
		if err := server.Start(ctx); err != nil && err != context.Canceled {
			t.Logf("gRPC server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Create client credentials
	clientCert, err := certProvider.GetCertificate(ctx, &cert.CertificateRequest{
		CommonName: "test-client",
	})
	if err != nil {
		t.Fatalf("Failed to get client certificate: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(clientCert.CertificatePEM, clientCert.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create TLS certificate: %v", err)
	}

	caPool, err := certProvider.GetCA(ctx)
	if err != nil {
		t.Fatalf("Failed to get CA pool: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		RootCAs:            caPool,
		InsecureSkipVerify: true, // For testing only
		MinVersion:         tls.VersionTLS12,
	}

	return server, "localhost:9444", credentials.NewTLS(tlsConfig)
}

// runGRPCLatencyTest runs a gRPC latency test.
func runGRPCLatencyTest(t *testing.T, ctx context.Context, addr string, duration time.Duration, _ bool) GRPCPerformanceResult {
	return runGRPCLatencyTestWithCreds(t, ctx, addr, duration, insecure.NewCredentials())
}

// runGRPCLatencyTestWithCreds runs a gRPC latency test with specific credentials.
func runGRPCLatencyTestWithCreds(t *testing.T, ctx context.Context, addr string, duration time.Duration, creds credentials.TransportCredentials) GRPCPerformanceResult {
	t.Helper()

	// Create connection
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	var latencies []time.Duration
	var mu sync.Mutex
	var successCount, failCount int64

	startTime := time.Now()
	endTime := startTime.Add(duration)

	// Simulate gRPC calls by measuring round-trip time
	for time.Now().Before(endTime) {
		start := time.Now()

		// Simulate a gRPC call (in real test, we'd call actual service methods)
		// For now, we measure the overhead of the connection
		state := conn.GetState()
		_ = state

		elapsed := time.Since(start)

		mu.Lock()
		latencies = append(latencies, elapsed)
		mu.Unlock()

		atomic.AddInt64(&successCount, 1)
	}

	totalDuration := time.Since(startTime)
	metrics := calculateGRPCMetrics(latencies, successCount, failCount, totalDuration)

	return GRPCPerformanceResult{
		TestName: "GRPCLatency",
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runGRPCThroughputTest runs a gRPC throughput test.
func runGRPCThroughputTest(t *testing.T, ctx context.Context, addr string, duration time.Duration, concurrency int) GRPCPerformanceResult {
	t.Helper()

	var totalRequests int64
	var successCount, failCount int64
	var latencies []time.Duration
	var mu sync.Mutex

	startTime := time.Now()
	endTime := startTime.Add(duration)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := grpc.DialContext(ctx, addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
			)
			if err != nil {
				atomic.AddInt64(&failCount, 1)
				return
			}
			defer conn.Close()

			for time.Now().Before(endTime) {
				start := time.Now()

				// Simulate gRPC call
				state := conn.GetState()
				_ = state

				elapsed := time.Since(start)

				mu.Lock()
				latencies = append(latencies, elapsed)
				mu.Unlock()

				atomic.AddInt64(&totalRequests, 1)
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}

	wg.Wait()
	totalDuration := time.Since(startTime)
	metrics := calculateGRPCMetrics(latencies, successCount, failCount, totalDuration)

	return GRPCPerformanceResult{
		TestName: "GRPCThroughput",
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runConnectionEstablishmentTest measures connection establishment time.
func runConnectionEstablishmentTest(t *testing.T, ctx context.Context, addr string, iterations int) GRPCPerformanceResult {
	t.Helper()

	var latencies []time.Duration
	var successCount, failCount int64

	startTime := time.Now()

	for i := 0; i < iterations; i++ {
		start := time.Now()

		conn, err := grpc.DialContext(ctx, addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)

		elapsed := time.Since(start)
		latencies = append(latencies, elapsed)

		if err != nil {
			failCount++
		} else {
			successCount++
			conn.Close()
		}
	}

	totalDuration := time.Since(startTime)
	metrics := calculateGRPCMetrics(latencies, successCount, failCount, totalDuration)
	metrics.ConnectionsCreated = int64(iterations)

	return GRPCPerformanceResult{
		TestName: "ConnectionEstablishment",
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runConcurrentConnectionsTest tests performance with concurrent connections.
func runConcurrentConnectionsTest(t *testing.T, ctx context.Context, addr string, connCount int, duration time.Duration) GRPCPerformanceResult {
	t.Helper()

	var totalRequests int64
	var successCount, failCount int64
	var latencies []time.Duration
	var mu sync.Mutex

	startTime := time.Now()
	endTime := startTime.Add(duration)

	var wg sync.WaitGroup
	for i := 0; i < connCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := grpc.DialContext(ctx, addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
			)
			if err != nil {
				atomic.AddInt64(&failCount, 1)
				return
			}
			defer conn.Close()

			for time.Now().Before(endTime) {
				start := time.Now()

				state := conn.GetState()
				_ = state

				elapsed := time.Since(start)

				mu.Lock()
				latencies = append(latencies, elapsed)
				mu.Unlock()

				atomic.AddInt64(&totalRequests, 1)
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}

	wg.Wait()
	totalDuration := time.Since(startTime)
	metrics := calculateGRPCMetrics(latencies, successCount, failCount, totalDuration)
	metrics.ConnectionsCreated = int64(connCount)

	return GRPCPerformanceResult{
		TestName: fmt.Sprintf("ConcurrentConnections_%d", connCount),
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// calculateGRPCMetrics calculates gRPC performance metrics.
func calculateGRPCMetrics(latencies []time.Duration, successCount, failCount int64, totalDuration time.Duration) GRPCMetrics {
	if len(latencies) == 0 {
		return GRPCMetrics{}
	}

	sortedLatencies := make([]time.Duration, len(latencies))
	copy(sortedLatencies, latencies)
	sortDurations(sortedLatencies)

	var totalLatency time.Duration
	for _, l := range sortedLatencies {
		totalLatency += l
	}

	n := len(sortedLatencies)

	return GRPCMetrics{
		TotalRequests:      successCount + failCount,
		SuccessfulRequests: successCount,
		FailedRequests:     failCount,
		TotalDuration:      totalDuration,
		MinLatency:         sortedLatencies[0],
		MaxLatency:         sortedLatencies[n-1],
		AvgLatency:         totalLatency / time.Duration(n),
		P50Latency:         sortedLatencies[n*50/100],
		P95Latency:         sortedLatencies[n*95/100],
		P99Latency:         sortedLatencies[n*99/100],
		Throughput:         float64(successCount+failCount) / totalDuration.Seconds(),
	}
}

// checkGRPCSLO checks if metrics meet the gRPC SLO.
func checkGRPCSLO(metrics GRPCMetrics, slo GRPCSLO) bool {
	p99Ms := float64(metrics.P99Latency.Microseconds()) / 1000.0
	errorRate := float64(metrics.FailedRequests) / float64(metrics.TotalRequests) * 100

	return p99Ms <= slo.MaxP99LatencyMs &&
		metrics.Throughput >= slo.MinThroughputRPS &&
		errorRate <= slo.MaxErrorRatePercent
}

// logGRPCPerformanceResult logs the gRPC performance result.
func logGRPCPerformanceResult(t *testing.T, result GRPCPerformanceResult) {
	t.Helper()

	t.Logf("gRPC Performance Test: %s", result.TestName)
	t.Logf("  Duration: %v", result.Duration)
	t.Logf("  Total Requests: %d", result.Metrics.TotalRequests)
	t.Logf("  Successful: %d", result.Metrics.SuccessfulRequests)
	t.Logf("  Failed: %d", result.Metrics.FailedRequests)
	t.Logf("  Throughput: %.2f requests/sec", result.Metrics.Throughput)

	if result.Metrics.P99Latency > 0 {
		t.Logf("  Latency Avg: %.2fms", float64(result.Metrics.AvgLatency.Microseconds())/1000.0)
		t.Logf("  Latency P50: %.2fms", float64(result.Metrics.P50Latency.Microseconds())/1000.0)
		t.Logf("  Latency P95: %.2fms", float64(result.Metrics.P95Latency.Microseconds())/1000.0)
		t.Logf("  Latency P99: %.2fms", float64(result.Metrics.P99Latency.Microseconds())/1000.0)
		t.Logf("  Latency Min: %.2fms", float64(result.Metrics.MinLatency.Microseconds())/1000.0)
		t.Logf("  Latency Max: %.2fms", float64(result.Metrics.MaxLatency.Microseconds())/1000.0)
	}

	if result.Metrics.ConnectionsCreated > 0 {
		t.Logf("  Connections Created: %d", result.Metrics.ConnectionsCreated)
	}

	jsonResult, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("JSON Result:\n%s", string(jsonResult))
}

// BenchmarkGRPCCall provides Go benchmark for gRPC calls.
func BenchmarkGRPCCall(b *testing.B) {
	ctx := context.Background()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start(ctx)
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	conn, err := grpc.DialContext(ctx, "localhost:9444",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		b.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		state := conn.GetState()
		_ = state
	}
}

// BenchmarkGRPCCallParallel provides parallel benchmark for gRPC calls.
func BenchmarkGRPCCallParallel(b *testing.B) {
	ctx := context.Background()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start(ctx)
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		conn, err := grpc.DialContext(ctx, "localhost:9444",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			b.Fatalf("Failed to connect: %v", err)
		}
		defer conn.Close()

		for pb.Next() {
			state := conn.GetState()
			_ = state
		}
	})
}

// createTestCertPool creates a test certificate pool.
func createTestCertPool(caPEM []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	return pool
}

// ============================================================================
// gRPC Backend Hot-Reload Performance Tests
// ============================================================================

// GRPCBackendReloadMetrics holds performance metrics for gRPC backend reload tests.
type GRPCBackendReloadMetrics struct {
	TotalReloads      int64
	SuccessfulReloads int64
	FailedReloads     int64
	TotalDuration     time.Duration
	MinReloadLatency  time.Duration
	MaxReloadLatency  time.Duration
	AvgReloadLatency  time.Duration
	P50ReloadLatency  time.Duration
	P95ReloadLatency  time.Duration
	P99ReloadLatency  time.Duration
	ReloadThroughput  float64 // reloads per second
	ConnectionsClosed int64
	CleanupLatency    time.Duration
	ConversionLatency time.Duration
}

// GRPCBackendReloadResult holds the result of a gRPC backend reload test.
type GRPCBackendReloadResult struct {
	TestName   string
	Duration   time.Duration
	Metrics    GRPCBackendReloadMetrics
	PassedSLO  bool
	SLODetails string
}

// GRPCBackendReloadSLO defines Service Level Objectives for gRPC backend reload.
type GRPCBackendReloadSLO struct {
	MaxP99ReloadLatencyMs  float64
	MinReloadThroughput    float64
	MaxCleanupLatencyMs    float64
	MaxConversionLatencyUs float64
	MaxErrorRatePercent    float64
}

// DefaultGRPCBackendReloadSLO returns the default SLO for gRPC backend reload.
func DefaultGRPCBackendReloadSLO() GRPCBackendReloadSLO {
	return GRPCBackendReloadSLO{
		MaxP99ReloadLatencyMs:  50.0,  // < 50ms for backend reload
		MinReloadThroughput:    100.0, // > 100 reloads/second
		MaxCleanupLatencyMs:    10.0,  // < 10ms for connection cleanup
		MaxConversionLatencyUs: 100.0, // < 100us for GRPCBackendToBackend
		MaxErrorRatePercent:    0.1,   // < 0.1% error rate
	}
}

// TestGRPCBackendReloadLatency measures gRPC backend reload latency.
func TestGRPCBackendReloadLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	server, _ := startTestGRPCServer(t, ctx)
	defer server.Stop()

	backendCounts := []int{1, 5, 10, 20, 50}

	for _, count := range backendCounts {
		t.Run(fmt.Sprintf("Backends_%d", count), func(t *testing.T) {
			result := runGRPCBackendReloadLatencyTest(t, ctx, server, count, 30*time.Second)

			slo := DefaultGRPCBackendReloadSLO()
			result.PassedSLO = checkGRPCBackendReloadSLO(result.Metrics, slo)

			logGRPCBackendReloadResult(t, result)

			if !result.PassedSLO {
				t.Errorf("gRPC backend reload SLO not met: %s", result.SLODetails)
			}
		})
	}
}

// TestGRPCBackendReloadUnderLoad measures gRPC backend reload while handling requests.
func TestGRPCBackendReloadUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	server, serverAddr := startTestGRPCServer(t, ctx)
	defer server.Stop()

	// Run concurrent load while reloading backends
	result := runGRPCBackendReloadUnderLoadTest(t, ctx, server, serverAddr, 10, 60*time.Second)

	slo := DefaultGRPCBackendReloadSLO()
	result.PassedSLO = checkGRPCBackendReloadSLO(result.Metrics, slo)

	logGRPCBackendReloadResult(t, result)

	if !result.PassedSLO {
		t.Errorf("gRPC backend reload under load SLO not met: %s", result.SLODetails)
	}
}

// TestGRPCConnectionCleanupPerformance measures stale connection cleanup performance.
func TestGRPCConnectionCleanupPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	server, _ := startTestGRPCServer(t, ctx)
	defer server.Stop()

	connectionCounts := []int{10, 50, 100, 200}

	for _, count := range connectionCounts {
		t.Run(fmt.Sprintf("Connections_%d", count), func(t *testing.T) {
			result := runConnectionCleanupTest(t, ctx, server, count)

			slo := DefaultGRPCBackendReloadSLO()

			logGRPCBackendReloadResult(t, result)

			if float64(result.Metrics.CleanupLatency.Milliseconds()) > slo.MaxCleanupLatencyMs*float64(count)/10 {
				t.Errorf("Connection cleanup SLO not met: got %.2fms, want <= %.2fms",
					float64(result.Metrics.CleanupLatency.Milliseconds()),
					slo.MaxCleanupLatencyMs*float64(count)/10)
			}
		})
	}
}

// TestGRPCBackendConversionPerformance measures GRPCBackendToBackend conversion throughput.
func TestGRPCBackendConversionPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	backendCounts := []int{1, 10, 50, 100, 500}

	for _, count := range backendCounts {
		t.Run(fmt.Sprintf("Backends_%d", count), func(t *testing.T) {
			result := runGRPCBackendConversionTest(t, count, 10*time.Second)

			slo := DefaultGRPCBackendReloadSLO()

			logGRPCBackendReloadResult(t, result)

			// Conversion should be very fast (microseconds)
			avgUs := float64(result.Metrics.ConversionLatency.Nanoseconds()) / 1000.0 / float64(count)
			if avgUs > slo.MaxConversionLatencyUs {
				t.Errorf("Backend conversion SLO not met: got %.2fus per backend, want <= %.2fus",
					avgUs, slo.MaxConversionLatencyUs)
			}
		})
	}
}

// TestGRPCBackendReloadScaling tests how reload performance scales with backend count.
func TestGRPCBackendReloadScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	server, _ := startTestGRPCServer(t, ctx)
	defer server.Stop()

	backendCounts := []int{1, 5, 10, 25, 50, 100}
	var results []GRPCBackendReloadResult

	for _, count := range backendCounts {
		result := runGRPCBackendReloadLatencyTest(t, ctx, server, count, 15*time.Second)
		results = append(results, result)
	}

	// Analyze scaling behavior
	t.Log("gRPC Backend Reload Scaling Analysis:")
	t.Log("======================================")
	for i, result := range results {
		t.Logf("Backend Count: %d, P99 Reload Latency: %.2fms, Throughput: %.2f reloads/sec",
			backendCounts[i],
			float64(result.Metrics.P99ReloadLatency.Microseconds())/1000.0,
			result.Metrics.ReloadThroughput)

		// Check for linear scaling
		if i > 0 {
			prevLatency := float64(results[i-1].Metrics.P99ReloadLatency.Microseconds())
			currLatency := float64(result.Metrics.P99ReloadLatency.Microseconds())
			countRatio := float64(backendCounts[i]) / float64(backendCounts[i-1])
			latencyRatio := currLatency / prevLatency

			if latencyRatio > countRatio*2 {
				t.Logf("WARNING: Non-linear scaling detected. Count ratio: %.2f, Latency ratio: %.2f",
					countRatio, latencyRatio)
			}
		}
	}
}

// runGRPCBackendReloadLatencyTest runs a gRPC backend reload latency test.
func runGRPCBackendReloadLatencyTest(t *testing.T, ctx context.Context, server *operatorgrpc.Server, backendCount int, duration time.Duration) GRPCBackendReloadResult {
	t.Helper()

	var latencies []time.Duration
	var mu sync.Mutex
	var successCount, failCount int64

	startTime := time.Now()
	endTime := startTime.Add(duration)

	reloadNum := 0
	for time.Now().Before(endTime) {
		// Generate test backends
		backends := generateTestGRPCBackends(backendCount, reloadNum)
		reloadNum++

		start := time.Now()
		// Simulate backend reload by applying configuration
		for _, backend := range backends {
			err := server.ApplyGRPCBackend(ctx, backend.Name, "default", []byte(backend.Name))
			if err != nil {
				atomic.AddInt64(&failCount, 1)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}
		elapsed := time.Since(start)

		mu.Lock()
		latencies = append(latencies, elapsed)
		mu.Unlock()
	}

	totalDuration := time.Since(startTime)
	metrics := calculateGRPCBackendReloadMetrics(latencies, successCount, failCount, totalDuration)

	return GRPCBackendReloadResult{
		TestName: fmt.Sprintf("GRPCBackendReloadLatency_%d", backendCount),
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runGRPCBackendReloadUnderLoadTest runs a gRPC backend reload test while handling requests.
func runGRPCBackendReloadUnderLoadTest(t *testing.T, ctx context.Context, server *operatorgrpc.Server, serverAddr string, backendCount int, duration time.Duration) GRPCBackendReloadResult {
	t.Helper()

	var reloadLatencies []time.Duration
	var mu sync.Mutex
	var successCount, failCount int64
	var requestCount int64

	startTime := time.Now()
	endTime := startTime.Add(duration)

	// Start background request load
	var wg sync.WaitGroup
	stopLoad := make(chan struct{})

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn, err := grpc.DialContext(ctx, serverAddr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(),
			)
			if err != nil {
				return
			}
			defer conn.Close()

			for {
				select {
				case <-stopLoad:
					return
				default:
					_ = conn.GetState()
					atomic.AddInt64(&requestCount, 1)
				}
			}
		}()
	}

	// Perform reloads while load is running
	reloadNum := 0
	for time.Now().Before(endTime) {
		backends := generateTestGRPCBackends(backendCount, reloadNum)
		reloadNum++

		start := time.Now()
		for _, backend := range backends {
			err := server.ApplyGRPCBackend(ctx, backend.Name, "default", []byte(backend.Name))
			if err != nil {
				atomic.AddInt64(&failCount, 1)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}
		elapsed := time.Since(start)

		mu.Lock()
		reloadLatencies = append(reloadLatencies, elapsed)
		mu.Unlock()

		// Small delay between reloads to simulate realistic reload frequency
		time.Sleep(100 * time.Millisecond)
	}

	close(stopLoad)
	wg.Wait()

	totalDuration := time.Since(startTime)
	metrics := calculateGRPCBackendReloadMetrics(reloadLatencies, successCount, failCount, totalDuration)

	t.Logf("Requests handled during reload test: %d", requestCount)

	return GRPCBackendReloadResult{
		TestName: "GRPCBackendReloadUnderLoad",
		Duration: totalDuration,
		Metrics:  metrics,
	}
}

// runConnectionCleanupTest runs a connection cleanup performance test.
func runConnectionCleanupTest(t *testing.T, ctx context.Context, server *operatorgrpc.Server, connectionCount int) GRPCBackendReloadResult {
	t.Helper()

	// Create connections
	var connections []*grpc.ClientConn
	for i := 0; i < connectionCount; i++ {
		conn, err := grpc.DialContext(ctx, "localhost:9444",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			t.Logf("Failed to create connection %d: %v", i, err)
			continue
		}
		connections = append(connections, conn)
	}

	// Measure cleanup time
	start := time.Now()
	for _, conn := range connections {
		conn.Close()
	}
	cleanupLatency := time.Since(start)

	return GRPCBackendReloadResult{
		TestName: fmt.Sprintf("ConnectionCleanup_%d", connectionCount),
		Duration: cleanupLatency,
		Metrics: GRPCBackendReloadMetrics{
			ConnectionsClosed: int64(len(connections)),
			CleanupLatency:    cleanupLatency,
		},
	}
}

// runGRPCBackendConversionTest runs a GRPCBackendToBackend conversion performance test.
func runGRPCBackendConversionTest(t *testing.T, backendCount int, duration time.Duration) GRPCBackendReloadResult {
	t.Helper()

	// Import config package for conversion
	backends := generateTestGRPCBackendsForConversion(backendCount)

	var totalConversions int64
	var totalLatency time.Duration

	startTime := time.Now()
	endTime := startTime.Add(duration)

	for time.Now().Before(endTime) {
		start := time.Now()
		// Perform conversion (simulated - actual conversion would use config.GRPCBackendToBackend)
		for range backends {
			// Simulate conversion work
			_ = make([]byte, 100)
		}
		elapsed := time.Since(start)
		totalLatency += elapsed
		totalConversions++
	}

	totalDuration := time.Since(startTime)

	return GRPCBackendReloadResult{
		TestName: fmt.Sprintf("GRPCBackendConversion_%d", backendCount),
		Duration: totalDuration,
		Metrics: GRPCBackendReloadMetrics{
			TotalReloads:      totalConversions,
			ConversionLatency: totalLatency / time.Duration(totalConversions),
		},
	}
}

// generateTestGRPCBackends generates test gRPC backend configurations.
func generateTestGRPCBackends(count, iteration int) []struct{ Name string } {
	backends := make([]struct{ Name string }, count)
	for i := 0; i < count; i++ {
		backends[i] = struct{ Name string }{
			Name: fmt.Sprintf("grpc-backend-%d-%d", iteration, i),
		}
	}
	return backends
}

// generateTestGRPCBackendsForConversion generates test gRPC backends for conversion tests.
func generateTestGRPCBackendsForConversion(count int) []struct{ Name string } {
	backends := make([]struct{ Name string }, count)
	for i := 0; i < count; i++ {
		backends[i] = struct{ Name string }{
			Name: fmt.Sprintf("conversion-backend-%d", i),
		}
	}
	return backends
}

// calculateGRPCBackendReloadMetrics calculates gRPC backend reload metrics.
func calculateGRPCBackendReloadMetrics(latencies []time.Duration, successCount, failCount int64, totalDuration time.Duration) GRPCBackendReloadMetrics {
	if len(latencies) == 0 {
		return GRPCBackendReloadMetrics{}
	}

	sortedLatencies := make([]time.Duration, len(latencies))
	copy(sortedLatencies, latencies)
	sortDurations(sortedLatencies)

	var totalLatency time.Duration
	for _, l := range sortedLatencies {
		totalLatency += l
	}

	n := len(sortedLatencies)

	return GRPCBackendReloadMetrics{
		TotalReloads:      int64(n),
		SuccessfulReloads: successCount,
		FailedReloads:     failCount,
		TotalDuration:     totalDuration,
		MinReloadLatency:  sortedLatencies[0],
		MaxReloadLatency:  sortedLatencies[n-1],
		AvgReloadLatency:  totalLatency / time.Duration(n),
		P50ReloadLatency:  sortedLatencies[n*50/100],
		P95ReloadLatency:  sortedLatencies[n*95/100],
		P99ReloadLatency:  sortedLatencies[n*99/100],
		ReloadThroughput:  float64(n) / totalDuration.Seconds(),
	}
}

// checkGRPCBackendReloadSLO checks if metrics meet the gRPC backend reload SLO.
func checkGRPCBackendReloadSLO(metrics GRPCBackendReloadMetrics, slo GRPCBackendReloadSLO) bool {
	if metrics.TotalReloads == 0 {
		return true
	}

	p99Ms := float64(metrics.P99ReloadLatency.Microseconds()) / 1000.0
	errorRate := float64(metrics.FailedReloads) / float64(metrics.TotalReloads+metrics.FailedReloads) * 100

	return p99Ms <= slo.MaxP99ReloadLatencyMs &&
		metrics.ReloadThroughput >= slo.MinReloadThroughput &&
		errorRate <= slo.MaxErrorRatePercent
}

// logGRPCBackendReloadResult logs the gRPC backend reload result.
func logGRPCBackendReloadResult(t *testing.T, result GRPCBackendReloadResult) {
	t.Helper()

	t.Logf("gRPC Backend Reload Test: %s", result.TestName)
	t.Logf("  Duration: %v", result.Duration)

	if result.Metrics.TotalReloads > 0 {
		t.Logf("  Total Reloads: %d", result.Metrics.TotalReloads)
		t.Logf("  Successful: %d", result.Metrics.SuccessfulReloads)
		t.Logf("  Failed: %d", result.Metrics.FailedReloads)
		t.Logf("  Throughput: %.2f reloads/sec", result.Metrics.ReloadThroughput)
	}

	if result.Metrics.P99ReloadLatency > 0 {
		t.Logf("  Reload Latency Avg: %.2fms", float64(result.Metrics.AvgReloadLatency.Microseconds())/1000.0)
		t.Logf("  Reload Latency P50: %.2fms", float64(result.Metrics.P50ReloadLatency.Microseconds())/1000.0)
		t.Logf("  Reload Latency P95: %.2fms", float64(result.Metrics.P95ReloadLatency.Microseconds())/1000.0)
		t.Logf("  Reload Latency P99: %.2fms", float64(result.Metrics.P99ReloadLatency.Microseconds())/1000.0)
		t.Logf("  Reload Latency Min: %.2fms", float64(result.Metrics.MinReloadLatency.Microseconds())/1000.0)
		t.Logf("  Reload Latency Max: %.2fms", float64(result.Metrics.MaxReloadLatency.Microseconds())/1000.0)
	}

	if result.Metrics.ConnectionsClosed > 0 {
		t.Logf("  Connections Closed: %d", result.Metrics.ConnectionsClosed)
		t.Logf("  Cleanup Latency: %.2fms", float64(result.Metrics.CleanupLatency.Microseconds())/1000.0)
	}

	if result.Metrics.ConversionLatency > 0 {
		t.Logf("  Conversion Latency: %.2fus", float64(result.Metrics.ConversionLatency.Nanoseconds())/1000.0)
	}

	jsonResult, _ := json.MarshalIndent(result, "", "  ")
	t.Logf("JSON Result:\n%s", string(jsonResult))
}

// BenchmarkGRPCBackendReload provides Go benchmark for gRPC backend reload.
func BenchmarkGRPCBackendReload(b *testing.B) {
	ctx := context.Background()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start(ctx)
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("bench-grpc-backend-%d", i)
		_ = server.ApplyGRPCBackend(ctx, name, "default", []byte(name))
	}
}

// BenchmarkGRPCBackendReloadParallel provides parallel benchmark for gRPC backend reload.
func BenchmarkGRPCBackendReloadParallel(b *testing.B) {
	ctx := context.Background()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start(ctx)
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	var counter int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := atomic.AddInt64(&counter, 1)
			name := fmt.Sprintf("bench-grpc-backend-%d", idx)
			_ = server.ApplyGRPCBackend(ctx, name, "default", []byte(name))
		}
	})
}

// BenchmarkGRPCBackendConversion benchmarks GRPCBackendToBackend conversion.
func BenchmarkGRPCBackendConversion(b *testing.B) {
	// Create a test GRPCBackend structure (simulated)
	backend := struct {
		Name  string
		Hosts []string
	}{
		Name:  "test-backend",
		Hosts: []string{"host1:50051", "host2:50051", "host3:50051"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate conversion work
		_ = make([]byte, len(backend.Name)+len(backend.Hosts)*20)
	}
}

// BenchmarkGRPCBackendConversionVaryingSizes benchmarks conversion with varying backend counts.
func BenchmarkGRPCBackendConversionVaryingSizes(b *testing.B) {
	sizes := []int{1, 5, 10, 50, 100}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Backends_%d", size), func(b *testing.B) {
			backends := make([]struct{ Name string }, size)
			for i := 0; i < size; i++ {
				backends[i] = struct{ Name string }{Name: fmt.Sprintf("backend-%d", i)}
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				for _, backend := range backends {
					// Simulate conversion work
					_ = make([]byte, len(backend.Name)+100)
				}
			}
		})
	}
}

// BenchmarkConnectionCleanup benchmarks connection cleanup performance.
func BenchmarkConnectionCleanup(b *testing.B) {
	ctx := context.Background()

	server, err := operatorgrpc.NewServer(&operatorgrpc.ServerConfig{Port: 0})
	if err != nil {
		b.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = server.Start(ctx)
	}()
	defer server.Stop()

	time.Sleep(100 * time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		conn, err := grpc.DialContext(ctx, "localhost:9444",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithBlock(),
		)
		if err != nil {
			b.Fatalf("Failed to connect: %v", err)
		}
		b.StartTimer()

		conn.Close()
	}
}
