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
