package backend

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewHealthChecker(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 8080, 1)}
	cfg := config.HealthCheck{
		Path:               "/health",
		Interval:           config.Duration(10 * time.Second),
		Timeout:            config.Duration(5 * time.Second),
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
	}

	hc := NewHealthChecker(hosts, cfg)

	assert.NotNil(t, hc)
	assert.Equal(t, 2, hc.healthyThreshold)
	assert.Equal(t, 3, hc.unhealthyThreshold)
}

func TestNewHealthChecker_DefaultThresholds(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 8080, 1)}
	cfg := config.HealthCheck{
		Path: "/health",
	}

	hc := NewHealthChecker(hosts, cfg)

	assert.Equal(t, 2, hc.healthyThreshold)
	assert.Equal(t, 3, hc.unhealthyThreshold)
}

func TestNewHealthChecker_DefaultTimeout(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 8080, 1)}
	cfg := config.HealthCheck{
		Path: "/health",
	}

	hc := NewHealthChecker(hosts, cfg)

	assert.Equal(t, 5*time.Second, hc.client.Timeout)
}

func TestNewHealthChecker_WithOptions(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 8080, 1)}
	cfg := config.HealthCheck{Path: "/health"}

	logger := observability.NopLogger()
	client := &http.Client{Timeout: 10 * time.Second}

	hc := NewHealthChecker(hosts, cfg,
		WithHealthCheckLogger(logger),
		WithHealthCheckClient(client),
	)

	assert.Equal(t, client, hc.client)
}

func TestHealthChecker_StartStop(t *testing.T) {
	t.Parallel()

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Parse server URL to get host and port
	hosts := []*Host{NewHost("127.0.0.1", 0, 1)} // Port will be ignored

	cfg := config.HealthCheck{
		Path:     "/health",
		Interval: config.Duration(50 * time.Millisecond),
	}

	hc := NewHealthChecker(hosts, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hc.Start(ctx)
	assert.True(t, hc.IsRunning())

	// Starting again should be no-op
	hc.Start(ctx)

	hc.Stop()
	assert.False(t, hc.IsRunning())

	// Stopping again should be no-op
	hc.Stop()
}

func TestHealthChecker_IsRunning(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 8080, 1)}
	cfg := config.HealthCheck{Path: "/health"}

	hc := NewHealthChecker(hosts, cfg)

	assert.False(t, hc.IsRunning())
}

func TestHealthChecker_CheckHost_Success(t *testing.T) {
	t.Parallel()

	// Create a test server that returns 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Extract host and port from test server
	host := NewHost(server.Listener.Addr().(*net.TCPAddr).IP.String(),
		server.Listener.Addr().(*net.TCPAddr).Port, 1)

	cfg := config.HealthCheck{
		Path:             "/health",
		HealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg)

	ctx := context.Background()
	hc.checkHost(ctx, host)

	// After one successful check with threshold 1, should be healthy
	assert.Equal(t, StatusHealthy, host.Status())
}

func TestHealthChecker_CheckHost_Failure(t *testing.T) {
	t.Parallel()

	// Create a test server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	host := NewHost(server.Listener.Addr().(*net.TCPAddr).IP.String(),
		server.Listener.Addr().(*net.TCPAddr).Port, 1)
	host.SetStatus(StatusHealthy) // Start healthy

	cfg := config.HealthCheck{
		Path:               "/health",
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg)

	ctx := context.Background()
	hc.checkHost(ctx, host)

	// After one failed check with threshold 1, should be unhealthy
	assert.Equal(t, StatusUnhealthy, host.Status())
}

func TestHealthChecker_RecordSuccess(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)
	cfg := config.HealthCheck{
		Path:             "/health",
		HealthyThreshold: 2,
	}

	hc := NewHealthChecker([]*Host{host}, cfg)

	// First success
	hc.recordSuccess(host)
	assert.Equal(t, StatusUnknown, host.Status())
	assert.Equal(t, 1, hc.healthyCounts[host])

	// Second success - should become healthy
	hc.recordSuccess(host)
	assert.Equal(t, StatusHealthy, host.Status())
	assert.Equal(t, 2, hc.healthyCounts[host])
}

func TestHealthChecker_RecordFailure(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)
	host.SetStatus(StatusHealthy)

	cfg := config.HealthCheck{
		Path:               "/health",
		UnhealthyThreshold: 2,
	}

	hc := NewHealthChecker([]*Host{host}, cfg)

	// First failure
	hc.recordFailure(host, nil)
	assert.Equal(t, StatusHealthy, host.Status())
	assert.Equal(t, 1, hc.unhealthyCounts[host])

	// Second failure - should become unhealthy
	hc.recordFailure(host, nil)
	assert.Equal(t, StatusUnhealthy, host.Status())
	assert.Equal(t, 2, hc.unhealthyCounts[host])
}

func TestHealthChecker_RecordSuccess_ResetsFailureCount(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)
	cfg := config.HealthCheck{
		Path:               "/health",
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
	}

	hc := NewHealthChecker([]*Host{host}, cfg)

	// Record a failure
	hc.recordFailure(host, nil)
	assert.Equal(t, 1, hc.unhealthyCounts[host])

	// Record a success - should reset failure count
	hc.recordSuccess(host)
	assert.Equal(t, 0, hc.unhealthyCounts[host])
}

func TestHealthChecker_RecordFailure_ResetsSuccessCount(t *testing.T) {
	t.Parallel()

	host := NewHost("10.0.0.1", 8080, 1)
	cfg := config.HealthCheck{
		Path:               "/health",
		HealthyThreshold:   2,
		UnhealthyThreshold: 2,
	}

	hc := NewHealthChecker([]*Host{host}, cfg)

	// Record a success
	hc.recordSuccess(host)
	assert.Equal(t, 1, hc.healthyCounts[host])

	// Record a failure - should reset success count
	hc.recordFailure(host, nil)
	assert.Equal(t, 0, hc.healthyCounts[host])
}

func TestHealthChecker_ContextCancellation(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 8080, 1)}
	cfg := config.HealthCheck{
		Path:     "/health",
		Interval: config.Duration(1 * time.Hour), // Long interval
	}

	hc := NewHealthChecker(hosts, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	hc.Start(ctx)

	// Cancel context
	cancel()

	// Wait a bit for goroutine to exit
	time.Sleep(100 * time.Millisecond)
}

// ============================================================
// Helper: start a real gRPC health server for testing
// ============================================================

func startTestGRPCHealthServer(
	t *testing.T,
) (string, *health.Server, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	hs := health.NewServer()
	healthpb.RegisterHealthServer(srv, hs)

	go func() {
		_ = srv.Serve(lis)
	}()

	cleanup := func() {
		srv.GracefulStop()
		_ = lis.Close()
	}

	return lis.Addr().String(), hs, cleanup
}

// ============================================================
// gRPC health check tests
// ============================================================

func TestNewHealthChecker_WithGRPCConfig(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 50051, 1)}
	cfg := config.HealthCheck{
		Path:               "/grpc.health.v1.Health/Check",
		Interval:           config.Duration(10 * time.Second),
		Timeout:            config.Duration(5 * time.Second),
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
		UseGRPC:            true,
		GRPCService:        "my.service.v1",
	}

	hc := NewHealthChecker(hosts, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
	)

	assert.True(t, hc.useGRPC)
	assert.Equal(t, "my.service.v1", hc.grpcService)
	assert.NotNil(t, hc.grpcConns)
}

func TestNewHealthChecker_WithGRPCOption(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 50051, 1)}
	cfg := config.HealthCheck{
		Path: "/health",
	}

	hc := NewHealthChecker(hosts, cfg,
		WithGRPCHealthCheck("my.svc"),
	)

	assert.True(t, hc.useGRPC)
	assert.Equal(t, "my.svc", hc.grpcService)
}

func TestNewHealthChecker_WithGRPCTransportCredentials(
	t *testing.T,
) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 50051, 1)}
	cfg := config.HealthCheck{Path: "/health"}

	creds := insecure.NewCredentials()
	hc := NewHealthChecker(hosts, cfg,
		WithGRPCTransportCredentials(creds),
	)

	assert.Equal(t, creds, hc.grpcCreds)
}

func TestHealthChecker_GRPCHealthCheck_Serving(t *testing.T) {
	t.Parallel()

	// Arrange: start a real gRPC health server
	addr, hs, cleanup := startTestGRPCHealthServer(t)
	defer cleanup()

	hs.SetServingStatus(
		"", healthpb.HealthCheckResponse_SERVING,
	)

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)

	host := NewHost(
		tcpAddr.IP.String(), tcpAddr.Port, 1,
	)

	cfg := config.HealthCheck{
		Path:             "/grpc.health.v1.Health/Check",
		Timeout:          config.Duration(5 * time.Second),
		UseGRPC:          true,
		GRPCService:      "",
		HealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-grpc-serving"),
	)

	// Act
	hc.checkHost(context.Background(), host)

	// Assert: host should become healthy
	assert.Equal(t, StatusHealthy, host.Status())

	// Cleanup gRPC connections
	hc.closeAllGRPCConns()
}

func TestHealthChecker_GRPCHealthCheck_NotServing(
	t *testing.T,
) {
	t.Parallel()

	// Arrange
	addr, hs, cleanup := startTestGRPCHealthServer(t)
	defer cleanup()

	hs.SetServingStatus(
		"", healthpb.HealthCheckResponse_NOT_SERVING,
	)

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)

	host := NewHost(
		tcpAddr.IP.String(), tcpAddr.Port, 1,
	)
	host.SetStatus(StatusHealthy) // Start healthy

	cfg := config.HealthCheck{
		Path:               "/grpc.health.v1.Health/Check",
		Timeout:            config.Duration(5 * time.Second),
		UseGRPC:            true,
		GRPCService:        "",
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-grpc-not-serving"),
	)

	// Act
	hc.checkHost(context.Background(), host)

	// Assert: host should become unhealthy
	assert.Equal(t, StatusUnhealthy, host.Status())

	hc.closeAllGRPCConns()
}

func TestHealthChecker_GRPCHealthCheck_ConnectionError(
	t *testing.T,
) {
	t.Parallel()

	// Arrange: use an address that is not reachable
	host := NewHost("127.0.0.1", 1, 1)
	host.SetStatus(StatusHealthy)

	cfg := config.HealthCheck{
		Path:               "/grpc.health.v1.Health/Check",
		Timeout:            config.Duration(500 * time.Millisecond),
		UseGRPC:            true,
		GRPCService:        "",
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-grpc-conn-error"),
	)

	// Act
	hc.checkHost(context.Background(), host)

	// Assert: host should become unhealthy
	assert.Equal(t, StatusUnhealthy, host.Status())

	hc.closeAllGRPCConns()
}

func TestHealthChecker_GRPCHealthCheck_ServiceSpecific(
	t *testing.T,
) {
	t.Parallel()

	// Arrange
	addr, hs, cleanup := startTestGRPCHealthServer(t)
	defer cleanup()

	svcName := "my.custom.Service"
	hs.SetServingStatus(
		svcName, healthpb.HealthCheckResponse_SERVING,
	)

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)

	host := NewHost(
		tcpAddr.IP.String(), tcpAddr.Port, 1,
	)

	cfg := config.HealthCheck{
		Path:             "/grpc.health.v1.Health/Check",
		Timeout:          config.Duration(5 * time.Second),
		UseGRPC:          true,
		GRPCService:      svcName,
		HealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-grpc-svc-specific"),
	)

	// Act
	hc.checkHost(context.Background(), host)

	// Assert: host should become healthy
	assert.Equal(t, StatusHealthy, host.Status())
	assert.Equal(t, svcName, hc.grpcService)

	hc.closeAllGRPCConns()
}

func TestHealthChecker_GRPCConnPool_Reuse(t *testing.T) {
	t.Parallel()

	// Arrange
	addr, hs, cleanup := startTestGRPCHealthServer(t)
	defer cleanup()

	hs.SetServingStatus(
		"", healthpb.HealthCheckResponse_SERVING,
	)

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)

	host := NewHost(
		tcpAddr.IP.String(), tcpAddr.Port, 1,
	)

	cfg := config.HealthCheck{
		Path:             "/grpc.health.v1.Health/Check",
		Timeout:          config.Duration(5 * time.Second),
		UseGRPC:          true,
		GRPCService:      "",
		HealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-grpc-pool-reuse"),
	)

	ctx := context.Background()

	// Act: first check creates a connection
	hc.checkHost(ctx, host)
	assert.Equal(t, StatusHealthy, host.Status())

	// Get the connection from the pool
	connAddr := net.JoinHostPort(
		host.Address,
		strconv.Itoa(host.Port),
	)
	hc.grpcMu.Lock()
	firstConn := hc.grpcConns[connAddr]
	hc.grpcMu.Unlock()
	require.NotNil(t, firstConn)

	// Act: second check should reuse the connection
	hc.checkHost(ctx, host)

	hc.grpcMu.Lock()
	secondConn := hc.grpcConns[connAddr]
	hc.grpcMu.Unlock()

	// Assert: same connection object is reused
	assert.Same(t, firstConn, secondConn)

	hc.closeAllGRPCConns()
}

func TestHealthChecker_GRPCConnPool_CloseOnError(
	t *testing.T,
) {
	t.Parallel()

	// Arrange: start server, then stop it to cause errors
	addr, _, cleanup := startTestGRPCHealthServer(t)

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)

	host := NewHost(
		tcpAddr.IP.String(), tcpAddr.Port, 1,
	)
	host.SetStatus(StatusHealthy)

	cfg := config.HealthCheck{
		Path:               "/grpc.health.v1.Health/Check",
		Timeout:            config.Duration(500 * time.Millisecond),
		UseGRPC:            true,
		GRPCService:        "",
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-grpc-close-on-err"),
	)

	ctx := context.Background()

	// First check succeeds (server is running)
	hc.checkHost(ctx, host)

	connAddr := net.JoinHostPort(
		host.Address,
		strconv.Itoa(host.Port),
	)
	hc.grpcMu.Lock()
	connBefore := hc.grpcConns[connAddr]
	hc.grpcMu.Unlock()

	// Stop the server to cause connection errors
	cleanup()

	// Give time for the connection to detect the failure
	time.Sleep(100 * time.Millisecond)

	// Reset host status for next check
	host.SetStatus(StatusHealthy)

	// Act: check again - should fail and close stale conn
	hc.checkHost(ctx, host)

	// Assert: connection should have been removed
	hc.grpcMu.Lock()
	connAfter, exists := hc.grpcConns[connAddr]
	hc.grpcMu.Unlock()

	// Either the connection was removed or replaced
	if exists {
		assert.NotSame(t, connBefore, connAfter)
	}

	hc.closeAllGRPCConns()
}

func TestHealthChecker_Stop_ClosesGRPCConns(t *testing.T) {
	t.Parallel()

	// Arrange
	addr, hs, cleanup := startTestGRPCHealthServer(t)
	defer cleanup()

	hs.SetServingStatus(
		"", healthpb.HealthCheckResponse_SERVING,
	)

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)

	host := NewHost(
		tcpAddr.IP.String(), tcpAddr.Port, 1,
	)

	cfg := config.HealthCheck{
		Path:             "/grpc.health.v1.Health/Check",
		Interval:         config.Duration(50 * time.Millisecond),
		Timeout:          config.Duration(5 * time.Second),
		UseGRPC:          true,
		GRPCService:      "",
		HealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-grpc-stop-conns"),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Act: start and let it run a health check
	hc.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Verify connections exist before stop
	hc.grpcMu.Lock()
	connCount := len(hc.grpcConns)
	hc.grpcMu.Unlock()
	assert.Greater(t, connCount, 0)

	// Act: stop should close all gRPC connections
	hc.Stop()

	// Assert: all connections should be closed
	hc.grpcMu.Lock()
	connCountAfter := len(hc.grpcConns)
	hc.grpcMu.Unlock()
	assert.Equal(t, 0, connCountAfter)
}

// ============================================================
// HTTP health check port override tests
// ============================================================

func TestHealthChecker_CheckHostHTTP_WithPortOverride(
	t *testing.T,
) {
	t.Parallel()

	// Arrange: create an HTTP test server on a random port
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}),
	)
	defer server.Close()

	// Extract the test server's port
	serverAddr := server.Listener.Addr().(*net.TCPAddr)
	serverPort := serverAddr.Port

	// Create a host with a DIFFERENT port (not the test server's port).
	// If the health checker ignores the override, it would hit the wrong
	// port and fail.
	host := NewHost("127.0.0.1", 19999, 1)

	cfg := config.HealthCheck{
		Path:             "/healthz",
		Timeout:          config.Duration(5 * time.Second),
		Port:             serverPort, // override port
		HealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-http-port-override"),
	)

	// Act
	hc.checkHost(context.Background(), host)

	// Assert: host should become healthy because the override
	// port directed the check to the running test server.
	assert.Equal(t, StatusHealthy, host.Status())
}

func TestHealthChecker_CheckHostHTTP_WithPortOverride_UsesHTTP(
	t *testing.T,
) {
	t.Parallel()

	// Arrange: create an HTTP (plain) test server.
	// If the health checker incorrectly uses https:// when
	// useTLS=true AND Port override is set, the request will
	// fail because the server only speaks plain HTTP.
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	defer server.Close()

	serverAddr := server.Listener.Addr().(*net.TCPAddr)
	serverPort := serverAddr.Port

	host := NewHost("127.0.0.1", 29999, 1)

	cfg := config.HealthCheck{
		Path:             "/healthz",
		Timeout:          config.Duration(5 * time.Second),
		Port:             serverPort,
		HealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-http-port-override-scheme"),
		WithHealthCheckTLS(true), // TLS enabled globally
	)

	// Act
	hc.checkHost(context.Background(), host)

	// Assert: the check must succeed because the port override
	// forces plain http:// regardless of useTLS.
	assert.Equal(t, StatusHealthy, host.Status())
}

func TestNewHealthChecker_PortFromConfig(t *testing.T) {
	t.Parallel()

	hosts := []*Host{NewHost("10.0.0.1", 50051, 1)}
	cfg := config.HealthCheck{
		Path:             "/healthz",
		Port:             9090,
		HealthyThreshold: 2,
	}

	hc := NewHealthChecker(hosts, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
	)

	// When Port is set (HTTP monitoring port), useGRPC must be false
	// because the override port is meant for plain HTTP health checks.
	assert.False(t, hc.useGRPC)
	assert.Equal(t, 9090, hc.config.Port)
}

func TestHealthChecker_GRPCCheckHost_ContextCanceled(
	t *testing.T,
) {
	t.Parallel()

	// Arrange
	host := NewHost("127.0.0.1", 50051, 1)
	cfg := config.HealthCheck{
		Path:               "/grpc.health.v1.Health/Check",
		Timeout:            config.Duration(5 * time.Second),
		UseGRPC:            true,
		GRPCService:        "",
		HealthyThreshold:   1,
		UnhealthyThreshold: 1,
	}

	hc := NewHealthChecker([]*Host{host}, cfg,
		WithHealthCheckLogger(observability.NopLogger()),
		WithBackendName("test-grpc-ctx-cancel"),
	)

	// Cancel context before checking
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act: checkHost should return early
	hc.checkHost(ctx, host)

	// Assert: host status should remain unchanged
	assert.Equal(t, StatusUnknown, host.Status())

	hc.closeAllGRPCConns()
}
