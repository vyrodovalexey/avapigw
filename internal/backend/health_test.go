package backend

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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
