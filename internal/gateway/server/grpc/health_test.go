package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// TestNewHealthServer tests creating a new health server
func TestNewHealthServer(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()

	assert.NotNil(t, server)
	assert.NotNil(t, server.checks)
	assert.NotNil(t, server.status)
	assert.Empty(t, server.checks)
	assert.Empty(t, server.status)
}

// TestHealthServerCheck tests the Check RPC
func TestHealthServerCheck(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	ctx := context.Background()

	t.Run("returns SERVING for empty service by default", func(t *testing.T) {
		req := &healthpb.HealthCheckRequest{Service: ""}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("returns error for unknown service", func(t *testing.T) {
		req := &healthpb.HealthCheckRequest{Service: "unknown-service"}
		resp, err := server.Check(ctx, req)

		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("returns status for known service", func(t *testing.T) {
		server.SetServingStatus("test-service", healthpb.HealthCheckResponse_SERVING)

		req := &healthpb.HealthCheckRequest{Service: "test-service"}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("returns NOT_SERVING status", func(t *testing.T) {
		server.SetServingStatus("unhealthy-service", healthpb.HealthCheckResponse_NOT_SERVING)

		req := &healthpb.HealthCheckRequest{Service: "unhealthy-service"}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.Status)
	})

	t.Run("uses dynamic check function", func(t *testing.T) {
		callCount := 0
		server.SetCheck("dynamic-service", func() healthpb.HealthCheckResponse_ServingStatus {
			callCount++
			return healthpb.HealthCheckResponse_SERVING
		})

		req := &healthpb.HealthCheckRequest{Service: "dynamic-service"}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
		assert.Equal(t, 1, callCount)
	})
}

// TestHealthServerSetServingStatus tests SetServingStatus
func TestHealthServerSetServingStatus(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	ctx := context.Background()

	t.Run("sets SERVING status", func(t *testing.T) {
		server.SetServingStatus("service1", healthpb.HealthCheckResponse_SERVING)

		req := &healthpb.HealthCheckRequest{Service: "service1"}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("sets NOT_SERVING status", func(t *testing.T) {
		server.SetServingStatus("service2", healthpb.HealthCheckResponse_NOT_SERVING)

		req := &healthpb.HealthCheckRequest{Service: "service2"}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.Status)
	})

	t.Run("sets SERVICE_UNKNOWN status", func(t *testing.T) {
		server.SetServingStatus("service3", healthpb.HealthCheckResponse_SERVICE_UNKNOWN)

		req := &healthpb.HealthCheckRequest{Service: "service3"}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVICE_UNKNOWN, resp.Status)
	})

	t.Run("updates existing status", func(t *testing.T) {
		server.SetServingStatus("service4", healthpb.HealthCheckResponse_SERVING)
		server.SetServingStatus("service4", healthpb.HealthCheckResponse_NOT_SERVING)

		req := &healthpb.HealthCheckRequest{Service: "service4"}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.Status)
	})
}

// TestHealthServerSetCheck tests SetCheck
func TestHealthServerSetCheck(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	ctx := context.Background()

	t.Run("sets dynamic check function", func(t *testing.T) {
		server.SetCheck("dynamic", func() healthpb.HealthCheckResponse_ServingStatus {
			return healthpb.HealthCheckResponse_SERVING
		})

		req := &healthpb.HealthCheckRequest{Service: "dynamic"}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	})

	t.Run("dynamic check takes precedence over static status", func(t *testing.T) {
		server.SetServingStatus("precedence", healthpb.HealthCheckResponse_NOT_SERVING)
		server.SetCheck("precedence", func() healthpb.HealthCheckResponse_ServingStatus {
			return healthpb.HealthCheckResponse_SERVING
		})

		req := &healthpb.HealthCheckRequest{Service: "precedence"}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	})
}

// TestHealthServerRemoveCheck tests RemoveCheck
func TestHealthServerRemoveCheck(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	ctx := context.Background()

	// Set up a service with both check and status
	server.SetServingStatus("remove-test", healthpb.HealthCheckResponse_SERVING)
	server.SetCheck("remove-test", func() healthpb.HealthCheckResponse_ServingStatus {
		return healthpb.HealthCheckResponse_NOT_SERVING
	})

	// Remove the check
	server.RemoveCheck("remove-test")

	// Service should now return error (both check and status are removed)
	req := &healthpb.HealthCheckRequest{Service: "remove-test"}
	resp, err := server.Check(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
}

// TestHealthServerShutdown tests Shutdown
func TestHealthServerShutdown(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	ctx := context.Background()

	// Set up multiple services
	server.SetServingStatus("service1", healthpb.HealthCheckResponse_SERVING)
	server.SetServingStatus("service2", healthpb.HealthCheckResponse_SERVING)
	server.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	// Shutdown
	server.Shutdown()

	// All services should be NOT_SERVING
	services := []string{"service1", "service2", ""}
	for _, svc := range services {
		req := &healthpb.HealthCheckRequest{Service: svc}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.Status)
	}
}

// TestHealthServerResume tests Resume
func TestHealthServerResume(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	ctx := context.Background()

	// Set up services and shutdown
	server.SetServingStatus("service1", healthpb.HealthCheckResponse_SERVING)
	server.SetServingStatus("service2", healthpb.HealthCheckResponse_SERVING)
	server.Shutdown()

	// Resume
	server.Resume()

	// All services should be SERVING
	services := []string{"service1", "service2", ""}
	for _, svc := range services {
		req := &healthpb.HealthCheckRequest{Service: svc}
		resp, err := server.Check(ctx, req)

		assert.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	}
}

// TestHealthServerRegister tests Register
func TestHealthServerRegister(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	grpcServer := grpc.NewServer()

	// Should not panic
	server.Register(grpcServer)
}

// TestHealthChecker tests the HealthChecker helper
func TestHealthChecker(t *testing.T) {
	t.Parallel()

	t.Run("returns SERVING when all checks pass", func(t *testing.T) {
		checker := NewHealthChecker()
		checker.AddCheck(func() bool { return true })
		checker.AddCheck(func() bool { return true })

		status := checker.Check()
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)
	})

	t.Run("returns NOT_SERVING when any check fails", func(t *testing.T) {
		checker := NewHealthChecker()
		checker.AddCheck(func() bool { return true })
		checker.AddCheck(func() bool { return false })

		status := checker.Check()
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)
	})

	t.Run("returns SERVING when no checks", func(t *testing.T) {
		checker := NewHealthChecker()

		status := checker.Check()
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)
	})

	t.Run("ToCheckFunc returns callable function", func(t *testing.T) {
		checker := NewHealthChecker()
		checker.AddCheck(func() bool { return true })

		checkFunc := checker.ToCheckFunc()
		assert.NotNil(t, checkFunc)

		status := checkFunc()
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)
	})
}

// TestNewHealthChecker tests creating a new health checker
func TestNewHealthChecker(t *testing.T) {
	t.Parallel()

	checker := NewHealthChecker()

	assert.NotNil(t, checker)
	assert.NotNil(t, checker.checks)
	assert.Empty(t, checker.checks)
}

// TestHealthCheckerAddCheck tests adding checks
func TestHealthCheckerAddCheck(t *testing.T) {
	t.Parallel()

	checker := NewHealthChecker()

	checker.AddCheck(func() bool { return true })
	assert.Len(t, checker.checks, 1)

	checker.AddCheck(func() bool { return false })
	assert.Len(t, checker.checks, 2)
}

// mockHealthWatchServer implements healthpb.Health_WatchServer for testing
type mockHealthWatchServer struct {
	grpc.ServerStream
	ctx      context.Context
	sent     []*healthpb.HealthCheckResponse
	sendErr  error
	canceled bool
}

func (m *mockHealthWatchServer) Context() context.Context {
	return m.ctx
}

func (m *mockHealthWatchServer) Send(resp *healthpb.HealthCheckResponse) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, resp)
	return nil
}

// TestHealthServerWatch tests the Watch RPC
func TestHealthServerWatch(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()

	t.Run("sends initial status for known service", func(t *testing.T) {
		server.SetServingStatus("watch-service", healthpb.HealthCheckResponse_SERVING)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		stream := &mockHealthWatchServer{
			ctx: ctx,
		}

		req := &healthpb.HealthCheckRequest{Service: "watch-service"}
		err := server.Watch(req, stream)

		// Should return context error after timeout
		assert.Error(t, err)
		assert.Len(t, stream.sent, 1)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, stream.sent[0].Status)
	})

	t.Run("sends initial status for empty service", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		stream := &mockHealthWatchServer{
			ctx: ctx,
		}

		req := &healthpb.HealthCheckRequest{Service: ""}
		err := server.Watch(req, stream)

		assert.Error(t, err)
		assert.Len(t, stream.sent, 1)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, stream.sent[0].Status)
	})

	t.Run("returns error for unknown service", func(t *testing.T) {
		ctx := context.Background()
		stream := &mockHealthWatchServer{
			ctx: ctx,
		}

		req := &healthpb.HealthCheckRequest{Service: "unknown-watch-service"}
		err := server.Watch(req, stream)

		assert.Error(t, err)
		assert.Empty(t, stream.sent)
	})

	t.Run("uses dynamic check for initial status", func(t *testing.T) {
		server.SetCheck("dynamic-watch", func() healthpb.HealthCheckResponse_ServingStatus {
			return healthpb.HealthCheckResponse_NOT_SERVING
		})

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		stream := &mockHealthWatchServer{
			ctx: ctx,
		}

		req := &healthpb.HealthCheckRequest{Service: "dynamic-watch"}
		err := server.Watch(req, stream)

		assert.Error(t, err)
		require.Len(t, stream.sent, 1)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, stream.sent[0].Status)
	})
}

// TestHealthServerConcurrentAccess tests concurrent access to health server
func TestHealthServerConcurrentAccess(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	ctx := context.Background()

	done := make(chan bool)

	// Concurrent status updates
	go func() {
		for i := 0; i < 100; i++ {
			server.SetServingStatus("concurrent-service", healthpb.HealthCheckResponse_SERVING)
		}
		done <- true
	}()

	// Concurrent checks
	go func() {
		for i := 0; i < 100; i++ {
			req := &healthpb.HealthCheckRequest{Service: "concurrent-service"}
			_, _ = server.Check(ctx, req)
		}
		done <- true
	}()

	// Concurrent check function updates
	go func() {
		for i := 0; i < 100; i++ {
			server.SetCheck("concurrent-service", func() healthpb.HealthCheckResponse_ServingStatus {
				return healthpb.HealthCheckResponse_SERVING
			})
		}
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		<-done
	}
}

// ============================================================================
// Additional Watch Tests
// ============================================================================

// TestHealthServerWatch_SendError tests Watch when Send returns error
func TestHealthServerWatch_SendError(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	server.SetServingStatus("send-error-service", healthpb.HealthCheckResponse_SERVING)

	ctx := context.Background()
	stream := &mockHealthWatchServer{
		ctx:     ctx,
		sendErr: assert.AnError,
	}

	req := &healthpb.HealthCheckRequest{Service: "send-error-service"}
	err := server.Watch(req, stream)

	assert.Error(t, err)
	assert.Empty(t, stream.sent)
}

// TestHealthServerWatch_WithStaticStatus tests Watch with static status
func TestHealthServerWatch_WithStaticStatus(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	server.SetServingStatus("static-watch-service", healthpb.HealthCheckResponse_NOT_SERVING)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	stream := &mockHealthWatchServer{
		ctx: ctx,
	}

	req := &healthpb.HealthCheckRequest{Service: "static-watch-service"}
	err := server.Watch(req, stream)

	assert.Error(t, err) // Context timeout
	require.Len(t, stream.sent, 1)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, stream.sent[0].Status)
}

// TestHealthServerWatch_EmptyServiceWithStatus tests Watch for empty service with status set
func TestHealthServerWatch_EmptyServiceWithStatus(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	server.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	stream := &mockHealthWatchServer{
		ctx: ctx,
	}

	req := &healthpb.HealthCheckRequest{Service: ""}
	err := server.Watch(req, stream)

	assert.Error(t, err) // Context timeout
	require.Len(t, stream.sent, 1)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, stream.sent[0].Status)
}

// ============================================================================
// Additional HealthChecker Tests
// ============================================================================

// TestHealthChecker_FirstCheckFails tests HealthChecker when first check fails
func TestHealthChecker_FirstCheckFails(t *testing.T) {
	t.Parallel()

	checker := NewHealthChecker()
	checker.AddCheck(func() bool { return false })
	checker.AddCheck(func() bool { return true })

	status := checker.Check()
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)
}

// TestHealthChecker_LastCheckFails tests HealthChecker when last check fails
func TestHealthChecker_LastCheckFails(t *testing.T) {
	t.Parallel()

	checker := NewHealthChecker()
	checker.AddCheck(func() bool { return true })
	checker.AddCheck(func() bool { return true })
	checker.AddCheck(func() bool { return false })

	status := checker.Check()
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)
}

// TestHealthChecker_AllChecksFail tests HealthChecker when all checks fail
func TestHealthChecker_AllChecksFail(t *testing.T) {
	t.Parallel()

	checker := NewHealthChecker()
	checker.AddCheck(func() bool { return false })
	checker.AddCheck(func() bool { return false })
	checker.AddCheck(func() bool { return false })

	status := checker.Check()
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)
}

// TestHealthChecker_IntegrationWithHealthServer tests HealthChecker integration
func TestHealthChecker_IntegrationWithHealthServer(t *testing.T) {
	t.Parallel()

	server := NewHealthServer()
	checker := NewHealthChecker()

	isHealthy := true
	checker.AddCheck(func() bool { return isHealthy })

	server.SetCheck("checker-service", checker.ToCheckFunc())

	ctx := context.Background()

	// Check when healthy
	req := &healthpb.HealthCheckRequest{Service: "checker-service"}
	resp, err := server.Check(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)

	// Change to unhealthy
	isHealthy = false
	resp, err = server.Check(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.Status)
}
