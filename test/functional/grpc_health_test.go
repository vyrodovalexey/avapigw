//go:build functional
// +build functional

package functional

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/grpc/health"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestFunctional_GRPCHealth_Check(t *testing.T) {
	t.Parallel()

	t.Run("check overall health", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		ctx := context.Background()
		resp, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
	})

	t.Run("check specific service health", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Set service status
		hs.SetServingStatus("api.v1.TestService", healthpb.HealthCheckResponse_SERVING)

		ctx := context.Background()
		resp, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: "api.v1.TestService"})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
	})

	t.Run("check unknown service returns not found", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		ctx := context.Background()
		_, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: "unknown.Service"})
		require.Error(t, err)
	})

	t.Run("check not serving status", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Set service to not serving
		hs.SetServingStatus("api.v1.TestService", healthpb.HealthCheckResponse_NOT_SERVING)

		ctx := context.Background()
		resp, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: "api.v1.TestService"})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.GetStatus())
	})

	t.Run("check after shutdown returns not serving", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Shutdown
		hs.Shutdown()

		ctx := context.Background()
		resp, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.GetStatus())
	})
}

func TestFunctional_GRPCHealth_Watch(t *testing.T) {
	t.Parallel()

	t.Run("watch receives initial status", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Set initial status
		hs.SetServingStatus("api.v1.TestService", healthpb.HealthCheckResponse_SERVING)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Create mock stream
		stream := &mockHealthWatchServer{
			ctx:       ctx,
			responses: make(chan *healthpb.HealthCheckResponse, 10),
		}

		// Start watch in goroutine
		errCh := make(chan error, 1)
		go func() {
			errCh <- hs.Watch(&healthpb.HealthCheckRequest{Service: "api.v1.TestService"}, stream)
		}()

		// Wait for initial status
		select {
		case resp := <-stream.responses:
			assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
		case <-ctx.Done():
			t.Fatal("timeout waiting for initial status")
		}

		cancel() // Stop the watch
	})

	t.Run("watch receives status updates", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Set initial status
		hs.SetServingStatus("api.v1.TestService", healthpb.HealthCheckResponse_SERVING)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Create mock stream
		stream := &mockHealthWatchServer{
			ctx:       ctx,
			responses: make(chan *healthpb.HealthCheckResponse, 10),
		}

		// Start watch in goroutine
		go func() {
			_ = hs.Watch(&healthpb.HealthCheckRequest{Service: "api.v1.TestService"}, stream)
		}()

		// Wait for initial status
		select {
		case resp := <-stream.responses:
			assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
		case <-ctx.Done():
			t.Fatal("timeout waiting for initial status")
		}

		// Update status
		hs.SetServingStatus("api.v1.TestService", healthpb.HealthCheckResponse_NOT_SERVING)

		// Wait for update
		select {
		case resp := <-stream.responses:
			assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.GetStatus())
		case <-ctx.Done():
			t.Fatal("timeout waiting for status update")
		}

		cancel()
	})

	t.Run("watch unknown service returns service unknown", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Create mock stream
		stream := &mockHealthWatchServer{
			ctx:       ctx,
			responses: make(chan *healthpb.HealthCheckResponse, 10),
		}

		// Start watch in goroutine
		go func() {
			_ = hs.Watch(&healthpb.HealthCheckRequest{Service: "unknown.Service"}, stream)
		}()

		// Wait for initial status (should be SERVICE_UNKNOWN)
		select {
		case resp := <-stream.responses:
			assert.Equal(t, healthpb.HealthCheckResponse_SERVICE_UNKNOWN, resp.GetStatus())
		case <-ctx.Done():
			t.Fatal("timeout waiting for initial status")
		}

		cancel()
	})
}

func TestFunctional_GRPCHealth_SetStatus(t *testing.T) {
	t.Parallel()

	t.Run("set and get serving status", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Set status
		hs.SetServingStatus("api.v1.TestService", healthpb.HealthCheckResponse_SERVING)

		// Get status
		status, ok := hs.GetServingStatus("api.v1.TestService")
		require.True(t, ok)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)
	})

	t.Run("set multiple service statuses", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Set multiple statuses
		hs.SetServingStatus("service1", healthpb.HealthCheckResponse_SERVING)
		hs.SetServingStatus("service2", healthpb.HealthCheckResponse_NOT_SERVING)
		hs.SetServingStatus("service3", healthpb.HealthCheckResponse_UNKNOWN)

		// Verify all statuses
		status, ok := hs.GetServingStatus("service1")
		require.True(t, ok)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)

		status, ok = hs.GetServingStatus("service2")
		require.True(t, ok)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)

		status, ok = hs.GetServingStatus("service3")
		require.True(t, ok)
		assert.Equal(t, healthpb.HealthCheckResponse_UNKNOWN, status)
	})

	t.Run("get all statuses", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Set multiple statuses
		hs.SetServingStatus("service1", healthpb.HealthCheckResponse_SERVING)
		hs.SetServingStatus("service2", healthpb.HealthCheckResponse_NOT_SERVING)

		// Get all statuses
		statuses := hs.GetAllStatuses()
		assert.Len(t, statuses, 3) // 2 services + overall health ("")
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, statuses["service1"])
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, statuses["service2"])
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, statuses[""])
	})

	t.Run("update existing status", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Set initial status
		hs.SetServingStatus("api.v1.TestService", healthpb.HealthCheckResponse_SERVING)

		status, ok := hs.GetServingStatus("api.v1.TestService")
		require.True(t, ok)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)

		// Update status
		hs.SetServingStatus("api.v1.TestService", healthpb.HealthCheckResponse_NOT_SERVING)

		status, ok = hs.GetServingStatus("api.v1.TestService")
		require.True(t, ok)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)
	})

	t.Run("shutdown sets all to not serving", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Set multiple statuses
		hs.SetServingStatus("service1", healthpb.HealthCheckResponse_SERVING)
		hs.SetServingStatus("service2", healthpb.HealthCheckResponse_SERVING)

		// Shutdown
		hs.Shutdown()

		// All should be NOT_SERVING
		statuses := hs.GetAllStatuses()
		for _, status := range statuses {
			assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)
		}
	})

	t.Run("resume after shutdown", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Shutdown
		hs.Shutdown()

		// Verify shutdown
		status, ok := hs.GetServingStatus("")
		require.True(t, ok)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)

		// Resume
		hs.Resume()

		// Overall health should be serving again
		status, ok = hs.GetServingStatus("")
		require.True(t, ok)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)
	})

	t.Run("set status after shutdown is ignored", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		// Shutdown
		hs.Shutdown()

		// Try to set status (should be ignored)
		hs.SetServingStatus("api.v1.TestService", healthpb.HealthCheckResponse_SERVING)

		// Status should still be NOT_SERVING
		status, ok := hs.GetServingStatus("")
		require.True(t, ok)
		assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)
	})

	t.Run("concurrent status updates", func(t *testing.T) {
		t.Parallel()

		hs := health.NewHealthServer(health.WithHealthLogger(observability.NopLogger()))

		var wg sync.WaitGroup
		numGoroutines := 10
		numUpdates := 100

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				serviceName := "service"
				for j := 0; j < numUpdates; j++ {
					if j%2 == 0 {
						hs.SetServingStatus(serviceName, healthpb.HealthCheckResponse_SERVING)
					} else {
						hs.SetServingStatus(serviceName, healthpb.HealthCheckResponse_NOT_SERVING)
					}
				}
			}(i)
		}

		wg.Wait()

		// Should not panic and status should be valid
		status, ok := hs.GetServingStatus("service")
		require.True(t, ok)
		assert.True(t, status == healthpb.HealthCheckResponse_SERVING ||
			status == healthpb.HealthCheckResponse_NOT_SERVING)
	})
}

// mockHealthWatchServer is a mock implementation of Health_WatchServer for testing.
type mockHealthWatchServer struct {
	ctx       context.Context
	responses chan *healthpb.HealthCheckResponse
	mu        sync.Mutex
}

func (m *mockHealthWatchServer) Send(resp *healthpb.HealthCheckResponse) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	select {
	case m.responses <- resp:
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}

func (m *mockHealthWatchServer) Context() context.Context {
	return m.ctx
}

func (m *mockHealthWatchServer) SetHeader(_ metadata.MD) error {
	return nil
}

func (m *mockHealthWatchServer) SendHeader(_ metadata.MD) error {
	return nil
}

func (m *mockHealthWatchServer) SetTrailer(_ metadata.MD) {
}

func (m *mockHealthWatchServer) SendMsg(_ interface{}) error {
	return nil
}

func (m *mockHealthWatchServer) RecvMsg(_ interface{}) error {
	return nil
}
