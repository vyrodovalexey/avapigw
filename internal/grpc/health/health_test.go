package health

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewHealthServer(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()

	assert.NotNil(t, hs)
	assert.NotNil(t, hs.services)
	assert.NotNil(t, hs.watchers)
	assert.False(t, hs.shutdown)

	// Default overall health should be SERVING
	status, ok := hs.GetServingStatus("")
	assert.True(t, ok)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)
}

func TestNewHealthServer_WithLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	hs := NewHealthServer(WithHealthLogger(logger))

	assert.NotNil(t, hs)
	assert.NotNil(t, hs.logger)
}

func TestHealthServer_Check_OverallHealth(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	ctx := context.Background()

	resp, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
}

func TestHealthServer_Check_SpecificService(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	ctx := context.Background()

	// Set status for a specific service
	hs.SetServingStatus("user.UserService", healthpb.HealthCheckResponse_SERVING)

	resp, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: "user.UserService"})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
}

func TestHealthServer_Check_UnknownService(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	ctx := context.Background()

	_, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: "unknown.Service"})
	assert.Error(t, err)
}

func TestHealthServer_Check_AfterShutdown(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	ctx := context.Background()

	hs.Shutdown()

	resp, err := hs.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, resp.Status)
}

func TestHealthServer_SetServingStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		service string
		status  healthpb.HealthCheckResponse_ServingStatus
	}{
		{
			name:    "set serving",
			service: "test.Service",
			status:  healthpb.HealthCheckResponse_SERVING,
		},
		{
			name:    "set not serving",
			service: "test.Service",
			status:  healthpb.HealthCheckResponse_NOT_SERVING,
		},
		{
			name:    "set unknown",
			service: "test.Service",
			status:  healthpb.HealthCheckResponse_SERVICE_UNKNOWN,
		},
		{
			name:    "set overall health",
			service: "",
			status:  healthpb.HealthCheckResponse_NOT_SERVING,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hs := NewHealthServer()
			hs.SetServingStatus(tt.service, tt.status)

			status, ok := hs.GetServingStatus(tt.service)
			assert.True(t, ok)
			assert.Equal(t, tt.status, status)
		})
	}
}

func TestHealthServer_SetServingStatus_AfterShutdown(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	hs.Shutdown()

	// Should not update status after shutdown
	hs.SetServingStatus("test.Service", healthpb.HealthCheckResponse_SERVING)

	_, ok := hs.GetServingStatus("test.Service")
	assert.False(t, ok)
}

func TestHealthServer_Shutdown(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()

	// Set some services
	hs.SetServingStatus("service1", healthpb.HealthCheckResponse_SERVING)
	hs.SetServingStatus("service2", healthpb.HealthCheckResponse_SERVING)

	hs.Shutdown()

	// All services should be NOT_SERVING
	status, ok := hs.GetServingStatus("")
	assert.True(t, ok)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)

	status, ok = hs.GetServingStatus("service1")
	assert.True(t, ok)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)

	status, ok = hs.GetServingStatus("service2")
	assert.True(t, ok)
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, status)

	assert.True(t, hs.shutdown)
}

func TestHealthServer_Resume(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	hs.Shutdown()

	assert.True(t, hs.shutdown)

	hs.Resume()

	assert.False(t, hs.shutdown)

	// Overall health should be SERVING again
	status, ok := hs.GetServingStatus("")
	assert.True(t, ok)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)
}

func TestHealthServer_GetServingStatus(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()

	// Existing service
	hs.SetServingStatus("test.Service", healthpb.HealthCheckResponse_SERVING)
	status, ok := hs.GetServingStatus("test.Service")
	assert.True(t, ok)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, status)

	// Non-existing service
	_, ok = hs.GetServingStatus("unknown.Service")
	assert.False(t, ok)
}

func TestHealthServer_GetAllStatuses(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()

	hs.SetServingStatus("service1", healthpb.HealthCheckResponse_SERVING)
	hs.SetServingStatus("service2", healthpb.HealthCheckResponse_NOT_SERVING)

	statuses := hs.GetAllStatuses()

	assert.Len(t, statuses, 3) // "" (overall), service1, service2
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, statuses[""])
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, statuses["service1"])
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, statuses["service2"])
}

func TestHealthServer_Watch(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()

	// Create a mock stream
	stream := &mockWatchStream{
		ctx:       context.Background(),
		responses: make(chan *healthpb.HealthCheckResponse, 10),
	}

	// Start watching in a goroutine
	done := make(chan error, 1)
	go func() {
		done <- hs.Watch(&healthpb.HealthCheckRequest{Service: "test.Service"}, stream)
	}()

	// Wait for initial status
	select {
	case resp := <-stream.responses:
		// Initial status should be SERVICE_UNKNOWN for unregistered service
		assert.Equal(t, healthpb.HealthCheckResponse_SERVICE_UNKNOWN, resp.Status)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for initial status")
	}

	// Update status
	hs.SetServingStatus("test.Service", healthpb.HealthCheckResponse_SERVING)

	// Wait for update
	select {
	case resp := <-stream.responses:
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for status update")
	}

	// Cancel context to stop watching
	stream.cancel()

	// Wait for Watch to return
	select {
	case err := <-done:
		assert.Equal(t, context.Canceled, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for Watch to return")
	}
}

func TestHealthServer_Watch_OverallHealth(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()

	stream := &mockWatchStream{
		ctx:       context.Background(),
		responses: make(chan *healthpb.HealthCheckResponse, 10),
	}

	done := make(chan error, 1)
	go func() {
		done <- hs.Watch(&healthpb.HealthCheckRequest{Service: ""}, stream)
	}()

	// Wait for initial status
	select {
	case resp := <-stream.responses:
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for initial status")
	}

	stream.cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for Watch to return")
	}
}

func TestHealthServer_Concurrency(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	ctx := context.Background()

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = hs.Check(ctx, &healthpb.HealthCheckRequest{Service: ""})
		}()
	}

	// Concurrent writes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			service := "service" + string(rune('0'+i%10))
			hs.SetServingStatus(service, healthpb.HealthCheckResponse_SERVING)
		}(i)
	}

	// Concurrent GetAllStatuses
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = hs.GetAllStatuses()
		}()
	}

	wg.Wait()
}

func TestWithHealthLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	hs := &HealthServer{}

	opt := WithHealthLogger(logger)
	opt(hs)

	assert.NotNil(t, hs.logger)
}

func TestStatusError(t *testing.T) {
	t.Parallel()

	err := statusError(5, "test error: %s", "details")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test error: details")
}

// mockWatchStream implements healthpb.Health_WatchServer for testing
type mockWatchStream struct {
	ctx        context.Context
	cancelFunc context.CancelFunc
	responses  chan *healthpb.HealthCheckResponse
	mu         sync.Mutex
}

func (m *mockWatchStream) Send(resp *healthpb.HealthCheckResponse) error {
	select {
	case m.responses <- resp:
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}

func (m *mockWatchStream) Context() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancelFunc == nil {
		m.ctx, m.cancelFunc = context.WithCancel(m.ctx)
	}
	return m.ctx
}

func (m *mockWatchStream) cancel() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancelFunc != nil {
		m.cancelFunc()
	}
}

func (m *mockWatchStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockWatchStream) SendHeader(_ metadata.MD) error { return nil }
func (m *mockWatchStream) SetTrailer(_ metadata.MD)       {}
func (m *mockWatchStream) SendMsg(_ interface{}) error    { return nil }
func (m *mockWatchStream) RecvMsg(_ interface{}) error    { return nil }
