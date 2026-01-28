package health

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewHealthAggregator(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{
		{Name: "backend1", Address: "localhost:50051", Service: ""},
		{Name: "backend2", Address: "localhost:50052", Service: "test.Service"},
	}

	a := NewHealthAggregator(hs, backends)

	assert.NotNil(t, a)
	assert.Equal(t, hs, a.healthServer)
	assert.Len(t, a.backends, 2)
	assert.Equal(t, 10*time.Second, a.interval)
	assert.Equal(t, 5*time.Second, a.timeout)
	assert.NotNil(t, a.logger)
	assert.NotNil(t, a.stopCh)
	assert.NotNil(t, a.statuses)
}

func TestNewHealthAggregator_WithOptions(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}
	logger := observability.NopLogger()

	a := NewHealthAggregator(hs, backends,
		WithAggregatorLogger(logger),
		WithCheckInterval(30*time.Second),
		WithCheckTimeout(10*time.Second),
	)

	assert.NotNil(t, a)
	assert.Equal(t, 30*time.Second, a.interval)
	assert.Equal(t, 10*time.Second, a.timeout)
}

func TestWithAggregatorLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	a := &HealthAggregator{}

	opt := WithAggregatorLogger(logger)
	opt(a)

	assert.NotNil(t, a.logger)
}

func TestWithCheckInterval(t *testing.T) {
	t.Parallel()

	a := &HealthAggregator{}

	opt := WithCheckInterval(30 * time.Second)
	opt(a)

	assert.Equal(t, 30*time.Second, a.interval)
}

func TestWithCheckTimeout(t *testing.T) {
	t.Parallel()

	a := &HealthAggregator{}

	opt := WithCheckTimeout(10 * time.Second)
	opt(a)

	assert.Equal(t, 10*time.Second, a.timeout)
}

func TestHealthAggregator_StartStop(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}

	a := NewHealthAggregator(hs, backends,
		WithCheckInterval(100*time.Millisecond),
	)

	ctx := context.Background()

	// Start aggregator
	a.Start(ctx)

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Stop aggregator
	a.Stop()
}

func TestHealthAggregator_StartStop_WithBackends(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{
		{Name: "backend1", Address: "localhost:59999", Service: ""},
	}

	a := NewHealthAggregator(hs, backends,
		WithCheckInterval(100*time.Millisecond),
		WithCheckTimeout(50*time.Millisecond),
	)

	ctx := context.Background()

	// Start aggregator
	a.Start(ctx)

	// Wait for at least one check
	time.Sleep(150 * time.Millisecond)

	// Stop aggregator
	a.Stop()

	// Backend should be marked as unhealthy (connection failed)
	health, ok := a.GetBackendHealth("backend1")
	assert.True(t, ok)
	assert.False(t, health.Healthy)
	assert.NotNil(t, health.Error)
}

func TestHealthAggregator_ContextCancellation(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}

	a := NewHealthAggregator(hs, backends,
		WithCheckInterval(100*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())

	// Start aggregator
	a.Start(ctx)

	// Cancel context
	cancel()

	// Wait for goroutine to exit
	time.Sleep(50 * time.Millisecond)

	// Stop should complete quickly
	done := make(chan struct{})
	go func() {
		a.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(time.Second):
		t.Fatal("Stop did not complete in time")
	}
}

func TestHealthAggregator_GetBackendHealth(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}

	a := NewHealthAggregator(hs, backends)

	// No backends yet
	_, ok := a.GetBackendHealth("nonexistent")
	assert.False(t, ok)

	// Add a status manually
	a.mu.Lock()
	a.statuses["backend1"] = &BackendHealth{
		Address:   "localhost:50051",
		Service:   "",
		Healthy:   true,
		LastCheck: time.Now(),
	}
	a.mu.Unlock()

	health, ok := a.GetBackendHealth("backend1")
	assert.True(t, ok)
	assert.True(t, health.Healthy)
	assert.Equal(t, "localhost:50051", health.Address)
}

func TestHealthAggregator_GetAllBackendHealth(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}

	a := NewHealthAggregator(hs, backends)

	// No backends yet
	all := a.GetAllBackendHealth()
	assert.Empty(t, all)

	// Add statuses manually
	a.mu.Lock()
	a.statuses["backend1"] = &BackendHealth{
		Address: "localhost:50051",
		Healthy: true,
	}
	a.statuses["backend2"] = &BackendHealth{
		Address: "localhost:50052",
		Healthy: false,
	}
	a.mu.Unlock()

	all = a.GetAllBackendHealth()
	assert.Len(t, all, 2)
	assert.True(t, all["backend1"].Healthy)
	assert.False(t, all["backend2"].Healthy)
}

func TestHealthAggregator_AddBackend(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}

	a := NewHealthAggregator(hs, backends)

	assert.Len(t, a.backends, 0)

	a.AddBackend(BackendConfig{
		Name:    "backend1",
		Address: "localhost:50051",
		Service: "",
	})

	assert.Len(t, a.backends, 1)
	assert.Equal(t, "backend1", a.backends[0].Name)
}

func TestHealthAggregator_RemoveBackend(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{
		{Name: "backend1", Address: "localhost:50051"},
		{Name: "backend2", Address: "localhost:50052"},
	}

	a := NewHealthAggregator(hs, backends)

	// Add status for backend1
	a.mu.Lock()
	a.statuses["backend1"] = &BackendHealth{Healthy: true}
	a.mu.Unlock()

	assert.Len(t, a.backends, 2)

	a.RemoveBackend("backend1")

	assert.Len(t, a.backends, 1)
	assert.Equal(t, "backend2", a.backends[0].Name)

	// Status should also be removed
	_, ok := a.GetBackendHealth("backend1")
	assert.False(t, ok)
}

func TestHealthAggregator_RemoveBackend_NotFound(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{
		{Name: "backend1", Address: "localhost:50051"},
	}

	a := NewHealthAggregator(hs, backends)

	// Remove non-existent backend - should not panic
	a.RemoveBackend("nonexistent")

	assert.Len(t, a.backends, 1)
}

func TestHealthAggregator_UpdateOverallHealth_AllHealthy(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}

	a := NewHealthAggregator(hs, backends)

	// Add healthy statuses
	a.mu.Lock()
	a.statuses["backend1"] = &BackendHealth{Healthy: true}
	a.statuses["backend2"] = &BackendHealth{Healthy: true}
	a.mu.Unlock()

	a.updateOverallHealth()

	// Overall health should be SERVING
	status, ok := hs.GetServingStatus("")
	require.True(t, ok)
	assert.Equal(t, int32(1), int32(status)) // SERVING = 1
}

func TestHealthAggregator_UpdateOverallHealth_SomeHealthy(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}

	a := NewHealthAggregator(hs, backends)

	// Add mixed statuses
	a.mu.Lock()
	a.statuses["backend1"] = &BackendHealth{Healthy: true}
	a.statuses["backend2"] = &BackendHealth{Healthy: false}
	a.mu.Unlock()

	a.updateOverallHealth()

	// Overall health should be SERVING (at least one healthy)
	status, ok := hs.GetServingStatus("")
	require.True(t, ok)
	assert.Equal(t, int32(1), int32(status)) // SERVING = 1
}

func TestHealthAggregator_UpdateOverallHealth_NoneHealthy(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}

	a := NewHealthAggregator(hs, backends)

	// Add unhealthy statuses
	a.mu.Lock()
	a.statuses["backend1"] = &BackendHealth{Healthy: false}
	a.statuses["backend2"] = &BackendHealth{Healthy: false}
	a.mu.Unlock()

	a.updateOverallHealth()

	// Overall health should be NOT_SERVING
	status, ok := hs.GetServingStatus("")
	require.True(t, ok)
	assert.Equal(t, int32(2), int32(status)) // NOT_SERVING = 2
}

func TestHealthAggregator_UpdateOverallHealth_NoBackends(t *testing.T) {
	t.Parallel()

	hs := NewHealthServer()
	backends := []BackendConfig{}

	a := NewHealthAggregator(hs, backends)

	a.updateOverallHealth()

	// Overall health should be SERVING when no backends
	status, ok := hs.GetServingStatus("")
	require.True(t, ok)
	assert.Equal(t, int32(1), int32(status)) // SERVING = 1
}

func TestBackendHealth_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	err := assert.AnError

	health := &BackendHealth{
		Address:   "localhost:50051",
		Service:   "test.Service",
		Healthy:   true,
		LastCheck: now,
		Error:     err,
	}

	assert.Equal(t, "localhost:50051", health.Address)
	assert.Equal(t, "test.Service", health.Service)
	assert.True(t, health.Healthy)
	assert.Equal(t, now, health.LastCheck)
	assert.Equal(t, err, health.Error)
}

func TestBackendConfig_Fields(t *testing.T) {
	t.Parallel()

	cfg := BackendConfig{
		Name:    "backend1",
		Address: "localhost:50051",
		Service: "test.Service",
	}

	assert.Equal(t, "backend1", cfg.Name)
	assert.Equal(t, "localhost:50051", cfg.Address)
	assert.Equal(t, "test.Service", cfg.Service)
}
