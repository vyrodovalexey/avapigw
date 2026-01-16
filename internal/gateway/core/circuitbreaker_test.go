package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/circuitbreaker"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewCircuitBreakerCore(t *testing.T) {
	t.Parallel()

	t.Run("creates with default registry when nil", func(t *testing.T) {
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{})

		assert.NotNil(t, core)
		assert.NotNil(t, core.registry)
	})

	t.Run("creates with provided registry", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)

		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			Registry: registry,
		})

		assert.NotNil(t, core)
		assert.Equal(t, registry, core.registry)
	})

	t.Run("initializes skip paths", func(t *testing.T) {
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			BaseConfig: BaseConfig{
				SkipPaths: []string{"/health", "/ready"},
			},
		})

		assert.True(t, core.ShouldSkip("/health"))
		assert.True(t, core.ShouldSkip("/ready"))
		assert.False(t, core.ShouldSkip("/api/v1/users"))
	})
}

func TestCircuitBreakerCore_Allow(t *testing.T) {
	t.Parallel()

	t.Run("allows when circuit is closed", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			Registry: registry,
		})

		allowed := core.Allow("test-service")

		assert.True(t, allowed)
	})

	t.Run("denies when circuit is open", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			Registry: registry,
		})

		// Open the circuit by recording failures
		cb := registry.GetOrCreate("test-service")
		for i := 0; i < 10; i++ {
			cb.RecordFailure()
		}

		allowed := core.Allow("test-service")

		assert.False(t, allowed)
	})

	t.Run("applies name function", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			Registry: registry,
			NameFunc: func(identifier string) string {
				return "prefix:" + identifier
			},
		})

		core.Allow("test-service")

		// Verify the circuit breaker was created with the prefixed name
		cb := registry.Get("prefix:test-service")
		assert.NotNil(t, cb)
	})
}

func TestCircuitBreakerCore_Execute(t *testing.T) {
	t.Parallel()

	t.Run("executes function when circuit is closed", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			Registry: registry,
		})

		executed := false
		err := core.Execute(context.Background(), "test-service", func() error {
			executed = true
			return nil
		})

		assert.NoError(t, err)
		assert.True(t, executed)
	})

	t.Run("returns error when circuit is open", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			Registry: registry,
		})

		// Open the circuit
		cb := registry.GetOrCreate("test-service")
		for i := 0; i < 10; i++ {
			cb.RecordFailure()
		}

		err := core.Execute(context.Background(), "test-service", func() error {
			return nil
		})

		assert.Error(t, err)
		assert.True(t, errors.Is(err, circuitbreaker.ErrCircuitOpen))
	})
}

func TestCircuitBreakerCore_RecordResult(t *testing.T) {
	t.Parallel()

	t.Run("records success for nil error", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			Registry: registry,
		})

		core.Allow("test-service") // Create the circuit breaker
		core.RecordResult("test-service", nil)

		cb := registry.Get("test-service")
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes)
	})

	t.Run("records failure for failure error", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			Registry: registry,
		})

		core.Allow("test-service") // Create the circuit breaker
		core.RecordResult("test-service", status.Error(codes.Unavailable, "unavailable"))

		cb := registry.Get("test-service")
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Failures)
	})

	t.Run("records success for non-failure error", func(t *testing.T) {
		registry := circuitbreaker.NewRegistry(nil, nil)
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			Registry: registry,
		})

		core.Allow("test-service") // Create the circuit breaker
		core.RecordResult("test-service", status.Error(codes.NotFound, "not found"))

		cb := registry.Get("test-service")
		stats := cb.Stats()
		assert.Equal(t, 1, stats.Successes)
	})
}

func TestCircuitBreakerCore_IsFailure(t *testing.T) {
	t.Parallel()

	core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{})

	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"circuit open error", circuitbreaker.ErrCircuitOpen, false},
		{"too many requests error", circuitbreaker.ErrTooManyRequests, false},
		{"unavailable gRPC error", status.Error(codes.Unavailable, "unavailable"), true},
		{"resource exhausted gRPC error", status.Error(codes.ResourceExhausted, "exhausted"), true},
		{"internal gRPC error", status.Error(codes.Internal, "internal"), true},
		{"unknown gRPC error", status.Error(codes.Unknown, "unknown"), true},
		{"deadline exceeded gRPC error", status.Error(codes.DeadlineExceeded, "timeout"), true},
		{"not found gRPC error", status.Error(codes.NotFound, "not found"), false},
		{"invalid argument gRPC error", status.Error(codes.InvalidArgument, "invalid"), false},
		{"generic error", errors.New("generic error"), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := core.IsFailure(tc.err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestCircuitBreakerCore_IsHTTPFailure(t *testing.T) {
	t.Parallel()

	core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{})

	testCases := []struct {
		statusCode int
		expected   bool
	}{
		{200, false},
		{201, false},
		{400, false},
		{401, false},
		{403, false},
		{404, false},
		{500, true},
		{501, true},
		{502, true},
		{503, true},
	}

	for _, tc := range testCases {
		result := core.IsHTTPFailure(tc.statusCode)
		assert.Equal(t, tc.expected, result, "status code %d", tc.statusCode)
	}
}

func TestCircuitBreakerCore_ShouldSkip(t *testing.T) {
	t.Parallel()

	t.Run("returns false when no skip paths", func(t *testing.T) {
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{})

		assert.False(t, core.ShouldSkip("/any/path"))
	})

	t.Run("returns true for skip paths", func(t *testing.T) {
		core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
			BaseConfig: BaseConfig{
				SkipPaths: []string{"/health", "/ready"},
			},
		})

		assert.True(t, core.ShouldSkip("/health"))
		assert.True(t, core.ShouldSkip("/ready"))
		assert.False(t, core.ShouldSkip("/api"))
	})
}

func TestCircuitBreakerCore_GetCircuitBreaker(t *testing.T) {
	t.Parallel()

	registry := circuitbreaker.NewRegistry(nil, nil)
	core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
		Registry: registry,
	})

	cb := core.GetCircuitBreaker("test-service")

	assert.NotNil(t, cb)
	assert.Equal(t, "test-service", cb.Name())
}

func TestCircuitBreakerCore_Registry(t *testing.T) {
	t.Parallel()

	registry := circuitbreaker.NewRegistry(nil, nil)
	core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
		Registry: registry,
	})

	assert.Equal(t, registry, core.Registry())
}

func TestCircuitBreakerCore_WithLogger(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	core := NewCircuitBreakerCore(CircuitBreakerCoreConfig{
		BaseConfig: BaseConfig{
			Logger: logger,
		},
	})

	// Just ensure it doesn't panic when logging
	core.Allow("test-service")
}
