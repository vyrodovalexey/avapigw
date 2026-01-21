package util

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContextWithRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		requestID string
	}{
		{
			name:      "valid request ID",
			requestID: "test-request-123",
		},
		{
			name:      "empty request ID",
			requestID: "",
		},
		{
			name:      "UUID format",
			requestID: "550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctx = ContextWithRequestID(ctx, tt.requestID)

			result := RequestIDFromContext(ctx)
			assert.Equal(t, tt.requestID, result)
		})
	}
}

func TestRequestIDFromContext_NotSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	result := RequestIDFromContext(ctx)
	assert.Empty(t, result)
}

func TestContextWithTraceID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		traceID string
	}{
		{
			name:    "valid trace ID",
			traceID: "trace-abc-123",
		},
		{
			name:    "empty trace ID",
			traceID: "",
		},
		{
			name:    "hex format",
			traceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctx = ContextWithTraceID(ctx, tt.traceID)

			result := TraceIDFromContext(ctx)
			assert.Equal(t, tt.traceID, result)
		})
	}
}

func TestTraceIDFromContext_NotSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	result := TraceIDFromContext(ctx)
	assert.Empty(t, result)
}

func TestContextWithSpanID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		spanID string
	}{
		{
			name:   "valid span ID",
			spanID: "span-xyz-789",
		},
		{
			name:   "empty span ID",
			spanID: "",
		},
		{
			name:   "hex format",
			spanID: "00f067aa0ba902b7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctx = ContextWithSpanID(ctx, tt.spanID)

			result := SpanIDFromContext(ctx)
			assert.Equal(t, tt.spanID, result)
		})
	}
}

func TestSpanIDFromContext_NotSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	result := SpanIDFromContext(ctx)
	assert.Empty(t, result)
}

func TestContextWithStartTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		startTime time.Time
	}{
		{
			name:      "current time",
			startTime: time.Now(),
		},
		{
			name:      "past time",
			startTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:      "zero time",
			startTime: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctx = ContextWithStartTime(ctx, tt.startTime)

			result := StartTimeFromContext(ctx)
			assert.Equal(t, tt.startTime, result)
		})
	}
}

func TestStartTimeFromContext_NotSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	result := StartTimeFromContext(ctx)
	assert.True(t, result.IsZero())
}

func TestContextWithRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		route string
	}{
		{
			name:  "valid route",
			route: "api-v1-users",
		},
		{
			name:  "empty route",
			route: "",
		},
		{
			name:  "route with special chars",
			route: "api/v1/users/{id}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctx = ContextWithRoute(ctx, tt.route)

			result := RouteFromContext(ctx)
			assert.Equal(t, tt.route, result)
		})
	}
}

func TestRouteFromContext_NotSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	result := RouteFromContext(ctx)
	assert.Empty(t, result)
}

func TestContextWithBackend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		backend string
	}{
		{
			name:    "valid backend",
			backend: "user-service",
		},
		{
			name:    "empty backend",
			backend: "",
		},
		{
			name:    "backend with port",
			backend: "user-service:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctx = ContextWithBackend(ctx, tt.backend)

			result := BackendFromContext(ctx)
			assert.Equal(t, tt.backend, result)
		})
	}
}

func TestBackendFromContext_NotSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	result := BackendFromContext(ctx)
	assert.Empty(t, result)
}

func TestContextWithPathParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params map[string]string
	}{
		{
			name:   "single param",
			params: map[string]string{"id": "123"},
		},
		{
			name:   "multiple params",
			params: map[string]string{"id": "123", "name": "test"},
		},
		{
			name:   "empty params",
			params: map[string]string{},
		},
		{
			name:   "nil params",
			params: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			ctx = ContextWithPathParams(ctx, tt.params)

			result := PathParamsFromContext(ctx)
			assert.Equal(t, tt.params, result)
		})
	}
}

func TestPathParamsFromContext_NotSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	result := PathParamsFromContext(ctx)
	assert.Nil(t, result)
}

func TestNewTimeoutContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	timeout := 100 * time.Millisecond

	timeoutCtx, cancel := NewTimeoutContext(ctx, timeout)
	defer cancel()

	require.NotNil(t, timeoutCtx)
	require.NotNil(t, cancel)

	deadline, ok := timeoutCtx.Deadline()
	assert.True(t, ok)
	assert.True(t, deadline.After(time.Now()))
}

func TestNewDeadlineContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	deadline := time.Now().Add(100 * time.Millisecond)

	deadlineCtx, cancel := NewDeadlineContext(ctx, deadline)
	defer cancel()

	require.NotNil(t, deadlineCtx)
	require.NotNil(t, cancel)

	ctxDeadline, ok := deadlineCtx.Deadline()
	assert.True(t, ok)
	assert.Equal(t, deadline, ctxDeadline)
}

func TestElapsedTime(t *testing.T) {
	t.Parallel()

	t.Run("with start time set", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		startTime := time.Now().Add(-100 * time.Millisecond)
		ctx = ContextWithStartTime(ctx, startTime)

		elapsed := ElapsedTime(ctx)
		assert.True(t, elapsed >= 100*time.Millisecond)
	})

	t.Run("without start time", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		elapsed := ElapsedTime(ctx)
		assert.Equal(t, time.Duration(0), elapsed)
	})

	t.Run("with zero start time", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		ctx = ContextWithStartTime(ctx, time.Time{})
		elapsed := ElapsedTime(ctx)
		assert.Equal(t, time.Duration(0), elapsed)
	})
}

func TestContextChaining(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = ContextWithRequestID(ctx, "req-123")
	ctx = ContextWithTraceID(ctx, "trace-456")
	ctx = ContextWithSpanID(ctx, "span-789")
	ctx = ContextWithRoute(ctx, "test-route")
	ctx = ContextWithBackend(ctx, "test-backend")
	ctx = ContextWithPathParams(ctx, map[string]string{"id": "100"})
	ctx = ContextWithStartTime(ctx, time.Now())

	assert.Equal(t, "req-123", RequestIDFromContext(ctx))
	assert.Equal(t, "trace-456", TraceIDFromContext(ctx))
	assert.Equal(t, "span-789", SpanIDFromContext(ctx))
	assert.Equal(t, "test-route", RouteFromContext(ctx))
	assert.Equal(t, "test-backend", BackendFromContext(ctx))
	assert.Equal(t, map[string]string{"id": "100"}, PathParamsFromContext(ctx))
	assert.False(t, StartTimeFromContext(ctx).IsZero())
}
