package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestDefaultRetryConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultRetryConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, 10*time.Second, cfg.PerTryTimeout)
	assert.Contains(t, cfg.RetryOn, codes.Unavailable)
	assert.Contains(t, cfg.RetryOn, codes.ResourceExhausted)
	assert.Equal(t, 100*time.Millisecond, cfg.BackoffBaseInterval)
	assert.Equal(t, 1*time.Second, cfg.BackoffMaxInterval)
}

func TestParseRetryOn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []codes.Code
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []codes.Code{codes.Unavailable, codes.ResourceExhausted},
		},
		{
			name:     "single code",
			input:    "unavailable",
			expected: []codes.Code{codes.Unavailable},
		},
		{
			name:     "multiple codes",
			input:    "unavailable,resource-exhausted,internal",
			expected: []codes.Code{codes.Unavailable, codes.ResourceExhausted, codes.Internal},
		},
		{
			name:     "with spaces",
			input:    "unavailable, resource-exhausted, internal",
			expected: []codes.Code{codes.Unavailable, codes.ResourceExhausted, codes.Internal},
		},
		{
			name:     "uppercase",
			input:    "UNAVAILABLE,INTERNAL",
			expected: []codes.Code{codes.Unavailable, codes.Internal},
		},
		{
			name:     "all codes",
			input:    "cancelled,deadline-exceeded,internal,resource-exhausted,unavailable,unknown,aborted,data-loss",
			expected: []codes.Code{codes.Canceled, codes.DeadlineExceeded, codes.Internal, codes.ResourceExhausted, codes.Unavailable, codes.Unknown, codes.Aborted, codes.DataLoss},
		},
		{
			name:     "invalid codes",
			input:    "invalid,unknown-code",
			expected: []codes.Code{codes.Unavailable, codes.ResourceExhausted},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ParseRetryOn(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShouldRetry(t *testing.T) {
	t.Parallel()

	retryOn := []codes.Code{codes.Unavailable, codes.ResourceExhausted}

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "retryable code",
			err:      status.Error(codes.Unavailable, "unavailable"),
			expected: true,
		},
		{
			name:     "another retryable code",
			err:      status.Error(codes.ResourceExhausted, "exhausted"),
			expected: true,
		},
		{
			name:     "non-retryable code",
			err:      status.Error(codes.Internal, "internal"),
			expected: false,
		},
		{
			name:     "not found",
			err:      status.Error(codes.NotFound, "not found"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := shouldRetry(tt.err, retryOn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateBackoff(t *testing.T) {
	t.Parallel()

	baseInterval := 100 * time.Millisecond
	maxInterval := 1 * time.Second

	tests := []struct {
		name     string
		attempt  int
		expected time.Duration
	}{
		{
			name:     "first attempt",
			attempt:  0,
			expected: 100 * time.Millisecond,
		},
		{
			name:     "second attempt",
			attempt:  1,
			expected: 200 * time.Millisecond,
		},
		{
			name:     "third attempt",
			attempt:  2,
			expected: 400 * time.Millisecond,
		},
		{
			name:     "fourth attempt",
			attempt:  3,
			expected: 800 * time.Millisecond,
		},
		{
			name:     "capped at max",
			attempt:  10,
			expected: 1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := calculateBackoff(tt.attempt, baseInterval, maxInterval)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUnaryRetryInterceptor_Success(t *testing.T) {
	t.Parallel()

	cfg := DefaultRetryConfig()
	logger := observability.NopLogger()
	interceptor := UnaryRetryInterceptor(cfg, logger)

	ctx := context.Background()
	callCount := 0

	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		callCount++
		return nil
	}

	err := interceptor(ctx, "/test.Service/Method", "request", nil, nil, invoker)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestUnaryRetryInterceptor_RetryOnError(t *testing.T) {
	t.Parallel()

	cfg := &RetryConfig{
		MaxAttempts:         3,
		PerTryTimeout:       1 * time.Second,
		RetryOn:             []codes.Code{codes.Unavailable},
		BackoffBaseInterval: 10 * time.Millisecond,
		BackoffMaxInterval:  100 * time.Millisecond,
	}
	logger := observability.NopLogger()
	interceptor := UnaryRetryInterceptor(cfg, logger)

	ctx := context.Background()
	callCount := 0

	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		callCount++
		if callCount < 3 {
			return status.Error(codes.Unavailable, "unavailable")
		}
		return nil
	}

	err := interceptor(ctx, "/test.Service/Method", "request", nil, nil, invoker)
	require.NoError(t, err)
	assert.Equal(t, 3, callCount)
}

func TestUnaryRetryInterceptor_MaxAttemptsExceeded(t *testing.T) {
	t.Parallel()

	cfg := &RetryConfig{
		MaxAttempts:         3,
		PerTryTimeout:       1 * time.Second,
		RetryOn:             []codes.Code{codes.Unavailable},
		BackoffBaseInterval: 10 * time.Millisecond,
		BackoffMaxInterval:  100 * time.Millisecond,
	}
	logger := observability.NopLogger()
	interceptor := UnaryRetryInterceptor(cfg, logger)

	ctx := context.Background()
	callCount := 0

	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		callCount++
		return status.Error(codes.Unavailable, "unavailable")
	}

	err := interceptor(ctx, "/test.Service/Method", "request", nil, nil, invoker)
	assert.Error(t, err)
	assert.Equal(t, 3, callCount)
}

func TestUnaryRetryInterceptor_NonRetryableError(t *testing.T) {
	t.Parallel()

	cfg := &RetryConfig{
		MaxAttempts:         3,
		PerTryTimeout:       1 * time.Second,
		RetryOn:             []codes.Code{codes.Unavailable},
		BackoffBaseInterval: 10 * time.Millisecond,
		BackoffMaxInterval:  100 * time.Millisecond,
	}
	logger := observability.NopLogger()
	interceptor := UnaryRetryInterceptor(cfg, logger)

	ctx := context.Background()
	callCount := 0

	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		callCount++
		return status.Error(codes.Internal, "internal error")
	}

	err := interceptor(ctx, "/test.Service/Method", "request", nil, nil, invoker)
	assert.Error(t, err)
	assert.Equal(t, 1, callCount) // Should not retry
}

func TestUnaryRetryInterceptor_NilConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := UnaryRetryInterceptor(nil, logger)

	ctx := context.Background()
	callCount := 0

	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		callCount++
		return nil
	}

	err := interceptor(ctx, "/test.Service/Method", "request", nil, nil, invoker)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)
}

func TestUnaryRetryInterceptor_ContextCanceled(t *testing.T) {
	t.Parallel()

	cfg := &RetryConfig{
		MaxAttempts:         3,
		PerTryTimeout:       1 * time.Second,
		RetryOn:             []codes.Code{codes.Unavailable},
		BackoffBaseInterval: 100 * time.Millisecond,
		BackoffMaxInterval:  1 * time.Second,
	}
	logger := observability.NopLogger()
	interceptor := UnaryRetryInterceptor(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	callCount := 0

	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		callCount++
		cancel() // Cancel after first call
		return status.Error(codes.Unavailable, "unavailable")
	}

	err := interceptor(ctx, "/test.Service/Method", "request", nil, nil, invoker)
	assert.Error(t, err)
	assert.Equal(t, 1, callCount)
}

func TestStreamRetryInterceptor_Success(t *testing.T) {
	t.Parallel()

	cfg := DefaultRetryConfig()
	logger := observability.NopLogger()
	interceptor := StreamRetryInterceptor(cfg, logger)

	ctx := context.Background()
	callCount := 0

	streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		callCount++
		return &mockClientStream{}, nil
	}

	stream, err := interceptor(ctx, nil, nil, "/test.Service/StreamMethod", streamer)
	require.NoError(t, err)
	assert.NotNil(t, stream)
	assert.Equal(t, 1, callCount)
}

func TestStreamRetryInterceptor_RetryOnError(t *testing.T) {
	t.Parallel()

	cfg := &RetryConfig{
		MaxAttempts:         3,
		PerTryTimeout:       1 * time.Second,
		RetryOn:             []codes.Code{codes.Unavailable},
		BackoffBaseInterval: 10 * time.Millisecond,
		BackoffMaxInterval:  100 * time.Millisecond,
	}
	logger := observability.NopLogger()
	interceptor := StreamRetryInterceptor(cfg, logger)

	ctx := context.Background()
	callCount := 0

	streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		callCount++
		if callCount < 3 {
			return nil, status.Error(codes.Unavailable, "unavailable")
		}
		return &mockClientStream{}, nil
	}

	stream, err := interceptor(ctx, nil, nil, "/test.Service/StreamMethod", streamer)
	require.NoError(t, err)
	assert.NotNil(t, stream)
	assert.Equal(t, 3, callCount)
}

func TestStreamRetryInterceptor_NilConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	interceptor := StreamRetryInterceptor(nil, logger)

	ctx := context.Background()
	callCount := 0

	streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		callCount++
		return &mockClientStream{}, nil
	}

	stream, err := interceptor(ctx, nil, nil, "/test.Service/StreamMethod", streamer)
	require.NoError(t, err)
	assert.NotNil(t, stream)
	assert.Equal(t, 1, callCount)
}

// mockClientStream implements grpc.ClientStream for testing
type mockClientStream struct{}

func (m *mockClientStream) Header() (metadata.MD, error) { return nil, nil }
func (m *mockClientStream) Trailer() metadata.MD         { return nil }
func (m *mockClientStream) CloseSend() error             { return nil }
func (m *mockClientStream) Context() context.Context     { return context.Background() }
func (m *mockClientStream) SendMsg(_ interface{}) error  { return nil }
func (m *mockClientStream) RecvMsg(_ interface{}) error  { return nil }
