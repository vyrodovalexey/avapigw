package interceptor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestDefaultRetryConfig tests the default retry configuration
func TestDefaultRetryConfig(t *testing.T) {
	t.Parallel()

	config := DefaultRetryConfig()

	assert.NotNil(t, config.Policy)
	assert.Len(t, config.RetryableCodes, 4)
	assert.Contains(t, config.RetryableCodes, codes.Unavailable)
	assert.Contains(t, config.RetryableCodes, codes.ResourceExhausted)
	assert.Contains(t, config.RetryableCodes, codes.Aborted)
	assert.Contains(t, config.RetryableCodes, codes.DeadlineExceeded)
}

// TestUnaryClientRetryInterceptor tests the basic unary client retry interceptor
func TestUnaryClientRetryInterceptor(t *testing.T) {
	t.Parallel()

	policy := retry.DefaultPolicy()
	interceptor := UnaryClientRetryInterceptor(policy)

	t.Run("succeeds on first attempt", func(t *testing.T) {
		callCount := 0
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			callCount++
			return nil
		}

		err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

		assert.NoError(t, err)
		assert.Equal(t, 1, callCount)
	})

	t.Run("retries on retryable error", func(t *testing.T) {
		callCount := 0
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			callCount++
			if callCount < 3 {
				return status.Error(codes.Unavailable, "unavailable")
			}
			return nil
		}

		err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

		assert.NoError(t, err)
		assert.Equal(t, 3, callCount)
	})

	t.Run("does not retry on non-retryable error", func(t *testing.T) {
		callCount := 0
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			callCount++
			return status.Error(codes.InvalidArgument, "invalid argument")
		}

		err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

		assert.Error(t, err)
		assert.Equal(t, 1, callCount)
	})
}

// TestUnaryClientRetryInterceptorWithConfig tests the configurable unary client retry interceptor
func TestUnaryClientRetryInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips retry for configured methods", func(t *testing.T) {
		callCount := 0
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			callCount++
			return status.Error(codes.Unavailable, "unavailable")
		}

		config := RetryConfig{
			Policy:      retry.DefaultPolicy(),
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := UnaryClientRetryInterceptorWithConfig(config)

		err := interceptor(context.Background(), "/test.Service/SkippedMethod", nil, nil, nil, invoker)

		assert.Error(t, err)
		assert.Equal(t, 1, callCount)
	})

	t.Run("uses custom retryable codes", func(t *testing.T) {
		callCount := 0
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			callCount++
			if callCount < 2 {
				return status.Error(codes.NotFound, "not found")
			}
			return nil
		}

		config := RetryConfig{
			Policy:         retry.DefaultPolicy(),
			RetryableCodes: []codes.Code{codes.NotFound},
		}

		interceptor := UnaryClientRetryInterceptorWithConfig(config)

		err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

		assert.NoError(t, err)
		assert.Equal(t, 2, callCount)
	})

	t.Run("respects max retries", func(t *testing.T) {
		callCount := 0
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			callCount++
			return status.Error(codes.Unavailable, "unavailable")
		}

		policy := &retry.Policy{
			MaxRetries:     2,
			InitialBackoff: 1 * time.Millisecond,
			MaxBackoff:     10 * time.Millisecond,
			BackoffFactor:  2.0,
		}

		config := RetryConfig{
			Policy: policy,
		}

		interceptor := UnaryClientRetryInterceptorWithConfig(config)

		err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

		assert.Error(t, err)
		assert.Equal(t, 3, callCount) // Initial + 2 retries
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		callCount := 0
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			callCount++
			return status.Error(codes.Unavailable, "unavailable")
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		config := RetryConfig{
			Policy: retry.DefaultPolicy(),
		}

		interceptor := UnaryClientRetryInterceptorWithConfig(config)

		err := interceptor(ctx, "/test.Service/Method", nil, nil, nil, invoker)

		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("uses default policy when nil", func(t *testing.T) {
		callCount := 0
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			callCount++
			return nil
		}

		config := RetryConfig{
			Policy: nil,
		}

		interceptor := UnaryClientRetryInterceptorWithConfig(config)

		err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

		assert.NoError(t, err)
		assert.Equal(t, 1, callCount)
	})

	t.Run("uses nop logger when nil", func(t *testing.T) {
		callCount := 0
		invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			callCount++
			if callCount < 2 {
				return status.Error(codes.Unavailable, "unavailable")
			}
			return nil
		}

		config := RetryConfig{
			Policy: &retry.Policy{
				MaxRetries:     3,
				InitialBackoff: 1 * time.Millisecond,
				MaxBackoff:     10 * time.Millisecond,
				BackoffFactor:  2.0,
			},
			Logger: nil,
		}

		interceptor := UnaryClientRetryInterceptorWithConfig(config)

		err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

		assert.NoError(t, err)
		assert.Equal(t, 2, callCount)
	})
}

// TestStreamClientRetryInterceptor tests the basic stream client retry interceptor
func TestStreamClientRetryInterceptor(t *testing.T) {
	t.Parallel()

	policy := retry.DefaultPolicy()
	interceptor := StreamClientRetryInterceptor(policy)

	t.Run("succeeds on first attempt", func(t *testing.T) {
		callCount := 0
		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			callCount++
			return nil, nil
		}

		stream, err := interceptor(context.Background(), nil, nil, "/test.Service/Method", streamer)

		assert.NoError(t, err)
		assert.Nil(t, stream)
		assert.Equal(t, 1, callCount)
	})

	t.Run("retries on retryable error", func(t *testing.T) {
		callCount := 0
		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			callCount++
			if callCount < 3 {
				return nil, status.Error(codes.Unavailable, "unavailable")
			}
			return nil, nil
		}

		stream, err := interceptor(context.Background(), nil, nil, "/test.Service/Method", streamer)

		assert.NoError(t, err)
		assert.Nil(t, stream)
		assert.Equal(t, 3, callCount)
	})

	t.Run("does not retry on non-retryable error", func(t *testing.T) {
		callCount := 0
		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			callCount++
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		}

		stream, err := interceptor(context.Background(), nil, nil, "/test.Service/Method", streamer)

		assert.Error(t, err)
		assert.Nil(t, stream)
		assert.Equal(t, 1, callCount)
	})
}

// TestStreamClientRetryInterceptorWithConfig tests the configurable stream client retry interceptor
func TestStreamClientRetryInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips retry for configured methods", func(t *testing.T) {
		callCount := 0
		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			callCount++
			return nil, status.Error(codes.Unavailable, "unavailable")
		}

		config := RetryConfig{
			Policy:      retry.DefaultPolicy(),
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := StreamClientRetryInterceptorWithConfig(config)

		stream, err := interceptor(context.Background(), nil, nil, "/test.Service/SkippedMethod", streamer)

		assert.Error(t, err)
		assert.Nil(t, stream)
		assert.Equal(t, 1, callCount)
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		callCount := 0
		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			callCount++
			return nil, status.Error(codes.Unavailable, "unavailable")
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		config := RetryConfig{
			Policy: retry.DefaultPolicy(),
		}

		interceptor := StreamClientRetryInterceptorWithConfig(config)

		stream, err := interceptor(ctx, nil, nil, "/test.Service/Method", streamer)

		assert.Error(t, err)
		assert.Nil(t, stream)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("uses default retryable codes when empty", func(t *testing.T) {
		callCount := 0
		streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			callCount++
			if callCount < 2 {
				return nil, status.Error(codes.Unavailable, "unavailable")
			}
			return nil, nil
		}

		config := RetryConfig{
			Policy:         retry.DefaultPolicy(),
			RetryableCodes: []codes.Code{}, // Empty
		}

		interceptor := StreamClientRetryInterceptorWithConfig(config)

		stream, err := interceptor(context.Background(), nil, nil, "/test.Service/Method", streamer)

		assert.NoError(t, err)
		assert.Nil(t, stream)
		assert.Equal(t, 2, callCount)
	})
}

// TestRetryConfig tests RetryConfig struct
func TestRetryConfig(t *testing.T) {
	t.Parallel()

	t.Run("default values", func(t *testing.T) {
		config := RetryConfig{}

		assert.Nil(t, config.Policy)
		assert.Nil(t, config.Logger)
		assert.Nil(t, config.SkipMethods)
		assert.Nil(t, config.RetryableCodes)
	})

	t.Run("with all fields", func(t *testing.T) {
		policy := retry.DefaultPolicy()
		logger := zap.NewNop()

		config := RetryConfig{
			Policy:         policy,
			Logger:         logger,
			SkipMethods:    []string{"/test.Service/Method"},
			RetryableCodes: []codes.Code{codes.Unavailable},
		}

		assert.NotNil(t, config.Policy)
		assert.NotNil(t, config.Logger)
		assert.Len(t, config.SkipMethods, 1)
		assert.Len(t, config.RetryableCodes, 1)
	})
}

// TestRetryWithBackoff tests retry with backoff timing
func TestRetryWithBackoff(t *testing.T) {
	t.Parallel()

	callCount := 0
	callTimes := make([]time.Time, 0)

	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		callCount++
		callTimes = append(callTimes, time.Now())
		if callCount < 3 {
			return status.Error(codes.Unavailable, "unavailable")
		}
		return nil
	}

	policy := &retry.Policy{
		MaxRetries:     3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
		BackoffFactor:  2.0,
		Jitter:         0, // No jitter for predictable timing
	}

	config := RetryConfig{
		Policy: policy,
	}

	interceptor := UnaryClientRetryInterceptorWithConfig(config)

	err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

	assert.NoError(t, err)
	assert.Equal(t, 3, callCount)
	require.Len(t, callTimes, 3)

	// Verify backoff timing (with some tolerance)
	if len(callTimes) >= 2 {
		firstBackoff := callTimes[1].Sub(callTimes[0])
		assert.GreaterOrEqual(t, firstBackoff, 5*time.Millisecond)
	}
}

// TestRetryExhaustsAllAttempts tests that retry exhausts all attempts
func TestRetryExhaustsAllAttempts(t *testing.T) {
	t.Parallel()

	callCount := 0
	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		callCount++
		return status.Error(codes.Unavailable, "always unavailable")
	}

	policy := &retry.Policy{
		MaxRetries:     5,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		BackoffFactor:  2.0,
	}

	config := RetryConfig{
		Policy: policy,
	}

	interceptor := UnaryClientRetryInterceptorWithConfig(config)

	err := interceptor(context.Background(), "/test.Service/Method", nil, nil, nil, invoker)

	assert.Error(t, err)
	assert.Equal(t, 6, callCount) // Initial + 5 retries
}
