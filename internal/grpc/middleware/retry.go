package middleware

import (
	"context"
	"math"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// RetryConfig contains retry configuration.
type RetryConfig struct {
	MaxAttempts         int
	PerTryTimeout       time.Duration
	RetryOn             []codes.Code
	BackoffBaseInterval time.Duration
	BackoffMaxInterval  time.Duration
}

// DefaultRetryConfig returns default retry configuration.
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:         3,
		PerTryTimeout:       10 * time.Second,
		RetryOn:             []codes.Code{codes.Unavailable, codes.ResourceExhausted},
		BackoffBaseInterval: 100 * time.Millisecond,
		BackoffMaxInterval:  1 * time.Second,
	}
}

// ParseRetryOn parses a comma-separated list of gRPC status codes.
func ParseRetryOn(retryOn string) []codes.Code {
	if retryOn == "" {
		return []codes.Code{codes.Unavailable, codes.ResourceExhausted}
	}

	codeMap := map[string]codes.Code{
		"cancelled":          codes.Canceled,
		"deadline-exceeded":  codes.DeadlineExceeded,
		"internal":           codes.Internal,
		"resource-exhausted": codes.ResourceExhausted,
		"unavailable":        codes.Unavailable,
		"unknown":            codes.Unknown,
		"aborted":            codes.Aborted,
		"data-loss":          codes.DataLoss,
	}

	var result []codes.Code
	parts := strings.Split(retryOn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if code, ok := codeMap[part]; ok {
			result = append(result, code)
		}
	}

	if len(result) == 0 {
		return []codes.Code{codes.Unavailable, codes.ResourceExhausted}
	}

	return result
}

// shouldRetry checks if the error should be retried.
func shouldRetry(err error, retryOn []codes.Code) bool {
	if err == nil {
		return false
	}

	code := status.Code(err)
	for _, c := range retryOn {
		if code == c {
			return true
		}
	}

	return false
}

// calculateBackoff calculates the backoff duration for a retry attempt.
func calculateBackoff(attempt int, baseInterval, maxInterval time.Duration) time.Duration {
	// Exponential backoff: base * 2^attempt
	backoff := float64(baseInterval) * math.Pow(2, float64(attempt))
	if backoff > float64(maxInterval) {
		backoff = float64(maxInterval)
	}
	return time.Duration(backoff)
}

// UnaryRetryInterceptor returns a unary client interceptor that retries failed requests.
// Note: This is a CLIENT interceptor, not a server interceptor.
func UnaryRetryInterceptor(cfg *RetryConfig, logger observability.Logger) grpc.UnaryClientInterceptor {
	if cfg == nil {
		cfg = DefaultRetryConfig()
	}

	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		return executeUnaryWithRetry(ctx, method, req, reply, cc, invoker, cfg, logger, opts...)
	}
}

// executeUnaryWithRetry executes a unary RPC with retry logic.
func executeUnaryWithRetry(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	cfg *RetryConfig,
	logger observability.Logger,
	opts ...grpc.CallOption,
) error {
	var lastErr error

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		err := executeUnaryAttempt(ctx, method, req, reply, cc, invoker, cfg, opts...)
		if err == nil {
			return nil
		}

		lastErr = err

		if !shouldRetry(err, cfg.RetryOn) || ctx.Err() != nil {
			return lastErr
		}

		if attempt == cfg.MaxAttempts-1 {
			break
		}

		if !waitForBackoff(ctx, attempt, cfg, logger, method, err) {
			return lastErr
		}
	}

	return lastErr
}

// executeUnaryAttempt executes a single unary RPC attempt.
func executeUnaryAttempt(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	cfg *RetryConfig,
	opts ...grpc.CallOption,
) error {
	tryCtx := ctx
	if cfg.PerTryTimeout > 0 {
		var cancel context.CancelFunc
		tryCtx, cancel = context.WithTimeout(ctx, cfg.PerTryTimeout)
		defer cancel()
	}
	return invoker(tryCtx, method, req, reply, cc, opts...)
}

// waitForBackoff waits for the backoff duration before retrying.
func waitForBackoff(
	ctx context.Context,
	attempt int,
	cfg *RetryConfig,
	logger observability.Logger,
	method string,
	err error,
) bool {
	backoff := calculateBackoff(attempt, cfg.BackoffBaseInterval, cfg.BackoffMaxInterval)

	logger.Debug("retrying gRPC request",
		observability.String("method", method),
		observability.Int("attempt", attempt+1),
		observability.Duration("backoff", backoff),
		observability.Error(err),
	)

	select {
	case <-time.After(backoff):
		return true
	case <-ctx.Done():
		return false
	}
}

// StreamRetryInterceptor returns a stream client interceptor.
// Note: Stream retries are more complex and typically not recommended.
// This implementation only retries the initial stream creation.
func StreamRetryInterceptor(cfg *RetryConfig, logger observability.Logger) grpc.StreamClientInterceptor {
	if cfg == nil {
		cfg = DefaultRetryConfig()
	}

	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		return executeStreamWithRetry(ctx, desc, cc, method, streamer, cfg, logger, opts...)
	}
}

// executeStreamWithRetry executes stream creation with retry logic.
func executeStreamWithRetry(
	ctx context.Context,
	desc *grpc.StreamDesc,
	cc *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	cfg *RetryConfig,
	logger observability.Logger,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	var lastErr error

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		stream, err := executeStreamAttempt(ctx, desc, cc, method, streamer, cfg, opts...)
		if err == nil {
			return stream, nil
		}

		lastErr = err

		if !shouldRetry(err, cfg.RetryOn) || ctx.Err() != nil {
			return nil, lastErr
		}

		if attempt == cfg.MaxAttempts-1 {
			break
		}

		if !waitForStreamBackoff(ctx, attempt, cfg, logger, method, err) {
			return nil, lastErr
		}
	}

	return nil, lastErr
}

// executeStreamAttempt executes a single stream creation attempt.
func executeStreamAttempt(
	ctx context.Context,
	desc *grpc.StreamDesc,
	cc *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	cfg *RetryConfig,
	opts ...grpc.CallOption,
) (grpc.ClientStream, error) {
	tryCtx := ctx
	if cfg.PerTryTimeout > 0 {
		var cancel context.CancelFunc
		tryCtx, cancel = context.WithTimeout(ctx, cfg.PerTryTimeout)
		defer cancel()
	}
	return streamer(tryCtx, desc, cc, method, opts...)
}

// waitForStreamBackoff waits for the backoff duration before retrying stream creation.
func waitForStreamBackoff(
	ctx context.Context,
	attempt int,
	cfg *RetryConfig,
	logger observability.Logger,
	method string,
	err error,
) bool {
	backoff := calculateBackoff(attempt, cfg.BackoffBaseInterval, cfg.BackoffMaxInterval)

	logger.Debug("retrying gRPC stream creation",
		observability.String("method", method),
		observability.Int("attempt", attempt+1),
		observability.Duration("backoff", backoff),
		observability.Error(err),
	)

	select {
	case <-time.After(backoff):
		return true
	case <-ctx.Done():
		return false
	}
}
