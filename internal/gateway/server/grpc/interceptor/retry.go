package interceptor

import (
	"context"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/retry"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RetryConfig holds configuration for the retry interceptor.
type RetryConfig struct {
	// Policy is the retry policy to use.
	Policy *retry.Policy

	// Logger for logging retry events.
	Logger *zap.Logger

	// SkipMethods is a list of methods to skip retry.
	SkipMethods []string

	// RetryableCodes is a list of gRPC codes that trigger retry.
	RetryableCodes []codes.Code
}

// DefaultRetryConfig returns a RetryConfig with default values.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		Policy: retry.DefaultPolicy(),
		RetryableCodes: []codes.Code{
			codes.Unavailable,
			codes.ResourceExhausted,
			codes.Aborted,
			codes.DeadlineExceeded,
		},
	}
}

// UnaryClientRetryInterceptor returns a unary client interceptor that applies retry logic.
func UnaryClientRetryInterceptor(policy *retry.Policy) grpc.UnaryClientInterceptor {
	return UnaryClientRetryInterceptorWithConfig(RetryConfig{Policy: policy})
}

// UnaryClientRetryInterceptorWithConfig returns a unary client retry interceptor with custom configuration.
func UnaryClientRetryInterceptorWithConfig(config RetryConfig) grpc.UnaryClientInterceptor {
	config = normalizeRetryConfig(config)
	skipMethods, retryableCodes := buildRetryMaps(config)

	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if skipMethods[method] {
			return invoker(ctx, method, req, reply, cc, opts...)
		}

		return executeUnaryWithRetry(ctx, method, req, reply, cc, invoker, opts, config, retryableCodes)
	}
}

// normalizeRetryConfig ensures config has all required defaults.
func normalizeRetryConfig(config RetryConfig) RetryConfig {
	if config.Policy == nil {
		config.Policy = retry.DefaultPolicy()
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if len(config.RetryableCodes) == 0 {
		config.RetryableCodes = []codes.Code{
			codes.Unavailable,
			codes.ResourceExhausted,
			codes.Aborted,
			codes.DeadlineExceeded,
		}
	}
	return config
}

// buildRetryMaps creates lookup maps for skip methods and retryable codes.
func buildRetryMaps(config RetryConfig) (skipMethods map[string]bool, retryableCodes map[codes.Code]bool) {
	skipMethods = make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	retryableCodes = make(map[codes.Code]bool)
	for _, code := range config.RetryableCodes {
		retryableCodes[code] = true
	}

	return skipMethods, retryableCodes
}

// executeUnaryWithRetry executes a unary call with retry logic.
func executeUnaryWithRetry(
	ctx context.Context,
	method string,
	req, reply interface{},
	cc *grpc.ClientConn,
	invoker grpc.UnaryInvoker,
	opts []grpc.CallOption,
	config RetryConfig,
	retryableCodes map[codes.Code]bool,
) error {
	backoff := retry.NewExponentialBackoff(
		config.Policy.InitialBackoff,
		config.Policy.MaxBackoff,
		config.Policy.BackoffFactor,
		config.Policy.Jitter,
	)

	var lastErr error
	for attempt := 0; attempt <= config.Policy.MaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := invoker(ctx, method, req, reply, cc, opts...)
		if err == nil {
			return nil
		}

		lastErr = err
		if !isRetryableGRPCError(err, retryableCodes) {
			return err
		}

		if attempt >= config.Policy.MaxRetries {
			break
		}

		retryErr := waitForGRPCRetry(
			ctx, backoff, config.Logger, method, attempt, config.Policy.MaxRetries, lastErr)
		if retryErr != nil {
			return err
		}
	}

	return lastErr
}

// isRetryableGRPCError checks if the error is retryable based on gRPC status code.
func isRetryableGRPCError(err error, retryableCodes map[codes.Code]bool) bool {
	st, ok := status.FromError(err)
	return ok && retryableCodes[st.Code()]
}

// waitForGRPCRetry waits before the next retry attempt.
func waitForGRPCRetry(
	ctx context.Context,
	backoff *retry.ExponentialBackoff,
	logger *zap.Logger,
	method string,
	attempt, maxRetries int,
	err error,
) error {
	waitDuration := backoff.Next(attempt)

	logger.Debug("retrying gRPC call",
		zap.String("method", method),
		zap.Int("attempt", attempt+1),
		zap.Int("max_retries", maxRetries),
		zap.Duration("wait", waitDuration),
		zap.Error(err),
	)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(waitDuration):
		return nil
	}
}

// StreamClientRetryInterceptor returns a stream client interceptor that applies retry logic.
// Note: Stream retry is limited - only the initial connection can be retried.
func StreamClientRetryInterceptor(policy *retry.Policy) grpc.StreamClientInterceptor {
	return StreamClientRetryInterceptorWithConfig(RetryConfig{Policy: policy})
}

// StreamClientRetryInterceptorWithConfig returns a stream client retry interceptor with custom configuration.
func StreamClientRetryInterceptorWithConfig(config RetryConfig) grpc.StreamClientInterceptor {
	config = normalizeStreamRetryConfig(config)
	skipMethods, retryableCodes := buildRetryMaps(config)

	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		if skipMethods[method] {
			return streamer(ctx, desc, cc, method, opts...)
		}

		return executeStreamWithRetry(ctx, desc, cc, method, streamer, opts, config, retryableCodes)
	}
}

// normalizeStreamRetryConfig ensures stream config has all required defaults.
func normalizeStreamRetryConfig(config RetryConfig) RetryConfig {
	if config.Policy == nil {
		config.Policy = retry.DefaultPolicy()
	}
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if len(config.RetryableCodes) == 0 {
		config.RetryableCodes = []codes.Code{
			codes.Unavailable,
			codes.ResourceExhausted,
			codes.Aborted,
		}
	}
	return config
}

// executeStreamWithRetry executes a stream call with retry logic.
func executeStreamWithRetry(
	ctx context.Context,
	desc *grpc.StreamDesc,
	cc *grpc.ClientConn,
	method string,
	streamer grpc.Streamer,
	opts []grpc.CallOption,
	config RetryConfig,
	retryableCodes map[codes.Code]bool,
) (grpc.ClientStream, error) {
	backoff := retry.NewExponentialBackoff(
		config.Policy.InitialBackoff,
		config.Policy.MaxBackoff,
		config.Policy.BackoffFactor,
		config.Policy.Jitter,
	)

	var lastErr error
	for attempt := 0; attempt <= config.Policy.MaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err == nil {
			return stream, nil
		}

		lastErr = err
		if !isRetryableGRPCError(err, retryableCodes) {
			return nil, err
		}

		if attempt >= config.Policy.MaxRetries {
			break
		}

		retryErr := waitForStreamRetry(
			ctx, backoff, config.Logger, method, attempt, config.Policy.MaxRetries, lastErr)
		if retryErr != nil {
			return nil, err
		}
	}

	return nil, lastErr
}

// waitForStreamRetry waits before the next stream retry attempt.
func waitForStreamRetry(
	ctx context.Context,
	backoff *retry.ExponentialBackoff,
	logger *zap.Logger,
	method string,
	attempt, maxRetries int,
	err error,
) error {
	waitDuration := backoff.Next(attempt)

	logger.Debug("retrying gRPC stream",
		zap.String("method", method),
		zap.Int("attempt", attempt+1),
		zap.Int("max_retries", maxRetries),
		zap.Duration("wait", waitDuration),
		zap.Error(err),
	)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(waitDuration):
		return nil
	}
}
