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

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	retryableCodes := make(map[codes.Code]bool)
	for _, code := range config.RetryableCodes {
		retryableCodes[code] = true
	}

	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		// Skip retry for certain methods
		if skipMethods[method] {
			return invoker(ctx, method, req, reply, cc, opts...)
		}

		backoff := retry.NewExponentialBackoff(
			config.Policy.InitialBackoff,
			config.Policy.MaxBackoff,
			config.Policy.BackoffFactor,
			config.Policy.Jitter,
		)

		var lastErr error
		for attempt := 0; attempt <= config.Policy.MaxRetries; attempt++ {
			// Check context before each attempt
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Execute the call
			err := invoker(ctx, method, req, reply, cc, opts...)
			if err == nil {
				return nil
			}

			lastErr = err

			// Check if we should retry
			st, ok := status.FromError(err)
			if !ok || !retryableCodes[st.Code()] {
				return err
			}

			// Don't retry on last attempt
			if attempt >= config.Policy.MaxRetries {
				break
			}

			// Calculate wait duration
			waitDuration := backoff.Next(attempt)

			config.Logger.Debug("retrying gRPC call",
				zap.String("method", method),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", config.Policy.MaxRetries),
				zap.Duration("wait", waitDuration),
				zap.Error(err),
			)

			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(waitDuration):
			}
		}

		return lastErr
	}
}

// StreamClientRetryInterceptor returns a stream client interceptor that applies retry logic.
// Note: Stream retry is limited - only the initial connection can be retried.
func StreamClientRetryInterceptor(policy *retry.Policy) grpc.StreamClientInterceptor {
	return StreamClientRetryInterceptorWithConfig(RetryConfig{Policy: policy})
}

// StreamClientRetryInterceptorWithConfig returns a stream client retry interceptor with custom configuration.
func StreamClientRetryInterceptorWithConfig(config RetryConfig) grpc.StreamClientInterceptor {
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

	skipMethods := make(map[string]bool)
	for _, method := range config.SkipMethods {
		skipMethods[method] = true
	}

	retryableCodes := make(map[codes.Code]bool)
	for _, code := range config.RetryableCodes {
		retryableCodes[code] = true
	}

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		// Skip retry for certain methods
		if skipMethods[method] {
			return streamer(ctx, desc, cc, method, opts...)
		}

		backoff := retry.NewExponentialBackoff(
			config.Policy.InitialBackoff,
			config.Policy.MaxBackoff,
			config.Policy.BackoffFactor,
			config.Policy.Jitter,
		)

		var lastErr error
		for attempt := 0; attempt <= config.Policy.MaxRetries; attempt++ {
			// Check context before each attempt
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			// Execute the call
			stream, err := streamer(ctx, desc, cc, method, opts...)
			if err == nil {
				return stream, nil
			}

			lastErr = err

			// Check if we should retry
			st, ok := status.FromError(err)
			if !ok || !retryableCodes[st.Code()] {
				return nil, err
			}

			// Don't retry on last attempt
			if attempt >= config.Policy.MaxRetries {
				break
			}

			// Calculate wait duration
			waitDuration := backoff.Next(attempt)

			config.Logger.Debug("retrying gRPC stream",
				zap.String("method", method),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", config.Policy.MaxRetries),
				zap.Duration("wait", waitDuration),
				zap.Error(err),
			)

			// Wait before retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitDuration):
			}
		}

		return nil, lastErr
	}
}

// retryableServerStream wraps a server stream with retry tracking.
type retryableServerStream struct {
	grpc.ServerStream
	method string
	logger *zap.Logger
}

// RecvMsg implements grpc.ServerStream.
func (s *retryableServerStream) RecvMsg(m interface{}) error {
	return s.ServerStream.RecvMsg(m)
}

// SendMsg implements grpc.ServerStream.
func (s *retryableServerStream) SendMsg(m interface{}) error {
	return s.ServerStream.SendMsg(m)
}
