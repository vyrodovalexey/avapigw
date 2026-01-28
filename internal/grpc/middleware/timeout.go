package middleware

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryTimeoutInterceptor returns a unary server interceptor that enforces a timeout.
func UnaryTimeoutInterceptor(timeout time.Duration) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Check if context already has a deadline
		if deadline, ok := ctx.Deadline(); ok {
			// Use the shorter of the two deadlines
			remaining := time.Until(deadline)
			if remaining < timeout {
				timeout = remaining
			}
		}

		// Create timeout context
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		// Create channel for result
		type result struct {
			resp interface{}
			err  error
		}
		done := make(chan result, 1)

		// Execute handler in goroutine
		go func() {
			resp, err := handler(ctx, req)
			done <- result{resp: resp, err: err}
		}()

		// Wait for result or timeout
		select {
		case r := <-done:
			return r.resp, r.err
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return nil, status.Error(codes.DeadlineExceeded, "request timeout")
			}
			return nil, status.Error(codes.Canceled, "request canceled")
		}
	}
}

// StreamTimeoutInterceptor returns a stream server interceptor that enforces a timeout.
// Note: For streams, this sets a deadline for the entire stream duration.
func StreamTimeoutInterceptor(timeout time.Duration) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := stream.Context()

		// Check if context already has a deadline
		if deadline, ok := ctx.Deadline(); ok {
			// Use the shorter of the two deadlines
			remaining := time.Until(deadline)
			if remaining < timeout {
				timeout = remaining
			}
		}

		// Create timeout context
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		// Wrap stream with new context
		wrapped := &timeoutServerStream{
			ServerStream: stream,
			ctx:          ctx,
		}

		// Create channel for result
		done := make(chan error, 1)

		// Execute handler in goroutine
		go func() {
			done <- handler(srv, wrapped)
		}()

		// Wait for result or timeout
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return status.Error(codes.DeadlineExceeded, "stream timeout")
			}
			return status.Error(codes.Canceled, "stream canceled")
		}
	}
}

// timeoutServerStream wraps grpc.ServerStream with a timeout context.
type timeoutServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the timeout context.
func (s *timeoutServerStream) Context() context.Context {
	return s.ctx
}
