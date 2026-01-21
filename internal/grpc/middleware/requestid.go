package middleware

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

const (
	// RequestIDHeader is the metadata key for request ID.
	RequestIDHeader = "x-request-id"
)

// UnaryRequestIDInterceptor returns a unary server interceptor that adds a request ID.
func UnaryRequestIDInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		ctx = ensureRequestID(ctx)
		return handler(ctx, req)
	}
}

// StreamRequestIDInterceptor returns a stream server interceptor that adds a request ID.
func StreamRequestIDInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ensureRequestID(stream.Context())
		wrapped := &requestIDServerStream{
			ServerStream: stream,
			ctx:          ctx,
		}
		return handler(srv, wrapped)
	}
}

// ensureRequestID ensures a request ID exists in the context.
func ensureRequestID(ctx context.Context) context.Context {
	// Check if request ID already exists in metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(RequestIDHeader); len(values) > 0 && values[0] != "" {
			// Add to observability context
			return observability.ContextWithRequestID(ctx, values[0])
		}
	}

	// Generate new request ID
	requestID := uuid.New().String()

	// Add to observability context
	ctx = observability.ContextWithRequestID(ctx, requestID)

	// Add to outgoing metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}
	md = md.Copy()
	md.Set(RequestIDHeader, requestID)

	return metadata.NewIncomingContext(ctx, md)
}

// requestIDServerStream wraps grpc.ServerStream with request ID context.
type requestIDServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the context with request ID.
func (s *requestIDServerStream) Context() context.Context {
	return s.ctx
}

// GetRequestID extracts the request ID from context.
func GetRequestID(ctx context.Context) string {
	// First check observability context
	if requestID := observability.RequestIDFromContext(ctx); requestID != "" {
		return requestID
	}

	// Then check metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(RequestIDHeader); len(values) > 0 {
			return values[0]
		}
	}

	return ""
}

// SetRequestIDInOutgoingContext sets the request ID in outgoing metadata.
func SetRequestIDInOutgoingContext(ctx context.Context, requestID string) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.MD{}
	}
	md = md.Copy()
	md.Set(RequestIDHeader, requestID)
	return metadata.NewOutgoingContext(ctx, md)
}
