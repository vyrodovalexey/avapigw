// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// MessageTransformer transforms Protocol Buffer messages.
type MessageTransformer interface {
	// TransformMessage transforms a protobuf message according to the configuration.
	TransformMessage(ctx context.Context, msg proto.Message, cfg *config.GRPCTransformConfig) (proto.Message, error)
}

// RequestTransformer transforms gRPC requests.
type RequestTransformer interface {
	// TransformRequest transforms a gRPC request message.
	TransformRequest(
		ctx context.Context,
		msg proto.Message,
		md metadata.MD,
		cfg *config.GRPCRequestTransformConfig,
	) (proto.Message, metadata.MD, error)
}

// ResponseTransformer transforms gRPC responses.
type ResponseTransformer interface {
	// TransformResponse transforms a gRPC response message.
	TransformResponse(
		ctx context.Context,
		msg proto.Message,
		cfg *config.GRPCResponseTransformConfig,
	) (proto.Message, error)
}

// StreamTransformer transforms streaming messages.
type StreamTransformer interface {
	// TransformStreamMessage transforms a single message in a stream.
	// Returns the transformed message, a boolean indicating if the message should be sent,
	// and any error that occurred.
	TransformStreamMessage(
		ctx context.Context,
		msg proto.Message,
		sequence int,
		cfg *config.StreamingTransformConfig,
	) (proto.Message, bool, error)

	// ShouldFilter returns true if the message should be filtered out.
	ShouldFilter(ctx context.Context, msg proto.Message, cfg *config.StreamingTransformConfig) (bool, error)
}

// MetadataTransformer transforms gRPC metadata.
type MetadataTransformer interface {
	// TransformMetadata transforms incoming metadata.
	TransformMetadata(
		ctx context.Context,
		md metadata.MD,
		cfg *config.GRPCRequestTransformConfig,
	) (metadata.MD, error)

	// TransformTrailerMetadata transforms trailer metadata.
	TransformTrailerMetadata(
		ctx context.Context,
		md metadata.MD,
		cfg *config.GRPCResponseTransformConfig,
	) (metadata.MD, error)
}

// TransformContext holds context for transformation operations.
type TransformContext struct {
	// Logger for transformation operations.
	Logger observability.Logger

	// IncomingMetadata contains the incoming gRPC metadata.
	IncomingMetadata metadata.MD

	// Claims contains JWT claims if available.
	Claims map[string]interface{}

	// PeerAddress contains the peer's network address.
	PeerAddress string

	// RequestID contains the unique request identifier.
	RequestID string

	// TraceID contains the distributed trace identifier.
	TraceID string

	// SpanID contains the current span identifier.
	SpanID string

	// CustomData contains additional custom data for transformations.
	CustomData map[string]interface{}
}

// NewTransformContext creates a new transformation context.
func NewTransformContext(logger observability.Logger) *TransformContext {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &TransformContext{
		Logger:           logger,
		IncomingMetadata: metadata.MD{},
		Claims:           make(map[string]interface{}),
		CustomData:       make(map[string]interface{}),
	}
}

// WithMetadata sets the incoming metadata.
func (tc *TransformContext) WithMetadata(md metadata.MD) *TransformContext {
	if md != nil {
		tc.IncomingMetadata = md
	}
	return tc
}

// WithClaims sets the JWT claims.
func (tc *TransformContext) WithClaims(claims map[string]interface{}) *TransformContext {
	if claims != nil {
		tc.Claims = claims
	}
	return tc
}

// WithPeerAddress sets the peer address.
func (tc *TransformContext) WithPeerAddress(addr string) *TransformContext {
	tc.PeerAddress = addr
	return tc
}

// WithRequestID sets the request ID.
func (tc *TransformContext) WithRequestID(id string) *TransformContext {
	tc.RequestID = id
	return tc
}

// WithTraceID sets the trace ID.
func (tc *TransformContext) WithTraceID(id string) *TransformContext {
	tc.TraceID = id
	return tc
}

// WithSpanID sets the span ID.
func (tc *TransformContext) WithSpanID(id string) *TransformContext {
	tc.SpanID = id
	return tc
}

// SetCustomData sets a custom data value.
func (tc *TransformContext) SetCustomData(key string, value interface{}) {
	tc.CustomData[key] = value
}

// GetCustomData retrieves a custom data value.
func (tc *TransformContext) GetCustomData(key string) (interface{}, bool) {
	val, ok := tc.CustomData[key]
	return val, ok
}

// Context key type for type safety.
type contextKey string

const (
	// transformContextKey is the context key for TransformContext.
	transformContextKey contextKey = "grpc_transform_context"
)

// ContextWithTransformContext adds a TransformContext to the context.
func ContextWithTransformContext(ctx context.Context, tc *TransformContext) context.Context {
	return context.WithValue(ctx, transformContextKey, tc)
}

// TransformContextFromContext extracts a TransformContext from the context.
// Returns a new TransformContext if none is found.
func TransformContextFromContext(ctx context.Context) *TransformContext {
	if tc, ok := ctx.Value(transformContextKey).(*TransformContext); ok {
		return tc
	}
	return NewTransformContext(nil)
}
