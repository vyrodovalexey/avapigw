// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"context"
	"errors"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// Common transformation errors.
var (
	// ErrNilConfig indicates that the transformation config is nil.
	ErrNilConfig = errors.New("transformation config is nil")

	// ErrNilData indicates that the input data is nil.
	ErrNilData = errors.New("input data is nil")

	// ErrInvalidDataType indicates that the data type is not supported.
	ErrInvalidDataType = errors.New("invalid data type for transformation")

	// ErrFieldNotFound indicates that a required field was not found.
	ErrFieldNotFound = errors.New("field not found")

	// ErrInvalidFieldPath indicates that a field path is invalid.
	ErrInvalidFieldPath = errors.New("invalid field path")

	// ErrTemplateExecution indicates a template execution error.
	ErrTemplateExecution = errors.New("template execution failed")

	// ErrMergeConflict indicates a conflict during response merging.
	ErrMergeConflict = errors.New("merge conflict")
)

// Transformer is the main interface for data transformation.
type Transformer interface {
	// Transform applies transformation to the input data.
	Transform(ctx context.Context, data interface{}) (interface{}, error)
}

// ResponseTransformer transforms response data.
type ResponseTransformer interface {
	Transformer

	// TransformResponse transforms response data using the provided configuration.
	TransformResponse(
		ctx context.Context,
		response interface{},
		cfg *config.ResponseTransformConfig,
	) (interface{}, error)
}

// RequestTransformer transforms request data.
type RequestTransformer interface {
	Transformer

	// TransformRequest transforms request data using the provided configuration.
	TransformRequest(
		ctx context.Context,
		request interface{},
		cfg *config.RequestTransformConfig,
	) (interface{}, error)
}

// GRPCResponseTransformer transforms gRPC response data.
type GRPCResponseTransformer interface {
	Transformer

	// TransformGRPCResponse transforms gRPC response data using the provided configuration.
	TransformGRPCResponse(
		ctx context.Context,
		response interface{},
		cfg *config.GRPCResponseTransformConfig,
	) (interface{}, error)
}

// GRPCRequestTransformer transforms gRPC request data.
type GRPCRequestTransformer interface {
	Transformer

	// TransformGRPCRequest transforms gRPC request data using the provided configuration.
	TransformGRPCRequest(
		ctx context.Context,
		request interface{},
		cfg *config.GRPCRequestTransformConfig,
	) (interface{}, error)
}

// FieldMapper handles field mapping/renaming operations.
type FieldMapper interface {
	// MapFields applies field mappings to the data.
	MapFields(data map[string]interface{}, mappings []config.FieldMapping) (map[string]interface{}, error)
}

// FieldFilter handles field filtering operations.
type FieldFilter interface {
	// FilterAllow filters data to include only allowed fields.
	FilterAllow(data map[string]interface{}, allowFields []string) map[string]interface{}

	// FilterDeny filters data to exclude denied fields.
	FilterDeny(data map[string]interface{}, denyFields []string) map[string]interface{}
}

// ResponseMerger handles response merging operations.
type ResponseMerger interface {
	// Merge merges multiple responses into one.
	Merge(responses []interface{}, strategy string) (interface{}, error)
}

// TemplateEngine handles template-based transformations.
type TemplateEngine interface {
	// Execute executes a template with the given data.
	Execute(template string, data interface{}) (interface{}, error)
}

// TransformContext holds context information for transformations.
type TransformContext struct {
	// RequestID is the unique request identifier.
	RequestID string

	// TraceID is the distributed trace identifier.
	TraceID string

	// JWTClaims contains JWT claims if available.
	JWTClaims map[string]interface{}

	// Metadata contains additional metadata.
	Metadata map[string]interface{}

	// Headers contains request/response headers.
	Headers map[string]string
}

// NewTransformContext creates a new TransformContext from a context.Context.
func NewTransformContext(ctx context.Context) *TransformContext {
	tc := &TransformContext{
		JWTClaims: make(map[string]interface{}),
		Metadata:  make(map[string]interface{}),
		Headers:   make(map[string]string),
	}

	// Extract request ID if available
	if requestID, ok := ctx.Value(contextKeyRequestID).(string); ok {
		tc.RequestID = requestID
	}

	// Extract trace ID if available
	if traceID, ok := ctx.Value(contextKeyTraceID).(string); ok {
		tc.TraceID = traceID
	}

	// Extract JWT claims if available
	if claims, ok := ctx.Value(contextKeyJWTClaims).(map[string]interface{}); ok {
		tc.JWTClaims = claims
	}

	// Extract metadata if available
	if metadata, ok := ctx.Value(contextKeyMetadata).(map[string]interface{}); ok {
		tc.Metadata = metadata
	}

	return tc
}

// Context key types for type safety.
type contextKey string

const (
	contextKeyRequestID contextKey = "request_id"
	contextKeyTraceID   contextKey = "trace_id"
	contextKeyJWTClaims contextKey = "jwt_claims"
	contextKeyMetadata  contextKey = "metadata"
	contextKeyTransform contextKey = "transform_context"
)

// ContextWithTransformContext adds a TransformContext to the context.
func ContextWithTransformContext(ctx context.Context, tc *TransformContext) context.Context {
	return context.WithValue(ctx, contextKeyTransform, tc)
}

// TransformContextFromContext extracts a TransformContext from the context.
func TransformContextFromContext(ctx context.Context) *TransformContext {
	if tc, ok := ctx.Value(contextKeyTransform).(*TransformContext); ok {
		return tc
	}
	return NewTransformContext(ctx)
}

// ContextWithJWTClaims adds JWT claims to the context.
func ContextWithJWTClaims(ctx context.Context, claims map[string]interface{}) context.Context {
	return context.WithValue(ctx, contextKeyJWTClaims, claims)
}

// ContextWithMetadata adds metadata to the context.
func ContextWithMetadata(ctx context.Context, metadata map[string]interface{}) context.Context {
	return context.WithValue(ctx, contextKeyMetadata, metadata)
}
