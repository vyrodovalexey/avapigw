// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrNilConfig",
			err:      ErrNilConfig,
			expected: "transformation config is nil",
		},
		{
			name:     "ErrNilData",
			err:      ErrNilData,
			expected: "input data is nil",
		},
		{
			name:     "ErrInvalidDataType",
			err:      ErrInvalidDataType,
			expected: "invalid data type for transformation",
		},
		{
			name:     "ErrFieldNotFound",
			err:      ErrFieldNotFound,
			expected: "field not found",
		},
		{
			name:     "ErrInvalidFieldPath",
			err:      ErrInvalidFieldPath,
			expected: "invalid field path",
		},
		{
			name:     "ErrTemplateExecution",
			err:      ErrTemplateExecution,
			expected: "template execution failed",
		},
		{
			name:     "ErrMergeConflict",
			err:      ErrMergeConflict,
			expected: "merge conflict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestNewTransformContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{
			name: "empty context",
			ctx:  context.Background(),
		},
		{
			name: "context with request ID",
			ctx:  context.WithValue(context.Background(), contextKeyRequestID, "req-123"),
		},
		{
			name: "context with trace ID",
			ctx:  context.WithValue(context.Background(), contextKeyTraceID, "trace-456"),
		},
		{
			name: "context with JWT claims",
			ctx:  context.WithValue(context.Background(), contextKeyJWTClaims, map[string]interface{}{"sub": "user-123"}),
		},
		{
			name: "context with metadata",
			ctx:  context.WithValue(context.Background(), contextKeyMetadata, map[string]interface{}{"key": "value"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := NewTransformContext(tt.ctx)
			require.NotNil(t, tc)
			assert.NotNil(t, tc.JWTClaims)
			assert.NotNil(t, tc.Metadata)
			assert.NotNil(t, tc.Headers)
		})
	}
}

func TestNewTransformContext_WithRequestID(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextKeyRequestID, "req-123")
	tc := NewTransformContext(ctx)

	assert.Equal(t, "req-123", tc.RequestID)
}

func TestNewTransformContext_WithTraceID(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextKeyTraceID, "trace-456")
	tc := NewTransformContext(ctx)

	assert.Equal(t, "trace-456", tc.TraceID)
}

func TestNewTransformContext_WithJWTClaims(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   "user-123",
		"email": "user@example.com",
	}
	ctx := context.WithValue(context.Background(), contextKeyJWTClaims, claims)
	tc := NewTransformContext(ctx)

	assert.Equal(t, "user-123", tc.JWTClaims["sub"])
	assert.Equal(t, "user@example.com", tc.JWTClaims["email"])
}

func TestNewTransformContext_WithMetadata(t *testing.T) {
	metadata := map[string]interface{}{
		"key1": "value1",
		"key2": 123,
	}
	ctx := context.WithValue(context.Background(), contextKeyMetadata, metadata)
	tc := NewTransformContext(ctx)

	assert.Equal(t, "value1", tc.Metadata["key1"])
	assert.Equal(t, 123, tc.Metadata["key2"])
}

func TestContextWithTransformContext(t *testing.T) {
	tc := &TransformContext{
		RequestID: "req-123",
		TraceID:   "trace-456",
		JWTClaims: map[string]interface{}{"sub": "user-123"},
		Metadata:  map[string]interface{}{"key": "value"},
		Headers:   map[string]string{"X-Custom": "header"},
	}

	ctx := ContextWithTransformContext(context.Background(), tc)
	require.NotNil(t, ctx)

	// Verify we can extract it back
	extracted := TransformContextFromContext(ctx)
	assert.Equal(t, tc.RequestID, extracted.RequestID)
	assert.Equal(t, tc.TraceID, extracted.TraceID)
	assert.Equal(t, tc.JWTClaims["sub"], extracted.JWTClaims["sub"])
}

func TestTransformContextFromContext_NotFound(t *testing.T) {
	ctx := context.Background()
	tc := TransformContextFromContext(ctx)

	// Should return a new TransformContext
	require.NotNil(t, tc)
	assert.NotNil(t, tc.JWTClaims)
	assert.NotNil(t, tc.Metadata)
	assert.NotNil(t, tc.Headers)
}

func TestContextWithJWTClaims(t *testing.T) {
	claims := map[string]interface{}{
		"sub":   "user-123",
		"email": "user@example.com",
		"roles": []string{"admin", "user"},
	}

	ctx := ContextWithJWTClaims(context.Background(), claims)
	require.NotNil(t, ctx)

	// Verify we can extract it
	tc := NewTransformContext(ctx)
	assert.Equal(t, "user-123", tc.JWTClaims["sub"])
	assert.Equal(t, "user@example.com", tc.JWTClaims["email"])
}

func TestContextWithMetadata(t *testing.T) {
	metadata := map[string]interface{}{
		"key1":   "value1",
		"key2":   123,
		"nested": map[string]interface{}{"a": "b"},
	}

	ctx := ContextWithMetadata(context.Background(), metadata)
	require.NotNil(t, ctx)

	// Verify we can extract it
	tc := NewTransformContext(ctx)
	assert.Equal(t, "value1", tc.Metadata["key1"])
	assert.Equal(t, 123, tc.Metadata["key2"])
}

func TestTransformContext_Struct(t *testing.T) {
	tc := &TransformContext{
		RequestID: "req-123",
		TraceID:   "trace-456",
		JWTClaims: map[string]interface{}{
			"sub":   "user-123",
			"email": "user@example.com",
		},
		Metadata: map[string]interface{}{
			"key": "value",
		},
		Headers: map[string]string{
			"X-Custom":     "header",
			"X-Request-ID": "req-123",
		},
	}

	assert.Equal(t, "req-123", tc.RequestID)
	assert.Equal(t, "trace-456", tc.TraceID)
	assert.Equal(t, "user-123", tc.JWTClaims["sub"])
	assert.Equal(t, "value", tc.Metadata["key"])
	assert.Equal(t, "header", tc.Headers["X-Custom"])
}

func TestContextKeys(t *testing.T) {
	// Verify context keys are unique
	assert.NotEqual(t, contextKeyRequestID, contextKeyTraceID)
	assert.NotEqual(t, contextKeyRequestID, contextKeyJWTClaims)
	assert.NotEqual(t, contextKeyRequestID, contextKeyMetadata)
	assert.NotEqual(t, contextKeyRequestID, contextKeyTransform)
	assert.NotEqual(t, contextKeyTraceID, contextKeyJWTClaims)
	assert.NotEqual(t, contextKeyTraceID, contextKeyMetadata)
	assert.NotEqual(t, contextKeyTraceID, contextKeyTransform)
	assert.NotEqual(t, contextKeyJWTClaims, contextKeyMetadata)
	assert.NotEqual(t, contextKeyJWTClaims, contextKeyTransform)
	assert.NotEqual(t, contextKeyMetadata, contextKeyTransform)
}

func TestTransformContext_EmptyMaps(t *testing.T) {
	tc := NewTransformContext(context.Background())

	// Verify maps are initialized but empty
	assert.NotNil(t, tc.JWTClaims)
	assert.Len(t, tc.JWTClaims, 0)

	assert.NotNil(t, tc.Metadata)
	assert.Len(t, tc.Metadata, 0)

	assert.NotNil(t, tc.Headers)
	assert.Len(t, tc.Headers, 0)
}

func TestTransformContext_WithInvalidTypes(t *testing.T) {
	// Test with wrong types in context
	ctx := context.WithValue(context.Background(), contextKeyRequestID, 123) // int instead of string
	tc := NewTransformContext(ctx)

	// Should not panic, RequestID should be empty
	assert.Empty(t, tc.RequestID)
}

func TestTransformContext_WithInvalidJWTClaims(t *testing.T) {
	// Test with wrong type for JWT claims
	ctx := context.WithValue(context.Background(), contextKeyJWTClaims, "invalid") // string instead of map
	tc := NewTransformContext(ctx)

	// Should not panic, JWTClaims should be empty map
	assert.NotNil(t, tc.JWTClaims)
	assert.Len(t, tc.JWTClaims, 0)
}

func TestTransformContext_WithInvalidMetadata(t *testing.T) {
	// Test with wrong type for metadata
	ctx := context.WithValue(context.Background(), contextKeyMetadata, []string{"invalid"}) // slice instead of map
	tc := NewTransformContext(ctx)

	// Should not panic, Metadata should be empty map
	assert.NotNil(t, tc.Metadata)
	assert.Len(t, tc.Metadata, 0)
}

func TestTransformContext_ChainedContextValues(t *testing.T) {
	// Build context with multiple values
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextKeyRequestID, "req-123")
	ctx = context.WithValue(ctx, contextKeyTraceID, "trace-456")
	ctx = context.WithValue(ctx, contextKeyJWTClaims, map[string]interface{}{"sub": "user-123"})
	ctx = context.WithValue(ctx, contextKeyMetadata, map[string]interface{}{"key": "value"})

	tc := NewTransformContext(ctx)

	assert.Equal(t, "req-123", tc.RequestID)
	assert.Equal(t, "trace-456", tc.TraceID)
	assert.Equal(t, "user-123", tc.JWTClaims["sub"])
	assert.Equal(t, "value", tc.Metadata["key"])
}
