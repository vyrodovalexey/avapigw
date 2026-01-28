// Package transform provides gRPC-specific data transformation capabilities.
package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewTransformContext(t *testing.T) {
	tests := []struct {
		name   string
		logger observability.Logger
	}{
		{
			name:   "with logger",
			logger: observability.NopLogger(),
		},
		{
			name:   "nil logger",
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := NewTransformContext(tt.logger)

			require.NotNil(t, tc)
			assert.NotNil(t, tc.Logger)
			assert.NotNil(t, tc.IncomingMetadata)
			assert.NotNil(t, tc.Claims)
			assert.NotNil(t, tc.CustomData)
		})
	}
}

func TestTransformContext_WithMetadata(t *testing.T) {
	tests := []struct {
		name string
		md   metadata.MD
	}{
		{
			name: "with metadata",
			md:   metadata.Pairs("key", "value"),
		},
		{
			name: "nil metadata",
			md:   nil,
		},
		{
			name: "empty metadata",
			md:   metadata.MD{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := NewTransformContext(nil)
			result := tc.WithMetadata(tt.md)

			assert.Same(t, tc, result, "should return same instance for chaining")

			if tt.md != nil {
				assert.Equal(t, tt.md, tc.IncomingMetadata)
			}
		})
	}
}

func TestTransformContext_WithClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]interface{}
	}{
		{
			name:   "with claims",
			claims: map[string]interface{}{"sub": "user123", "role": "admin"},
		},
		{
			name:   "nil claims",
			claims: nil,
		},
		{
			name:   "empty claims",
			claims: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := NewTransformContext(nil)
			result := tc.WithClaims(tt.claims)

			assert.Same(t, tc, result, "should return same instance for chaining")

			if tt.claims != nil {
				assert.Equal(t, tt.claims, tc.Claims)
			}
		})
	}
}

func TestTransformContext_WithPeerAddress(t *testing.T) {
	tc := NewTransformContext(nil)
	result := tc.WithPeerAddress("192.168.1.1:8080")

	assert.Same(t, tc, result)
	assert.Equal(t, "192.168.1.1:8080", tc.PeerAddress)
}

func TestTransformContext_WithRequestID(t *testing.T) {
	tc := NewTransformContext(nil)
	result := tc.WithRequestID("req-123")

	assert.Same(t, tc, result)
	assert.Equal(t, "req-123", tc.RequestID)
}

func TestTransformContext_WithTraceID(t *testing.T) {
	tc := NewTransformContext(nil)
	result := tc.WithTraceID("trace-456")

	assert.Same(t, tc, result)
	assert.Equal(t, "trace-456", tc.TraceID)
}

func TestTransformContext_WithSpanID(t *testing.T) {
	tc := NewTransformContext(nil)
	result := tc.WithSpanID("span-789")

	assert.Same(t, tc, result)
	assert.Equal(t, "span-789", tc.SpanID)
}

func TestTransformContext_CustomData(t *testing.T) {
	tc := NewTransformContext(nil)

	// Set custom data
	tc.SetCustomData("key1", "value1")
	tc.SetCustomData("key2", 123)
	tc.SetCustomData("key3", map[string]string{"nested": "value"})

	// Get custom data
	val1, ok1 := tc.GetCustomData("key1")
	assert.True(t, ok1)
	assert.Equal(t, "value1", val1)

	val2, ok2 := tc.GetCustomData("key2")
	assert.True(t, ok2)
	assert.Equal(t, 123, val2)

	val3, ok3 := tc.GetCustomData("key3")
	assert.True(t, ok3)
	assert.Equal(t, map[string]string{"nested": "value"}, val3)

	// Get non-existent key
	_, ok4 := tc.GetCustomData("nonexistent")
	assert.False(t, ok4)
}

func TestTransformContext_Chaining(t *testing.T) {
	tc := NewTransformContext(observability.NopLogger()).
		WithMetadata(metadata.Pairs("key", "value")).
		WithClaims(map[string]interface{}{"sub": "user123"}).
		WithPeerAddress("192.168.1.1:8080").
		WithRequestID("req-123").
		WithTraceID("trace-456").
		WithSpanID("span-789")

	assert.Equal(t, "value", tc.IncomingMetadata.Get("key")[0])
	assert.Equal(t, "user123", tc.Claims["sub"])
	assert.Equal(t, "192.168.1.1:8080", tc.PeerAddress)
	assert.Equal(t, "req-123", tc.RequestID)
	assert.Equal(t, "trace-456", tc.TraceID)
	assert.Equal(t, "span-789", tc.SpanID)
}

func TestContextWithTransformContext(t *testing.T) {
	tc := NewTransformContext(observability.NopLogger())
	tc.RequestID = "test-request-id"

	ctx := context.Background()
	ctxWithTC := ContextWithTransformContext(ctx, tc)

	// Should be able to retrieve the transform context
	retrieved := TransformContextFromContext(ctxWithTC)
	assert.Equal(t, tc, retrieved)
	assert.Equal(t, "test-request-id", retrieved.RequestID)
}

func TestTransformContextFromContext(t *testing.T) {
	tests := []struct {
		name        string
		setupCtx    func() context.Context
		expectNewTC bool
	}{
		{
			name: "context with transform context",
			setupCtx: func() context.Context {
				tc := NewTransformContext(nil)
				tc.RequestID = "existing-id"
				return ContextWithTransformContext(context.Background(), tc)
			},
			expectNewTC: false,
		},
		{
			name: "context without transform context",
			setupCtx: func() context.Context {
				return context.Background()
			},
			expectNewTC: true,
		},
		{
			name: "context with wrong type value",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), transformContextKey, "wrong type")
			},
			expectNewTC: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			tc := TransformContextFromContext(ctx)

			require.NotNil(t, tc)

			if tt.expectNewTC {
				// Should be a new empty transform context
				assert.Empty(t, tc.RequestID)
			}
		})
	}
}

func TestTransformContext_OverwriteCustomData(t *testing.T) {
	tc := NewTransformContext(nil)

	// Set initial value
	tc.SetCustomData("key", "initial")
	val, ok := tc.GetCustomData("key")
	assert.True(t, ok)
	assert.Equal(t, "initial", val)

	// Overwrite value
	tc.SetCustomData("key", "updated")
	val, ok = tc.GetCustomData("key")
	assert.True(t, ok)
	assert.Equal(t, "updated", val)
}

func TestTransformContext_NilValueInCustomData(t *testing.T) {
	tc := NewTransformContext(nil)

	// Set nil value
	tc.SetCustomData("key", nil)

	val, ok := tc.GetCustomData("key")
	assert.True(t, ok)
	assert.Nil(t, val)
}

func TestContextKey(t *testing.T) {
	// Verify the context key is a specific type
	assert.Equal(t, contextKey("grpc_transform_context"), transformContextKey)
}
