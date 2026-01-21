// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewRequestTransformer(t *testing.T) {
	tests := []struct {
		name   string
		logger observability.Logger
		opts   []RequestTransformerOption
	}{
		{
			name:   "with nil logger",
			logger: nil,
		},
		{
			name:   "with nop logger",
			logger: observability.NopLogger(),
		},
		{
			name:   "with custom field mapper",
			logger: observability.NopLogger(),
			opts:   []RequestTransformerOption{WithRequestFieldMapper(NewFieldMapper(nil))},
		},
		{
			name:   "with custom template engine",
			logger: observability.NopLogger(),
			opts:   []RequestTransformerOption{WithRequestTemplateEngine(NewTemplateEngine(nil))},
		},
		{
			name:   "with request logger",
			logger: observability.NopLogger(),
			opts:   []RequestTransformerOption{WithRequestLogger(observability.NopLogger())},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformer := NewRequestTransformer(tt.logger, tt.opts...)
			require.NotNil(t, transformer)
		})
	}
}

func TestRequestTransformer_Transform(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	data := map[string]interface{}{"name": "test"}
	result, err := transformer.Transform(context.Background(), data)

	require.NoError(t, err)
	assert.Equal(t, data, result)
}

func TestRequestTransformer_TransformRequest(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	tests := []struct {
		name      string
		request   interface{}
		cfg       *config.RequestTransformConfig
		expected  interface{}
		expectErr bool
	}{
		{
			name:     "nil config returns request",
			request:  map[string]interface{}{"name": "test"},
			cfg:      nil,
			expected: map[string]interface{}{"name": "test"},
		},
		{
			name:    "passthrough mode returns request as-is",
			request: map[string]interface{}{"name": "test"},
			cfg: &config.RequestTransformConfig{
				PassthroughBody: true,
			},
			expected: map[string]interface{}{"name": "test"},
		},
		{
			name:    "nil request with no injections returns nil",
			request: nil,
			cfg: &config.RequestTransformConfig{
				PassthroughBody: false,
			},
			expected: nil,
		},
		{
			name:    "nil request with default values creates map",
			request: nil,
			cfg: &config.RequestTransformConfig{
				DefaultValues: map[string]interface{}{"status": "active"},
			},
			expected: map[string]interface{}{"status": "active"},
		},
		{
			name: "apply default values",
			request: map[string]interface{}{
				"name": "test",
			},
			cfg: &config.RequestTransformConfig{
				DefaultValues: map[string]interface{}{
					"status": "active",
					"name":   "default", // Should not override existing
				},
			},
			expected: map[string]interface{}{
				"name":   "test",
				"status": "active",
			},
		},
		{
			name: "remove fields",
			request: map[string]interface{}{
				"name":     "test",
				"internal": "hidden",
				"secret":   "password",
			},
			cfg: &config.RequestTransformConfig{
				RemoveFields: []string{"internal", "secret"},
			},
			expected: map[string]interface{}{
				"name": "test",
			},
		},
		{
			name: "inject static fields",
			request: map[string]interface{}{
				"name": "test",
			},
			cfg: &config.RequestTransformConfig{
				InjectFields: []config.FieldInjection{
					{Field: "version", Value: "1.0"},
					{Field: "type", Value: "request"},
				},
			},
			expected: map[string]interface{}{
				"name":    "test",
				"version": "1.0",
				"type":    "request",
			},
		},
		{
			name: "body template transformation",
			request: map[string]interface{}{
				"name": "test",
			},
			cfg: &config.RequestTransformConfig{
				BodyTemplate: `{"user": "{{.request.name}}"}`,
			},
			expected: map[string]interface{}{
				"user": "test",
			},
		},
		{
			name:    "non-map request returns as-is",
			request: "string request",
			cfg: &config.RequestTransformConfig{
				RemoveFields: []string{"field"},
			},
			expected: "string request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := transformer.TransformRequest(context.Background(), tt.request, tt.cfg)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequestTransformer_InjectFieldsWithSource(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	// Create context with JWT claims
	claims := map[string]interface{}{
		"sub":   "user-123",
		"email": "user@example.com",
	}
	ctx := ContextWithJWTClaims(context.Background(), claims)

	request := map[string]interface{}{
		"name": "test",
	}

	cfg := &config.RequestTransformConfig{
		InjectFields: []config.FieldInjection{
			{Field: "user_id", Source: "jwt.claim.sub"},
			{Field: "email", Source: "jwt.email"},
		},
	}

	result, err := transformer.TransformRequest(ctx, request, cfg)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "test", resultMap["name"])
	assert.Equal(t, "user-123", resultMap["user_id"])
	assert.Equal(t, "user@example.com", resultMap["email"])
}

func TestRequestTransformer_InjectFieldsFromContext(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	// Create transform context
	tc := &TransformContext{
		RequestID: "req-123",
		TraceID:   "trace-456",
		JWTClaims: map[string]interface{}{
			"sub": "user-123",
		},
		Metadata: map[string]interface{}{
			"key": "value",
		},
		Headers: map[string]string{
			"X-Custom": "header-value",
		},
	}
	ctx := ContextWithTransformContext(context.Background(), tc)

	request := map[string]interface{}{
		"name": "test",
	}

	cfg := &config.RequestTransformConfig{
		InjectFields: []config.FieldInjection{
			{Field: "request_id", Source: "context.request_id"},
			{Field: "trace_id", Source: "context.trace_id"},
			{Field: "user_id", Source: "jwt.claim.sub"},
			{Field: "meta_key", Source: "metadata.key"},
			{Field: "custom_header", Source: "headers.X-Custom"},
		},
	}

	result, err := transformer.TransformRequest(ctx, request, cfg)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "req-123", resultMap["request_id"])
	assert.Equal(t, "trace-456", resultMap["trace_id"])
	assert.Equal(t, "user-123", resultMap["user_id"])
	assert.Equal(t, "value", resultMap["meta_key"])
	assert.Equal(t, "header-value", resultMap["custom_header"])
}

func TestRequestTransformer_InjectFieldsSourceNotFound(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	request := map[string]interface{}{
		"name": "test",
	}

	cfg := &config.RequestTransformConfig{
		InjectFields: []config.FieldInjection{
			{Field: "missing", Source: "jwt.claim.nonexistent"},
		},
	}

	result, err := transformer.TransformRequest(context.Background(), request, cfg)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	// Field should not be injected if source not found
	assert.NotContains(t, resultMap, "missing")
}

func TestRequestTransformer_RemoveNestedFields(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	request := map[string]interface{}{
		"user": map[string]interface{}{
			"name":     "test",
			"password": "secret",
		},
		"data": "value",
	}

	cfg := &config.RequestTransformConfig{
		RemoveFields: []string{"user.password"},
	}

	result, err := transformer.TransformRequest(context.Background(), request, cfg)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	user, ok := resultMap["user"].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "test", user["name"])
	assert.NotContains(t, user, "password")
}

func TestRequestTransformer_CombinedTransformations(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	request := map[string]interface{}{
		"name":     "test",
		"internal": "hidden",
	}

	cfg := &config.RequestTransformConfig{
		DefaultValues: map[string]interface{}{
			"status": "active",
		},
		RemoveFields: []string{"internal"},
		InjectFields: []config.FieldInjection{
			{Field: "version", Value: "1.0"},
		},
	}

	result, err := transformer.TransformRequest(context.Background(), request, cfg)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "test", resultMap["name"])
	assert.Equal(t, "active", resultMap["status"])
	assert.Equal(t, "1.0", resultMap["version"])
	assert.NotContains(t, resultMap, "internal")
}

func TestTransformHeaders(t *testing.T) {
	tests := []struct {
		name      string
		headers   map[string]string
		cfg       *config.RequestTransformConfig
		ctx       context.Context
		expected  map[string]string
		expectErr bool
	}{
		{
			name: "nil config returns headers",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			cfg: nil,
			ctx: context.Background(),
			expected: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			name: "add static headers",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			cfg: &config.RequestTransformConfig{
				StaticHeaders: map[string]string{
					"X-API-Key": "secret",
					"X-Version": "1.0",
				},
			},
			ctx: context.Background(),
			expected: map[string]string{
				"Content-Type": "application/json",
				"X-API-Key":    "secret",
				"X-Version":    "1.0",
			},
		},
		{
			name:    "add dynamic headers from context",
			headers: map[string]string{},
			cfg: &config.RequestTransformConfig{
				DynamicHeaders: []config.DynamicHeader{
					{Name: "X-User-ID", Source: "jwt.claim.sub"},
					{Name: "X-Request-ID", Source: "context.request_id"},
				},
			},
			ctx: func() context.Context {
				tc := &TransformContext{
					RequestID: "req-123",
					JWTClaims: map[string]interface{}{
						"sub": "user-456",
					},
				}
				return ContextWithTransformContext(context.Background(), tc)
			}(),
			expected: map[string]string{
				"X-User-ID":    "user-456",
				"X-Request-ID": "req-123",
			},
		},
		{
			name:    "dynamic header source not found",
			headers: map[string]string{},
			cfg: &config.RequestTransformConfig{
				DynamicHeaders: []config.DynamicHeader{
					{Name: "X-Missing", Source: "jwt.claim.nonexistent"},
				},
			},
			ctx:      context.Background(),
			expected: map[string]string{
				// X-Missing should not be added
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := TransformHeaders(tt.ctx, tt.headers, tt.cfg, observability.NopLogger())

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTransformHeaders_NilLogger(t *testing.T) {
	headers := map[string]string{"Content-Type": "application/json"}
	cfg := &config.RequestTransformConfig{
		StaticHeaders: map[string]string{"X-Custom": "value"},
	}

	result, err := TransformHeaders(context.Background(), headers, cfg, nil)
	require.NoError(t, err)
	assert.Equal(t, "value", result["X-Custom"])
}

func TestRequestTransformer_ResolveSource(t *testing.T) {
	rt := &requestTransformer{
		logger: observability.NopLogger(),
	}

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
			"X-Custom": "header-value",
		},
	}

	tests := []struct {
		name     string
		source   string
		expected interface{}
	}{
		{
			name:     "jwt claim with prefix",
			source:   "jwt.claim.sub",
			expected: "user-123",
		},
		{
			name:     "jwt claim direct",
			source:   "jwt.email",
			expected: "user@example.com",
		},
		{
			name:     "context request_id",
			source:   "context.request_id",
			expected: "req-123",
		},
		{
			name:     "context trace_id",
			source:   "context.trace_id",
			expected: "trace-456",
		},
		{
			name:     "metadata",
			source:   "metadata.key",
			expected: "value",
		},
		{
			name:     "headers",
			source:   "headers.X-Custom",
			expected: "header-value",
		},
		{
			name:     "unknown category",
			source:   "unknown.field",
			expected: nil,
		},
		{
			name:     "invalid source format",
			source:   "invalid",
			expected: nil,
		},
		{
			name:     "unknown context field",
			source:   "context.unknown",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rt.resolveSource(tc, tt.source)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequestTransformer_DoesNotModifyOriginal(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	original := map[string]interface{}{
		"name":     "test",
		"internal": "hidden",
	}

	// Make a copy to compare later
	originalCopy := map[string]interface{}{
		"name":     "test",
		"internal": "hidden",
	}

	cfg := &config.RequestTransformConfig{
		RemoveFields: []string{"internal"},
		InjectFields: []config.FieldInjection{
			{Field: "version", Value: "1.0"},
		},
	}

	result, err := transformer.TransformRequest(context.Background(), original, cfg)
	require.NoError(t, err)

	// Original should be unchanged
	assert.Equal(t, originalCopy, original)

	// Result should have transformations applied
	resultMap := result.(map[string]interface{})
	assert.NotContains(t, resultMap, "internal")
	assert.Contains(t, resultMap, "version")
}

func TestRequestTransformer_BodyTemplateWithContext(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	tc := &TransformContext{
		RequestID: "req-123",
		JWTClaims: map[string]interface{}{
			"sub": "user-456",
		},
		Metadata: map[string]interface{}{
			"env": "production",
		},
		Headers: map[string]string{
			"X-Custom": "header-value",
		},
	}
	ctx := ContextWithTransformContext(context.Background(), tc)

	request := map[string]interface{}{
		"name": "test",
	}

	cfg := &config.RequestTransformConfig{
		BodyTemplate: `{"name": "{{.request.name}}", "request_id": "{{.context.RequestID}}", "user": "{{index .jwt "sub"}}"}`,
	}

	result, err := transformer.TransformRequest(ctx, request, cfg)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "test", resultMap["name"])
	assert.Equal(t, "req-123", resultMap["request_id"])
	assert.Equal(t, "user-456", resultMap["user"])
}

func TestRequestTransformer_NilRequestWithInjectFields(t *testing.T) {
	transformer := NewRequestTransformer(observability.NopLogger())

	cfg := &config.RequestTransformConfig{
		InjectFields: []config.FieldInjection{
			{Field: "version", Value: "1.0"},
		},
	}

	result, err := transformer.TransformRequest(context.Background(), nil, cfg)
	require.NoError(t, err)

	resultMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "1.0", resultMap["version"])
}
