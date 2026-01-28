package authz

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewGRPCAuthorizer(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics()))
	assert.NotNil(t, authorizer)
}

func TestNewGRPCAuthorizer_WithOptions(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}
	logger := observability.NopLogger()
	metrics := newNoopMetrics()

	authorizer := NewGRPCAuthorizer(mockAuth, config,
		WithGRPCAuthorizerLogger(logger),
		WithGRPCAuthorizerMetrics(metrics),
	)
	assert.NotNil(t, authorizer)
}

func TestGRPCAuthorizer_Authorize_Success(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{
			Allowed: true,
			Reason:  "allowed by policy",
			Policy:  "test-policy",
		},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics()))

	// Create context with identity
	identity := &auth.Identity{
		Subject: "user123",
		Roles:   []string{"admin"},
	}
	ctx := auth.ContextWithIdentity(context.Background(), identity)

	decision, err := authorizer.Authorize(ctx, "/test.Service/Method")
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "allowed by policy", decision.Reason)
}

func TestGRPCAuthorizer_Authorize_Denied(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{
			Allowed: false,
			Reason:  "access denied",
			Policy:  "deny-policy",
		},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics()))

	identity := &auth.Identity{
		Subject: "user123",
		Roles:   []string{"guest"},
	}
	ctx := auth.ContextWithIdentity(context.Background(), identity)

	decision, err := authorizer.Authorize(ctx, "/admin.Service/DeleteAll")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.Equal(t, "access denied", decision.Reason)
}

func TestGRPCAuthorizer_Authorize_NoIdentity(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics()))

	// Context without identity
	ctx := context.Background()

	decision, err := authorizer.Authorize(ctx, "/test.Service/Method")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoIdentity)
	assert.Nil(t, decision)
}

func TestGRPCAuthorizer_UnaryInterceptor_Allowed(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config,
		WithGRPCAuthorizerLogger(observability.NopLogger()),
		WithGRPCAuthorizerMetrics(newNoopMetrics()),
	)

	interceptor := authorizer.UnaryInterceptor()

	// Create context with identity
	identity := &auth.Identity{Subject: "user123"}
	ctx := auth.ContextWithIdentity(context.Background(), identity)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	resp, err := interceptor(ctx, "request", info, handler)
	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, "response", resp)
}

func TestGRPCAuthorizer_UnaryInterceptor_Denied(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{
			Allowed: false,
			Reason:  "access denied",
		},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config,
		WithGRPCAuthorizerLogger(observability.NopLogger()),
		WithGRPCAuthorizerMetrics(newNoopMetrics()),
	)

	interceptor := authorizer.UnaryInterceptor()

	identity := &auth.Identity{Subject: "user123"}
	ctx := auth.ContextWithIdentity(context.Background(), identity)

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/admin.Service/DeleteAll",
	}

	resp, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	assert.False(t, handlerCalled)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Contains(t, st.Message(), "access denied")
}

func TestGRPCAuthorizer_UnaryInterceptor_NoIdentity(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics()))

	interceptor := authorizer.UnaryInterceptor()

	// Context without identity
	ctx := context.Background()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	resp, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

// mockServerStream is a mock implementation of grpc.ServerStream for testing.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func TestGRPCAuthorizer_StreamInterceptor_Allowed(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config,
		WithGRPCAuthorizerLogger(observability.NopLogger()),
		WithGRPCAuthorizerMetrics(newNoopMetrics()),
	)

	interceptor := authorizer.StreamInterceptor()

	identity := &auth.Identity{Subject: "user123"}
	ctx := auth.ContextWithIdentity(context.Background(), identity)

	stream := &mockServerStream{ctx: ctx}

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestGRPCAuthorizer_StreamInterceptor_Denied(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{
			Allowed: false,
			Reason:  "access denied",
		},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config,
		WithGRPCAuthorizerLogger(observability.NopLogger()),
		WithGRPCAuthorizerMetrics(newNoopMetrics()),
	)

	interceptor := authorizer.StreamInterceptor()

	identity := &auth.Identity{Subject: "user123"}
	ctx := auth.ContextWithIdentity(context.Background(), identity)

	stream := &mockServerStream{ctx: ctx}

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/admin.Service/StreamAll",
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)
	assert.False(t, handlerCalled)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

func TestGRPCAuthorizer_StreamInterceptor_NoIdentity(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics()))

	interceptor := authorizer.StreamInterceptor()

	// Context without identity
	stream := &mockServerStream{ctx: context.Background()}

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	err := interceptor(nil, stream, info, handler)
	assert.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestGRPCAuthorizer_ToGRPCError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{
			name:         "no identity",
			err:          ErrNoIdentity,
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "access denied",
			err:          ErrAccessDenied,
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "timeout",
			err:          ErrExternalAuthzTimeout,
			expectedCode: codes.DeadlineExceeded,
		},
		{
			name:         "unavailable",
			err:          ErrExternalAuthzUnavailable,
			expectedCode: codes.Unavailable,
		},
		{
			name:         "generic error",
			err:          assert.AnError,
			expectedCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockAuth := &mockAuthorizer{}
			config := &Config{Enabled: true}
			authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics())).(*grpcAuthorizer)

			grpcErr := authorizer.toGRPCError(tt.err)
			st, ok := status.FromError(grpcErr)
			require.True(t, ok)
			assert.Equal(t, tt.expectedCode, st.Code())
		})
	}
}

func TestParseFullMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		fullMethod     string
		expectedSvc    string
		expectedMethod string
	}{
		{
			name:           "standard format",
			fullMethod:     "/package.Service/Method",
			expectedSvc:    "package.Service",
			expectedMethod: "Method",
		},
		{
			name:           "nested package",
			fullMethod:     "/com.example.api.v1.UserService/GetUser",
			expectedSvc:    "com.example.api.v1.UserService",
			expectedMethod: "GetUser",
		},
		{
			name:           "empty string",
			fullMethod:     "",
			expectedSvc:    "",
			expectedMethod: "",
		},
		{
			name:           "no leading slash",
			fullMethod:     "package.Service/Method",
			expectedSvc:    "",
			expectedMethod: "package.Service/Method",
		},
		{
			name:           "only service",
			fullMethod:     "/package.Service",
			expectedSvc:    "",
			expectedMethod: "/package.Service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, method := parseFullMethod(tt.fullMethod)
			assert.Equal(t, tt.expectedSvc, service)
			assert.Equal(t, tt.expectedMethod, method)
		})
	}
}

func TestIsSensitiveMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		key      string
		expected bool
	}{
		{"authorization", true},
		{"x-api-key", true},
		{"x-auth-token", true},
		{"cookie", true},
		{"content-type", false},
		{"x-request-id", false},
		{"user-agent", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, isSensitiveMetadata(tt.key))
		})
	}
}

func TestGRPCAuthorizer_BuildRequestContext(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics())).(*grpcAuthorizer)

	// Create context with metadata
	md := metadata.Pairs(
		"content-type", "application/grpc",
		"x-request-id", "req-123",
		"authorization", "Bearer token", // Should be filtered
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	reqCtx := authorizer.buildRequestContext(ctx, "test.Service", "GetUser")

	assert.Equal(t, "test.Service", reqCtx["service"])
	assert.Equal(t, "GetUser", reqCtx["method"])

	headers := reqCtx["metadata"].(map[string]string)
	assert.Equal(t, "application/grpc", headers["content-type"])
	assert.Equal(t, "req-123", headers["x-request-id"])
	_, hasAuth := headers["authorization"]
	assert.False(t, hasAuth, "authorization should be filtered")
}

func TestGRPCAuthorizer_BuildRequestContext_NoMetadata(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics())).(*grpcAuthorizer)

	// Context without metadata
	ctx := context.Background()

	reqCtx := authorizer.buildRequestContext(ctx, "test.Service", "GetUser")

	assert.Equal(t, "test.Service", reqCtx["service"])
	assert.Equal(t, "GetUser", reqCtx["method"])
	_, hasMetadata := reqCtx["metadata"]
	assert.False(t, hasMetadata)
}
