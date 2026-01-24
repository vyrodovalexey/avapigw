package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewGRPCAuthenticator(t *testing.T) {
	t.Parallel()

	t.Run("nil config returns error", func(t *testing.T) {
		t.Parallel()

		auth, err := NewGRPCAuthenticator(nil)
		assert.Error(t, err)
		assert.Nil(t, auth)
	})

	t.Run("disabled config", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: false,
		}

		auth, err := NewGRPCAuthenticator(config)
		require.NoError(t, err)
		assert.NotNil(t, auth)
	})

	t.Run("with logger option", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: false,
		}

		auth, err := NewGRPCAuthenticator(config,
			WithGRPCAuthenticatorLogger(observability.NopLogger()),
		)
		require.NoError(t, err)
		assert.NotNil(t, auth)
	})

	t.Run("with metrics option", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: false,
		}

		auth, err := NewGRPCAuthenticator(config,
			WithGRPCAuthenticatorMetrics(NewMetrics("test")),
		)
		require.NoError(t, err)
		assert.NotNil(t, auth)
	})
}

func TestGRPCAuthenticator_Authenticate_JWT(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
		Extraction: &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
			},
		},
	}

	mockValidator := &mockJWTValidator{
		claims: &jwt.Claims{
			Subject:  "user123",
			Issuer:   "test-issuer",
			Audience: jwt.Audience{"api"},
		},
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Create context with metadata
	md := metadata.Pairs("authorization", "Bearer valid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	identity, err := auth.Authenticate(ctx)
	require.NoError(t, err)
	assert.Equal(t, "user123", identity.Subject)
	assert.Equal(t, "test-issuer", identity.Issuer)
	assert.Equal(t, AuthTypeJWT, identity.AuthType)
}

func TestGRPCAuthenticator_Authenticate_APIKey(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		APIKey: &apikey.Config{
			Enabled: true,
		},
		Extraction: &ExtractionConfig{
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "x-api-key"},
			},
		},
	}

	mockValidator := &mockAPIKeyValidator{
		keyInfo: &apikey.KeyInfo{
			ID:     "key-123",
			Roles:  []string{"api-user"},
			Scopes: []string{"read", "write"},
		},
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCAPIKeyValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	md := metadata.Pairs("x-api-key", "valid-api-key")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	identity, err := auth.Authenticate(ctx)
	require.NoError(t, err)
	assert.Equal(t, "key-123", identity.Subject)
	assert.Equal(t, AuthTypeAPIKey, identity.AuthType)
	assert.Equal(t, []string{"api-user"}, identity.Roles)
}

func TestGRPCAuthenticator_Authenticate_NoCredentials(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
	}

	mockValidator := &mockJWTValidator{
		claims: &jwt.Claims{Subject: "user123"},
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Context without metadata
	ctx := context.Background()

	identity, err := auth.Authenticate(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCredentials)
	assert.Nil(t, identity)
}

func TestGRPCAuthenticator_Authenticate_AllowAnonymous(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:        true,
		AllowAnonymous: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
	}

	mockValidator := &mockJWTValidator{
		err: ErrNoCredentials,
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Context without credentials but anonymous allowed
	ctx := context.Background()

	identity, err := auth.Authenticate(ctx)
	require.NoError(t, err)
	assert.Equal(t, "anonymous", identity.Subject)
	assert.Equal(t, AuthTypeAnonymous, identity.AuthType)
}

func TestGRPCAuthenticator_UnaryInterceptor_Success(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
		Extraction: &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
			},
		},
	}

	mockValidator := &mockJWTValidator{
		claims: &jwt.Claims{Subject: "user123"},
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	interceptor := auth.UnaryInterceptor()

	md := metadata.Pairs("authorization", "Bearer valid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	handlerCalled := false
	var capturedIdentity *Identity
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		capturedIdentity, _ = IdentityFromContext(ctx)
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	resp, err := interceptor(ctx, "request", info, handler)
	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, "response", resp)
	assert.NotNil(t, capturedIdentity)
	assert.Equal(t, "user123", capturedIdentity.Subject)
}

func TestGRPCAuthenticator_UnaryInterceptor_Unauthenticated(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
	}

	mockValidator := &mockJWTValidator{
		err: ErrNoCredentials,
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	interceptor := auth.UnaryInterceptor()

	// Context without credentials
	ctx := context.Background()

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}

	resp, err := interceptor(ctx, "request", info, handler)
	assert.Error(t, err)
	assert.False(t, handlerCalled)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestGRPCAuthenticator_UnaryInterceptor_ExpiredToken(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
		Extraction: &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
			},
		},
	}

	mockValidator := &mockJWTValidator{
		err: ErrTokenExpired,
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	interceptor := auth.UnaryInterceptor()

	md := metadata.Pairs("authorization", "Bearer expired-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

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
	assert.Contains(t, st.Message(), "token expired")
}

func TestGRPCAuthenticator_UnaryInterceptor_InvalidToken(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
		Extraction: &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
			},
		},
	}

	mockValidator := &mockJWTValidator{
		err: ErrInvalidToken,
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	interceptor := auth.UnaryInterceptor()

	md := metadata.Pairs("authorization", "Bearer invalid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

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
	assert.Contains(t, st.Message(), "invalid token")
}

// mockGRPCServerStream is a mock implementation of grpc.ServerStream for testing.
type mockGRPCServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockGRPCServerStream) Context() context.Context {
	return m.ctx
}

func TestGRPCAuthenticator_StreamInterceptor_Success(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
		Extraction: &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
			},
		},
	}

	mockValidator := &mockJWTValidator{
		claims: &jwt.Claims{Subject: "user123"},
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	interceptor := auth.StreamInterceptor()

	md := metadata.Pairs("authorization", "Bearer valid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	stream := &mockGRPCServerStream{ctx: ctx}

	handlerCalled := false
	var capturedIdentity *Identity
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		capturedIdentity, _ = IdentityFromContext(stream.Context())
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	err = interceptor(nil, stream, info, handler)
	require.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.NotNil(t, capturedIdentity)
	assert.Equal(t, "user123", capturedIdentity.Subject)
}

func TestGRPCAuthenticator_StreamInterceptor_Unauthenticated(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
	}

	mockValidator := &mockJWTValidator{
		err: ErrNoCredentials,
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockValidator),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	interceptor := auth.StreamInterceptor()

	// Context without credentials
	stream := &mockGRPCServerStream{ctx: context.Background()}

	handlerCalled := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	info := &grpc.StreamServerInfo{
		FullMethod: "/test.Service/StreamMethod",
	}

	err = interceptor(nil, stream, info, handler)
	assert.Error(t, err)
	assert.False(t, handlerCalled)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestGRPCAuthenticator_ToGRPCError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
		expectedMsg  string
	}{
		{
			name:         "no credentials",
			err:          ErrNoCredentials,
			expectedCode: codes.Unauthenticated,
			expectedMsg:  "authentication required",
		},
		{
			name:         "token expired",
			err:          ErrTokenExpired,
			expectedCode: codes.Unauthenticated,
			expectedMsg:  "token expired",
		},
		{
			name:         "invalid token",
			err:          ErrInvalidToken,
			expectedCode: codes.Unauthenticated,
			expectedMsg:  "invalid token",
		},
		{
			name:         "invalid signature",
			err:          ErrInvalidSignature,
			expectedCode: codes.Unauthenticated,
			expectedMsg:  "invalid token",
		},
		{
			name:         "invalid API key",
			err:          ErrInvalidAPIKey,
			expectedCode: codes.Unauthenticated,
			expectedMsg:  "invalid API key",
		},
		{
			name:         "generic error",
			err:          assert.AnError,
			expectedCode: codes.Unauthenticated,
			expectedMsg:  "authentication failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &Config{Enabled: false}
			auth, err := NewGRPCAuthenticator(config)
			require.NoError(t, err)

			grpcAuth := auth.(*grpcAuthenticator)
			grpcErr := grpcAuth.toGRPCError(tt.err)

			st, ok := status.FromError(grpcErr)
			require.True(t, ok)
			assert.Equal(t, tt.expectedCode, st.Code())
			assert.Contains(t, st.Message(), tt.expectedMsg)
		})
	}
}

func TestAuthenticatedServerStream_Context(t *testing.T) {
	t.Parallel()

	identity := &Identity{Subject: "user123"}
	ctx := ContextWithIdentity(context.Background(), identity)

	baseStream := &mockGRPCServerStream{ctx: context.Background()}
	wrappedStream := &authenticatedServerStream{
		ServerStream: baseStream,
		ctx:          ctx,
	}

	// The wrapped stream should return the authenticated context
	retrievedIdentity, ok := IdentityFromContext(wrappedStream.Context())
	require.True(t, ok)
	assert.Equal(t, "user123", retrievedIdentity.Subject)
}

func TestGRPCAuthenticator_FallbackToAPIKey(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
		APIKey: &apikey.Config{
			Enabled: true,
		},
		Extraction: &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
			},
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "x-api-key"},
			},
		},
	}

	// JWT validator returns no credentials
	mockJWT := &mockJWTValidator{
		err: ErrNoCredentials,
	}

	// API key validator succeeds
	mockAPIKey := &mockAPIKeyValidator{
		keyInfo: &apikey.KeyInfo{
			ID:    "key-123",
			Roles: []string{"api-user"},
		},
	}

	auth, err := NewGRPCAuthenticator(config,
		WithGRPCJWTValidator(mockJWT),
		WithGRPCAPIKeyValidator(mockAPIKey),
		WithGRPCAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Request with only API key
	md := metadata.Pairs("x-api-key", "valid-key")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	identity, err := auth.Authenticate(ctx)
	require.NoError(t, err)
	assert.Equal(t, "key-123", identity.Subject)
	assert.Equal(t, AuthTypeAPIKey, identity.AuthType)
}
