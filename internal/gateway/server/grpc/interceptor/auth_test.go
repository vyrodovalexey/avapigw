package interceptor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockUnaryHandler is a mock unary handler for testing
func mockUnaryHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return "response", nil
}

// mockStreamHandler is a mock stream handler for testing
func mockStreamHandler(srv interface{}, ss grpc.ServerStream) error {
	return nil
}

// mockServerStream implements grpc.ServerStream for testing
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

// TestUnaryAuthInterceptor tests the basic unary auth interceptor
func TestUnaryAuthInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("passes with valid validator", func(t *testing.T) {
		validator := &NoopValidator{}
		interceptor := UnaryAuthInterceptor(validator)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestExtractCredentialsFromMetadata tests the extractCredentialsFromMetadata function
func TestExtractCredentialsFromMetadata(t *testing.T) {
	t.Parallel()

	t.Run("extracts bearer token", func(t *testing.T) {
		md := metadata.MD{
			"authorization": []string{"Bearer my-jwt-token"},
		}

		credentials := extractCredentialsFromMetadata(md)

		assert.Equal(t, "my-jwt-token", credentials.BearerToken)
		assert.Empty(t, credentials.APIKey)
		assert.Nil(t, credentials.BasicAuth)
	})

	t.Run("extracts bearer token with lowercase prefix", func(t *testing.T) {
		md := metadata.MD{
			"authorization": []string{"bearer my-jwt-token"},
		}

		credentials := extractCredentialsFromMetadata(md)

		assert.Equal(t, "my-jwt-token", credentials.BearerToken)
	})

	t.Run("extracts basic auth credentials", func(t *testing.T) {
		// "user:password" base64 encoded
		encoded := "dXNlcjpwYXNzd29yZA=="
		md := metadata.MD{
			"authorization": []string{"Basic " + encoded},
		}

		credentials := extractCredentialsFromMetadata(md)

		assert.Empty(t, credentials.BearerToken)
		assert.NotNil(t, credentials.BasicAuth)
		assert.Equal(t, "user", credentials.BasicAuth.Username)
		assert.Equal(t, "password", credentials.BasicAuth.Password)
	})

	t.Run("extracts basic auth with lowercase prefix", func(t *testing.T) {
		// "admin:secret" base64 encoded
		encoded := "YWRtaW46c2VjcmV0"
		md := metadata.MD{
			"authorization": []string{"basic " + encoded},
		}

		credentials := extractCredentialsFromMetadata(md)

		assert.NotNil(t, credentials.BasicAuth)
		assert.Equal(t, "admin", credentials.BasicAuth.Username)
		assert.Equal(t, "secret", credentials.BasicAuth.Password)
	})

	t.Run("extracts API key", func(t *testing.T) {
		md := metadata.MD{
			"x-api-key": []string{"my-api-key"},
		}

		credentials := extractCredentialsFromMetadata(md)

		assert.Equal(t, "my-api-key", credentials.APIKey)
		assert.Empty(t, credentials.BearerToken)
		assert.Nil(t, credentials.BasicAuth)
	})

	t.Run("extracts both bearer token and API key", func(t *testing.T) {
		md := metadata.MD{
			"authorization": []string{"Bearer my-token"},
			"x-api-key":     []string{"my-api-key"},
		}

		credentials := extractCredentialsFromMetadata(md)

		assert.Equal(t, "my-token", credentials.BearerToken)
		assert.Equal(t, "my-api-key", credentials.APIKey)
	})

	t.Run("handles empty metadata", func(t *testing.T) {
		md := metadata.MD{}

		credentials := extractCredentialsFromMetadata(md)

		assert.Empty(t, credentials.BearerToken)
		assert.Empty(t, credentials.APIKey)
		assert.Nil(t, credentials.BasicAuth)
	})

	t.Run("handles invalid basic auth encoding", func(t *testing.T) {
		md := metadata.MD{
			"authorization": []string{"Basic invalid-base64!!!"},
		}

		credentials := extractCredentialsFromMetadata(md)

		assert.Nil(t, credentials.BasicAuth)
	})

	t.Run("handles basic auth without colon", func(t *testing.T) {
		// "useronly" base64 encoded (no colon)
		encoded := "dXNlcm9ubHk="
		md := metadata.MD{
			"authorization": []string{"Basic " + encoded},
		}

		credentials := extractCredentialsFromMetadata(md)

		assert.Nil(t, credentials.BasicAuth)
	})
}

// TestDecodeBasicAuth tests the decodeBasicAuth function
func TestDecodeBasicAuth(t *testing.T) {
	t.Parallel()

	t.Run("decodes valid credentials", func(t *testing.T) {
		// "user:password" base64 encoded
		encoded := "dXNlcjpwYXNzd29yZA=="

		username, password, ok := decodeBasicAuth(encoded)

		assert.True(t, ok)
		assert.Equal(t, "user", username)
		assert.Equal(t, "password", password)
	})

	t.Run("decodes credentials with colon in password", func(t *testing.T) {
		// "user:pass:word" base64 encoded
		encoded := "dXNlcjpwYXNzOndvcmQ="

		username, password, ok := decodeBasicAuth(encoded)

		assert.True(t, ok)
		assert.Equal(t, "user", username)
		assert.Equal(t, "pass:word", password)
	})

	t.Run("decodes credentials with empty password", func(t *testing.T) {
		// "user:" base64 encoded
		encoded := "dXNlcjo="

		username, password, ok := decodeBasicAuth(encoded)

		assert.True(t, ok)
		assert.Equal(t, "user", username)
		assert.Empty(t, password)
	})

	t.Run("returns false for invalid base64", func(t *testing.T) {
		encoded := "not-valid-base64!!!"

		_, _, ok := decodeBasicAuth(encoded)

		assert.False(t, ok)
	})

	t.Run("returns false for missing colon", func(t *testing.T) {
		// "useronly" base64 encoded
		encoded := "dXNlcm9ubHk="

		_, _, ok := decodeBasicAuth(encoded)

		assert.False(t, ok)
	})
}

// TestUnaryAuthInterceptorWithCore tests the core-based unary auth interceptor
func TestUnaryAuthInterceptorWithCore(t *testing.T) {
	t.Parallel()

	t.Run("skips auth for configured methods", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			BaseConfig: core.BaseConfig{
				SkipPaths: []string{"/test.Service/SkippedMethod"},
			},
		})

		interceptor := UnaryAuthInterceptorWithCore(authCore)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("allows anonymous access for configured paths", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			AllowAnonymous: true,
			AnonymousPaths: []string{"/test.Service/PublicMethod"},
		})

		interceptor := UnaryAuthInterceptorWithCore(authCore)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/PublicMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("returns unauthenticated when auth required and no credentials", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: true,
		})

		interceptor := UnaryAuthInterceptorWithCore(authCore)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})

	t.Run("allows request when auth not required", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: false,
		})

		interceptor := UnaryAuthInterceptorWithCore(authCore)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("handles missing metadata gracefully", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: false,
		})

		interceptor := UnaryAuthInterceptorWithCore(authCore)

		ctx := context.Background() // No metadata
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestStreamAuthInterceptorWithCore tests the core-based stream auth interceptor
func TestStreamAuthInterceptorWithCore(t *testing.T) {
	t.Parallel()

	t.Run("skips auth for configured methods", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			BaseConfig: core.BaseConfig{
				SkipPaths: []string{"/test.Service/SkippedMethod"},
			},
		})

		interceptor := StreamAuthInterceptorWithCore(authCore)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("allows anonymous access for configured paths", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			AllowAnonymous: true,
			AnonymousPaths: []string{"/test.Service/PublicMethod"},
		})

		interceptor := StreamAuthInterceptorWithCore(authCore)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/PublicMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("returns unauthenticated when auth required and no credentials", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: true,
		})

		interceptor := StreamAuthInterceptorWithCore(authCore)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.Error(t, err)
		st, ok := status.FromError(err)
		assert.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})

	t.Run("allows stream when auth not required", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: false,
		})

		interceptor := StreamAuthInterceptorWithCore(authCore)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("handles missing metadata gracefully", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: false,
		})

		interceptor := StreamAuthInterceptorWithCore(authCore)

		ctx := context.Background() // No metadata
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})
}

// TestCompositeModeAnyWithNoValidators tests CompositeModeAny with no validators
func TestCompositeModeAnyWithNoValidators(t *testing.T) {
	t.Parallel()

	validator := &CompositeValidator{
		Validators: []AuthValidator{},
		Mode:       CompositeModeAny,
	}

	err := validator.Validate(context.Background(), "/test.Service/Method", metadata.MD{})

	// Empty validators should pass
	assert.NoError(t, err)
}

// TestUnaryAuthInterceptorWithConfig tests the configurable unary auth interceptor
func TestUnaryAuthInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips auth for configured methods", func(t *testing.T) {
		failingValidator := &BearerTokenValidator{
			ValidateFunc: func(ctx context.Context, token string) error {
				return errors.New("should not be called")
			},
		}

		config := AuthConfig{
			Validator:   failingValidator,
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := UnaryAuthInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("validates non-skipped methods", func(t *testing.T) {
		validator := &NoopValidator{}
		config := AuthConfig{
			Validator:   validator,
			Logger:      zap.NewNop(),
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := UnaryAuthInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/ValidatedMethod"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("returns error on validation failure", func(t *testing.T) {
		validator := &BearerTokenValidator{
			ValidateFunc: func(ctx context.Context, token string) error {
				return status.Error(codes.Unauthenticated, "invalid token")
			},
		}

		config := AuthConfig{
			Validator: validator,
			Logger:    zap.NewNop(),
		}

		interceptor := UnaryAuthInterceptorWithConfig(config)

		ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
			"authorization": []string{"Bearer invalid-token"},
		})
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("uses nop logger when nil", func(t *testing.T) {
		config := AuthConfig{
			Validator: &NoopValidator{},
			Logger:    nil,
		}

		interceptor := UnaryAuthInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestStreamAuthInterceptor tests the basic stream auth interceptor
func TestStreamAuthInterceptor(t *testing.T) {
	t.Parallel()

	t.Run("passes with valid validator", func(t *testing.T) {
		validator := &NoopValidator{}
		interceptor := StreamAuthInterceptor(validator)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("passes with nil validator", func(t *testing.T) {
		interceptor := StreamAuthInterceptor(nil)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})
}

// TestStreamAuthInterceptorWithConfig tests the configurable stream auth interceptor
func TestStreamAuthInterceptorWithConfig(t *testing.T) {
	t.Parallel()

	t.Run("skips auth for configured methods", func(t *testing.T) {
		failingValidator := &BearerTokenValidator{
			ValidateFunc: func(ctx context.Context, token string) error {
				return errors.New("should not be called")
			},
		}

		config := AuthConfig{
			Validator:   failingValidator,
			SkipMethods: []string{"/test.Service/SkippedMethod"},
		}

		interceptor := StreamAuthInterceptorWithConfig(config)

		ctx := context.Background()
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/SkippedMethod"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.NoError(t, err)
	})

	t.Run("returns error on validation failure", func(t *testing.T) {
		validator := &BearerTokenValidator{
			ValidateFunc: func(ctx context.Context, token string) error {
				return status.Error(codes.Unauthenticated, "invalid token")
			},
		}

		config := AuthConfig{
			Validator: validator,
			Logger:    zap.NewNop(),
		}

		interceptor := StreamAuthInterceptorWithConfig(config)

		ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{
			"authorization": []string{"Bearer invalid-token"},
		})
		stream := &mockServerStream{ctx: ctx}
		info := &grpc.StreamServerInfo{FullMethod: "/test.Service/Method"}

		err := interceptor(nil, stream, info, mockStreamHandler)

		assert.Error(t, err)
	})
}

// TestBearerTokenValidator tests the bearer token validator
func TestBearerTokenValidator(t *testing.T) {
	t.Parallel()

	t.Run("returns error for missing authorization header", func(t *testing.T) {
		validator := &BearerTokenValidator{}
		md := metadata.MD{}

		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "missing authorization header")
	})

	t.Run("returns error for invalid format", func(t *testing.T) {
		validator := &BearerTokenValidator{}
		md := metadata.MD{
			"authorization": []string{"Basic dXNlcjpwYXNz"},
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "invalid authorization header format")
	})

	t.Run("extracts and validates bearer token", func(t *testing.T) {
		var receivedToken string
		validator := &BearerTokenValidator{
			ValidateFunc: func(ctx context.Context, token string) error {
				receivedToken = token
				return nil
			},
		}
		md := metadata.MD{
			"authorization": []string{"Bearer my-token"},
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.NoError(t, err)
		assert.Equal(t, "my-token", receivedToken)
	})

	t.Run("handles lowercase bearer prefix", func(t *testing.T) {
		var receivedToken string
		validator := &BearerTokenValidator{
			ValidateFunc: func(ctx context.Context, token string) error {
				receivedToken = token
				return nil
			},
		}
		md := metadata.MD{
			"authorization": []string{"bearer my-token"},
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.NoError(t, err)
		assert.Equal(t, "my-token", receivedToken)
	})

	t.Run("passes with nil validate func", func(t *testing.T) {
		validator := &BearerTokenValidator{}
		md := metadata.MD{
			"authorization": []string{"Bearer my-token"},
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.NoError(t, err)
	})
}

// TestAPIKeyValidator tests the API key validator
func TestAPIKeyValidator(t *testing.T) {
	t.Parallel()

	t.Run("returns error for missing API key header", func(t *testing.T) {
		validator := &APIKeyValidator{}
		md := metadata.MD{}

		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "missing x-api-key header")
	})

	t.Run("uses default header name", func(t *testing.T) {
		var receivedKey string
		validator := &APIKeyValidator{
			ValidateFunc: func(ctx context.Context, apiKey string) error {
				receivedKey = apiKey
				return nil
			},
		}
		md := metadata.MD{
			"x-api-key": []string{"my-api-key"},
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.NoError(t, err)
		assert.Equal(t, "my-api-key", receivedKey)
	})

	t.Run("uses custom header name", func(t *testing.T) {
		var receivedKey string
		validator := &APIKeyValidator{
			HeaderName: "x-custom-key",
			ValidateFunc: func(ctx context.Context, apiKey string) error {
				receivedKey = apiKey
				return nil
			},
		}
		md := metadata.MD{
			"x-custom-key": []string{"custom-key-value"},
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.NoError(t, err)
		assert.Equal(t, "custom-key-value", receivedKey)
	})

	t.Run("passes with nil validate func", func(t *testing.T) {
		validator := &APIKeyValidator{}
		md := metadata.MD{
			"x-api-key": []string{"my-api-key"},
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.NoError(t, err)
	})
}

// TestCompositeValidator tests the composite validator
func TestCompositeValidator(t *testing.T) {
	t.Parallel()

	t.Run("passes with empty validators", func(t *testing.T) {
		validator := &CompositeValidator{
			Validators: []AuthValidator{},
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", metadata.MD{})

		assert.NoError(t, err)
	})

	t.Run("CompositeModeAll requires all validators to pass", func(t *testing.T) {
		validator := &CompositeValidator{
			Validators: []AuthValidator{
				&NoopValidator{},
				&NoopValidator{},
			},
			Mode: CompositeModeAll,
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", metadata.MD{})

		assert.NoError(t, err)
	})

	t.Run("CompositeModeAll fails if any validator fails", func(t *testing.T) {
		failingValidator := &BearerTokenValidator{
			ValidateFunc: func(ctx context.Context, token string) error {
				return status.Error(codes.Unauthenticated, "failed")
			},
		}

		validator := &CompositeValidator{
			Validators: []AuthValidator{
				&NoopValidator{},
				failingValidator,
			},
			Mode: CompositeModeAll,
		}

		md := metadata.MD{
			"authorization": []string{"Bearer token"},
		}
		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.Error(t, err)
	})

	t.Run("CompositeModeAny passes if any validator passes", func(t *testing.T) {
		failingValidator := &BearerTokenValidator{
			ValidateFunc: func(ctx context.Context, token string) error {
				return status.Error(codes.Unauthenticated, "failed")
			},
		}

		validator := &CompositeValidator{
			Validators: []AuthValidator{
				failingValidator,
				&NoopValidator{},
			},
			Mode: CompositeModeAny,
		}

		md := metadata.MD{
			"authorization": []string{"Bearer token"},
		}
		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.NoError(t, err)
	})

	t.Run("CompositeModeAny fails if all validators fail", func(t *testing.T) {
		failingValidator := &BearerTokenValidator{
			ValidateFunc: func(ctx context.Context, token string) error {
				return status.Error(codes.Unauthenticated, "failed")
			},
		}

		validator := &CompositeValidator{
			Validators: []AuthValidator{
				failingValidator,
				failingValidator,
			},
			Mode: CompositeModeAny,
		}

		md := metadata.MD{
			"authorization": []string{"Bearer token"},
		}
		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.Error(t, err)
	})

	t.Run("returns error for invalid mode", func(t *testing.T) {
		validator := &CompositeValidator{
			Validators: []AuthValidator{&NoopValidator{}},
			Mode:       CompositeMode(999),
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", metadata.MD{})

		assert.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

// TestMethodAuthValidator tests the method-based auth validator
func TestMethodAuthValidator(t *testing.T) {
	t.Parallel()

	t.Run("uses exact match rule", func(t *testing.T) {
		var calledValidator string
		validator := &MethodAuthValidator{
			Rules: map[string]AuthValidator{
				"/test.Service/ExactMethod": &BearerTokenValidator{
					ValidateFunc: func(ctx context.Context, token string) error {
						calledValidator = "exact"
						return nil
					},
				},
			},
		}

		md := metadata.MD{
			"authorization": []string{"Bearer token"},
		}
		err := validator.Validate(context.Background(), "/test.Service/ExactMethod", md)

		assert.NoError(t, err)
		assert.Equal(t, "exact", calledValidator)
	})

	t.Run("uses prefix match rule", func(t *testing.T) {
		var calledValidator string
		validator := &MethodAuthValidator{
			Rules: map[string]AuthValidator{
				"/test.Service/*": &BearerTokenValidator{
					ValidateFunc: func(ctx context.Context, token string) error {
						calledValidator = "prefix"
						return nil
					},
				},
			},
		}

		md := metadata.MD{
			"authorization": []string{"Bearer token"},
		}
		err := validator.Validate(context.Background(), "/test.Service/AnyMethod", md)

		assert.NoError(t, err)
		assert.Equal(t, "prefix", calledValidator)
	})

	t.Run("uses default validator when no rule matches", func(t *testing.T) {
		var calledValidator string
		validator := &MethodAuthValidator{
			Rules: map[string]AuthValidator{
				"/other.Service/*": &NoopValidator{},
			},
			DefaultValidator: &BearerTokenValidator{
				ValidateFunc: func(ctx context.Context, token string) error {
					calledValidator = "default"
					return nil
				},
			},
		}

		md := metadata.MD{
			"authorization": []string{"Bearer token"},
		}
		err := validator.Validate(context.Background(), "/test.Service/Method", md)

		assert.NoError(t, err)
		assert.Equal(t, "default", calledValidator)
	})

	t.Run("passes when no rule matches and no default", func(t *testing.T) {
		validator := &MethodAuthValidator{
			Rules: map[string]AuthValidator{
				"/other.Service/*": &NoopValidator{},
			},
		}

		err := validator.Validate(context.Background(), "/test.Service/Method", metadata.MD{})

		assert.NoError(t, err)
	})
}

// TestNoopValidator tests the noop validator
func TestNoopValidator(t *testing.T) {
	t.Parallel()

	validator := &NoopValidator{}

	err := validator.Validate(context.Background(), "/test.Service/Method", metadata.MD{})

	assert.NoError(t, err)
}

// TestAuthConfigDefaults tests AuthConfig default handling
func TestAuthConfigDefaults(t *testing.T) {
	t.Parallel()

	t.Run("handles nil logger", func(t *testing.T) {
		config := AuthConfig{
			Validator: &NoopValidator{},
			Logger:    nil,
		}

		interceptor := UnaryAuthInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("handles empty skip methods", func(t *testing.T) {
		config := AuthConfig{
			Validator:   &NoopValidator{},
			SkipMethods: []string{},
		}

		interceptor := UnaryAuthInterceptorWithConfig(config)

		ctx := context.Background()
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}

// TestAuthInterceptorWithMetadata tests auth interceptor with various metadata scenarios
func TestAuthInterceptorWithMetadata(t *testing.T) {
	t.Parallel()

	t.Run("handles missing metadata", func(t *testing.T) {
		validator := &NoopValidator{}
		interceptor := UnaryAuthInterceptorWithConfig(AuthConfig{
			Validator: validator,
		})

		ctx := context.Background() // No metadata
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})

	t.Run("handles empty metadata", func(t *testing.T) {
		validator := &NoopValidator{}
		interceptor := UnaryAuthInterceptorWithConfig(AuthConfig{
			Validator: validator,
		})

		ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
		info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}

		resp, err := interceptor(ctx, "request", info, mockUnaryHandler)

		assert.NoError(t, err)
		assert.Equal(t, "response", resp)
	})
}
