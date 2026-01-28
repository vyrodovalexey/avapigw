package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestNewExtractor(t *testing.T) {
	t.Parallel()

	t.Run("with nil config uses defaults", func(t *testing.T) {
		t.Parallel()

		extractor := NewExtractor(nil)
		assert.NotNil(t, extractor)
	})

	t.Run("with custom config", func(t *testing.T) {
		t.Parallel()

		config := &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-Custom-Token"},
			},
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-Custom-Key"},
			},
		}

		extractor := NewExtractor(config)
		assert.NotNil(t, extractor)
	})
}

func TestExtractor_ExtractJWT(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     *ExtractionConfig
		setupReq   func(*http.Request)
		wantValue  string
		wantSource string
		wantErr    bool
	}{
		{
			name: "extract from Authorization header with Bearer prefix",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
				},
			},
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
			},
			wantValue:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantSource: "header:Authorization",
			wantErr:    false,
		},
		{
			name: "extract from custom header without prefix",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "X-JWT-Token"},
				},
			},
			setupReq: func(r *http.Request) {
				r.Header.Set("X-JWT-Token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
			},
			wantValue:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantSource: "header:X-JWT-Token",
			wantErr:    false,
		},
		{
			name: "extract from cookie",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeCookie, Name: "jwt_token"},
				},
			},
			setupReq: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "jwt_token", Value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"})
			},
			wantValue:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantSource: "cookie:jwt_token",
			wantErr:    false,
		},
		{
			name: "extract from query parameter",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeQuery, Name: "token"},
				},
			},
			setupReq: func(r *http.Request) {
				q := r.URL.Query()
				q.Set("token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
				r.URL.RawQuery = q.Encode()
			},
			wantValue:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantSource: "query:token",
			wantErr:    false,
		},
		{
			name: "no credentials found",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
				},
			},
			setupReq: func(r *http.Request) {
				// No header set
			},
			wantErr: true,
		},
		{
			name: "wrong prefix",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
				},
			},
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
			},
			wantErr: true,
		},
		{
			name: "try multiple sources - first match wins",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
					{Type: ExtractionTypeCookie, Name: "jwt_token"},
				},
			},
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer header_token")
				r.AddCookie(&http.Cookie{Name: "jwt_token", Value: "cookie_token"})
			},
			wantValue:  "header_token",
			wantSource: "header:Authorization",
			wantErr:    false,
		},
		{
			name: "fallback to second source",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
					{Type: ExtractionTypeCookie, Name: "jwt_token"},
				},
			},
			setupReq: func(r *http.Request) {
				r.AddCookie(&http.Cookie{Name: "jwt_token", Value: "cookie_token"})
			},
			wantValue:  "cookie_token",
			wantSource: "cookie:jwt_token",
			wantErr:    false,
		},
		{
			name: "trim whitespace",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
				},
			},
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer   token_with_spaces   ")
			},
			wantValue:  "token_with_spaces",
			wantSource: "header:Authorization",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			extractor := NewExtractor(tt.config)
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupReq(req)

			creds, err := extractor.ExtractJWT(req)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrNoCredentials)
				assert.Nil(t, creds)
			} else {
				require.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, CredentialTypeJWT, creds.Type)
				assert.Equal(t, tt.wantValue, creds.Value)
				assert.Equal(t, tt.wantSource, creds.Source)
			}
		})
	}
}

func TestExtractor_ExtractAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     *ExtractionConfig
		setupReq   func(*http.Request)
		wantValue  string
		wantSource string
		wantErr    bool
	}{
		{
			name: "extract from X-API-Key header",
			config: &ExtractionConfig{
				APIKey: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "X-API-Key"},
				},
			},
			setupReq: func(r *http.Request) {
				r.Header.Set("X-API-Key", "api_key_123")
			},
			wantValue:  "api_key_123",
			wantSource: "header:X-API-Key",
			wantErr:    false,
		},
		{
			name: "extract from query parameter",
			config: &ExtractionConfig{
				APIKey: []ExtractionSource{
					{Type: ExtractionTypeQuery, Name: "api_key"},
				},
			},
			setupReq: func(r *http.Request) {
				q := r.URL.Query()
				q.Set("api_key", "api_key_456")
				r.URL.RawQuery = q.Encode()
			},
			wantValue:  "api_key_456",
			wantSource: "query:api_key",
			wantErr:    false,
		},
		{
			name: "no API key found",
			config: &ExtractionConfig{
				APIKey: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "X-API-Key"},
				},
			},
			setupReq: func(r *http.Request) {
				// No header set
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			extractor := NewExtractor(tt.config)
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupReq(req)

			creds, err := extractor.ExtractAPIKey(req)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrNoCredentials)
				assert.Nil(t, creds)
			} else {
				require.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, CredentialTypeAPIKey, creds.Type)
				assert.Equal(t, tt.wantValue, creds.Value)
				assert.Equal(t, tt.wantSource, creds.Source)
			}
		})
	}
}

func TestExtractor_ExtractJWTFromGRPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     *ExtractionConfig
		setupCtx   func() context.Context
		wantValue  string
		wantSource string
		wantErr    bool
	}{
		{
			name: "extract from authorization metadata with Bearer prefix",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
				},
			},
			setupCtx: func() context.Context {
				md := metadata.Pairs("authorization", "Bearer grpc_token_123")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			wantValue:  "grpc_token_123",
			wantSource: "metadata:authorization",
			wantErr:    false,
		},
		{
			name: "extract from custom metadata",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeMetadata, Name: "x-jwt-token"},
				},
			},
			setupCtx: func() context.Context {
				md := metadata.Pairs("x-jwt-token", "custom_token_456")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			wantValue:  "custom_token_456",
			wantSource: "metadata:x-jwt-token",
			wantErr:    false,
		},
		{
			name: "no metadata in context",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
				},
			},
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantErr: true,
		},
		{
			name: "metadata key not found",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
				},
			},
			setupCtx: func() context.Context {
				md := metadata.Pairs("other-key", "value")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			wantErr: true,
		},
		{
			name: "skip non-metadata/header sources",
			config: &ExtractionConfig{
				JWT: []ExtractionSource{
					{Type: ExtractionTypeCookie, Name: "jwt_token"},
					{Type: ExtractionTypeQuery, Name: "token"},
					{Type: ExtractionTypeHeader, Name: "authorization", Prefix: "Bearer "},
				},
			},
			setupCtx: func() context.Context {
				md := metadata.Pairs("authorization", "Bearer grpc_token")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			wantValue:  "grpc_token",
			wantSource: "metadata:authorization",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			extractor := NewExtractor(tt.config)
			ctx := tt.setupCtx()

			creds, err := extractor.ExtractJWTFromGRPC(ctx)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrNoCredentials)
				assert.Nil(t, creds)
			} else {
				require.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, CredentialTypeJWT, creds.Type)
				assert.Equal(t, tt.wantValue, creds.Value)
				assert.Equal(t, tt.wantSource, creds.Source)
			}
		})
	}
}

func TestExtractor_ExtractAPIKeyFromGRPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     *ExtractionConfig
		setupCtx   func() context.Context
		wantValue  string
		wantSource string
		wantErr    bool
	}{
		{
			name: "extract from x-api-key metadata",
			config: &ExtractionConfig{
				APIKey: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "x-api-key"},
				},
			},
			setupCtx: func() context.Context {
				md := metadata.Pairs("x-api-key", "grpc_api_key_123")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			wantValue:  "grpc_api_key_123",
			wantSource: "metadata:x-api-key",
			wantErr:    false,
		},
		{
			name: "no API key in metadata",
			config: &ExtractionConfig{
				APIKey: []ExtractionSource{
					{Type: ExtractionTypeHeader, Name: "x-api-key"},
				},
			},
			setupCtx: func() context.Context {
				return context.Background()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			extractor := NewExtractor(tt.config)
			ctx := tt.setupCtx()

			creds, err := extractor.ExtractAPIKeyFromGRPC(ctx)
			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrNoCredentials)
				assert.Nil(t, creds)
			} else {
				require.NoError(t, err)
				require.NotNil(t, creds)
				assert.Equal(t, CredentialTypeAPIKey, creds.Type)
				assert.Equal(t, tt.wantValue, creds.Value)
				assert.Equal(t, tt.wantSource, creds.Source)
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setupReq func(*http.Request)
		expected string
	}{
		{
			name: "valid bearer token",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer my_token_123")
			},
			expected: "my_token_123",
		},
		{
			name: "no authorization header",
			setupReq: func(r *http.Request) {
				// No header
			},
			expected: "",
		},
		{
			name: "wrong prefix",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
			},
			expected: "",
		},
		{
			name: "bearer prefix only",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer ")
			},
			expected: "",
		},
		{
			name: "token with whitespace",
			setupReq: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer   token_with_spaces   ")
			},
			expected: "token_with_spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupReq(req)

			token := ExtractBearerToken(req)
			assert.Equal(t, tt.expected, token)
		})
	}
}

func TestExtractBearerTokenFromGRPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setupCtx func() context.Context
		expected string
	}{
		{
			name: "valid bearer token",
			setupCtx: func() context.Context {
				md := metadata.Pairs("authorization", "Bearer grpc_token_123")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expected: "grpc_token_123",
		},
		{
			name: "no metadata",
			setupCtx: func() context.Context {
				return context.Background()
			},
			expected: "",
		},
		{
			name: "no authorization in metadata",
			setupCtx: func() context.Context {
				md := metadata.Pairs("other-key", "value")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expected: "",
		},
		{
			name: "wrong prefix",
			setupCtx: func() context.Context {
				md := metadata.Pairs("authorization", "Basic dXNlcjpwYXNz")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expected: "",
		},
		{
			name: "token with whitespace",
			setupCtx: func() context.Context {
				md := metadata.Pairs("authorization", "Bearer   token_with_spaces   ")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expected: "token_with_spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.setupCtx()
			token := ExtractBearerTokenFromGRPC(ctx)
			assert.Equal(t, tt.expected, token)
		})
	}
}

func TestCredentialTypeConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, CredentialType("jwt"), CredentialTypeJWT)
	assert.Equal(t, CredentialType("apikey"), CredentialTypeAPIKey)
	assert.Equal(t, CredentialType("basic"), CredentialTypeBasic)
}

func TestCredentials_Fields(t *testing.T) {
	t.Parallel()

	creds := &Credentials{
		Type:   CredentialTypeJWT,
		Value:  "token_value",
		Source: "header:Authorization",
	}

	assert.Equal(t, CredentialTypeJWT, creds.Type)
	assert.Equal(t, "token_value", creds.Value)
	assert.Equal(t, "header:Authorization", creds.Source)
}
