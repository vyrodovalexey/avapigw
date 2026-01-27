package auth

import (
	"context"
	"crypto/tls"
	crypto_x509 "crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockJWTValidator is a mock implementation of jwt.Validator for testing.
type mockJWTValidator struct {
	claims *jwt.Claims
	err    error
}

func (m *mockJWTValidator) Validate(_ context.Context, _ string) (*jwt.Claims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

func (m *mockJWTValidator) ValidateWithOptions(_ context.Context, _ string, _ jwt.ValidationOptions) (*jwt.Claims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

// mockAPIKeyValidator is a mock implementation of apikey.Validator for testing.
type mockAPIKeyValidator struct {
	keyInfo *apikey.KeyInfo
	err     error
}

func (m *mockAPIKeyValidator) Validate(_ context.Context, _ string) (*apikey.KeyInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.keyInfo, nil
}

func (m *mockAPIKeyValidator) Close() error {
	return nil
}

func TestNewAuthenticator(t *testing.T) {
	t.Parallel()

	t.Run("nil config returns error", func(t *testing.T) {
		t.Parallel()

		auth, err := NewAuthenticator(nil)
		assert.Error(t, err)
		assert.Nil(t, auth)
	})

	t.Run("disabled config", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: false,
		}

		auth, err := NewAuthenticator(config)
		require.NoError(t, err)
		assert.NotNil(t, auth)
	})

	t.Run("with logger option", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: false,
		}

		auth, err := NewAuthenticator(config,
			WithAuthenticatorLogger(observability.NopLogger()),
		)
		require.NoError(t, err)
		assert.NotNil(t, auth)
	})

	t.Run("with metrics option", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: false,
		}

		auth, err := NewAuthenticator(config,
			WithAuthenticatorMetrics(NewMetrics("test")),
		)
		require.NoError(t, err)
		assert.NotNil(t, auth)
	})
}

func TestAuthenticator_Authenticate_SkipPath(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:   true,
		SkipPaths: []string{"/health", "/metrics", "/api/public/*"},
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

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"health endpoint", "/health", true},
		{"metrics endpoint", "/metrics", true},
		{"public API", "/api/public/docs", true},
		{"protected API", "/api/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if !tt.expected {
				req.Header.Set("Authorization", "Bearer test-token")
			}

			identity, err := auth.Authenticate(req)
			if tt.expected {
				require.NoError(t, err)
				assert.Equal(t, "anonymous", identity.Subject)
				assert.Equal(t, AuthTypeAnonymous, identity.AuthType)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, identity)
			}
		})
	}
}

func TestAuthenticator_Authenticate_JWT(t *testing.T) {
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
		claims: &jwt.Claims{
			Subject:  "user123",
			Issuer:   "test-issuer",
			Audience: jwt.Audience{"api"},
		},
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)
	assert.Equal(t, "user123", identity.Subject)
	assert.Equal(t, "test-issuer", identity.Issuer)
	assert.Equal(t, AuthTypeJWT, identity.AuthType)
}

func TestAuthenticator_Authenticate_APIKey(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		APIKey: &apikey.Config{
			Enabled: true,
		},
		Extraction: &ExtractionConfig{
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-API-Key"},
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

	auth, err := NewAuthenticator(config,
		WithAPIKeyValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("X-API-Key", "valid-api-key")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)
	assert.Equal(t, "key-123", identity.Subject)
	assert.Equal(t, AuthTypeAPIKey, identity.AuthType)
	assert.Equal(t, []string{"api-user"}, identity.Roles)
	assert.Equal(t, []string{"read", "write"}, identity.Scopes)
}

func TestAuthenticator_Authenticate_NoCredentials(t *testing.T) {
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

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Request without credentials
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	identity, err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCredentials)
	assert.Nil(t, identity)
}

func TestAuthenticator_Authenticate_AllowAnonymous(t *testing.T) {
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

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Request without credentials but anonymous allowed
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)
	assert.Equal(t, "anonymous", identity.Subject)
	assert.Equal(t, AuthTypeAnonymous, identity.AuthType)
}

func TestAuthenticator_Authenticate_InvalidToken(t *testing.T) {
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
		err: ErrInvalidToken,
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	identity, err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Nil(t, identity)
}

func TestAuthenticator_HTTPMiddleware_Success(t *testing.T) {
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

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	nextCalled := false
	var capturedIdentity *Identity
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		capturedIdentity, _ = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	middleware := auth.HTTPMiddleware()
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotNil(t, capturedIdentity)
	assert.Equal(t, "user123", capturedIdentity.Subject)
}

func TestAuthenticator_HTTPMiddleware_Unauthorized(t *testing.T) {
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

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	middleware := auth.HTTPMiddleware()
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, "Bearer", rr.Header().Get("WWW-Authenticate"))

	var response map[string]string
	err = json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "authentication required", response["error"])
}

func TestAuthenticator_HTTPMiddleware_ExpiredToken(t *testing.T) {
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
		err: ErrTokenExpired,
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	middleware := auth.HTTPMiddleware()
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer expired-token")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]string
	err = json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "token expired", response["error"])
}

func TestAuthenticator_HTTPMiddleware_InvalidToken(t *testing.T) {
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
		err: ErrInvalidToken,
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	middleware := auth.HTTPMiddleware()
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]string
	err = json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "invalid token", response["error"])
}

func TestAuthenticator_HTTPMiddleware_InvalidAPIKey(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		APIKey: &apikey.Config{
			Enabled: true,
		},
		Extraction: &ExtractionConfig{
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-API-Key"},
			},
		},
	}

	mockValidator := &mockAPIKeyValidator{
		err: ErrInvalidAPIKey,
	}

	auth, err := NewAuthenticator(config,
		WithAPIKeyValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	middleware := auth.HTTPMiddleware()
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("X-API-Key", "invalid-key")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]string
	err = json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "invalid API key", response["error"])
}

func TestAuthenticator_ClaimsToIdentity_WithClaimMapping(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
			ClaimMapping: &jwt.ClaimMapping{
				Roles:       "roles",
				Permissions: "permissions",
				Groups:      "groups",
				Scopes:      "scope",
				Email:       "email",
				Name:        "name",
			},
		},
	}

	expiresAt := time.Now().Add(time.Hour)
	claims := &jwt.Claims{
		Subject:   "user123",
		Issuer:    "test-issuer",
		Audience:  jwt.Audience{"api"},
		ExpiresAt: &jwt.Time{Time: expiresAt},
		Extra: map[string]interface{}{
			"roles":       []interface{}{"admin", "user"},
			"permissions": []interface{}{"read:all", "write:all"},
			"groups":      []interface{}{"engineering"},
			"scope":       []interface{}{"openid", "profile"},
			"email":       "user@example.com",
			"name":        "Test User",
		},
	}

	mockValidator := &mockJWTValidator{
		claims: claims,
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)

	assert.Equal(t, "user123", identity.Subject)
	assert.Equal(t, "test-issuer", identity.Issuer)
	assert.Equal(t, AuthTypeJWT, identity.AuthType)
	assert.Equal(t, []string{"admin", "user"}, identity.Roles)
	assert.Equal(t, []string{"read:all", "write:all"}, identity.Permissions)
	assert.Equal(t, []string{"engineering"}, identity.Groups)
	assert.Equal(t, []string{"openid", "profile"}, identity.Scopes)
	assert.Equal(t, "user@example.com", identity.Email)
	assert.Equal(t, "Test User", identity.Name)
}

func TestAuthenticator_KeyInfoToIdentity(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		APIKey: &apikey.Config{
			Enabled: true,
		},
		Extraction: &ExtractionConfig{
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-API-Key"},
			},
		},
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	mockValidator := &mockAPIKeyValidator{
		keyInfo: &apikey.KeyInfo{
			ID:        "key-123",
			Roles:     []string{"api-user", "reader"},
			Scopes:    []string{"read", "write"},
			ExpiresAt: &expiresAt,
			Metadata: map[string]string{
				"app": "test-app",
			},
		},
	}

	auth, err := NewAuthenticator(config,
		WithAPIKeyValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("X-API-Key", "valid-key")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)

	assert.Equal(t, "key-123", identity.Subject)
	assert.Equal(t, AuthTypeAPIKey, identity.AuthType)
	assert.Equal(t, []string{"api-user", "reader"}, identity.Roles)
	assert.Equal(t, []string{"read", "write"}, identity.Scopes)
	assert.Equal(t, "key-123", identity.ClientID)
	assert.Equal(t, expiresAt, identity.ExpiresAt)
	assert.Equal(t, "test-app", identity.Metadata["app"])
}

func TestAuthenticator_FallbackToAPIKey(t *testing.T) {
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
				{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
			},
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-API-Key"},
			},
		},
	}

	// JWT validator returns no credentials (no JWT provided)
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

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockJWT),
		WithAPIKeyValidator(mockAPIKey),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Request with only API key
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("X-API-Key", "valid-key")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)
	assert.Equal(t, "key-123", identity.Subject)
	assert.Equal(t, AuthTypeAPIKey, identity.AuthType)
}

func TestAuthenticator_InvalidSignature(t *testing.T) {
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
		err: ErrInvalidSignature,
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	middleware := auth.HTTPMiddleware()
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer tampered-token")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]string
	err = json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "invalid token", response["error"])
}

func TestAuthenticator_GenericError(t *testing.T) {
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
		err: errors.New("some generic error"),
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	middleware := auth.HTTPMiddleware()
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	var response map[string]string
	err = json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "authentication failed", response["error"])
}

func TestAuthenticator_ClaimsToIdentity_WithExpiresAt(t *testing.T) {
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

	expiresAt := time.Now().Add(time.Hour)
	claims := &jwt.Claims{
		Subject:   "user123",
		Issuer:    "test-issuer",
		Audience:  jwt.Audience{"api"},
		ExpiresAt: &jwt.Time{Time: expiresAt},
	}

	mockValidator := &mockJWTValidator{
		claims: claims,
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)

	assert.Equal(t, "user123", identity.Subject)
	assert.Equal(t, expiresAt.Unix(), identity.ExpiresAt.Unix())
}

func TestAuthenticator_ClaimsToIdentity_WithoutExpiresAt(t *testing.T) {
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

	claims := &jwt.Claims{
		Subject:   "user123",
		Issuer:    "test-issuer",
		Audience:  jwt.Audience{"api"},
		ExpiresAt: nil, // No expiration
	}

	mockValidator := &mockJWTValidator{
		claims: claims,
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)

	assert.Equal(t, "user123", identity.Subject)
	assert.True(t, identity.ExpiresAt.IsZero())
}

func TestAuthenticator_KeyInfoToIdentity_WithoutExpiresAt(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		APIKey: &apikey.Config{
			Enabled: true,
		},
		Extraction: &ExtractionConfig{
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-API-Key"},
			},
		},
	}

	mockValidator := &mockAPIKeyValidator{
		keyInfo: &apikey.KeyInfo{
			ID:        "key-123",
			Roles:     []string{"api-user"},
			ExpiresAt: nil, // No expiration
		},
	}

	auth, err := NewAuthenticator(config,
		WithAPIKeyValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("X-API-Key", "valid-key")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)

	assert.Equal(t, "key-123", identity.Subject)
	assert.True(t, identity.ExpiresAt.IsZero())
}

func TestAuthenticator_JWTValidationFails_FallbackToAPIKey(t *testing.T) {
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
				{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
			},
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-API-Key"},
			},
		},
	}

	// JWT validator fails with invalid token
	mockJWT := &mockJWTValidator{
		err: ErrInvalidToken,
	}

	// API key validator succeeds
	mockAPIKey := &mockAPIKeyValidator{
		keyInfo: &apikey.KeyInfo{
			ID:    "key-123",
			Roles: []string{"api-user"},
		},
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockJWT),
		WithAPIKeyValidator(mockAPIKey),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Request with both JWT and API key
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	req.Header.Set("X-API-Key", "valid-key")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)
	assert.Equal(t, "key-123", identity.Subject)
	assert.Equal(t, AuthTypeAPIKey, identity.AuthType)
}

func TestAuthenticator_BothAuthMethodsFail(t *testing.T) {
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
				{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
			},
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-API-Key"},
			},
		},
	}

	// Both validators fail
	mockJWT := &mockJWTValidator{
		err: ErrInvalidToken,
	}
	mockAPIKey := &mockAPIKeyValidator{
		err: ErrInvalidAPIKey,
	}

	auth, err := NewAuthenticator(config,
		WithJWTValidator(mockJWT),
		WithAPIKeyValidator(mockAPIKey),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	req.Header.Set("X-API-Key", "invalid-key")

	identity, err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Nil(t, identity)
}

// mockMTLSValidator is a mock implementation of mtls.Validator for testing.
type mockMTLSValidator struct {
	certInfo *mtls.CertificateInfo
	err      error
}

func (m *mockMTLSValidator) Validate(_ context.Context, _ *crypto_x509.Certificate, _ []*crypto_x509.Certificate) (*mtls.CertificateInfo, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.certInfo, nil
}

func TestWithMTLSValidator(t *testing.T) {
	t.Parallel()

	mockValidator := &mockMTLSValidator{}
	opt := WithMTLSValidator(mockValidator)

	a := &authenticator{}
	opt(a)

	assert.Equal(t, mockValidator, a.mtlsValidator)
}

func TestAuthenticator_MTLSAuthentication(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		MTLS: &mtls.Config{
			Enabled: true,
			ExtractIdentity: &mtls.IdentityExtractionConfig{
				SubjectField: "CN",
			},
		},
	}

	mockValidator := &mockMTLSValidator{
		certInfo: &mtls.CertificateInfo{
			SubjectDN:    "CN=test-client,O=Test Org",
			IssuerDN:     "CN=Test CA,O=Test Org",
			SerialNumber: "123456",
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			DNSNames:     []string{"test-client.example.com"},
			Fingerprint:  "abc123",
			Subject: &mtls.SubjectInfo{
				CommonName:   "test-client",
				Organization: []string{"Test Org"},
			},
		},
	}

	auth, err := NewAuthenticator(config,
		WithMTLSValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Create request with TLS connection and peer certificate
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*crypto_x509.Certificate{
			{}, // Mock certificate
		},
	}

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)
	assert.NotNil(t, identity)
	assert.Equal(t, AuthTypeMTLS, identity.AuthType)
	assert.NotNil(t, identity.CertificateInfo)
}

func TestAuthenticator_MTLSAuthentication_NoCertificate(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		MTLS: &mtls.Config{
			Enabled: true,
			ExtractIdentity: &mtls.IdentityExtractionConfig{
				SubjectField: "CN",
			},
		},
	}

	mockValidator := &mockMTLSValidator{
		err: mtls.ErrNoCertificate,
	}

	auth, err := NewAuthenticator(config,
		WithMTLSValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Request without TLS
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)

	identity, err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Nil(t, identity)
}

func TestAuthenticator_MTLSAuthentication_ValidationFails(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		MTLS: &mtls.Config{
			Enabled: true,
			ExtractIdentity: &mtls.IdentityExtractionConfig{
				SubjectField: "CN",
			},
		},
	}

	mockValidator := &mockMTLSValidator{
		err: mtls.ErrCertificateExpired,
	}

	auth, err := NewAuthenticator(config,
		WithMTLSValidator(mockValidator),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Create request with TLS connection and peer certificate
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*crypto_x509.Certificate{
			{}, // Mock certificate
		},
	}

	identity, err := auth.Authenticate(req)
	assert.Error(t, err)
	assert.Nil(t, identity)
}

func TestAuthenticator_MTLSFallbackToJWT(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		MTLS: &mtls.Config{
			Enabled: true,
			ExtractIdentity: &mtls.IdentityExtractionConfig{
				SubjectField: "CN",
			},
		},
		JWT: &jwt.Config{
			Enabled:    true,
			Algorithms: []string{"HS256"},
			StaticKeys: []jwt.StaticKey{
				{KeyID: "test", Algorithm: "HS256", Key: "dGVzdC1zZWNyZXQtdGVzdC1zZWNyZXQ="},
			},
		},
		Extraction: &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
			},
		},
	}

	// mTLS fails
	mockMTLS := &mockMTLSValidator{
		err: mtls.ErrCertificateExpired,
	}

	// JWT succeeds
	mockJWT := &mockJWTValidator{
		claims: &jwt.Claims{
			Subject:  "user123",
			Issuer:   "test-issuer",
			Audience: jwt.Audience{"api"},
		},
	}

	auth, err := NewAuthenticator(config,
		WithMTLSValidator(mockMTLS),
		WithJWTValidator(mockJWT),
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// Request with TLS and JWT
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*crypto_x509.Certificate{
			{}, // Mock certificate
		},
	}
	req.Header.Set("Authorization", "Bearer valid-token")

	identity, err := auth.Authenticate(req)
	require.NoError(t, err)
	assert.NotNil(t, identity)
	assert.Equal(t, AuthTypeJWT, identity.AuthType)
	assert.Equal(t, "user123", identity.Subject)
}
