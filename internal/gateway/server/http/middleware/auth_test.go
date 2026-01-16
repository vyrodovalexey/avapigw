package middleware

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/basic"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/authz"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"go.uber.org/zap"
)

// Mock JWT Validator
type mockJWTValidator struct {
	validateFunc func(ctx context.Context, token string) (*jwt.Claims, error)
}

func (m *mockJWTValidator) Validate(ctx context.Context, token string) (*jwt.Claims, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return &jwt.Claims{
		Subject: "test-user",
		Roles:   []string{"admin"},
		Groups:  []string{"developers"},
		Scope:   "read write",
	}, nil
}

// Mock JWT Extractor
type mockJWTExtractor struct {
	extractFunc func(r *http.Request) (string, error)
}

func (m *mockJWTExtractor) Extract(r *http.Request) (string, error) {
	if m.extractFunc != nil {
		return m.extractFunc(r)
	}
	return "mock-token", nil
}

// Mock API Key Store
type mockAPIKeyStore struct {
	keys map[string]*apikey.APIKey
}

func (m *mockAPIKeyStore) Get(ctx context.Context, keyHash string) (*apikey.APIKey, error) {
	if key, ok := m.keys[keyHash]; ok {
		return key, nil
	}
	return nil, apikey.ErrKeyNotFound
}

func (m *mockAPIKeyStore) List(ctx context.Context) ([]*apikey.APIKey, error) {
	var keys []*apikey.APIKey
	for _, k := range m.keys {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockAPIKeyStore) Create(ctx context.Context, key *apikey.APIKey) error {
	m.keys[key.KeyHash] = key
	return nil
}

func (m *mockAPIKeyStore) Delete(ctx context.Context, keyHash string) error {
	delete(m.keys, keyHash)
	return nil
}

func (m *mockAPIKeyStore) Validate(ctx context.Context, keyHash string) (bool, error) {
	_, ok := m.keys[keyHash]
	return ok, nil
}

// Mock API Key Extractor
type mockAPIKeyExtractor struct {
	extractFunc func(r *http.Request) (string, error)
}

func (m *mockAPIKeyExtractor) Extract(r *http.Request) (string, error) {
	if m.extractFunc != nil {
		return m.extractFunc(r)
	}
	return "mock-api-key", nil
}

// Mock Authorizer
type mockAuthorizer struct {
	authorizeFunc func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error)
}

func (m *mockAuthorizer) Authorize(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
	if m.authorizeFunc != nil {
		return m.authorizeFunc(ctx, subject, resource)
	}
	return &authz.Decision{Allowed: true}, nil
}

func TestDefaultAuthConfig(t *testing.T) {
	config := DefaultAuthConfig()

	assert.Equal(t, "jwt_claims", config.JWTClaimsKey)
	assert.Equal(t, "api_key", config.APIKeyKey)
	assert.True(t, config.RequireAuth)
	assert.False(t, config.AllowAnonymous)
	assert.True(t, config.ForwardAuthHeader)
}

func TestAuth_NoAuthRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &AuthConfig{
		RequireAuth: false,
	}

	router := gin.New()
	router.Use(Auth(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuth_RequireAuthNoCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &AuthConfig{
		RequireAuth: true,
		Logger:      zap.NewNop(),
	}

	router := gin.New()
	router.Use(Auth(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authentication required")
}

func TestAuth_AnonymousPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &AuthConfig{
		RequireAuth:    true,
		AllowAnonymous: true,
		AnonymousPaths: []string{"/public"},
	}

	router := gin.New()
	router.Use(Auth(config))
	router.GET("/public", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})
	router.GET("/private", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	t.Run("anonymous path allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/public", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("private path requires auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestAuth_NilConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(Auth(nil))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Default config requires auth, so should fail
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuth_SkipPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &AuthConfig{
		RequireAuth:  true,
		JWTEnabled:   true,
		JWTSkipPaths: []string{"/health"},
	}

	router := gin.New()
	router.Use(Auth(config))
	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Still requires auth because RequireAuth is true and no auth method succeeded
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		subject        *authz.Subject
		requiredRoles  []string
		expectedStatus int
	}{
		{
			name: "has required role",
			subject: &authz.Subject{
				User:  "test-user",
				Roles: []string{"admin", "user"},
			},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing required role",
			subject: &authz.Subject{
				User:  "test-user",
				Roles: []string{"user"},
			},
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "no subject in context",
			subject:        nil,
			requiredRoles:  []string{"admin"},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "has one of required roles",
			subject: &authz.Subject{
				User:  "test-user",
				Roles: []string{"editor"},
			},
			requiredRoles:  []string{"admin", "editor"},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				if tt.subject != nil {
					ctx := authz.ContextWithSubject(c.Request.Context(), tt.subject)
					c.Request = c.Request.WithContext(ctx)
				}
				c.Next()
			})
			router.Use(RequireRoles(tt.requiredRoles...))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestRequireScopes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		subject        *authz.Subject
		requiredScopes []string
		expectedStatus int
	}{
		{
			name: "has all required scopes",
			subject: &authz.Subject{
				User:   "test-user",
				Scopes: []string{"read", "write"},
			},
			requiredScopes: []string{"read", "write"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing required scope",
			subject: &authz.Subject{
				User:   "test-user",
				Scopes: []string{"read"},
			},
			requiredScopes: []string{"read", "write"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "no subject in context",
			subject:        nil,
			requiredScopes: []string{"read"},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				if tt.subject != nil {
					ctx := authz.ContextWithSubject(c.Request.Context(), tt.subject)
					c.Request = c.Request.WithContext(ctx)
				}
				c.Next()
			})
			router.Use(RequireScopes(tt.requiredScopes...))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestRequireGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		subject        *authz.Subject
		requiredGroups []string
		expectedStatus int
	}{
		{
			name: "has required group",
			subject: &authz.Subject{
				User:   "test-user",
				Groups: []string{"developers", "admins"},
			},
			requiredGroups: []string{"developers"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "missing required group",
			subject: &authz.Subject{
				User:   "test-user",
				Groups: []string{"users"},
			},
			requiredGroups: []string{"developers"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "no subject in context",
			subject:        nil,
			requiredGroups: []string{"developers"},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "has one of required groups",
			subject: &authz.Subject{
				User:   "test-user",
				Groups: []string{"admins"},
			},
			requiredGroups: []string{"developers", "admins"},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				if tt.subject != nil {
					ctx := authz.ContextWithSubject(c.Request.Context(), tt.subject)
					c.Request = c.Request.WithContext(ctx)
				}
				c.Next()
			})
			router.Use(RequireGroups(tt.requiredGroups...))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestOptionalAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := &AuthConfig{
		RequireAuth: true, // Will be overridden
	}

	router := gin.New()
	router.Use(OptionalAuth(config))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should succeed even without auth
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetJWTClaims(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns claims when set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		claims := &jwt.Claims{Subject: "test-user"}
		c.Set("jwt_claims", claims)

		result, ok := GetJWTClaims(c)
		assert.True(t, ok)
		assert.Equal(t, "test-user", result.Subject)
	})

	t.Run("returns false when not set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		result, ok := GetJWTClaims(c)
		assert.False(t, ok)
		assert.Nil(t, result)
	})

	t.Run("returns false when wrong type", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("jwt_claims", "not a claims object")

		result, ok := GetJWTClaims(c)
		assert.False(t, ok)
		assert.Nil(t, result)
	})
}

func TestGetAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns API key when set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		key := &apikey.APIKey{ID: "test-key"}
		c.Set("api_key", key)

		result, ok := GetAPIKey(c)
		assert.True(t, ok)
		assert.Equal(t, "test-key", result.ID)
	})

	t.Run("returns false when not set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		result, ok := GetAPIKey(c)
		assert.False(t, ok)
		assert.Nil(t, result)
	})
}

func TestGetSubject(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns subject when set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		subject := &authz.Subject{User: "test-user"}
		ctx := authz.ContextWithSubject(c.Request.Context(), subject)
		c.Request = c.Request.WithContext(ctx)

		result, ok := GetSubject(c)
		assert.True(t, ok)
		assert.Equal(t, "test-user", result.User)
	})

	t.Run("returns false when not set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		result, ok := GetSubject(c)
		assert.False(t, ok)
		assert.Nil(t, result)
	})
}

func TestSkipAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SkipAuth())
	router.GET("/test", func(c *gin.Context) {
		skip := ShouldSkipAuth(c)
		assert.True(t, skip)
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestShouldSkipAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns true when set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("skip_auth", true)

		assert.True(t, ShouldSkipAuth(c))
	})

	t.Run("returns false when not set", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		assert.False(t, ShouldSkipAuth(c))
	})

	t.Run("returns false when set to false", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set("skip_auth", false)

		assert.False(t, ShouldSkipAuth(c))
	})
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedToken string
		expectedOK    bool
	}{
		{
			name:          "valid bearer token",
			authHeader:    "Bearer my-token-123",
			expectedToken: "my-token-123",
			expectedOK:    true,
		},
		{
			name:          "bearer token with extra spaces",
			authHeader:    "Bearer   my-token-123  ",
			expectedToken: "my-token-123",
			expectedOK:    true,
		},
		{
			name:          "lowercase bearer",
			authHeader:    "bearer my-token-123",
			expectedToken: "my-token-123",
			expectedOK:    true,
		},
		{
			name:          "no auth header",
			authHeader:    "",
			expectedToken: "",
			expectedOK:    false,
		},
		{
			name:          "wrong prefix",
			authHeader:    "Basic dXNlcjpwYXNz",
			expectedToken: "",
			expectedOK:    false,
		},
		{
			name:          "bearer only",
			authHeader:    "Bearer",
			expectedToken: "",
			expectedOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			token, ok := ExtractBearerToken(req)
			assert.Equal(t, tt.expectedOK, ok)
			assert.Equal(t, tt.expectedToken, token)
		})
	}
}

func TestBasicAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a memory store and add a user
	store := basic.NewMemoryStore()
	_ = store.AddUser("testuser", "testpass", []string{"admin"}, []string{"developers"})

	validator := basic.NewValidator(store, "Test Realm", zap.NewNop())

	router := gin.New()
	router.Use(BasicAuth(validator, zap.NewNop()))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	t.Run("valid credentials", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		credentials := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
		req.Header.Set("Authorization", "Basic "+credentials)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("invalid credentials", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		credentials := base64.StdEncoding.EncodeToString([]byte("testuser:wrongpass"))
		req.Header.Set("Authorization", "Basic "+credentials)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Basic realm=")
	})

	t.Run("no credentials", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestBasicAuth_NilLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := basic.NewMemoryStore()
	_ = store.AddUser("testuser", "testpass", nil, nil)

	validator := basic.NewValidator(store, "Test Realm", nil)

	router := gin.New()
	router.Use(BasicAuth(validator, nil))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	credentials := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
	req.Header.Set("Authorization", "Basic "+credentials)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthorization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		authorizer     authz.Authorizer
		subject        *authz.Subject
		expectedStatus int
	}{
		{
			name: "allowed",
			authorizer: &mockAuthorizer{
				authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
					return &authz.Decision{Allowed: true}, nil
				},
			},
			subject:        &authz.Subject{User: "test-user"},
			expectedStatus: http.StatusOK,
		},
		{
			name: "denied",
			authorizer: &mockAuthorizer{
				authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
					return &authz.Decision{Allowed: false, Reason: "access denied"}, nil
				},
			},
			subject:        &authz.Subject{User: "test-user"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "error",
			authorizer: &mockAuthorizer{
				authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
					return nil, assert.AnError
				},
			},
			subject:        &authz.Subject{User: "test-user"},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(func(c *gin.Context) {
				if tt.subject != nil {
					ctx := authz.ContextWithSubject(c.Request.Context(), tt.subject)
					c.Request = c.Request.WithContext(ctx)
				}
				c.Next()
			})
			router.Use(Authorization(tt.authorizer, zap.NewNop()))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "OK")
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestAuthorization_NilLogger(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authorizer := &mockAuthorizer{
		authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
			return &authz.Decision{Allowed: true}, nil
		},
	}

	router := gin.New()
	router.Use(Authorization(authorizer, nil))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestClaimsToSubject(t *testing.T) {
	claims := &jwt.Claims{
		Subject: "user-123",
		Groups:  []string{"group1", "group2"},
		Roles:   []string{"admin", "user"},
		Scope:   "read write",
	}

	subject := core.ClaimsToSubject(claims)

	assert.Equal(t, "user-123", subject.User)
	assert.Equal(t, []string{"group1", "group2"}, subject.Groups)
	assert.Equal(t, []string{"admin", "user"}, subject.Roles)
	assert.Equal(t, []string{"read", "write"}, subject.Scopes)
}

func TestAPIKeyToSubject(t *testing.T) {
	key := &apikey.APIKey{
		ID:     "key-123",
		Name:   "Test Key",
		Scopes: []string{"read", "write"},
	}

	subject := core.APIKeyToSubject(key)

	assert.Equal(t, "key-123", subject.User)
	assert.Equal(t, []string{"read", "write"}, subject.Scopes)
	assert.Equal(t, "Test Key", subject.Metadata["api_key_name"])
}

func TestUserToSubject(t *testing.T) {
	user := &basic.User{
		Username: "testuser",
		Groups:   []string{"developers"},
		Roles:    []string{"admin"},
		Metadata: map[string]string{"department": "engineering"},
	}

	subject := core.UserToSubject(user)

	assert.Equal(t, "testuser", subject.User)
	assert.Equal(t, []string{"developers"}, subject.Groups)
	assert.Equal(t, []string{"admin"}, subject.Roles)
	assert.Equal(t, "engineering", subject.Metadata["department"])
}
