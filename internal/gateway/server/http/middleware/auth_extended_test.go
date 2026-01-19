package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/authz"
	"github.com/vyrodovalexey/avapigw/internal/gateway/core"
	"go.uber.org/zap"
)

// TestExtractCredentialsFromHTTPRequest tests the extractCredentialsFromHTTPRequest function
func TestExtractCredentialsFromHTTPRequest(t *testing.T) {
	tests := []struct {
		name              string
		setupRequest      func(*http.Request)
		expectBearerToken string
		expectAPIKey      string
		expectBasicAuth   bool
	}{
		{
			name: "bearer token extraction",
			setupRequest: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer test-token-123")
			},
			expectBearerToken: "test-token-123",
		},
		{
			name: "bearer token lowercase",
			setupRequest: func(r *http.Request) {
				r.Header.Set("Authorization", "bearer test-token-lowercase")
			},
			expectBearerToken: "test-token-lowercase",
		},
		{
			name: "API key extraction",
			setupRequest: func(r *http.Request) {
				r.Header.Set("X-API-Key", "my-api-key")
			},
			expectAPIKey: "my-api-key",
		},
		{
			name: "basic auth extraction",
			setupRequest: func(r *http.Request) {
				r.SetBasicAuth("user", "pass")
			},
			expectBasicAuth: true,
		},
		{
			name: "all credentials",
			setupRequest: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer token")
				r.Header.Set("X-API-Key", "api-key")
			},
			expectBearerToken: "token",
			expectAPIKey:      "api-key",
		},
		{
			name:         "no credentials",
			setupRequest: func(r *http.Request) {},
		},
		{
			name: "non-bearer authorization",
			setupRequest: func(r *http.Request) {
				r.Header.Set("Authorization", "Digest something")
			},
			expectBearerToken: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupRequest(req)

			creds := extractCredentialsFromHTTPRequest(req)

			assert.Equal(t, tt.expectBearerToken, creds.BearerToken)
			assert.Equal(t, tt.expectAPIKey, creds.APIKey)
			if tt.expectBasicAuth {
				assert.NotNil(t, creds.BasicAuth)
				assert.Equal(t, "user", creds.BasicAuth.Username)
				assert.Equal(t, "pass", creds.BasicAuth.Password)
			}
		})
	}
}

// TestAuthWithCore tests the AuthWithCore middleware
func TestAuthWithCore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("anonymous path allowed", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			RequireAuth:    true,
			AllowAnonymous: true,
			AnonymousPaths: []string{"/public"},
		})

		router := gin.New()
		router.Use(AuthWithCore(authCore, nil, zap.NewNop()))
		router.GET("/public", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/public", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("requires auth when not anonymous", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			BaseConfig: core.BaseConfig{
				Logger: zap.NewNop(),
			},
			RequireAuth:    true,
			AllowAnonymous: false,
		})

		router := gin.New()
		router.Use(AuthWithCore(authCore, nil, zap.NewNop()))
		router.GET("/private", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("nil logger uses nop", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: false,
		})

		router := gin.New()
		router.Use(AuthWithCore(authCore, nil, nil))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("with authorizer allowed", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: false,
		})

		authorizer := &mockAuthorizer{
			authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
				return &authz.Decision{Allowed: true}, nil
			},
		}

		router := gin.New()
		router.Use(AuthWithCore(authCore, authorizer, zap.NewNop()))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("with authorizer denied", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: false,
		})

		authorizer := &mockAuthorizer{
			authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
				return &authz.Decision{Allowed: false, Reason: "denied"}, nil
			},
		}

		router := gin.New()
		router.Use(AuthWithCore(authCore, authorizer, zap.NewNop()))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("with authorizer error", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			RequireAuth: false,
		})

		authorizer := &mockAuthorizer{
			authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
				return nil, errors.New("authorization error")
			},
		}

		router := gin.New()
		router.Use(AuthWithCore(authCore, authorizer, zap.NewNop()))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestExtractCredentialsFromRequest tests the extractCredentialsFromRequest function
func TestExtractCredentialsFromRequest(t *testing.T) {
	tests := []struct {
		name         string
		config       *AuthConfig
		setupRequest func(*http.Request)
		expectToken  bool
		expectAPIKey bool
		expectBasic  bool
	}{
		{
			name: "JWT enabled with token",
			config: &AuthConfig{
				JWTEnabled: true,
			},
			setupRequest: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer test-token")
			},
			expectToken: true,
		},
		{
			name: "API key enabled",
			config: &AuthConfig{
				APIKeyEnabled: true,
			},
			setupRequest: func(r *http.Request) {
				r.Header.Set("X-API-Key", "test-key")
			},
			expectAPIKey: true,
		},
		{
			name: "Basic auth enabled",
			config: &AuthConfig{
				BasicEnabled: true,
			},
			setupRequest: func(r *http.Request) {
				r.SetBasicAuth("user", "pass")
			},
			expectBasic: true,
		},
		{
			name: "all disabled",
			config: &AuthConfig{
				JWTEnabled:    false,
				APIKeyEnabled: false,
				BasicEnabled:  false,
			},
			setupRequest: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer test-token")
				r.Header.Set("X-API-Key", "test-key")
			},
			expectToken:  false,
			expectAPIKey: false,
			expectBasic:  false,
		},
		{
			name: "custom JWT extractor",
			config: &AuthConfig{
				JWTEnabled: true,
				JWTExtractor: &mockJWTExtractor{
					extractFunc: func(r *http.Request) (string, error) {
						return "custom-token", nil
					},
				},
			},
			setupRequest: func(r *http.Request) {},
			expectToken:  true,
		},
		{
			name: "custom API key extractor",
			config: &AuthConfig{
				APIKeyEnabled: true,
				APIKeyExtractor: &mockAPIKeyExtractor{
					extractFunc: func(r *http.Request) (string, error) {
						return "custom-api-key", nil
					},
				},
			},
			setupRequest: func(r *http.Request) {},
			expectAPIKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tt.setupRequest(req)

			creds := extractCredentialsFromRequest(req, tt.config)

			if tt.expectToken {
				assert.NotEmpty(t, creds.BearerToken)
			} else {
				assert.Empty(t, creds.BearerToken)
			}

			if tt.expectAPIKey {
				assert.NotEmpty(t, creds.APIKey)
			} else {
				assert.Empty(t, creds.APIKey)
			}

			if tt.expectBasic {
				assert.NotNil(t, creds.BasicAuth)
			} else {
				assert.Nil(t, creds.BasicAuth)
			}
		})
	}
}

// TestStoreAuthResultInContext tests the storeAuthResultInContext function
func TestStoreAuthResultInContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		result       *core.AuthResult
		config       *AuthConfig
		checkContext func(*testing.T, *gin.Context)
	}{
		{
			name: "not authenticated",
			result: &core.AuthResult{
				Authenticated: false,
			},
			config: DefaultAuthConfig(),
			checkContext: func(t *testing.T, c *gin.Context) {
				_, exists := c.Get("jwt_claims")
				assert.False(t, exists)
			},
		},
		{
			name: "JWT authenticated",
			result: &core.AuthResult{
				Authenticated: true,
				Method:        "jwt",
				JWTClaims:     &jwt.Claims{Subject: "test-user"},
			},
			config: DefaultAuthConfig(),
			checkContext: func(t *testing.T, c *gin.Context) {
				claims, exists := c.Get("jwt_claims")
				assert.True(t, exists)
				assert.NotNil(t, claims)
			},
		},
		{
			name: "API key authenticated",
			result: &core.AuthResult{
				Authenticated: true,
				Method:        "apikey",
				APIKey:        &apikey.APIKey{ID: "key-1"},
			},
			config: DefaultAuthConfig(),
			checkContext: func(t *testing.T, c *gin.Context) {
				key, exists := c.Get("api_key")
				assert.True(t, exists)
				assert.NotNil(t, key)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

			storeAuthResultInContext(c, tt.result, tt.config)

			tt.checkContext(t, c)
		})
	}
}

// TestAuthWithAuthorizationEnabled tests Auth middleware with authorization
func TestAuthWithAuthorizationEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("authorization allowed", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
				return &authz.Decision{Allowed: true}, nil
			},
		}

		config := &AuthConfig{
			RequireAuth:  false,
			AuthzEnabled: true,
			Authorizer:   authorizer,
			Logger:       zap.NewNop(),
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
	})

	t.Run("authorization denied", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
				return &authz.Decision{Allowed: false, Reason: "access denied"}, nil
			},
		}

		config := &AuthConfig{
			RequireAuth:  false,
			AuthzEnabled: true,
			Authorizer:   authorizer,
			Logger:       zap.NewNop(),
		}

		router := gin.New()
		router.Use(Auth(config))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("authorization error", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
				return nil, errors.New("authorization error")
			},
		}

		config := &AuthConfig{
			RequireAuth:  false,
			AuthzEnabled: true,
			Authorizer:   authorizer,
			Logger:       zap.NewNop(),
		}

		router := gin.New()
		router.Use(Auth(config))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("authorization skip path", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			authorizeFunc: func(ctx context.Context, subject *authz.Subject, resource *authz.Resource) (*authz.Decision, error) {
				return &authz.Decision{Allowed: false}, nil
			},
		}

		config := &AuthConfig{
			RequireAuth:    false,
			AuthzEnabled:   true,
			Authorizer:     authorizer,
			AuthzSkipPaths: []string{"/skip"},
			Logger:         zap.NewNop(),
		}

		router := gin.New()
		router.Use(Auth(config))
		router.GET("/skip", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		req := httptest.NewRequest(http.MethodGet, "/skip", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestConfigureAuthValidators tests the configureAuthValidators function
func TestConfigureAuthValidators(t *testing.T) {
	t.Run("with API key validator", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{})
		store := &mockAPIKeyStore{keys: map[string]*apikey.APIKey{}}
		config := &AuthConfig{
			APIKeyValidator: apikey.NewValidator(store, zap.NewNop()),
		}

		configureAuthValidators(authCore, config)
		// No panic means success
	})

	t.Run("with all validators nil", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{})
		config := &AuthConfig{}

		configureAuthValidators(authCore, config)
		// No panic means success
	})
}

// TestBuildSkipPathsMap tests the buildSkipPathsMap function
func TestBuildSkipPathsMap(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		expected map[string]bool
	}{
		{
			name:     "empty paths",
			paths:    []string{},
			expected: map[string]bool{},
		},
		{
			name:  "single path",
			paths: []string{"/health"},
			expected: map[string]bool{
				"/health": true,
			},
		},
		{
			name:  "multiple paths",
			paths: []string{"/health", "/ready", "/metrics"},
			expected: map[string]bool{
				"/health":  true,
				"/ready":   true,
				"/metrics": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSkipPathsMap(tt.paths)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestOptionalAuthNilConfig tests OptionalAuth with nil config
func TestOptionalAuthNilConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(OptionalAuth(nil))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestHandleAuthRequired tests the handleAuthRequired function
func TestHandleAuthRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("basic auth only adds WWW-Authenticate header", func(t *testing.T) {
		authCore := core.NewAuthCore(core.AuthCoreConfig{
			BasicEnabled:  true,
			JWTEnabled:    false,
			APIKeyEnabled: false,
		})

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

		handleAuthRequired(c, authCore, zap.NewNop(), "/test")

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Basic realm=")
	})
}
