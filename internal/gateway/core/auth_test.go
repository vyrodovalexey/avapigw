package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/basic"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
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
	return &jwt.Claims{Subject: "test-user"}, nil
}

// Mock API Key Validator
type mockAPIKeyValidator struct {
	validateFunc func(ctx context.Context, key string) (*apikey.APIKey, error)
}

func (m *mockAPIKeyValidator) Validate(ctx context.Context, key string) (*apikey.APIKey, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, key)
	}
	return &apikey.APIKey{ID: "test-key"}, nil
}

// Mock Basic Validator
type mockBasicValidator struct {
	validateFunc func(ctx context.Context, username, password string) (*basic.User, error)
	realm        string
}

func (m *mockBasicValidator) Validate(ctx context.Context, username, password string) (*basic.User, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, username, password)
	}
	return &basic.User{Username: username}, nil
}

func (m *mockBasicValidator) Realm() string {
	if m.realm != "" {
		return m.realm
	}
	return "Test Realm"
}

func TestNewAuthCore(t *testing.T) {
	t.Parallel()

	t.Run("creates with default config", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})

		assert.NotNil(t, core)
	})

	t.Run("initializes skip paths", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			BaseConfig: BaseConfig{
				SkipPaths: []string{"/health", "/ready"},
			},
		})

		assert.True(t, core.ShouldSkip("/health"))
		assert.True(t, core.ShouldSkip("/ready"))
		assert.False(t, core.ShouldSkip("/api"))
	})

	t.Run("initializes anonymous paths", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			AllowAnonymous: true,
			AnonymousPaths: []string{"/public"},
		})

		assert.True(t, core.IsAnonymousPath("/public"))
		assert.False(t, core.IsAnonymousPath("/private"))
	})
}

func TestAuthCore_WithValidators(t *testing.T) {
	t.Parallel()

	t.Run("sets JWT validator", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})
		validator := &mockJWTValidator{}

		result := core.WithJWTValidator(validator)

		assert.Equal(t, core, result)
		assert.Equal(t, validator, core.jwtValidator)
	})

	t.Run("sets API key validator", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})
		validator := &mockAPIKeyValidator{}

		result := core.WithAPIKeyValidator(validator)

		assert.Equal(t, core, result)
		assert.Equal(t, validator, core.apiKeyValidator)
	})

	t.Run("sets basic validator", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})
		validator := &mockBasicValidator{}

		result := core.WithBasicValidator(validator)

		assert.Equal(t, core, result)
		assert.Equal(t, validator, core.basicValidator)
	})
}

func TestAuthCore_Authenticate(t *testing.T) {
	t.Parallel()

	t.Run("authenticates with JWT", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			JWTEnabled: true,
		})
		core.WithJWTValidator(&mockJWTValidator{
			validateFunc: func(ctx context.Context, token string) (*jwt.Claims, error) {
				return &jwt.Claims{
					Subject: "user-123",
					Roles:   []string{"admin"},
				}, nil
			},
		})

		result := core.Authenticate(context.Background(), AuthCredentials{
			BearerToken: "valid-token",
		})

		assert.True(t, result.Authenticated)
		assert.Equal(t, "jwt", result.Method)
		assert.NotNil(t, result.JWTClaims)
		assert.NotNil(t, result.Subject)
		assert.Equal(t, "user-123", result.Subject.User)
	})

	t.Run("authenticates with API key", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			APIKeyEnabled: true,
		})
		core.WithAPIKeyValidator(&mockAPIKeyValidator{
			validateFunc: func(ctx context.Context, key string) (*apikey.APIKey, error) {
				return &apikey.APIKey{
					ID:     "key-123",
					Name:   "Test Key",
					Scopes: []string{"read"},
				}, nil
			},
		})

		result := core.Authenticate(context.Background(), AuthCredentials{
			APIKey: "valid-key",
		})

		assert.True(t, result.Authenticated)
		assert.Equal(t, "apikey", result.Method)
		assert.NotNil(t, result.APIKey)
		assert.NotNil(t, result.Subject)
		assert.Equal(t, "key-123", result.Subject.User)
	})

	t.Run("authenticates with basic auth", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			BasicEnabled: true,
		})
		core.WithBasicValidator(&mockBasicValidator{
			validateFunc: func(ctx context.Context, username, password string) (*basic.User, error) {
				return &basic.User{
					Username: username,
					Roles:    []string{"user"},
				}, nil
			},
		})

		result := core.Authenticate(context.Background(), AuthCredentials{
			BasicAuth: &BasicCredentials{
				Username: "testuser",
				Password: "testpass",
			},
		})

		assert.True(t, result.Authenticated)
		assert.Equal(t, "basic", result.Method)
		assert.NotNil(t, result.User)
		assert.NotNil(t, result.Subject)
		assert.Equal(t, "testuser", result.Subject.User)
	})

	t.Run("returns not authenticated when no credentials", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			JWTEnabled:    true,
			APIKeyEnabled: true,
			BasicEnabled:  true,
		})

		result := core.Authenticate(context.Background(), AuthCredentials{})

		assert.False(t, result.Authenticated)
	})

	t.Run("returns not authenticated when validation fails", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			JWTEnabled: true,
		})
		core.WithJWTValidator(&mockJWTValidator{
			validateFunc: func(ctx context.Context, token string) (*jwt.Claims, error) {
				return nil, errors.New("invalid token")
			},
		})

		result := core.Authenticate(context.Background(), AuthCredentials{
			BearerToken: "invalid-token",
		})

		assert.False(t, result.Authenticated)
	})

	t.Run("tries methods in order: JWT, API Key, Basic", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			JWTEnabled:    true,
			APIKeyEnabled: true,
			BasicEnabled:  true,
		})
		core.WithJWTValidator(&mockJWTValidator{
			validateFunc: func(ctx context.Context, token string) (*jwt.Claims, error) {
				return nil, errors.New("invalid")
			},
		})
		core.WithAPIKeyValidator(&mockAPIKeyValidator{
			validateFunc: func(ctx context.Context, key string) (*apikey.APIKey, error) {
				return &apikey.APIKey{ID: "key-123"}, nil
			},
		})

		result := core.Authenticate(context.Background(), AuthCredentials{
			BearerToken: "invalid-token",
			APIKey:      "valid-key",
		})

		assert.True(t, result.Authenticated)
		assert.Equal(t, "apikey", result.Method)
	})
}

func TestAuthCore_AuthenticateJWT(t *testing.T) {
	t.Parallel()

	t.Run("returns error when no validator", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})

		result := core.AuthenticateJWT(context.Background(), "token")

		assert.False(t, result.Authenticated)
		assert.Equal(t, ErrNoJWTValidator, result.Error)
	})

	t.Run("authenticates successfully", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})
		core.WithJWTValidator(&mockJWTValidator{})

		result := core.AuthenticateJWT(context.Background(), "valid-token")

		assert.True(t, result.Authenticated)
		assert.Equal(t, "jwt", result.Method)
	})
}

func TestAuthCore_AuthenticateAPIKey(t *testing.T) {
	t.Parallel()

	t.Run("returns error when no validator", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})

		result := core.AuthenticateAPIKey(context.Background(), "key")

		assert.False(t, result.Authenticated)
		assert.Equal(t, ErrNoAPIKeyValidator, result.Error)
	})

	t.Run("authenticates successfully", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})
		core.WithAPIKeyValidator(&mockAPIKeyValidator{})

		result := core.AuthenticateAPIKey(context.Background(), "valid-key")

		assert.True(t, result.Authenticated)
		assert.Equal(t, "apikey", result.Method)
	})
}

func TestAuthCore_AuthenticateBasic(t *testing.T) {
	t.Parallel()

	t.Run("returns error when no validator", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})

		result := core.AuthenticateBasic(context.Background(), "user", "pass")

		assert.False(t, result.Authenticated)
		assert.Equal(t, ErrNoBasicValidator, result.Error)
	})

	t.Run("authenticates successfully", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})
		core.WithBasicValidator(&mockBasicValidator{})

		result := core.AuthenticateBasic(context.Background(), "user", "pass")

		assert.True(t, result.Authenticated)
		assert.Equal(t, "basic", result.Method)
	})
}

func TestAuthCore_ShouldSkip(t *testing.T) {
	t.Parallel()

	t.Run("returns false when no skip paths", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})

		assert.False(t, core.ShouldSkip("/any/path"))
	})

	t.Run("returns true for skip paths", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			BaseConfig: BaseConfig{
				SkipPaths: []string{"/health", "/ready"},
			},
		})

		assert.True(t, core.ShouldSkip("/health"))
		assert.True(t, core.ShouldSkip("/ready"))
		assert.False(t, core.ShouldSkip("/api"))
	})
}

func TestAuthCore_IsAnonymousPath(t *testing.T) {
	t.Parallel()

	t.Run("returns false when anonymous not allowed", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			AllowAnonymous: false,
			AnonymousPaths: []string{"/public"},
		})

		assert.False(t, core.IsAnonymousPath("/public"))
	})

	t.Run("returns true for anonymous paths when allowed", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			AllowAnonymous: true,
			AnonymousPaths: []string{"/public"},
		})

		assert.True(t, core.IsAnonymousPath("/public"))
		assert.False(t, core.IsAnonymousPath("/private"))
	})
}

func TestAuthCore_RequireAuth(t *testing.T) {
	t.Parallel()

	t.Run("returns configured value", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{RequireAuth: true})
		assert.True(t, core.RequireAuth())

		core = NewAuthCore(AuthCoreConfig{RequireAuth: false})
		assert.False(t, core.RequireAuth())
	})
}

func TestAuthCore_AllowAnonymous(t *testing.T) {
	t.Parallel()

	t.Run("returns configured value", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{AllowAnonymous: true})
		assert.True(t, core.AllowAnonymous())

		core = NewAuthCore(AuthCoreConfig{AllowAnonymous: false})
		assert.False(t, core.AllowAnonymous())
	})
}

func TestAuthCore_BasicRealm(t *testing.T) {
	t.Parallel()

	t.Run("returns default when no validator", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})

		assert.Equal(t, "Restricted", core.BasicRealm())
	})

	t.Run("returns validator realm", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{})
		core.WithBasicValidator(&mockBasicValidator{realm: "Custom Realm"})

		assert.Equal(t, "Custom Realm", core.BasicRealm())
	})
}

func TestAuthCore_IsOnlyBasicAuth(t *testing.T) {
	t.Parallel()

	t.Run("returns true when only basic enabled", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			BasicEnabled:  true,
			JWTEnabled:    false,
			APIKeyEnabled: false,
		})

		assert.True(t, core.IsOnlyBasicAuth())
	})

	t.Run("returns false when other methods enabled", func(t *testing.T) {
		core := NewAuthCore(AuthCoreConfig{
			BasicEnabled: true,
			JWTEnabled:   true,
		})

		assert.False(t, core.IsOnlyBasicAuth())
	})
}

func TestAuthCredentials_HasCredentials(t *testing.T) {
	t.Parallel()

	t.Run("returns false when empty", func(t *testing.T) {
		creds := AuthCredentials{}
		assert.False(t, creds.HasCredentials())
	})

	t.Run("returns true with bearer token", func(t *testing.T) {
		creds := AuthCredentials{BearerToken: "token"}
		assert.True(t, creds.HasCredentials())
	})

	t.Run("returns true with API key", func(t *testing.T) {
		creds := AuthCredentials{APIKey: "key"}
		assert.True(t, creds.HasCredentials())
	})

	t.Run("returns true with basic auth", func(t *testing.T) {
		creds := AuthCredentials{BasicAuth: &BasicCredentials{Username: "user"}}
		assert.True(t, creds.HasCredentials())
	})
}

func TestClaimsToSubject(t *testing.T) {
	t.Parallel()

	claims := &jwt.Claims{
		Subject: "user-123",
		Groups:  []string{"group1", "group2"},
		Roles:   []string{"admin", "user"},
		Scope:   "read write",
	}

	subject := ClaimsToSubject(claims)

	assert.Equal(t, "user-123", subject.User)
	assert.Equal(t, []string{"group1", "group2"}, subject.Groups)
	assert.Equal(t, []string{"admin", "user"}, subject.Roles)
	assert.Equal(t, []string{"read", "write"}, subject.Scopes)
}

func TestAPIKeyToSubject(t *testing.T) {
	t.Parallel()

	key := &apikey.APIKey{
		ID:     "key-123",
		Name:   "Test Key",
		Scopes: []string{"read", "write"},
	}

	subject := APIKeyToSubject(key)

	assert.Equal(t, "key-123", subject.User)
	assert.Equal(t, []string{"read", "write"}, subject.Scopes)
	assert.Equal(t, "Test Key", subject.Metadata["api_key_name"])
}

func TestUserToSubject(t *testing.T) {
	t.Parallel()

	user := &basic.User{
		Username: "testuser",
		Groups:   []string{"developers"},
		Roles:    []string{"admin"},
		Metadata: map[string]string{"department": "engineering"},
	}

	subject := UserToSubject(user)

	assert.Equal(t, "testuser", subject.User)
	assert.Equal(t, []string{"developers"}, subject.Groups)
	assert.Equal(t, []string{"admin"}, subject.Roles)
	assert.Equal(t, "engineering", subject.Metadata["department"])
}

func TestAuthCore_WithLogger(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()
	core := NewAuthCore(AuthCoreConfig{
		BaseConfig: BaseConfig{
			Logger: logger,
		},
	})

	// Just ensure it doesn't panic
	assert.NotNil(t, core)
}
