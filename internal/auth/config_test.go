package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/auth/apikey"
	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
)

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled without auth methods",
			config: &Config{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "at least one authentication method must be configured",
		},
		{
			name: "enabled with JWT",
			config: &Config{
				Enabled: true,
				JWT: &jwt.Config{
					Enabled: true,
					JWKSUrl: "https://example.com/.well-known/jwks.json",
				},
			},
			wantErr: false,
		},
		{
			name: "enabled with API key",
			config: &Config{
				Enabled: true,
				APIKey: &apikey.Config{
					Enabled: true,
					Store: &apikey.StoreConfig{
						Type: "memory",
						Keys: []apikey.StaticKey{
							{ID: "key1", Hash: "hash1"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "enabled with mTLS",
			config: &Config{
				Enabled: true,
				MTLS: &mtls.Config{
					Enabled: true,
					CACert:  "cert-data",
				},
			},
			wantErr: false,
		},
		{
			name: "enabled with OIDC",
			config: &Config{
				Enabled: true,
				OIDC: &oidc.Config{
					Enabled: true,
					Providers: []oidc.ProviderConfig{
						{
							Name:     "test",
							Issuer:   "https://issuer.example.com",
							ClientID: "client-id",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid JWT config",
			config: &Config{
				Enabled: true,
				JWT: &jwt.Config{
					Enabled: true,
					// Missing JWKSUrl
				},
			},
			wantErr: true,
			errMsg:  "jwt config",
		},
		{
			name: "invalid extraction config",
			config: &Config{
				Enabled: true,
				JWT: &jwt.Config{
					Enabled: true,
					JWKSUrl: "https://example.com/.well-known/jwks.json",
				},
				Extraction: &ExtractionConfig{
					JWT: []ExtractionSource{
						{Type: "invalid", Name: "test"},
					},
				},
			},
			wantErr: true,
			errMsg:  "extraction config",
		},
		{
			name: "invalid cache config - negative TTL",
			config: &Config{
				Enabled: true,
				JWT: &jwt.Config{
					Enabled: true,
					JWKSUrl: "https://example.com/.well-known/jwks.json",
				},
				Cache: &AuthCacheConfig{
					Enabled: true,
					TTL:     -1 * time.Second,
				},
			},
			wantErr: true,
			errMsg:  "cache config",
		},
		{
			name: "invalid cache config - negative maxSize",
			config: &Config{
				Enabled: true,
				JWT: &jwt.Config{
					Enabled: true,
					JWKSUrl: "https://example.com/.well-known/jwks.json",
				},
				Cache: &AuthCacheConfig{
					Enabled: true,
					MaxSize: -1,
				},
			},
			wantErr: true,
			errMsg:  "cache config",
		},
		{
			name: "invalid cache config - invalid type",
			config: &Config{
				Enabled: true,
				JWT: &jwt.Config{
					Enabled: true,
					JWKSUrl: "https://example.com/.well-known/jwks.json",
				},
				Cache: &AuthCacheConfig{
					Enabled: true,
					Type:    "invalid",
				},
			},
			wantErr: true,
			errMsg:  "cache config",
		},
		{
			name: "valid cache config - memory",
			config: &Config{
				Enabled: true,
				JWT: &jwt.Config{
					Enabled: true,
					JWKSUrl: "https://example.com/.well-known/jwks.json",
				},
				Cache: &AuthCacheConfig{
					Enabled: true,
					Type:    "memory",
					TTL:     5 * time.Minute,
					MaxSize: 1000,
				},
			},
			wantErr: false,
		},
		{
			name: "valid cache config - redis",
			config: &Config{
				Enabled: true,
				JWT: &jwt.Config{
					Enabled: true,
					JWKSUrl: "https://example.com/.well-known/jwks.json",
				},
				Cache: &AuthCacheConfig{
					Enabled: true,
					Type:    "redis",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfig_IsJWTEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name:   "nil config",
			config: nil,
			want:   false,
		},
		{
			name:   "nil JWT",
			config: &Config{},
			want:   false,
		},
		{
			name: "JWT disabled",
			config: &Config{
				JWT: &jwt.Config{Enabled: false},
			},
			want: false,
		},
		{
			name: "JWT enabled",
			config: &Config{
				JWT: &jwt.Config{Enabled: true},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.IsJWTEnabled()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_IsAPIKeyEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name:   "nil config",
			config: nil,
			want:   false,
		},
		{
			name:   "nil APIKey",
			config: &Config{},
			want:   false,
		},
		{
			name: "APIKey disabled",
			config: &Config{
				APIKey: &apikey.Config{Enabled: false},
			},
			want: false,
		},
		{
			name: "APIKey enabled",
			config: &Config{
				APIKey: &apikey.Config{Enabled: true},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.IsAPIKeyEnabled()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_IsMTLSEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name:   "nil config",
			config: nil,
			want:   false,
		},
		{
			name:   "nil MTLS",
			config: &Config{},
			want:   false,
		},
		{
			name: "MTLS disabled",
			config: &Config{
				MTLS: &mtls.Config{Enabled: false},
			},
			want: false,
		},
		{
			name: "MTLS enabled",
			config: &Config{
				MTLS: &mtls.Config{Enabled: true},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.IsMTLSEnabled()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_IsOIDCEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name:   "nil config",
			config: nil,
			want:   false,
		},
		{
			name:   "nil OIDC",
			config: &Config{},
			want:   false,
		},
		{
			name: "OIDC disabled",
			config: &Config{
				OIDC: &oidc.Config{Enabled: false},
			},
			want: false,
		},
		{
			name: "OIDC enabled",
			config: &Config{
				OIDC: &oidc.Config{Enabled: true},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.IsOIDCEnabled()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfig_ShouldSkipPath(t *testing.T) {
	t.Parallel()

	config := &Config{
		SkipPaths: []string{
			"/health",
			"/metrics",
			"/api/public/*",
		},
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "exact match - health",
			path: "/health",
			want: true,
		},
		{
			name: "exact match - metrics",
			path: "/metrics",
			want: true,
		},
		{
			name: "wildcard match",
			path: "/api/public/resource",
			want: true,
		},
		{
			name: "wildcard match - nested",
			path: "/api/public/resource/sub",
			want: true,
		},
		{
			name: "no match",
			path: "/api/private/resource",
			want: false,
		},
		{
			name: "partial match - not wildcard",
			path: "/healthcheck",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := config.ShouldSkipPath(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{
			name:    "exact match",
			pattern: "/health",
			path:    "/health",
			want:    true,
		},
		{
			name:    "no match",
			pattern: "/health",
			path:    "/metrics",
			want:    false,
		},
		{
			name:    "wildcard match",
			pattern: "/api/*",
			path:    "/api/resource",
			want:    true,
		},
		{
			name:    "wildcard match - exact prefix",
			pattern: "/api/*",
			path:    "/api/",
			want:    true,
		},
		{
			name:    "wildcard no match",
			pattern: "/api/*",
			path:    "/other/resource",
			want:    false,
		},
		{
			name:    "empty pattern",
			pattern: "",
			path:    "/any",
			want:    false,
		},
		{
			name:    "just wildcard",
			pattern: "*",
			path:    "/any/path",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := matchPath(tt.pattern, tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.False(t, config.Enabled)
	assert.NotNil(t, config.Extraction)
	assert.Len(t, config.Extraction.JWT, 1)
	assert.Equal(t, ExtractionTypeHeader, config.Extraction.JWT[0].Type)
	assert.Equal(t, "Authorization", config.Extraction.JWT[0].Name)
	assert.Equal(t, "Bearer ", config.Extraction.JWT[0].Prefix)
	assert.Len(t, config.Extraction.APIKey, 1)
	assert.Equal(t, ExtractionTypeHeader, config.Extraction.APIKey[0].Type)
	assert.Equal(t, "X-API-Key", config.Extraction.APIKey[0].Name)
	assert.NotNil(t, config.Cache)
	assert.True(t, config.Cache.Enabled)
	assert.Equal(t, 5*time.Minute, config.Cache.TTL)
	assert.Equal(t, 10000, config.Cache.MaxSize)
	assert.Equal(t, "memory", config.Cache.Type)
}

func TestValidateExtractionSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		source  ExtractionSource
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid header",
			source: ExtractionSource{
				Type: ExtractionTypeHeader,
				Name: "Authorization",
			},
			wantErr: false,
		},
		{
			name: "valid cookie",
			source: ExtractionSource{
				Type: ExtractionTypeCookie,
				Name: "session",
			},
			wantErr: false,
		},
		{
			name: "valid query",
			source: ExtractionSource{
				Type: ExtractionTypeQuery,
				Name: "token",
			},
			wantErr: false,
		},
		{
			name: "valid metadata",
			source: ExtractionSource{
				Type: ExtractionTypeMetadata,
				Name: "authorization",
			},
			wantErr: false,
		},
		{
			name: "invalid type",
			source: ExtractionSource{
				Type: "invalid",
				Name: "test",
			},
			wantErr: true,
			errMsg:  "invalid extraction type",
		},
		{
			name: "missing name",
			source: ExtractionSource{
				Type: ExtractionTypeHeader,
				Name: "",
			},
			wantErr: true,
			errMsg:  "name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateExtractionSource(tt.source)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
