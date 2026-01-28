package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBackendAuthConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *BackendAuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "valid jwt type",
			cfg: &BackendAuthConfig{
				Type: "jwt",
				JWT: &BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "static",
					StaticToken: "test-token",
				},
			},
			wantErr: false,
		},
		{
			name: "valid basic type",
			cfg: &BackendAuthConfig{
				Type: "basic",
				Basic: &BackendBasicAuthConfig{
					Enabled:  true,
					Username: "user",
					Password: "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "valid mtls type",
			cfg: &BackendAuthConfig{
				Type: "mtls",
				MTLS: &BackendMTLSAuthConfig{
					Enabled:  true,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid type",
			cfg: &BackendAuthConfig{
				Type: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid backend auth type",
		},
		{
			name: "empty type is valid",
			cfg: &BackendAuthConfig{
				Type: "",
			},
			wantErr: false,
		},
		{
			name: "jwt config validation error",
			cfg: &BackendAuthConfig{
				Type: "jwt",
				JWT: &BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "jwt auth config",
		},
		{
			name: "basic config validation error",
			cfg: &BackendAuthConfig{
				Type: "basic",
				Basic: &BackendBasicAuthConfig{
					Enabled: true,
					// Missing username and password
				},
			},
			wantErr: true,
			errMsg:  "basic auth config",
		},
		{
			name: "mtls config validation error",
			cfg: &BackendAuthConfig{
				Type: "mtls",
				MTLS: &BackendMTLSAuthConfig{
					Enabled: true,
					// Missing cert and key files
				},
			},
			wantErr: true,
			errMsg:  "mtls auth config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
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

func TestBackendJWTAuthConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *BackendJWTAuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			cfg: &BackendJWTAuthConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid static token source",
			cfg: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "test-token",
			},
			wantErr: false,
		},
		{
			name: "valid vault token source",
			cfg: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "vault",
				VaultPath:   "secret/jwt-token",
			},
			wantErr: false,
		},
		{
			name: "valid oidc token source",
			cfg: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &BackendOIDCConfig{
					IssuerURL:    "https://issuer.example.com",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid token source",
			cfg: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid token source",
		},
		{
			name: "static source without token",
			cfg: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "",
			},
			wantErr: true,
			errMsg:  "staticToken is required",
		},
		{
			name: "vault source without path",
			cfg: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "vault",
				VaultPath:   "",
			},
			wantErr: true,
			errMsg:  "vaultPath is required",
		},
		{
			name: "oidc source without config",
			cfg: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC:        nil,
			},
			wantErr: true,
			errMsg:  "oidc config is required",
		},
		{
			name: "oidc source with invalid config",
			cfg: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &BackendOIDCConfig{
					IssuerURL: "", // Missing required field
					ClientID:  "client-id",
				},
			},
			wantErr: true,
			errMsg:  "issuerUrl is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
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

func TestBackendOIDCConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *BackendOIDCConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "valid config with client secret",
			cfg: &BackendOIDCConfig{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			wantErr: false,
		},
		{
			name: "valid config with vault path",
			cfg: &BackendOIDCConfig{
				IssuerURL:             "https://issuer.example.com",
				ClientID:              "client-id",
				ClientSecretVaultPath: "secret/oidc-secret",
			},
			wantErr: false,
		},
		{
			name: "missing issuer URL",
			cfg: &BackendOIDCConfig{
				IssuerURL:    "",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			wantErr: true,
			errMsg:  "issuerUrl is required",
		},
		{
			name: "missing client ID",
			cfg: &BackendOIDCConfig{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "",
				ClientSecret: "client-secret",
			},
			wantErr: true,
			errMsg:  "clientId is required",
		},
		{
			name: "missing both client secret and vault path",
			cfg: &BackendOIDCConfig{
				IssuerURL: "https://issuer.example.com",
				ClientID:  "client-id",
			},
			wantErr: true,
			errMsg:  "either clientSecret or clientSecretVaultPath is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
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

func TestBackendBasicAuthConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *BackendBasicAuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			cfg: &BackendBasicAuthConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid static credentials",
			cfg: &BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
			wantErr: false,
		},
		{
			name: "valid vault credentials",
			cfg: &BackendBasicAuthConfig{
				Enabled:   true,
				VaultPath: "secret/credentials",
			},
			wantErr: false,
		},
		{
			name: "missing credentials",
			cfg: &BackendBasicAuthConfig{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "either username/password or vaultPath is required",
		},
		{
			name: "partial static credentials - missing password",
			cfg: &BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
			},
			wantErr: true,
			errMsg:  "either username/password or vaultPath is required",
		},
		{
			name: "partial static credentials - missing username",
			cfg: &BackendBasicAuthConfig{
				Enabled:  true,
				Password: "pass",
			},
			wantErr: true,
			errMsg:  "either username/password or vaultPath is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
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

func TestBackendMTLSAuthConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *BackendMTLSAuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			cfg: &BackendMTLSAuthConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid file-based config",
			cfg: &BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			wantErr: false,
		},
		{
			name: "valid vault-based config",
			cfg: &BackendMTLSAuthConfig{
				Enabled: true,
				Vault: &VaultBackendTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "role",
					CommonName: "cn",
				},
			},
			wantErr: false,
		},
		{
			name: "missing cert and vault",
			cfg: &BackendMTLSAuthConfig{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "either certFile/keyFile or vault config is required",
		},
		{
			name: "partial file config - missing key",
			cfg: &BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: "/path/to/cert.pem",
			},
			wantErr: true,
			errMsg:  "either certFile/keyFile or vault config is required",
		},
		{
			name: "partial file config - missing cert",
			cfg: &BackendMTLSAuthConfig{
				Enabled: true,
				KeyFile: "/path/to/key.pem",
			},
			wantErr: true,
			errMsg:  "either certFile/keyFile or vault config is required",
		},
		{
			name: "invalid vault config",
			cfg: &BackendMTLSAuthConfig{
				Enabled: true,
				Vault: &VaultBackendTLSConfig{
					Enabled: true,
					// Missing required fields
				},
			},
			wantErr: true,
			errMsg:  "pkiMount is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
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

func TestBackendJWTAuthConfig_GetEffectiveHeaderName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *BackendJWTAuthConfig
		expected string
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: "Authorization",
		},
		{
			name:     "empty header name",
			cfg:      &BackendJWTAuthConfig{HeaderName: ""},
			expected: "Authorization",
		},
		{
			name:     "custom header name",
			cfg:      &BackendJWTAuthConfig{HeaderName: "X-Auth-Token"},
			expected: "X-Auth-Token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveHeaderName())
		})
	}
}

func TestBackendJWTAuthConfig_GetEffectiveHeaderPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *BackendJWTAuthConfig
		expected string
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: "Bearer",
		},
		{
			name:     "empty header prefix",
			cfg:      &BackendJWTAuthConfig{HeaderPrefix: ""},
			expected: "Bearer",
		},
		{
			name:     "custom header prefix",
			cfg:      &BackendJWTAuthConfig{HeaderPrefix: "Token"},
			expected: "Token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveHeaderPrefix())
		})
	}
}

func TestBackendBasicAuthConfig_GetEffectiveUsernameKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *BackendBasicAuthConfig
		expected string
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: "username",
		},
		{
			name:     "empty username key",
			cfg:      &BackendBasicAuthConfig{UsernameKey: ""},
			expected: "username",
		},
		{
			name:     "custom username key",
			cfg:      &BackendBasicAuthConfig{UsernameKey: "user"},
			expected: "user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveUsernameKey())
		})
	}
}

func TestBackendBasicAuthConfig_GetEffectivePasswordKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *BackendBasicAuthConfig
		expected string
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: "password",
		},
		{
			name:     "empty password key",
			cfg:      &BackendBasicAuthConfig{PasswordKey: ""},
			expected: "password",
		},
		{
			name:     "custom password key",
			cfg:      &BackendBasicAuthConfig{PasswordKey: "pass"},
			expected: "pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectivePasswordKey())
		})
	}
}

func TestBackendOIDCConfig_TokenCacheTTL(t *testing.T) {
	t.Parallel()

	t.Run("zero TTL", func(t *testing.T) {
		t.Parallel()

		cfg := &BackendOIDCConfig{
			TokenCacheTTL: 0,
		}
		assert.Equal(t, time.Duration(0), cfg.TokenCacheTTL.Duration())
	})

	t.Run("custom TTL", func(t *testing.T) {
		t.Parallel()

		cfg := &BackendOIDCConfig{
			TokenCacheTTL: Duration(5 * time.Minute),
		}
		assert.Equal(t, 5*time.Minute, cfg.TokenCacheTTL.Duration())
	})
}

func TestBackendAuthConfig_WithCircuitBreaker(t *testing.T) {
	t.Parallel()

	t.Run("backend with circuit breaker config", func(t *testing.T) {
		t.Parallel()

		backend := Backend{
			Name: "test-backend",
			Hosts: []BackendHost{
				{Address: "localhost", Port: 8080},
			},
			CircuitBreaker: &CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          Duration(30 * time.Second),
				HalfOpenRequests: 3,
			},
		}

		assert.NotNil(t, backend.CircuitBreaker)
		assert.True(t, backend.CircuitBreaker.Enabled)
		assert.Equal(t, 5, backend.CircuitBreaker.Threshold)
		assert.Equal(t, 30*time.Second, backend.CircuitBreaker.Timeout.Duration())
		assert.Equal(t, 3, backend.CircuitBreaker.HalfOpenRequests)
	})
}

func TestBackendAuthConfig_WithAuthentication(t *testing.T) {
	t.Parallel()

	t.Run("backend with authentication config", func(t *testing.T) {
		t.Parallel()

		backend := Backend{
			Name: "test-backend",
			Hosts: []BackendHost{
				{Address: "localhost", Port: 8080},
			},
			Authentication: &BackendAuthConfig{
				Type: "jwt",
				JWT: &BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "static",
					StaticToken: "test-token",
				},
			},
		}

		assert.NotNil(t, backend.Authentication)
		assert.Equal(t, "jwt", backend.Authentication.Type)
		assert.NotNil(t, backend.Authentication.JWT)
		assert.True(t, backend.Authentication.JWT.Enabled)
	})
}

func TestRouteConfig_WithRequestLimits(t *testing.T) {
	t.Parallel()

	t.Run("route with request limits", func(t *testing.T) {
		t.Parallel()

		route := Route{
			Name: "test-route",
			RequestLimits: &RequestLimitsConfig{
				MaxBodySize:   20 << 20, // 20MB
				MaxHeaderSize: 2 << 20,  // 2MB
			},
		}

		assert.NotNil(t, route.RequestLimits)
		assert.Equal(t, int64(20<<20), route.RequestLimits.MaxBodySize)
		assert.Equal(t, int64(2<<20), route.RequestLimits.MaxHeaderSize)
	})
}

func TestRouteConfig_WithCORS(t *testing.T) {
	t.Parallel()

	t.Run("route with CORS config", func(t *testing.T) {
		t.Parallel()

		route := Route{
			Name: "test-route",
			CORS: &CORSConfig{
				AllowOrigins:     []string{"https://example.com"},
				AllowMethods:     []string{"GET", "POST"},
				AllowHeaders:     []string{"Content-Type", "Authorization"},
				ExposeHeaders:    []string{"X-Request-ID"},
				MaxAge:           3600,
				AllowCredentials: true,
			},
		}

		assert.NotNil(t, route.CORS)
		assert.Equal(t, []string{"https://example.com"}, route.CORS.AllowOrigins)
		assert.Equal(t, []string{"GET", "POST"}, route.CORS.AllowMethods)
		assert.True(t, route.CORS.AllowCredentials)
	})
}

func TestRouteConfig_WithSecurity(t *testing.T) {
	t.Parallel()

	t.Run("route with security config", func(t *testing.T) {
		t.Parallel()

		route := Route{
			Name: "test-route",
			Security: &SecurityConfig{
				Enabled:        true,
				ReferrerPolicy: "strict-origin",
				Headers: &SecurityHeadersConfig{
					Enabled:             true,
					XFrameOptions:       "DENY",
					XContentTypeOptions: "nosniff",
				},
			},
		}

		assert.NotNil(t, route.Security)
		assert.True(t, route.Security.Enabled)
		assert.Equal(t, "strict-origin", route.Security.ReferrerPolicy)
		assert.NotNil(t, route.Security.Headers)
		assert.Equal(t, "DENY", route.Security.Headers.XFrameOptions)
	})
}
