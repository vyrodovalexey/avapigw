package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name: "valid config",
			config: &Config{
				Enabled: true,
				Headers: &HeadersConfig{
					Enabled:       true,
					XFrameOptions: "DENY",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid X-Frame-Options",
			config: &Config{
				Enabled: true,
				Headers: &HeadersConfig{
					Enabled:       true,
					XFrameOptions: "INVALID",
				},
			},
			wantErr: true,
			errMsg:  "invalid X-Frame-Options",
		},
		{
			name: "invalid X-Content-Type-Options",
			config: &Config{
				Enabled: true,
				Headers: &HeadersConfig{
					Enabled:             true,
					XContentTypeOptions: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "invalid X-Content-Type-Options",
		},
		{
			name: "invalid HSTS - negative maxAge",
			config: &Config{
				Enabled: true,
				HSTS: &HSTSConfig{
					Enabled: true,
					MaxAge:  -1,
				},
			},
			wantErr: true,
			errMsg:  "maxAge must be non-negative",
		},
		{
			name: "invalid HSTS - preload without includeSubDomains",
			config: &Config{
				Enabled: true,
				HSTS: &HSTSConfig{
					Enabled:           true,
					MaxAge:            31536000,
					IncludeSubDomains: false,
					Preload:           true,
				},
			},
			wantErr: true,
			errMsg:  "preload requires includeSubDomains",
		},
		{
			name: "invalid HSTS - preload with short maxAge",
			config: &Config{
				Enabled: true,
				HSTS: &HSTSConfig{
					Enabled:           true,
					MaxAge:            3600, // 1 hour, too short
					IncludeSubDomains: true,
					Preload:           true,
				},
			},
			wantErr: true,
			errMsg:  "preload requires maxAge >= 31536000",
		},
		{
			name: "invalid CSP - missing policy and directives",
			config: &Config{
				Enabled: true,
				CSP: &CSPConfig{
					Enabled: true,
				},
			},
			wantErr: true,
			errMsg:  "either policy or directives must be set",
		},
		{
			name: "invalid referrer policy",
			config: &Config{
				Enabled:        true,
				ReferrerPolicy: "invalid-policy",
			},
			wantErr: true,
			errMsg:  "invalid referrer policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHeadersConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *HeadersConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid DENY",
			config: &HeadersConfig{
				XFrameOptions: "DENY",
			},
			wantErr: false,
		},
		{
			name: "valid SAMEORIGIN",
			config: &HeadersConfig{
				XFrameOptions: "SAMEORIGIN",
			},
			wantErr: false,
		},
		{
			name: "valid ALLOW-FROM",
			config: &HeadersConfig{
				XFrameOptions: "ALLOW-FROM https://example.com",
			},
			wantErr: false,
		},
		{
			name: "valid nosniff",
			config: &HeadersConfig{
				XContentTypeOptions: "nosniff",
			},
			wantErr: false,
		},
		{
			name: "invalid X-Frame-Options",
			config: &HeadersConfig{
				XFrameOptions: "INVALID",
			},
			wantErr: true,
			errMsg:  "invalid X-Frame-Options",
		},
		{
			name: "invalid X-Content-Type-Options",
			config: &HeadersConfig{
				XContentTypeOptions: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid X-Content-Type-Options",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHSTSConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *HSTSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid config",
			config: &HSTSConfig{
				MaxAge:            31536000,
				IncludeSubDomains: true,
			},
			wantErr: false,
		},
		{
			name: "valid config with preload",
			config: &HSTSConfig{
				MaxAge:            31536000,
				IncludeSubDomains: true,
				Preload:           true,
			},
			wantErr: false,
		},
		{
			name: "negative maxAge",
			config: &HSTSConfig{
				MaxAge: -1,
			},
			wantErr: true,
			errMsg:  "maxAge must be non-negative",
		},
		{
			name: "preload without includeSubDomains",
			config: &HSTSConfig{
				MaxAge:  31536000,
				Preload: true,
			},
			wantErr: true,
			errMsg:  "preload requires includeSubDomains",
		},
		{
			name: "preload with short maxAge",
			config: &HSTSConfig{
				MaxAge:            3600,
				IncludeSubDomains: true,
				Preload:           true,
			},
			wantErr: true,
			errMsg:  "preload requires maxAge >= 31536000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCSPConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *CSPConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid with policy",
			config: &CSPConfig{
				Policy: "default-src 'self'",
			},
			wantErr: false,
		},
		{
			name: "valid with directives",
			config: &CSPConfig{
				Directives: &CSPDirectives{
					DefaultSrc: []string{"'self'"},
				},
			},
			wantErr: false,
		},
		{
			name:    "missing policy and directives",
			config:  &CSPConfig{},
			wantErr: true,
			errMsg:  "either policy or directives must be set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()

	assert.True(t, config.Enabled)
	assert.NotNil(t, config.Headers)
	assert.True(t, config.Headers.Enabled)
	assert.Equal(t, "DENY", config.Headers.XFrameOptions)
	assert.Equal(t, "nosniff", config.Headers.XContentTypeOptions)
	assert.Equal(t, "1; mode=block", config.Headers.XXSSProtection)
	assert.NotNil(t, config.HSTS)
	assert.True(t, config.HSTS.Enabled)
	assert.Equal(t, 31536000, config.HSTS.MaxAge)
	assert.True(t, config.HSTS.IncludeSubDomains)
	assert.Equal(t, "strict-origin-when-cross-origin", config.ReferrerPolicy)
}

func TestConfig_IsHeadersEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name: "disabled config",
			config: &Config{
				Enabled: false,
			},
			expected: false,
		},
		{
			name: "enabled config, nil headers",
			config: &Config{
				Enabled: true,
			},
			expected: false,
		},
		{
			name: "enabled config, disabled headers",
			config: &Config{
				Enabled: true,
				Headers: &HeadersConfig{
					Enabled: false,
				},
			},
			expected: false,
		},
		{
			name: "enabled config, enabled headers",
			config: &Config{
				Enabled: true,
				Headers: &HeadersConfig{
					Enabled: true,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.IsHeadersEnabled()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_IsHSTSEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name: "disabled config",
			config: &Config{
				Enabled: false,
			},
			expected: false,
		},
		{
			name: "enabled config, nil HSTS",
			config: &Config{
				Enabled: true,
			},
			expected: false,
		},
		{
			name: "enabled config, disabled HSTS",
			config: &Config{
				Enabled: true,
				HSTS: &HSTSConfig{
					Enabled: false,
				},
			},
			expected: false,
		},
		{
			name: "enabled config, enabled HSTS",
			config: &Config{
				Enabled: true,
				HSTS: &HSTSConfig{
					Enabled: true,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.IsHSTSEnabled()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_IsCSPEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name: "enabled config, enabled CSP",
			config: &Config{
				Enabled: true,
				CSP: &CSPConfig{
					Enabled: true,
				},
			},
			expected: true,
		},
		{
			name: "enabled config, disabled CSP",
			config: &Config{
				Enabled: true,
				CSP: &CSPConfig{
					Enabled: false,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.IsCSPEnabled()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_IsPermissionsPolicyEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name: "enabled config, enabled permissions policy",
			config: &Config{
				Enabled: true,
				PermissionsPolicy: &PermissionsPolicyConfig{
					Enabled: true,
				},
			},
			expected: true,
		},
		{
			name: "enabled config, disabled permissions policy",
			config: &Config{
				Enabled: true,
				PermissionsPolicy: &PermissionsPolicyConfig{
					Enabled: false,
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.IsPermissionsPolicyEnabled()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateReferrerPolicy(t *testing.T) {
	t.Parallel()

	validPolicies := []string{
		"no-referrer",
		"no-referrer-when-downgrade",
		"origin",
		"origin-when-cross-origin",
		"same-origin",
		"strict-origin",
		"strict-origin-when-cross-origin",
		"unsafe-url",
	}

	for _, policy := range validPolicies {
		t.Run("valid_"+policy, func(t *testing.T) {
			t.Parallel()

			config := &Config{
				Enabled:        true,
				ReferrerPolicy: policy,
			}

			err := config.Validate()
			assert.NoError(t, err)
		})
	}

	t.Run("invalid policy", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled:        true,
			ReferrerPolicy: "invalid-policy",
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid referrer policy")
	})

	t.Run("empty policy is valid", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled:        true,
			ReferrerPolicy: "",
		}

		err := config.Validate()
		assert.NoError(t, err)
	})
}
