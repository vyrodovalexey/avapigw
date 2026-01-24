package apikey

import (
	"testing"
	"time"

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
				Enabled:       true,
				HashAlgorithm: "sha256",
			},
			wantErr: false,
		},
		{
			name: "valid config with all hash algorithms",
			config: &Config{
				Enabled:       true,
				HashAlgorithm: "sha256",
			},
			wantErr: false,
		},
		{
			name: "invalid hash algorithm",
			config: &Config{
				Enabled:       true,
				HashAlgorithm: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid hash algorithm",
		},
		{
			name: "valid extraction sources",
			config: &Config{
				Enabled: true,
				Extraction: []ExtractionSource{
					{Type: "header", Name: "X-API-Key"},
					{Type: "query", Name: "api_key"},
					{Type: "metadata", Name: "api-key"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid extraction type",
			config: &Config{
				Enabled: true,
				Extraction: []ExtractionSource{
					{Type: "invalid", Name: "X-API-Key"},
				},
			},
			wantErr: true,
			errMsg:  "invalid extraction type",
		},
		{
			name: "extraction missing name",
			config: &Config{
				Enabled: true,
				Extraction: []ExtractionSource{
					{Type: "header", Name: ""},
				},
			},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "valid store config",
			config: &Config{
				Enabled: true,
				Store: &StoreConfig{
					Type: "memory",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid store type",
			config: &Config{
				Enabled: true,
				Store: &StoreConfig{
					Type: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "invalid store type",
		},
		{
			name: "file store missing path",
			config: &Config{
				Enabled: true,
				Store: &StoreConfig{
					Type: "file",
				},
			},
			wantErr: true,
			errMsg:  "filePath is required",
		},
		{
			name: "valid Vault config",
			config: &Config{
				Enabled: true,
				Vault: &VaultConfig{
					Enabled: true,
					KVMount: "secret",
				},
			},
			wantErr: false,
		},
		{
			name: "Vault config missing kvMount",
			config: &Config{
				Enabled: true,
				Vault: &VaultConfig{
					Enabled: true,
				},
			},
			wantErr: true,
			errMsg:  "kvMount is required",
		},
		{
			name: "negative cache TTL",
			config: &Config{
				Enabled: true,
				Cache: &CacheConfig{
					Enabled: true,
					TTL:     -time.Minute,
				},
			},
			wantErr: true,
			errMsg:  "cache.ttl must be non-negative",
		},
		{
			name: "negative cache maxSize",
			config: &Config{
				Enabled: true,
				Cache: &CacheConfig{
					Enabled: true,
					MaxSize: -1,
				},
			},
			wantErr: true,
			errMsg:  "cache.maxSize must be non-negative",
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

func TestStoreConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *StoreConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "empty type (defaults to memory)",
			config: &StoreConfig{
				Type: "",
			},
			wantErr: false,
		},
		{
			name: "memory type",
			config: &StoreConfig{
				Type: "memory",
			},
			wantErr: false,
		},
		{
			name: "vault type",
			config: &StoreConfig{
				Type: "vault",
			},
			wantErr: false,
		},
		{
			name: "file type with path",
			config: &StoreConfig{
				Type:     "file",
				FilePath: "/path/to/keys.json",
			},
			wantErr: false,
		},
		{
			name: "file type without path",
			config: &StoreConfig{
				Type: "file",
			},
			wantErr: true,
			errMsg:  "filePath is required",
		},
		{
			name: "invalid type",
			config: &StoreConfig{
				Type: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid store type",
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

func TestVaultConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *VaultConfig
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
			config: &VaultConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config",
			config: &VaultConfig{
				Enabled: true,
				KVMount: "secret",
				Path:    "api-keys",
			},
			wantErr: false,
		},
		{
			name: "missing kvMount",
			config: &VaultConfig{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "kvMount is required",
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

func TestValidateExtractionSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		source  ExtractionSource
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid header",
			source:  ExtractionSource{Type: "header", Name: "X-API-Key"},
			wantErr: false,
		},
		{
			name:    "valid query",
			source:  ExtractionSource{Type: "query", Name: "api_key"},
			wantErr: false,
		},
		{
			name:    "valid metadata",
			source:  ExtractionSource{Type: "metadata", Name: "api-key"},
			wantErr: false,
		},
		{
			name:    "with prefix",
			source:  ExtractionSource{Type: "header", Name: "Authorization", Prefix: "Bearer "},
			wantErr: false,
		},
		{
			name:    "invalid type",
			source:  ExtractionSource{Type: "invalid", Name: "X-API-Key"},
			wantErr: true,
			errMsg:  "invalid extraction type",
		},
		{
			name:    "missing name",
			source:  ExtractionSource{Type: "header", Name: ""},
			wantErr: true,
			errMsg:  "name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateExtractionSource(tt.source)
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

	assert.False(t, config.Enabled)
	assert.Equal(t, "sha256", config.HashAlgorithm)
	assert.Len(t, config.Extraction, 1)
	assert.Equal(t, "header", config.Extraction[0].Type)
	assert.Equal(t, "X-API-Key", config.Extraction[0].Name)
	assert.NotNil(t, config.Cache)
	assert.True(t, config.Cache.Enabled)
	assert.Equal(t, 5*time.Minute, config.Cache.TTL)
	assert.Equal(t, 10000, config.Cache.MaxSize)
}

func TestConfig_GetEffectiveHashAlgorithm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name: "custom algorithm",
			config: &Config{
				HashAlgorithm: "sha512",
			},
			expected: "sha512",
		},
		{
			name:     "default algorithm",
			config:   &Config{},
			expected: "sha256",
		},
		{
			name: "empty algorithm uses default",
			config: &Config{
				HashAlgorithm: "",
			},
			expected: "sha256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.GetEffectiveHashAlgorithm()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_Validate_AllHashAlgorithms(t *testing.T) {
	t.Parallel()

	validAlgorithms := []string{"sha256", "sha512", "bcrypt", "plaintext"}

	for _, alg := range validAlgorithms {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()

			config := &Config{
				Enabled:       true,
				HashAlgorithm: alg,
			}

			err := config.Validate()
			assert.NoError(t, err)
		})
	}
}
