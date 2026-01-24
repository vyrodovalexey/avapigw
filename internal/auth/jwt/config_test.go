package jwt

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
			name: "valid config with JWKS URL",
			config: &Config{
				Enabled:    true,
				JWKSUrl:    "https://example.com/.well-known/jwks.json",
				Algorithms: []string{"RS256", "ES256"},
			},
			wantErr: false,
		},
		{
			name: "valid config with static keys",
			config: &Config{
				Enabled: true,
				StaticKeys: []StaticKey{
					{
						KeyID:     "key1",
						Algorithm: "RS256",
						Key:       "test-key-data",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with Vault",
			config: &Config{
				Enabled: true,
				Vault: &VaultConfig{
					Enabled:      true,
					TransitMount: "transit",
					KeyName:      "jwt-key",
				},
			},
			wantErr: false,
		},
		{
			name: "no key source configured",
			config: &Config{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "at least one key source must be configured",
		},
		{
			name: "invalid algorithm",
			config: &Config{
				Enabled:    true,
				JWKSUrl:    "https://example.com/.well-known/jwks.json",
				Algorithms: []string{"INVALID"},
			},
			wantErr: true,
			errMsg:  "invalid algorithm",
		},
		{
			name: "negative JWKS cache TTL",
			config: &Config{
				Enabled:      true,
				JWKSUrl:      "https://example.com/.well-known/jwks.json",
				JWKSCacheTTL: -time.Hour,
			},
			wantErr: true,
			errMsg:  "jwksCacheTTL must be non-negative",
		},
		{
			name: "negative clock skew",
			config: &Config{
				Enabled:   true,
				JWKSUrl:   "https://example.com/.well-known/jwks.json",
				ClockSkew: -time.Minute,
			},
			wantErr: true,
			errMsg:  "clockSkew must be non-negative",
		},
		{
			name: "invalid static key - missing keyId",
			config: &Config{
				Enabled: true,
				StaticKeys: []StaticKey{
					{
						Algorithm: "RS256",
						Key:       "test-key-data",
					},
				},
			},
			wantErr: true,
			errMsg:  "keyId is required",
		},
		{
			name: "invalid static key - missing algorithm",
			config: &Config{
				Enabled: true,
				StaticKeys: []StaticKey{
					{
						KeyID: "key1",
						Key:   "test-key-data",
					},
				},
			},
			wantErr: true,
			errMsg:  "algorithm is required",
		},
		{
			name: "invalid static key - missing key",
			config: &Config{
				Enabled: true,
				StaticKeys: []StaticKey{
					{
						KeyID:     "key1",
						Algorithm: "RS256",
					},
				},
			},
			wantErr: true,
			errMsg:  "key or keyFile is required",
		},
		{
			name: "invalid static key - invalid algorithm",
			config: &Config{
				Enabled: true,
				StaticKeys: []StaticKey{
					{
						KeyID:     "key1",
						Algorithm: "INVALID",
						Key:       "test-key-data",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid algorithm",
		},
		{
			name: "invalid Vault config - missing transitMount",
			config: &Config{
				Enabled: true,
				Vault: &VaultConfig{
					Enabled: true,
					KeyName: "jwt-key",
				},
			},
			wantErr: true,
			errMsg:  "transitMount is required",
		},
		{
			name: "invalid Vault config - missing keyName",
			config: &Config{
				Enabled: true,
				Vault: &VaultConfig{
					Enabled:      true,
					TransitMount: "transit",
				},
			},
			wantErr: true,
			errMsg:  "keyName is required",
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
				Enabled:      true,
				TransitMount: "transit",
				KeyName:      "jwt-key",
			},
			wantErr: false,
		},
		{
			name: "missing transitMount",
			config: &VaultConfig{
				Enabled: true,
				KeyName: "jwt-key",
			},
			wantErr: true,
		},
		{
			name: "missing keyName",
			config: &VaultConfig{
				Enabled:      true,
				TransitMount: "transit",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsValidAlgorithm(t *testing.T) {
	t.Parallel()

	validAlgorithms := []string{
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"HS256", "HS384", "HS512",
		"EdDSA", "Ed25519",
		"PS256", "PS384", "PS512",
	}

	for _, alg := range validAlgorithms {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			assert.True(t, isValidAlgorithm(alg))
		})
	}

	invalidAlgorithms := []string{"INVALID", "none", "RS128", ""}

	for _, alg := range invalidAlgorithms {
		t.Run("invalid_"+alg, func(t *testing.T) {
			t.Parallel()
			assert.False(t, isValidAlgorithm(alg))
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()

	assert.False(t, config.Enabled)
	assert.Equal(t, []string{"RS256", "ES256"}, config.Algorithms)
	assert.Equal(t, time.Hour, config.JWKSCacheTTL)
	assert.Equal(t, 5*time.Minute, config.ClockSkew)
	assert.NotNil(t, config.ClaimMapping)
	assert.Equal(t, "sub", config.ClaimMapping.Subject)
	assert.Equal(t, "roles", config.ClaimMapping.Roles)
	assert.Equal(t, "email", config.ClaimMapping.Email)
	assert.Equal(t, "name", config.ClaimMapping.Name)
}

func TestConfig_GetAllowedIssuers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected []string
	}{
		{
			name: "multiple issuers",
			config: &Config{
				Issuers: []string{"issuer1", "issuer2"},
			},
			expected: []string{"issuer1", "issuer2"},
		},
		{
			name: "single issuer",
			config: &Config{
				Issuer: "single-issuer",
			},
			expected: []string{"single-issuer"},
		},
		{
			name: "issuers takes precedence",
			config: &Config{
				Issuer:  "single-issuer",
				Issuers: []string{"issuer1", "issuer2"},
			},
			expected: []string{"issuer1", "issuer2"},
		},
		{
			name:     "no issuers",
			config:   &Config{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.GetAllowedIssuers()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetEffectiveClockSkew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected time.Duration
	}{
		{
			name: "custom clock skew",
			config: &Config{
				ClockSkew: 10 * time.Minute,
			},
			expected: 10 * time.Minute,
		},
		{
			name:     "default clock skew",
			config:   &Config{},
			expected: 5 * time.Minute,
		},
		{
			name: "zero clock skew uses default",
			config: &Config{
				ClockSkew: 0,
			},
			expected: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.GetEffectiveClockSkew()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetEffectiveJWKSCacheTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected time.Duration
	}{
		{
			name: "custom TTL",
			config: &Config{
				JWKSCacheTTL: 30 * time.Minute,
			},
			expected: 30 * time.Minute,
		},
		{
			name:     "default TTL",
			config:   &Config{},
			expected: time.Hour,
		},
		{
			name: "zero TTL uses default",
			config: &Config{
				JWKSCacheTTL: 0,
			},
			expected: time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.GetEffectiveJWKSCacheTTL()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_HasKeySource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name: "has JWKS URL",
			config: &Config{
				JWKSUrl: "https://example.com/.well-known/jwks.json",
			},
			expected: true,
		},
		{
			name: "has static keys",
			config: &Config{
				StaticKeys: []StaticKey{{KeyID: "key1"}},
			},
			expected: true,
		},
		{
			name: "has Vault enabled",
			config: &Config{
				Vault: &VaultConfig{Enabled: true},
			},
			expected: true,
		},
		{
			name: "has Vault disabled",
			config: &Config{
				Vault: &VaultConfig{Enabled: false},
			},
			expected: false,
		},
		{
			name:     "no key source",
			config:   &Config{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.hasKeySource()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateStaticKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     StaticKey
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid key",
			key: StaticKey{
				KeyID:     "key1",
				Algorithm: "RS256",
				Key:       "key-data",
			},
			wantErr: false,
		},
		{
			name: "valid key with keyFile",
			key: StaticKey{
				KeyID:     "key1",
				Algorithm: "RS256",
				KeyFile:   "/path/to/key.pem",
			},
			wantErr: false,
		},
		{
			name: "missing keyId",
			key: StaticKey{
				Algorithm: "RS256",
				Key:       "key-data",
			},
			wantErr: true,
			errMsg:  "keyId is required",
		},
		{
			name: "missing algorithm",
			key: StaticKey{
				KeyID: "key1",
				Key:   "key-data",
			},
			wantErr: true,
			errMsg:  "algorithm is required",
		},
		{
			name: "invalid algorithm",
			key: StaticKey{
				KeyID:     "key1",
				Algorithm: "INVALID",
				Key:       "key-data",
			},
			wantErr: true,
			errMsg:  "invalid algorithm",
		},
		{
			name: "missing key and keyFile",
			key: StaticKey{
				KeyID:     "key1",
				Algorithm: "RS256",
			},
			wantErr: true,
			errMsg:  "key or keyFile is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateStaticKey(tt.key)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
