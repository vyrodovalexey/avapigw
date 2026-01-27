package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/auth/jwt"
	"github.com/vyrodovalexey/avapigw/internal/auth/mtls"
	"github.com/vyrodovalexey/avapigw/internal/auth/oidc"
)

// validJWTConfig returns a valid JWT config for testing.
func validJWTConfig() *jwt.Config {
	return &jwt.Config{
		Enabled:    true,
		Algorithms: []string{"RS256"},
		JWKSUrl:    "https://example.com/.well-known/jwks.json",
	}
}

// TestConfig_ValidateAuthMethods_AllMethods tests validateAuthMethods with all auth methods.
func TestConfig_ValidateAuthMethods_AllMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name: "MTLS enabled with valid config",
			config: &Config{
				Enabled: true,
				MTLS: &mtls.Config{
					Enabled: true,
					CAFile:  "/path/to/ca.pem",
				},
			},
			expectErr: false,
		},
		{
			name: "OIDC enabled with valid config",
			config: &Config{
				Enabled: true,
				OIDC: &oidc.Config{
					Enabled: true,
					Providers: []oidc.ProviderConfig{
						{
							Name:         "test",
							Issuer:       "https://issuer.example.com",
							ClientID:     "client-id",
							ClientSecret: "client-secret",
						},
					},
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.validateAuthMethods()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfig_ValidateExtraction_AllPaths tests validateExtraction with various configs.
func TestConfig_ValidateExtraction_AllPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name: "valid JWT extraction",
			config: &Config{
				Enabled: true,
				JWT:     validJWTConfig(),
				Extraction: &ExtractionConfig{
					JWT: []ExtractionSource{
						{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "valid APIKey extraction",
			config: &Config{
				Enabled: true,
				JWT:     validJWTConfig(),
				Extraction: &ExtractionConfig{
					APIKey: []ExtractionSource{
						{Type: ExtractionTypeHeader, Name: "X-API-Key"},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "invalid JWT extraction type",
			config: &Config{
				Enabled: true,
				JWT:     validJWTConfig(),
				Extraction: &ExtractionConfig{
					JWT: []ExtractionSource{
						{Type: "invalid", Name: "Authorization"},
					},
				},
			},
			expectErr: true,
		},
		{
			name: "invalid APIKey extraction - empty name",
			config: &Config{
				Enabled: true,
				JWT:     validJWTConfig(),
				Extraction: &ExtractionConfig{
					APIKey: []ExtractionSource{
						{Type: ExtractionTypeHeader, Name: ""},
					},
				},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfig_ValidateExtractionConfig_NilExtraction tests validateExtractionConfig with nil extraction.
func TestConfig_ValidateExtractionConfig_NilExtraction(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:    true,
		JWT:        validJWTConfig(),
		Extraction: nil,
	}

	err := config.validateExtractionConfig()
	assert.NoError(t, err)
}

// TestConfig_ValidateExtraction_BothJWTAndAPIKey tests validateExtraction with both JWT and APIKey sources.
func TestConfig_ValidateExtraction_BothJWTAndAPIKey(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		JWT:     validJWTConfig(),
		Extraction: &ExtractionConfig{
			JWT: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "Authorization", Prefix: "Bearer "},
			},
			APIKey: []ExtractionSource{
				{Type: ExtractionTypeHeader, Name: "X-API-Key"},
				{Type: ExtractionTypeQuery, Name: "api_key"},
			},
		},
	}

	err := config.validateExtraction()
	assert.NoError(t, err)
}

// TestExtractionType_Constants tests extraction type constants.
func TestExtractionType_Constants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ExtractionType("header"), ExtractionTypeHeader)
	assert.Equal(t, ExtractionType("cookie"), ExtractionTypeCookie)
	assert.Equal(t, ExtractionType("query"), ExtractionTypeQuery)
	assert.Equal(t, ExtractionType("metadata"), ExtractionTypeMetadata)
}

// TestConfig_ValidateAuthMethods_MTLSInvalid tests validateAuthMethods with invalid MTLS config.
func TestConfig_ValidateAuthMethods_MTLSInvalid(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		MTLS: &mtls.Config{
			Enabled: true,
			// Missing required CAFile
		},
	}

	err := config.validateAuthMethods()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mtls config")
}

// TestConfig_ValidateAuthMethods_OIDCInvalid tests validateAuthMethods with invalid OIDC config.
func TestConfig_ValidateAuthMethods_OIDCInvalid(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		OIDC: &oidc.Config{
			Enabled: true,
			// Missing required providers
		},
	}

	err := config.validateAuthMethods()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oidc config")
}
