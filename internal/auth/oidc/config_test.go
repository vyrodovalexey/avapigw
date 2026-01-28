package oidc

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
			name: "enabled without providers",
			config: &Config{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "at least one provider must be configured",
		},
		{
			name: "valid config with one provider",
			config: &Config{
				Enabled: true,
				Providers: []ProviderConfig{
					{
						Name:     "test",
						Issuer:   "https://issuer.example.com",
						ClientID: "client-id",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid provider config",
			config: &Config{
				Enabled: true,
				Providers: []ProviderConfig{
					{
						Name: "test",
						// Missing Issuer and ClientID
					},
				},
			},
			wantErr: true,
			errMsg:  "providers[0]",
		},
		{
			name: "default provider not found",
			config: &Config{
				Enabled:         true,
				DefaultProvider: "nonexistent",
				Providers: []ProviderConfig{
					{
						Name:     "test",
						Issuer:   "https://issuer.example.com",
						ClientID: "client-id",
					},
				},
			},
			wantErr: true,
			errMsg:  "default provider nonexistent not found",
		},
		{
			name: "valid config with default provider",
			config: &Config{
				Enabled:         true,
				DefaultProvider: "test",
				Providers: []ProviderConfig{
					{
						Name:     "test",
						Issuer:   "https://issuer.example.com",
						ClientID: "client-id",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple providers",
			config: &Config{
				Enabled: true,
				Providers: []ProviderConfig{
					{
						Name:     "provider1",
						Issuer:   "https://issuer1.example.com",
						ClientID: "client-id-1",
					},
					{
						Name:     "provider2",
						Issuer:   "https://issuer2.example.com",
						ClientID: "client-id-2",
					},
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

func TestProviderConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  ProviderConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty config",
			config:  ProviderConfig{},
			wantErr: true,
			errMsg:  "name is required",
		},
		{
			name: "missing issuer",
			config: ProviderConfig{
				Name: "test",
			},
			wantErr: true,
			errMsg:  "issuer is required",
		},
		{
			name: "missing clientId",
			config: ProviderConfig{
				Name:   "test",
				Issuer: "https://issuer.example.com",
			},
			wantErr: true,
			errMsg:  "clientId is required",
		},
		{
			name: "valid minimal config",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
			},
			wantErr: false,
		},
		{
			name: "valid provider type - generic",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
				Type:     "generic",
			},
			wantErr: false,
		},
		{
			name: "valid provider type - keycloak",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
				Type:     "keycloak",
			},
			wantErr: false,
		},
		{
			name: "valid provider type - auth0",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
				Type:     "auth0",
			},
			wantErr: false,
		},
		{
			name: "valid provider type - okta",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
				Type:     "okta",
			},
			wantErr: false,
		},
		{
			name: "valid provider type - azure",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
				Type:     "azure",
			},
			wantErr: false,
		},
		{
			name: "invalid provider type",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
				Type:     "invalid",
			},
			wantErr: true,
			errMsg:  "invalid provider type",
		},
		{
			name: "introspection enabled without URL",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
				Introspection: &IntrospectionConfig{
					Enabled: true,
				},
			},
			wantErr: true,
			errMsg:  "introspection URL is required",
		},
		{
			name: "introspection enabled with URL",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
				Introspection: &IntrospectionConfig{
					Enabled: true,
					URL:     "https://issuer.example.com/introspect",
				},
			},
			wantErr: false,
		},
		{
			name: "introspection enabled with discovery URL",
			config: ProviderConfig{
				Name:         "test",
				Issuer:       "https://issuer.example.com",
				ClientID:     "client-id",
				DiscoveryURL: "https://issuer.example.com/.well-known/openid-configuration",
				Introspection: &IntrospectionConfig{
					Enabled: true,
				},
			},
			wantErr: false,
		},
		{
			name: "introspection disabled",
			config: ProviderConfig{
				Name:     "test",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
				Introspection: &IntrospectionConfig{
					Enabled: false,
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

func TestProviderConfig_GetDiscoveryURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   ProviderConfig
		expected string
	}{
		{
			name: "custom discovery URL",
			config: ProviderConfig{
				Issuer:       "https://issuer.example.com",
				DiscoveryURL: "https://custom.example.com/.well-known/openid-configuration",
			},
			expected: "https://custom.example.com/.well-known/openid-configuration",
		},
		{
			name: "default discovery URL",
			config: ProviderConfig{
				Issuer: "https://issuer.example.com",
			},
			expected: "https://issuer.example.com/.well-known/openid-configuration",
		},
		{
			name: "issuer with trailing slash",
			config: ProviderConfig{
				Issuer: "https://issuer.example.com/",
			},
			expected: "https://issuer.example.com//.well-known/openid-configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.GetDiscoveryURL()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProviderConfig_GetEffectiveClaimMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   ProviderConfig
		expected *ClaimMapping
	}{
		{
			name: "custom claim mapping",
			config: ProviderConfig{
				ClaimMapping: &ClaimMapping{
					Subject: "custom_sub",
					Roles:   "custom_roles",
					Email:   "custom_email",
				},
			},
			expected: &ClaimMapping{
				Subject: "custom_sub",
				Roles:   "custom_roles",
				Email:   "custom_email",
			},
		},
		{
			name: "keycloak default mapping",
			config: ProviderConfig{
				Type: "keycloak",
			},
			expected: &ClaimMapping{
				Subject: "sub",
				Roles:   "realm_access.roles",
				Email:   "email",
				Name:    "name",
				Groups:  "groups",
			},
		},
		{
			name: "auth0 default mapping",
			config: ProviderConfig{
				Type: "auth0",
			},
			expected: &ClaimMapping{
				Subject:     "sub",
				Roles:       "https://auth0.com/roles",
				Permissions: "permissions",
				Email:       "email",
				Name:        "name",
			},
		},
		{
			name: "generic default mapping",
			config: ProviderConfig{
				Type: "generic",
			},
			expected: &ClaimMapping{
				Subject: "sub",
				Roles:   "roles",
				Email:   "email",
				Name:    "name",
			},
		},
		{
			name:   "no type - generic default",
			config: ProviderConfig{},
			expected: &ClaimMapping{
				Subject: "sub",
				Roles:   "roles",
				Email:   "email",
				Name:    "name",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.GetEffectiveClaimMapping()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetProvider(t *testing.T) {
	t.Parallel()

	config := &Config{
		Providers: []ProviderConfig{
			{Name: "provider1", Issuer: "https://issuer1.example.com", ClientID: "client1"},
			{Name: "provider2", Issuer: "https://issuer2.example.com", ClientID: "client2"},
			{Name: "provider3", Issuer: "https://issuer3.example.com", ClientID: "client3"},
		},
	}

	tests := []struct {
		name         string
		providerName string
		wantNil      bool
		wantIssuer   string
	}{
		{
			name:         "existing provider",
			providerName: "provider1",
			wantNil:      false,
			wantIssuer:   "https://issuer1.example.com",
		},
		{
			name:         "another existing provider",
			providerName: "provider2",
			wantNil:      false,
			wantIssuer:   "https://issuer2.example.com",
		},
		{
			name:         "non-existing provider",
			providerName: "nonexistent",
			wantNil:      true,
		},
		{
			name:         "empty name",
			providerName: "",
			wantNil:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := config.GetProvider(tt.providerName)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.wantIssuer, result.Issuer)
			}
		})
	}
}

func TestConfig_GetDefaultProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     *Config
		wantNil    bool
		wantIssuer string
	}{
		{
			name: "explicit default provider",
			config: &Config{
				DefaultProvider: "provider2",
				Providers: []ProviderConfig{
					{Name: "provider1", Issuer: "https://issuer1.example.com", ClientID: "client1"},
					{Name: "provider2", Issuer: "https://issuer2.example.com", ClientID: "client2"},
				},
			},
			wantNil:    false,
			wantIssuer: "https://issuer2.example.com",
		},
		{
			name: "no default - returns first",
			config: &Config{
				Providers: []ProviderConfig{
					{Name: "provider1", Issuer: "https://issuer1.example.com", ClientID: "client1"},
					{Name: "provider2", Issuer: "https://issuer2.example.com", ClientID: "client2"},
				},
			},
			wantNil:    false,
			wantIssuer: "https://issuer1.example.com",
		},
		{
			name: "no providers",
			config: &Config{
				Providers: []ProviderConfig{},
			},
			wantNil: true,
		},
		{
			name: "default provider not found",
			config: &Config{
				DefaultProvider: "nonexistent",
				Providers: []ProviderConfig{
					{Name: "provider1", Issuer: "https://issuer1.example.com", ClientID: "client1"},
				},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := tt.config.GetDefaultProvider()
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.wantIssuer, result.Issuer)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.False(t, config.Enabled)
	assert.Equal(t, time.Hour, config.DiscoveryCacheTTL)
	assert.NotNil(t, config.TokenValidation)
	assert.Equal(t, 5*time.Minute, config.TokenValidation.ClockSkew)
}
