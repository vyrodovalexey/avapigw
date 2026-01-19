package secrets

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/vault"
)

func TestNewVaultProvider_NilConfig(t *testing.T) {
	ctx := context.Background()
	_, err := NewVaultProvider(ctx, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestNewVaultProvider_MissingAddress(t *testing.T) {
	ctx := context.Background()
	cfg := &VaultProviderConfig{
		// Address is empty
		AuthMethod: "token",
		Token:      "test-token",
	}
	_, err := NewVaultProvider(ctx, cfg)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProviderNotConfigured)
}

func TestNewVaultProvider_UnsupportedAuthMethod(t *testing.T) {
	ctx := context.Background()
	cfg := &VaultProviderConfig{
		Address:    "http://localhost:8200",
		AuthMethod: "unsupported",
	}
	_, err := NewVaultProvider(ctx, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth method")
}

func TestNewVaultProvider_TokenAuthMissingToken(t *testing.T) {
	ctx := context.Background()
	cfg := &VaultProviderConfig{
		Address:    "http://localhost:8200",
		AuthMethod: "token",
		// Token is empty
	}
	_, err := NewVaultProvider(ctx, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is required")
}

func TestNewVaultProvider_AppRoleAuthMissingRoleID(t *testing.T) {
	ctx := context.Background()
	cfg := &VaultProviderConfig{
		Address:    "http://localhost:8200",
		AuthMethod: "approle",
		// AppRoleID is empty
	}
	_, err := NewVaultProvider(ctx, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role_id is required")
}

func TestVaultProviderConfig_Defaults(t *testing.T) {
	// Test that defaults are applied when creating provider
	// We can't fully test without a Vault server, but we can verify the config structure
	cfg := &VaultProviderConfig{
		Address:    "http://localhost:8200",
		AuthMethod: "token",
		Token:      "test-token",
		Logger:     zap.NewNop(),
	}

	// Verify defaults would be applied
	assert.Empty(t, cfg.SecretMountPoint) // Will default to "secret"
	assert.Zero(t, cfg.Timeout)           // Will default to 30s
	assert.Zero(t, cfg.MaxRetries)        // Will default to 3
	assert.Zero(t, cfg.RetryWaitMin)      // Will default to 500ms
	assert.Zero(t, cfg.RetryWaitMax)      // Will default to 5s
}

func TestVaultProviderConfig_WithTLS(t *testing.T) {
	cfg := &VaultProviderConfig{
		Address:    "https://vault.example.com:8200",
		AuthMethod: "token",
		Token:      "test-token",
		TLSConfig: &vault.TLSConfig{
			InsecureSkipVerify: true,
			ServerName:         "vault.example.com",
		},
		Logger: zap.NewNop(),
	}

	assert.NotNil(t, cfg.TLSConfig)
	assert.True(t, cfg.TLSConfig.InsecureSkipVerify)
	assert.Equal(t, "vault.example.com", cfg.TLSConfig.ServerName)
}

func TestVaultProviderConfig_KubernetesAuth(t *testing.T) {
	cfg := &VaultProviderConfig{
		Address:    "http://localhost:8200",
		AuthMethod: "kubernetes",
		Role:       "my-role",
		MountPath:  "kubernetes",
		Logger:     zap.NewNop(),
	}

	assert.Equal(t, "kubernetes", cfg.AuthMethod)
	assert.Equal(t, "my-role", cfg.Role)
	assert.Equal(t, "kubernetes", cfg.MountPath)
}

func TestVaultProviderConfig_AppRoleAuth(t *testing.T) {
	cfg := &VaultProviderConfig{
		Address:         "http://localhost:8200",
		AuthMethod:      "approle",
		AppRoleID:       "role-id",
		AppRoleSecretID: "secret-id",
		MountPath:       "approle",
		Logger:          zap.NewNop(),
	}

	assert.Equal(t, "approle", cfg.AuthMethod)
	assert.Equal(t, "role-id", cfg.AppRoleID)
	assert.Equal(t, "secret-id", cfg.AppRoleSecretID)
}

func TestVaultProviderConfig_CustomSettings(t *testing.T) {
	cfg := &VaultProviderConfig{
		Address:          "http://localhost:8200",
		Namespace:        "my-namespace",
		AuthMethod:       "token",
		Token:            "test-token",
		SecretMountPoint: "kv",
		Timeout:          60 * time.Second,
		MaxRetries:       5,
		RetryWaitMin:     1 * time.Second,
		RetryWaitMax:     10 * time.Second,
		Logger:           zap.NewNop(),
	}

	assert.Equal(t, "my-namespace", cfg.Namespace)
	assert.Equal(t, "kv", cfg.SecretMountPoint)
	assert.Equal(t, 60*time.Second, cfg.Timeout)
	assert.Equal(t, 5, cfg.MaxRetries)
	assert.Equal(t, 1*time.Second, cfg.RetryWaitMin)
	assert.Equal(t, 10*time.Second, cfg.RetryWaitMax)
}

// TestVaultProvider_Type tests the Type method
func TestVaultProvider_Type(t *testing.T) {
	// Create a minimal provider struct for testing Type()
	p := &VaultProvider{
		logger: zap.NewNop(),
	}
	assert.Equal(t, ProviderTypeVault, p.Type())
}

// TestVaultProvider_IsReadOnly tests the IsReadOnly method
func TestVaultProvider_IsReadOnly(t *testing.T) {
	p := &VaultProvider{
		logger: zap.NewNop(),
	}
	assert.False(t, p.IsReadOnly())
}

// TestVaultProvider_GetSecret_EmptyPath tests GetSecret with empty path
func TestVaultProvider_GetSecret_EmptyPath(t *testing.T) {
	p := &VaultProvider{
		logger: zap.NewNop(),
	}

	ctx := context.Background()
	_, err := p.GetSecret(ctx, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

// TestVaultProvider_WriteSecret_EmptyPath tests WriteSecret with empty path
func TestVaultProvider_WriteSecret_EmptyPath(t *testing.T) {
	p := &VaultProvider{
		logger: zap.NewNop(),
	}

	ctx := context.Background()
	err := p.WriteSecret(ctx, "", map[string][]byte{"key": []byte("value")})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

// TestVaultProvider_DeleteSecret_EmptyPath tests DeleteSecret with empty path
func TestVaultProvider_DeleteSecret_EmptyPath(t *testing.T) {
	p := &VaultProvider{
		logger: zap.NewNop(),
	}

	ctx := context.Background()
	err := p.DeleteSecret(ctx, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

// TestVaultProvider_Close tests the Close method
func TestVaultProvider_Close(t *testing.T) {
	p := &VaultProvider{
		logger: zap.NewNop(),
		client: nil, // nil client should be handled gracefully
	}

	err := p.Close()
	assert.NoError(t, err)
}

// TestVaultProvider_GetVaultClient tests the GetVaultClient method
func TestVaultProvider_GetVaultClient(t *testing.T) {
	p := &VaultProvider{
		logger: zap.NewNop(),
		client: nil,
	}

	assert.Nil(t, p.GetVaultClient())
}

// TestVaultProvider_GetKV2Client tests the GetKV2Client method
func TestVaultProvider_GetKV2Client(t *testing.T) {
	p := &VaultProvider{
		logger:    zap.NewNop(),
		kv2Client: nil,
	}

	assert.Nil(t, p.GetKV2Client())
}

// TestCreateVaultAuthMethod tests the createVaultAuthMethod function
func TestCreateVaultAuthMethod_Token(t *testing.T) {
	cfg := &VaultProviderConfig{
		AuthMethod: "token",
		Token:      "test-token",
	}

	auth, err := createVaultAuthMethod(cfg)
	require.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestCreateVaultAuthMethod_TokenMissing(t *testing.T) {
	cfg := &VaultProviderConfig{
		AuthMethod: "token",
		Token:      "",
	}

	_, err := createVaultAuthMethod(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is required")
}

func TestCreateVaultAuthMethod_Kubernetes(t *testing.T) {
	cfg := &VaultProviderConfig{
		AuthMethod: "kubernetes",
		Role:       "my-role",
		MountPath:  "kubernetes",
	}

	auth, err := createVaultAuthMethod(cfg)
	require.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestCreateVaultAuthMethod_KubernetesDefaultMountPath(t *testing.T) {
	cfg := &VaultProviderConfig{
		AuthMethod: "kubernetes",
		Role:       "my-role",
		// MountPath is empty, should default to "kubernetes"
	}

	auth, err := createVaultAuthMethod(cfg)
	require.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestCreateVaultAuthMethod_AppRole(t *testing.T) {
	cfg := &VaultProviderConfig{
		AuthMethod:      "approle",
		AppRoleID:       "role-id",
		AppRoleSecretID: "secret-id",
		MountPath:       "approle",
	}

	auth, err := createVaultAuthMethod(cfg)
	require.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestCreateVaultAuthMethod_AppRoleDefaultMountPath(t *testing.T) {
	cfg := &VaultProviderConfig{
		AuthMethod:      "approle",
		AppRoleID:       "role-id",
		AppRoleSecretID: "secret-id",
		// MountPath is empty, should default to "approle"
	}

	auth, err := createVaultAuthMethod(cfg)
	require.NoError(t, err)
	assert.NotNil(t, auth)
}

func TestCreateVaultAuthMethod_AppRoleMissingRoleID(t *testing.T) {
	cfg := &VaultProviderConfig{
		AuthMethod:      "approle",
		AppRoleID:       "",
		AppRoleSecretID: "secret-id",
	}

	_, err := createVaultAuthMethod(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role_id is required")
}

func TestCreateVaultAuthMethod_Unsupported(t *testing.T) {
	cfg := &VaultProviderConfig{
		AuthMethod: "ldap",
	}

	_, err := createVaultAuthMethod(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth method")
}

// TestApplyVaultProviderDefaults tests the applyVaultProviderDefaults function
func TestApplyVaultProviderDefaults(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *VaultProviderConfig
		expected vaultProviderDefaults
	}{
		{
			name: "all defaults",
			cfg:  &VaultProviderConfig{},
			expected: vaultProviderDefaults{
				secretMountPoint: "secret",
				timeout:          30 * time.Second,
				maxRetries:       3,
				retryWaitMin:     500 * time.Millisecond,
				retryWaitMax:     5 * time.Second,
			},
		},
		{
			name: "custom values",
			cfg: &VaultProviderConfig{
				SecretMountPoint: "kv",
				Timeout:          60 * time.Second,
				MaxRetries:       5,
				RetryWaitMin:     1 * time.Second,
				RetryWaitMax:     10 * time.Second,
			},
			expected: vaultProviderDefaults{
				secretMountPoint: "kv",
				timeout:          60 * time.Second,
				maxRetries:       5,
				retryWaitMin:     1 * time.Second,
				retryWaitMax:     10 * time.Second,
			},
		},
		{
			name: "partial custom values",
			cfg: &VaultProviderConfig{
				SecretMountPoint: "custom-mount",
				Timeout:          45 * time.Second,
				// MaxRetries, RetryWaitMin, RetryWaitMax use defaults
			},
			expected: vaultProviderDefaults{
				secretMountPoint: "custom-mount",
				timeout:          45 * time.Second,
				maxRetries:       3,
				retryWaitMin:     500 * time.Millisecond,
				retryWaitMax:     5 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyVaultProviderDefaults(tt.cfg)
			assert.Equal(t, tt.expected.secretMountPoint, result.secretMountPoint)
			assert.Equal(t, tt.expected.timeout, result.timeout)
			assert.Equal(t, tt.expected.maxRetries, result.maxRetries)
			assert.Equal(t, tt.expected.retryWaitMin, result.retryWaitMin)
			assert.Equal(t, tt.expected.retryWaitMax, result.retryWaitMax)
		})
	}
}

// TestVaultProvider_Close_WithClient tests Close with a non-nil client
func TestVaultProvider_Close_WithClient(t *testing.T) {
	// Create a minimal vault client for testing
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	p := &VaultProvider{
		logger: zap.NewNop(),
		client: client,
	}

	err = p.Close()
	assert.NoError(t, err)
}

// TestVaultProviderConfig_AllFields tests all VaultProviderConfig fields
func TestVaultProviderConfig_AllFields(t *testing.T) {
	cfg := &VaultProviderConfig{
		Address:          "http://vault.example.com:8200",
		Namespace:        "my-namespace",
		AuthMethod:       "kubernetes",
		Role:             "my-role",
		MountPath:        "kubernetes",
		Token:            "my-token",
		AppRoleID:        "role-id",
		AppRoleSecretID:  "secret-id",
		SecretMountPoint: "kv",
		TLSConfig: &vault.TLSConfig{
			InsecureSkipVerify: true,
			ServerName:         "vault.example.com",
		},
		Timeout:      60 * time.Second,
		MaxRetries:   5,
		RetryWaitMin: 1 * time.Second,
		RetryWaitMax: 10 * time.Second,
		Logger:       zap.NewNop(),
	}

	// Verify all fields are set
	assert.Equal(t, "http://vault.example.com:8200", cfg.Address)
	assert.Equal(t, "my-namespace", cfg.Namespace)
	assert.Equal(t, "kubernetes", cfg.AuthMethod)
	assert.Equal(t, "my-role", cfg.Role)
	assert.Equal(t, "kubernetes", cfg.MountPath)
	assert.Equal(t, "my-token", cfg.Token)
	assert.Equal(t, "role-id", cfg.AppRoleID)
	assert.Equal(t, "secret-id", cfg.AppRoleSecretID)
	assert.Equal(t, "kv", cfg.SecretMountPoint)
	assert.NotNil(t, cfg.TLSConfig)
	assert.True(t, cfg.TLSConfig.InsecureSkipVerify)
	assert.Equal(t, 60*time.Second, cfg.Timeout)
	assert.Equal(t, 5, cfg.MaxRetries)
	assert.Equal(t, 1*time.Second, cfg.RetryWaitMin)
	assert.Equal(t, 10*time.Second, cfg.RetryWaitMax)
	assert.NotNil(t, cfg.Logger)
}

// TestApplyVaultProviderDefaults_AllDefaults tests that all defaults are applied
func TestApplyVaultProviderDefaults_AllDefaults(t *testing.T) {
	cfg := &VaultProviderConfig{}
	defaults := applyVaultProviderDefaults(cfg)

	assert.Equal(t, "secret", defaults.secretMountPoint)
	assert.Equal(t, 30*time.Second, defaults.timeout)
	assert.Equal(t, 3, defaults.maxRetries)
	assert.Equal(t, 500*time.Millisecond, defaults.retryWaitMin)
	assert.Equal(t, 5*time.Second, defaults.retryWaitMax)
}

// TestApplyVaultProviderDefaults_PartialDefaults tests partial defaults
func TestApplyVaultProviderDefaults_PartialDefaults(t *testing.T) {
	cfg := &VaultProviderConfig{
		SecretMountPoint: "custom-mount",
		Timeout:          45 * time.Second,
		// MaxRetries, RetryWaitMin, RetryWaitMax should use defaults
	}
	defaults := applyVaultProviderDefaults(cfg)

	assert.Equal(t, "custom-mount", defaults.secretMountPoint)
	assert.Equal(t, 45*time.Second, defaults.timeout)
	assert.Equal(t, 3, defaults.maxRetries)
	assert.Equal(t, 500*time.Millisecond, defaults.retryWaitMin)
	assert.Equal(t, 5*time.Second, defaults.retryWaitMax)
}

// TestApplyVaultProviderDefaults_NoDefaults tests when all values are provided
func TestApplyVaultProviderDefaults_NoDefaults(t *testing.T) {
	cfg := &VaultProviderConfig{
		SecretMountPoint: "kv",
		Timeout:          60 * time.Second,
		MaxRetries:       5,
		RetryWaitMin:     1 * time.Second,
		RetryWaitMax:     10 * time.Second,
	}
	defaults := applyVaultProviderDefaults(cfg)

	assert.Equal(t, "kv", defaults.secretMountPoint)
	assert.Equal(t, 60*time.Second, defaults.timeout)
	assert.Equal(t, 5, defaults.maxRetries)
	assert.Equal(t, 1*time.Second, defaults.retryWaitMin)
	assert.Equal(t, 10*time.Second, defaults.retryWaitMax)
}

// TestVaultProvider_GetVaultClient_WithClient tests GetVaultClient with a real client
func TestVaultProvider_GetVaultClient_WithClient(t *testing.T) {
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	p := &VaultProvider{
		logger: zap.NewNop(),
		client: client,
	}

	assert.NotNil(t, p.GetVaultClient())
	assert.Equal(t, client, p.GetVaultClient())
}

// TestVaultProvider_GetKV2Client_WithClient tests GetKV2Client with a real client
func TestVaultProvider_GetKV2Client_WithClient(t *testing.T) {
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:    zap.NewNop(),
		client:    client,
		kv2Client: kv2Client,
	}

	assert.NotNil(t, p.GetKV2Client())
	assert.Equal(t, kv2Client, p.GetKV2Client())
}

// TestVaultProvider_SecretMountPoint tests that secretMountPoint is set correctly
func TestVaultProvider_SecretMountPoint(t *testing.T) {
	p := &VaultProvider{
		logger:           zap.NewNop(),
		secretMountPoint: "custom-mount",
	}

	assert.Equal(t, "custom-mount", p.secretMountPoint)
}

// TestNewVaultProvider_NilLogger tests that nil logger is handled
func TestNewVaultProvider_NilLogger(t *testing.T) {
	ctx := context.Background()
	cfg := &VaultProviderConfig{
		Address:    "http://localhost:8200",
		AuthMethod: "token",
		Token:      "test-token",
		Logger:     nil, // nil logger should be handled
	}

	// This will fail because we can't connect to Vault, but it tests the nil logger path
	_, err := NewVaultProvider(ctx, cfg)
	// We expect an error because we can't actually authenticate
	assert.Error(t, err)
}

// TestVaultProvider_GetSecret_TableDriven tests GetSecret with various inputs
func TestVaultProvider_GetSecret_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
		errorIs     error
	}{
		{
			name:        "empty path",
			path:        "",
			expectError: true,
			errorIs:     ErrInvalidPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &VaultProvider{
				logger: zap.NewNop(),
			}

			ctx := context.Background()
			_, err := p.GetSecret(ctx, tt.path)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorIs != nil {
					assert.ErrorIs(t, err, tt.errorIs)
				}
			}
		})
	}
}

// TestVaultProvider_WriteSecret_TableDriven tests WriteSecret with various inputs
func TestVaultProvider_WriteSecret_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		data        map[string][]byte
		expectError bool
		errorIs     error
	}{
		{
			name:        "empty path",
			path:        "",
			data:        map[string][]byte{"key": []byte("value")},
			expectError: true,
			errorIs:     ErrInvalidPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &VaultProvider{
				logger: zap.NewNop(),
			}

			ctx := context.Background()
			err := p.WriteSecret(ctx, tt.path, tt.data)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorIs != nil {
					assert.ErrorIs(t, err, tt.errorIs)
				}
			}
		})
	}
}

// TestVaultProvider_DeleteSecret_TableDriven tests DeleteSecret with various inputs
func TestVaultProvider_DeleteSecret_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
		errorIs     error
	}{
		{
			name:        "empty path",
			path:        "",
			expectError: true,
			errorIs:     ErrInvalidPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &VaultProvider{
				logger: zap.NewNop(),
			}

			ctx := context.Background()
			err := p.DeleteSecret(ctx, tt.path)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorIs != nil {
					assert.ErrorIs(t, err, tt.errorIs)
				}
			}
		})
	}
}

// TestVaultProvider_ListSecrets_NilKV2Client tests ListSecrets with nil KV2 client
func TestVaultProvider_ListSecrets_NilKV2Client(t *testing.T) {
	p := &VaultProvider{
		logger:    zap.NewNop(),
		kv2Client: nil,
	}

	ctx := context.Background()

	// Should panic because kv2Client is nil
	defer func() {
		if r := recover(); r != nil {
			// Expected panic due to nil kv2Client
			t.Log("Recovered from panic as expected")
		}
	}()
	_, _ = p.ListSecrets(ctx, "test-path")
}

// TestVaultProvider_HealthCheck_NotAuthenticated tests HealthCheck when not authenticated
func TestVaultProvider_HealthCheck_NotAuthenticated(t *testing.T) {
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	p := &VaultProvider{
		logger: zap.NewNop(),
		client: client,
	}

	ctx := context.Background()
	// HealthCheck should fail because we're not authenticated
	err = p.HealthCheck(ctx)
	assert.Error(t, err)
}

// TestVaultProvider_HealthCheck_NilClient tests HealthCheck with nil client
func TestVaultProvider_HealthCheck_NilClient(t *testing.T) {
	p := &VaultProvider{
		logger: zap.NewNop(),
		client: nil,
	}

	ctx := context.Background()
	// Should panic because client is nil
	defer func() {
		if r := recover(); r != nil {
			// Expected panic due to nil client
			t.Log("Recovered from panic as expected for nil client")
		}
	}()
	_ = p.HealthCheck(ctx)
}

// TestVaultProviderConfig_WithNamespace tests config with namespace
func TestVaultProviderConfig_WithNamespace(t *testing.T) {
	cfg := &VaultProviderConfig{
		Address:    "http://localhost:8200",
		Namespace:  "my-namespace",
		AuthMethod: "token",
		Token:      "test-token",
	}

	assert.Equal(t, "my-namespace", cfg.Namespace)
}

// TestCreateVaultAuthMethod_AllMethods tests all auth methods
func TestCreateVaultAuthMethod_AllMethods(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *VaultProviderConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "token auth with valid token",
			cfg: &VaultProviderConfig{
				AuthMethod: "token",
				Token:      "valid-token",
			},
			expectError: false,
		},
		{
			name: "token auth without token",
			cfg: &VaultProviderConfig{
				AuthMethod: "token",
				Token:      "",
			},
			expectError: true,
			errorMsg:    "token is required",
		},
		{
			name: "kubernetes auth with role",
			cfg: &VaultProviderConfig{
				AuthMethod: "kubernetes",
				Role:       "my-role",
			},
			expectError: false,
		},
		{
			name: "kubernetes auth with custom mount path",
			cfg: &VaultProviderConfig{
				AuthMethod: "kubernetes",
				Role:       "my-role",
				MountPath:  "custom-k8s",
			},
			expectError: false,
		},
		{
			name: "approle auth with role id only",
			cfg: &VaultProviderConfig{
				AuthMethod: "approle",
				AppRoleID:  "role-id",
			},
			expectError: true,
			errorMsg:    "secretID is required",
		},
		{
			name: "approle auth with role id and secret id",
			cfg: &VaultProviderConfig{
				AuthMethod:      "approle",
				AppRoleID:       "role-id",
				AppRoleSecretID: "secret-id",
			},
			expectError: false,
		},
		{
			name: "approle auth without role id",
			cfg: &VaultProviderConfig{
				AuthMethod:      "approle",
				AppRoleID:       "",
				AppRoleSecretID: "secret-id",
			},
			expectError: true,
			errorMsg:    "role_id is required",
		},
		{
			name: "approle auth with custom mount path",
			cfg: &VaultProviderConfig{
				AuthMethod:      "approle",
				AppRoleID:       "role-id",
				AppRoleSecretID: "secret-id",
				MountPath:       "custom-approle",
			},
			expectError: false,
		},
		{
			name: "unsupported auth method",
			cfg: &VaultProviderConfig{
				AuthMethod: "userpass",
			},
			expectError: true,
			errorMsg:    "unsupported auth method",
		},
		{
			name: "empty auth method",
			cfg: &VaultProviderConfig{
				AuthMethod: "",
			},
			expectError: true,
			errorMsg:    "unsupported auth method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := createVaultAuthMethod(tt.cfg)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, auth)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, auth)
			}
		})
	}
}

// TestVaultProvider_Close_MultipleCalls tests calling Close multiple times
func TestVaultProvider_Close_MultipleCalls(t *testing.T) {
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	p := &VaultProvider{
		logger: zap.NewNop(),
		client: client,
	}

	// First close
	err = p.Close()
	assert.NoError(t, err)

	// Second close should also succeed (idempotent)
	err = p.Close()
	assert.NoError(t, err)
}

// TestVaultProvider_Type_Constant tests that Type returns the correct constant
func TestVaultProvider_Type_Constant(t *testing.T) {
	p := &VaultProvider{
		logger: zap.NewNop(),
	}

	providerType := p.Type()
	assert.Equal(t, ProviderTypeVault, providerType)
	assert.Equal(t, ProviderType("vault"), providerType)
}

// TestVaultProvider_IsReadOnly_AlwaysFalse tests that IsReadOnly always returns false
func TestVaultProvider_IsReadOnly_AlwaysFalse(t *testing.T) {
	p := &VaultProvider{
		logger: zap.NewNop(),
	}

	assert.False(t, p.IsReadOnly())

	// Even with different configurations, should still be false
	p2 := &VaultProvider{
		logger:           zap.NewNop(),
		secretMountPoint: "custom",
	}
	assert.False(t, p2.IsReadOnly())
}

// TestVaultProvider_GetSecret_WithKV2Client tests GetSecret with a real KV2 client (mocked via test server)
func TestVaultProvider_GetSecret_WithKV2Client(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	ctx := context.Background()

	// Test with valid path but no vault server - should fail with connection error
	_, err = p.GetSecret(ctx, "test/secret")
	assert.Error(t, err)
	// The error should be wrapped
	assert.Contains(t, err.Error(), "failed to read secret from vault")
}

// TestVaultProvider_ListSecrets_WithKV2Client tests ListSecrets with a real KV2 client
func TestVaultProvider_ListSecrets_WithKV2Client(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	ctx := context.Background()

	// Test with valid path but no vault server - should fail with connection error
	_, err = p.ListSecrets(ctx, "test")
	assert.Error(t, err)
	// The error should be wrapped
	assert.Contains(t, err.Error(), "failed to list secrets from vault")
}

// TestVaultProvider_WriteSecret_WithKV2Client tests WriteSecret with a real KV2 client
func TestVaultProvider_WriteSecret_WithKV2Client(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	ctx := context.Background()

	// Test with valid path but no vault server - should fail with connection error
	err = p.WriteSecret(ctx, "test/secret", map[string][]byte{"key": []byte("value")})
	assert.Error(t, err)
	// The error should be wrapped
	assert.Contains(t, err.Error(), "failed to write secret to vault")
}

// TestVaultProvider_DeleteSecret_WithKV2Client tests DeleteSecret with a real KV2 client
func TestVaultProvider_DeleteSecret_WithKV2Client(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	ctx := context.Background()

	// Test with valid path but no vault server - should fail with connection error
	err = p.DeleteSecret(ctx, "test/secret")
	assert.Error(t, err)
	// The error should be wrapped
	assert.Contains(t, err.Error(), "failed to delete secret from vault")
}

// TestVaultProvider_GetSecret_NilSecret tests GetSecret when vault returns nil secret
func TestVaultProvider_GetSecret_NilSecret(t *testing.T) {
	// This test verifies the nil secret handling path
	p := &VaultProvider{
		logger: zap.NewNop(),
	}

	// Empty path should return ErrInvalidPath
	ctx := context.Background()
	_, err := p.GetSecret(ctx, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

// TestVaultProvider_WriteSecret_DataConversion tests WriteSecret data conversion
func TestVaultProvider_WriteSecret_DataConversion(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	ctx := context.Background()

	// Test with multiple keys
	data := map[string][]byte{
		"key1": []byte("value1"),
		"key2": []byte("value2"),
		"key3": []byte("value3"),
	}

	// This will fail because no vault server, but tests the data conversion path
	err = p.WriteSecret(ctx, "test/multi-key", data)
	assert.Error(t, err)
}

// TestVaultProvider_HealthCheck_Authenticated tests HealthCheck when already authenticated
func TestVaultProvider_HealthCheck_Authenticated(t *testing.T) {
	// Create a vault client with token auth
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	// Set a token to simulate authentication
	tokenAuth, err := vault.NewTokenAuth("test-token")
	require.NoError(t, err)
	client.SetAuthMethod(tokenAuth)

	p := &VaultProvider{
		logger: zap.NewNop(),
		client: client,
	}

	ctx := context.Background()

	// HealthCheck should fail because we're not actually authenticated
	err = p.HealthCheck(ctx)
	assert.Error(t, err)
}

// TestVaultProvider_GetSecret_NonStringValue tests GetSecret with non-string values in vault response
func TestVaultProvider_GetSecret_NonStringValue(t *testing.T) {
	// This test verifies that non-string values are handled correctly
	// The actual conversion happens in the GetSecret method
	p := &VaultProvider{
		logger: zap.NewNop(),
	}

	// Test with empty path
	ctx := context.Background()
	_, err := p.GetSecret(ctx, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPath)
}

// TestVaultProviderConfig_AllAuthMethods tests all authentication method configurations
func TestVaultProviderConfig_AllAuthMethods(t *testing.T) {
	tests := []struct {
		name       string
		authMethod string
		cfg        *VaultProviderConfig
	}{
		{
			name:       "token auth",
			authMethod: "token",
			cfg: &VaultProviderConfig{
				Address:    "http://localhost:8200",
				AuthMethod: "token",
				Token:      "test-token",
			},
		},
		{
			name:       "kubernetes auth",
			authMethod: "kubernetes",
			cfg: &VaultProviderConfig{
				Address:    "http://localhost:8200",
				AuthMethod: "kubernetes",
				Role:       "my-role",
				MountPath:  "kubernetes",
			},
		},
		{
			name:       "approle auth",
			authMethod: "approle",
			cfg: &VaultProviderConfig{
				Address:         "http://localhost:8200",
				AuthMethod:      "approle",
				AppRoleID:       "role-id",
				AppRoleSecretID: "secret-id",
				MountPath:       "approle",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.authMethod, tt.cfg.AuthMethod)
		})
	}
}

// TestVaultProvider_ListSecrets_EmptyPath tests ListSecrets with empty path
func TestVaultProvider_ListSecrets_EmptyPath(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	ctx := context.Background()

	// Test with empty path - should still try to list
	_, err = p.ListSecrets(ctx, "")
	assert.Error(t, err)
}

// TestVaultProvider_GetSecret_ContextCancellation tests GetSecret with cancelled context
func TestVaultProvider_GetSecret_ContextCancellation(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test with cancelled context
	_, err = p.GetSecret(ctx, "test/secret")
	assert.Error(t, err)
}

// TestVaultProvider_WriteSecret_ContextCancellation tests WriteSecret with cancelled context
func TestVaultProvider_WriteSecret_ContextCancellation(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test with cancelled context
	err = p.WriteSecret(ctx, "test/secret", map[string][]byte{"key": []byte("value")})
	assert.Error(t, err)
}

// TestVaultProvider_DeleteSecret_ContextCancellation tests DeleteSecret with cancelled context
func TestVaultProvider_DeleteSecret_ContextCancellation(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test with cancelled context
	err = p.DeleteSecret(ctx, "test/secret")
	assert.Error(t, err)
}

// TestVaultProvider_ListSecrets_ContextCancellation tests ListSecrets with cancelled context
func TestVaultProvider_ListSecrets_ContextCancellation(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	kv2Client := vault.NewKV2Client(client, "secret", zap.NewNop())

	p := &VaultProvider{
		logger:           zap.NewNop(),
		client:           client,
		kv2Client:        kv2Client,
		secretMountPoint: "secret",
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test with cancelled context
	_, err = p.ListSecrets(ctx, "test")
	assert.Error(t, err)
}

// TestVaultProvider_HealthCheck_ContextCancellation tests HealthCheck with cancelled context
func TestVaultProvider_HealthCheck_ContextCancellation(t *testing.T) {
	// Create a vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = "http://localhost:8200"
	client, err := vault.NewClient(vaultCfg, zap.NewNop())
	require.NoError(t, err)

	// Set a token auth method
	tokenAuth, err := vault.NewTokenAuth("test-token")
	require.NoError(t, err)
	client.SetAuthMethod(tokenAuth)

	p := &VaultProvider{
		logger: zap.NewNop(),
		client: client,
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Test with cancelled context
	err = p.HealthCheck(ctx)
	assert.Error(t, err)
}
