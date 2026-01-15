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
