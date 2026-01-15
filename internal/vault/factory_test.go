package vault

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewFactory(t *testing.T) {
	config := &FactoryConfig{
		Address:    "http://localhost:8200",
		AuthMethod: "kubernetes",
		Role:       "test-role",
	}

	factory := NewFactory(config, nil)

	assert.NotNil(t, factory)
	assert.Equal(t, config, factory.config)
}

func TestFactory_CreateAuthMethod(t *testing.T) {
	tests := []struct {
		name       string
		config     *FactoryConfig
		wantErr    bool
		wantMethod string
	}{
		{
			name: "kubernetes auth",
			config: &FactoryConfig{
				AuthMethod: "kubernetes",
				Role:       "test-role",
				MountPath:  "kubernetes",
			},
			wantErr:    false,
			wantMethod: "kubernetes",
		},
		{
			name: "token auth",
			config: &FactoryConfig{
				AuthMethod: "token",
				Token:      "test-token",
			},
			wantErr:    false,
			wantMethod: "token",
		},
		{
			name: "token auth without token",
			config: &FactoryConfig{
				AuthMethod: "token",
			},
			wantErr: true,
		},
		{
			name: "approle auth",
			config: &FactoryConfig{
				AuthMethod:      "approle",
				AppRoleID:       "role-id",
				AppRoleSecretID: "secret-id",
				MountPath:       "approle",
			},
			wantErr:    false,
			wantMethod: "approle",
		},
		{
			name: "approle auth without role_id",
			config: &FactoryConfig{
				AuthMethod: "approle",
			},
			wantErr: true,
		},
		{
			name: "unsupported auth method",
			config: &FactoryConfig{
				AuthMethod: "unsupported",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory(tt.config, nil)
			authMethod, err := factory.createAuthMethod()

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantMethod, authMethod.Name())
		})
	}
}

func TestFactory_CreateSecretManager(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	config := &FactoryConfig{
		CacheEnabled: true,
		CacheTTL:     10 * time.Minute,
	}

	factory := NewFactory(config, nil)
	manager := factory.CreateSecretManager(client)

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.cache)
}

func TestFactory_CreateKV2Client(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	factory := NewFactory(&FactoryConfig{}, nil)
	kv2 := factory.CreateKV2Client(client, "secret")

	assert.NotNil(t, kv2)
	assert.Equal(t, "secret", kv2.mountPoint)
}

func TestFactory_CreateCertificateManager(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	factory := NewFactory(&FactoryConfig{}, nil)
	certManager := factory.CreateCertificateManager(client, 5*time.Minute)

	assert.NotNil(t, certManager)
	assert.Equal(t, 5*time.Minute, certManager.refreshInterval)
}

func TestFactory_CreateTokenRenewalManager(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	config := &FactoryConfig{
		TokenRenewalInterval: 3 * time.Minute,
	}

	factory := NewFactory(config, nil)
	renewalManager := factory.CreateTokenRenewalManager(client)

	assert.NotNil(t, renewalManager)
	assert.Equal(t, 3*time.Minute, renewalManager.config.RenewalInterval)
}

func TestFactoryConfig(t *testing.T) {
	config := &FactoryConfig{
		Address:              "http://vault.example.com:8200",
		Namespace:            "test-ns",
		AuthMethod:           "kubernetes",
		Role:                 "my-role",
		MountPath:            "kubernetes",
		Timeout:              60 * time.Second,
		MaxRetries:           5,
		RetryWaitMin:         1 * time.Second,
		RetryWaitMax:         10 * time.Second,
		CacheEnabled:         true,
		CacheTTL:             10 * time.Minute,
		TokenRenewalEnabled:  true,
		TokenRenewalInterval: 5 * time.Minute,
	}

	assert.Equal(t, "http://vault.example.com:8200", config.Address)
	assert.Equal(t, "test-ns", config.Namespace)
	assert.Equal(t, "kubernetes", config.AuthMethod)
	assert.Equal(t, "my-role", config.Role)
	assert.Equal(t, "kubernetes", config.MountPath)
	assert.Equal(t, 60*time.Second, config.Timeout)
	assert.Equal(t, 5, config.MaxRetries)
	assert.Equal(t, 1*time.Second, config.RetryWaitMin)
	assert.Equal(t, 10*time.Second, config.RetryWaitMax)
	assert.True(t, config.CacheEnabled)
	assert.Equal(t, 10*time.Minute, config.CacheTTL)
	assert.True(t, config.TokenRenewalEnabled)
	assert.Equal(t, 5*time.Minute, config.TokenRenewalInterval)
}

func TestVaultService_Accessors(t *testing.T) {
	// Create a minimal service for testing accessors
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	service := &VaultService{
		client:        client,
		secretManager: NewSecretManager(client, nil),
		kv2Client:     NewKV2Client(client, "secret", nil),
		certManager:   NewCertificateManager(client, 5*time.Minute, nil),
		stopCh:        make(chan struct{}),
	}

	assert.Equal(t, client, service.Client())
	assert.NotNil(t, service.SecretManager())
	assert.NotNil(t, service.KV2Client())
	assert.NotNil(t, service.CertificateManager())
}

func TestVaultService_Close(t *testing.T) {
	client, err := NewClient(nil, nil)
	require.NoError(t, err)

	logger := zap.NewNop()

	service := &VaultService{
		client:        client,
		secretManager: NewSecretManager(client, logger),
		kv2Client:     NewKV2Client(client, "secret", logger),
		certManager:   NewCertificateManager(client, 5*time.Minute, logger),
		logger:        logger,
		stopCh:        make(chan struct{}),
	}

	err = service.Close()
	assert.NoError(t, err)
}
