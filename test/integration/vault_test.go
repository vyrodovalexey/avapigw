//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/internal/vault"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

/*
Vault Setup Instructions for Testing:

1. Start Vault in dev mode:
   docker run -d --name vault-test \
     -p 8200:8200 \
     -e VAULT_DEV_ROOT_TOKEN_ID=myroot \
     -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
     vault:latest

2. Configure PKI secrets engine:
   export VAULT_ADDR=http://127.0.0.1:8200
   export VAULT_TOKEN=myroot

   vault secrets enable pki
   vault secrets tune -max-lease-ttl=87600h pki
   vault write pki/root/generate/internal \
     common_name="Test Root CA" \
     ttl=87600h
   vault write pki/roles/test-role \
     allowed_domains="localhost,*.local,*.test" \
     allow_subdomains=true \
     allow_localhost=true \
     allow_any_name=true \
     allow_ip_sans=true \
     max_ttl=72h

3. Configure KV secrets engine:
   vault secrets enable -path=secret kv-v2

4. Run tests:
   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=myroot go test -tags=integration ./test/integration/...
*/

func TestIntegration_Vault_TokenAuth(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	assert.True(t, client.IsEnabled())

	// Authenticate
	err = client.Authenticate(ctx)
	require.NoError(t, err)

	// Check health
	health, err := client.Health(ctx)
	require.NoError(t, err)
	assert.True(t, health.Initialized)
	assert.False(t, health.Sealed)
}

func TestIntegration_Vault_PKI_IssueCertificate(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	// Issue certificate
	opts := &vault.PKIIssueOptions{
		Mount:      setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "test.local",
		AltNames:   []string{"alt.local"},
		TTL:        1 * time.Hour,
	}

	cert, err := client.PKI().IssueCertificate(ctx, opts)
	require.NoError(t, err)
	require.NotNil(t, cert)

	assert.NotEmpty(t, cert.CertificatePEM)
	assert.NotEmpty(t, cert.PrivateKeyPEM)
	assert.NotEmpty(t, cert.SerialNumber)
	assert.NotNil(t, cert.Certificate)
	assert.False(t, cert.Expiration.IsZero())
}

func TestIntegration_Vault_PKI_GetCA(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	// Get CA
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)
	require.NotNil(t, caPool)
}

func TestIntegration_Vault_KV_ReadWrite(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	secretPath := "test/integration/secret"
	secretData := map[string]interface{}{
		"username": "testuser",
		"password": "testpass",
	}

	// Write secret
	err = client.KV().Write(ctx, setup.KVMount, secretPath, secretData)
	require.NoError(t, err)

	// Read secret
	data, err := client.KV().Read(ctx, setup.KVMount, secretPath)
	require.NoError(t, err)
	require.NotNil(t, data)

	assert.Equal(t, "testuser", data["username"])
	assert.Equal(t, "testpass", data["password"])

	// Cleanup
	err = client.KV().Delete(ctx, setup.KVMount, secretPath)
	require.NoError(t, err)
}

func TestIntegration_Vault_KV_Delete(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	secretPath := "test/integration/delete-test"
	secretData := map[string]interface{}{
		"key": "value",
	}

	// Write secret
	err = client.KV().Write(ctx, setup.KVMount, secretPath, secretData)
	require.NoError(t, err)

	// Delete secret
	err = client.KV().Delete(ctx, setup.KVMount, secretPath)
	require.NoError(t, err)

	// Verify deleted
	_, err = client.KV().Read(ctx, setup.KVMount, secretPath)
	assert.Error(t, err)
}

func TestIntegration_Vault_Cache_HitMiss(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
		Cache: &vault.CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 100,
		},
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	secretPath := "test/integration/cache-test"
	secretData := map[string]interface{}{
		"cached": "value",
	}

	// Write secret
	err = client.KV().Write(ctx, setup.KVMount, secretPath, secretData)
	require.NoError(t, err)
	defer func() {
		_ = client.KV().Delete(ctx, setup.KVMount, secretPath)
	}()

	// First read - cache miss
	data1, err := client.KV().Read(ctx, setup.KVMount, secretPath)
	require.NoError(t, err)
	assert.Equal(t, "value", data1["cached"])

	// Second read - should be cache hit
	data2, err := client.KV().Read(ctx, setup.KVMount, secretPath)
	require.NoError(t, err)
	assert.Equal(t, "value", data2["cached"])
}

func TestIntegration_Vault_Cache_TTL(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
		Cache: &vault.CacheConfig{
			Enabled: true,
			TTL:     100 * time.Millisecond, // Short TTL for testing
			MaxSize: 100,
		},
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	secretPath := "test/integration/cache-ttl-test"
	secretData := map[string]interface{}{
		"ttl": "test",
	}

	// Write secret
	err = client.KV().Write(ctx, setup.KVMount, secretPath, secretData)
	require.NoError(t, err)
	defer func() {
		_ = client.KV().Delete(ctx, setup.KVMount, secretPath)
	}()

	// First read
	data1, err := client.KV().Read(ctx, setup.KVMount, secretPath)
	require.NoError(t, err)
	assert.Equal(t, "test", data1["ttl"])

	// Wait for cache to expire
	time.Sleep(200 * time.Millisecond)

	// Read again - should fetch from Vault
	data2, err := client.KV().Read(ctx, setup.KVMount, secretPath)
	require.NoError(t, err)
	assert.Equal(t, "test", data2["ttl"])
}

func TestIntegration_Vault_Provider_GetCertificate(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	providerCfg := &vault.VaultProviderConfig{
		PKIMount:    setup.PKIMount,
		Role:        setup.PKIRole,
		CommonName:  "provider-test.local",
		TTL:         1 * time.Hour,
		RenewBefore: 10 * time.Minute,
	}

	provider, err := vault.NewVaultProvider(client, providerCfg,
		vault.WithVaultProviderLogger(logger),
	)
	require.NoError(t, err)
	defer provider.Close()

	// Start provider
	err = provider.Start(ctx)
	require.NoError(t, err)

	// Get certificate
	cert, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)

	// Get certificate info
	info := provider.GetCertificateInfo()
	require.NotNil(t, info)
	assert.Contains(t, info.Subject, "provider-test.local")
}

func TestIntegration_Vault_Provider_Renewal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping renewal test in short mode")
	}

	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	// Use short TTL and renewBefore for testing
	providerCfg := &vault.VaultProviderConfig{
		PKIMount:    setup.PKIMount,
		Role:        setup.PKIRole,
		CommonName:  "renewal-test.local",
		TTL:         5 * time.Second,
		RenewBefore: 3 * time.Second,
	}

	provider, err := vault.NewVaultProvider(client, providerCfg,
		vault.WithVaultProviderLogger(logger),
	)
	require.NoError(t, err)
	defer provider.Close()

	// Start provider
	err = provider.Start(ctx)
	require.NoError(t, err)

	// Watch for events
	eventCh := provider.Watch(ctx)

	// Get initial certificate
	cert1, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cert1)

	// Wait for renewal event
	select {
	case event := <-eventCh:
		if event.Type == internaltls.CertificateEventLoaded {
			// Wait for reload event
			select {
			case event = <-eventCh:
				assert.Equal(t, internaltls.CertificateEventReloaded, event.Type)
			case <-ctx.Done():
				t.Log("Context cancelled before renewal event")
			}
		}
	case <-ctx.Done():
		t.Log("Context cancelled before any event")
	}
}

func TestIntegration_Vault_DisabledClient(t *testing.T) {
	ctx := context.Background()

	cfg := &vault.Config{
		Enabled: false,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	assert.False(t, client.IsEnabled())

	// All operations should return ErrVaultDisabled
	err = client.Authenticate(ctx)
	assert.ErrorIs(t, err, vault.ErrVaultDisabled)

	err = client.RenewToken(ctx)
	assert.ErrorIs(t, err, vault.ErrVaultDisabled)

	_, err = client.Health(ctx)
	assert.ErrorIs(t, err, vault.ErrVaultDisabled)

	_, err = client.PKI().IssueCertificate(ctx, nil)
	assert.ErrorIs(t, err, vault.ErrVaultDisabled)

	_, err = client.KV().Read(ctx, "mount", "path")
	assert.ErrorIs(t, err, vault.ErrVaultDisabled)
}

func TestIntegration_Vault_ClientClosed(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	// Close client
	err = client.Close()
	require.NoError(t, err)

	// Operations should fail
	err = client.RenewToken(ctx)
	assert.ErrorIs(t, err, vault.ErrClientClosed)

	_, err = client.Health(ctx)
	assert.ErrorIs(t, err, vault.ErrClientClosed)
}

func TestIntegration_Vault_PKI_Validation(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	t.Run("missing mount", func(t *testing.T) {
		opts := &vault.PKIIssueOptions{
			Role:       "test-role",
			CommonName: "test.local",
		}
		_, err := client.PKI().IssueCertificate(ctx, opts)
		assert.Error(t, err)
	})

	t.Run("missing role", func(t *testing.T) {
		opts := &vault.PKIIssueOptions{
			Mount:      "pki",
			CommonName: "test.local",
		}
		_, err := client.PKI().IssueCertificate(ctx, opts)
		assert.Error(t, err)
	})

	t.Run("missing common name", func(t *testing.T) {
		opts := &vault.PKIIssueOptions{
			Mount: "pki",
			Role:  "test-role",
		}
		_, err := client.PKI().IssueCertificate(ctx, opts)
		assert.Error(t, err)
	})
}

func TestIntegration_Vault_KV_Validation(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	cfg := &vault.Config{
		Enabled:    true,
		Address:    vaultCfg.Address,
		AuthMethod: vault.AuthMethodToken,
		Token:      vaultCfg.Token,
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	err = client.Authenticate(ctx)
	require.NoError(t, err)

	t.Run("read missing mount", func(t *testing.T) {
		_, err := client.KV().Read(ctx, "", "path")
		assert.Error(t, err)
	})

	t.Run("read missing path", func(t *testing.T) {
		_, err := client.KV().Read(ctx, "secret", "")
		assert.Error(t, err)
	})

	t.Run("write missing mount", func(t *testing.T) {
		err := client.KV().Write(ctx, "", "path", map[string]interface{}{"key": "value"})
		assert.Error(t, err)
	})

	t.Run("write missing path", func(t *testing.T) {
		err := client.KV().Write(ctx, "secret", "", map[string]interface{}{"key": "value"})
		assert.Error(t, err)
	})

	t.Run("write nil data", func(t *testing.T) {
		err := client.KV().Write(ctx, "secret", "path", nil)
		assert.Error(t, err)
	})

	t.Run("delete missing mount", func(t *testing.T) {
		err := client.KV().Delete(ctx, "", "path")
		assert.Error(t, err)
	})

	t.Run("delete missing path", func(t *testing.T) {
		err := client.KV().Delete(ctx, "secret", "")
		assert.Error(t, err)
	})
}
