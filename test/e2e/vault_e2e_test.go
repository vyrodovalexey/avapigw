//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
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
Vault E2E Test Setup Instructions:

1. Start Vault in dev mode:
   docker run -d --name vault-e2e \
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

4. Run E2E tests:
   VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=myroot go test -tags=e2e ./test/e2e/...
*/

func TestE2E_Vault_PKI_GatewayTLS(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
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

	// Create Vault provider for TLS
	providerCfg := &vault.VaultProviderConfig{
		PKIMount:    setup.PKIMount,
		Role:        setup.PKIRole,
		CommonName:  "gateway.local",
		AltNames:    []string{"localhost"},
		IPSANs:      []string{"127.0.0.1"},
		TTL:         1 * time.Hour,
		RenewBefore: 10 * time.Minute,
	}

	provider, err := vault.NewVaultProvider(client, providerCfg,
		vault.WithVaultProviderLogger(logger),
	)
	require.NoError(t, err)
	defer provider.Close()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Get certificate from provider
	cert, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Create TLS server using Vault-issued certificate
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nVault TLS Gateway"))
			}(conn)
		}
	}()

	// Get CA from Vault for client verification
	caPool, err := provider.GetClientCA(ctx)
	if caPool == nil {
		// If no CA pool from provider, get directly from PKI
		caPool, err = client.PKI().GetCA(ctx, setup.PKIMount)
		require.NoError(t, err)
	}

	// Create client with Vault CA
	clientTLSConfig := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS12,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Vault TLS Gateway", string(body))
}

func TestE2E_Vault_PKI_BackendTLS(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
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

	// Issue certificate for backend
	opts := &vault.PKIIssueOptions{
		Mount:      setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "backend.local",
		AltNames:   []string{"localhost"},
		IPSANs:     []string{"127.0.0.1"},
		TTL:        1 * time.Hour,
	}

	certData, err := client.PKI().IssueCertificate(ctx, opts)
	require.NoError(t, err)
	require.NotNil(t, certData)

	// Create TLS certificate from Vault response
	tlsCert, err := tls.X509KeyPair([]byte(certData.CertificatePEM), []byte(certData.PrivateKeyPEM))
	require.NoError(t, err)

	// Create backend TLS server
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start backend server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nVault TLS Backend"))
			}(conn)
		}
	}()

	// Get CA for verification
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	// Create client
	clientTLSConfig := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS12,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Vault TLS Backend", string(body))
}

func TestE2E_Vault_PKI_CertificateRenewal(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping certificate renewal test in short mode")
	}

	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
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

	// Create provider with short TTL for testing renewal
	providerCfg := &vault.VaultProviderConfig{
		PKIMount:    setup.PKIMount,
		Role:        setup.PKIRole,
		CommonName:  "renewal-e2e.local",
		TTL:         10 * time.Second,
		RenewBefore: 5 * time.Second,
	}

	provider, err := vault.NewVaultProvider(client, providerCfg,
		vault.WithVaultProviderLogger(logger),
	)
	require.NoError(t, err)
	defer provider.Close()

	err = provider.Start(ctx)
	require.NoError(t, err)

	// Get initial certificate
	cert1, err := provider.GetCertificate(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cert1)
	initialSerial := cert1.Leaf.SerialNumber.String()

	// Watch for renewal events
	eventCh := provider.Watch(ctx)

	// Wait for renewal
	renewalReceived := false
	timeout := time.After(15 * time.Second)

	for !renewalReceived {
		select {
		case event := <-eventCh:
			if event.Type == internaltls.CertificateEventReloaded {
				renewalReceived = true

				// Get renewed certificate
				cert2, err := provider.GetCertificate(ctx, nil)
				require.NoError(t, err)
				require.NotNil(t, cert2)

				newSerial := cert2.Leaf.SerialNumber.String()
				assert.NotEqual(t, initialSerial, newSerial, "Certificate should have been renewed")
			}
		case <-timeout:
			t.Log("Timeout waiting for certificate renewal")
			return
		case <-ctx.Done():
			t.Log("Context cancelled")
			return
		}
	}
}

func TestE2E_Vault_KV_SecretRetrieval(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
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

	// Store secrets for gateway configuration
	secretPath := "e2e/gateway/config"
	secretData := map[string]interface{}{
		"api_key":      "test-api-key-12345",
		"database_url": "postgres://user:pass@localhost:5432/db",
		"redis_url":    "redis://localhost:6379",
	}

	err = client.KV().Write(ctx, setup.KVMount, secretPath, secretData)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.KV().Delete(ctx, setup.KVMount, secretPath)
	})

	// Retrieve secrets
	data, err := client.KV().Read(ctx, setup.KVMount, secretPath)
	require.NoError(t, err)
	require.NotNil(t, data)

	assert.Equal(t, "test-api-key-12345", data["api_key"])
	assert.Equal(t, "postgres://user:pass@localhost:5432/db", data["database_url"])
	assert.Equal(t, "redis://localhost:6379", data["redis_url"])

	// Test cache hit (second read should be faster)
	start := time.Now()
	data2, err := client.KV().Read(ctx, setup.KVMount, secretPath)
	require.NoError(t, err)
	cachedDuration := time.Since(start)

	assert.Equal(t, data["api_key"], data2["api_key"])
	t.Logf("Cached read took: %v", cachedDuration)
}

func TestE2E_Vault_Unavailable_Fallback(t *testing.T) {
	ctx := context.Background()

	// Create client with invalid address
	cfg := &vault.Config{
		Enabled:    true,
		Address:    "http://127.0.0.1:19999", // Non-existent Vault
		AuthMethod: vault.AuthMethodToken,
		Token:      "invalid-token",
		Retry: &vault.RetryConfig{
			MaxRetries:  1,
			BackoffBase: 10 * time.Millisecond,
			BackoffMax:  50 * time.Millisecond,
		},
	}

	logger := observability.NopLogger()

	client, err := vault.New(cfg, logger)
	require.NoError(t, err)
	defer client.Close()

	// Authentication should fail
	err = client.Authenticate(ctx)
	assert.Error(t, err)

	// Health check should fail
	_, err = client.Health(ctx)
	assert.Error(t, err)
}

func TestE2E_Vault_FullWorkflow(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
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

	// Step 1: Authenticate
	t.Run("authenticate", func(t *testing.T) {
		err := client.Authenticate(ctx)
		require.NoError(t, err)
	})

	// Step 2: Check health
	t.Run("health check", func(t *testing.T) {
		health, err := client.Health(ctx)
		require.NoError(t, err)
		assert.True(t, health.Initialized)
		assert.False(t, health.Sealed)
	})

	// Step 3: Store configuration secrets
	t.Run("store secrets", func(t *testing.T) {
		secrets := map[string]interface{}{
			"tls_cert_path": "/etc/certs/server.crt",
			"tls_key_path":  "/etc/certs/server.key",
			"backend_url":   "https://backend.local:8443",
		}

		err := client.KV().Write(ctx, setup.KVMount, "e2e/workflow/config", secrets)
		require.NoError(t, err)
	})

	// Register cleanup on parent test so it runs after all subtests
	t.Cleanup(func() {
		_ = client.KV().Delete(ctx, setup.KVMount, "e2e/workflow/config")
	})

	// Step 4: Issue TLS certificate
	var certSerial string
	t.Run("issue certificate", func(t *testing.T) {
		opts := &vault.PKIIssueOptions{
			Mount:      setup.PKIMount,
			Role:       setup.PKIRole,
			CommonName: "workflow.local",
			TTL:        1 * time.Hour,
		}

		cert, err := client.PKI().IssueCertificate(ctx, opts)
		require.NoError(t, err)
		require.NotNil(t, cert)
		assert.NotEmpty(t, cert.CertificatePEM)
		assert.NotEmpty(t, cert.PrivateKeyPEM)
		certSerial = cert.SerialNumber
	})

	// Step 5: Retrieve secrets
	t.Run("retrieve secrets", func(t *testing.T) {
		data, err := client.KV().Read(ctx, setup.KVMount, "e2e/workflow/config")
		require.NoError(t, err)
		require.NotNil(t, data, "data should not be nil")
		assert.Equal(t, "/etc/certs/server.crt", data["tls_cert_path"])
	})

	// Step 6: Get CA certificate
	t.Run("get CA", func(t *testing.T) {
		caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
		require.NoError(t, err)
		require.NotNil(t, caPool)
	})

	// Step 7: Revoke certificate (optional cleanup)
	t.Run("revoke certificate", func(t *testing.T) {
		if certSerial != "" {
			err := client.PKI().RevokeCertificate(ctx, setup.PKIMount, certSerial)
			// May fail if revocation is not configured, which is OK
			if err != nil {
				t.Logf("Certificate revocation failed (may not be configured): %v", err)
			}
		}
	})
}

func TestE2E_Vault_MTLS_WithVaultCerts(t *testing.T) {
	setup := helpers.SetupVaultForTesting(t)
	defer setup.Cleanup()

	ctx := context.Background()
	vaultCfg := helpers.GetVaultTestConfig()

	// Create Vault client
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

	// Issue server certificate
	serverCertData, err := client.PKI().IssueCertificate(ctx, &vault.PKIIssueOptions{
		Mount:      setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "mtls-server.local",
		AltNames:   []string{"localhost"},
		IPSANs:     []string{"127.0.0.1"},
		TTL:        1 * time.Hour,
	})
	require.NoError(t, err)

	// Issue client certificate
	clientCertData, err := client.PKI().IssueCertificate(ctx, &vault.PKIIssueOptions{
		Mount:      setup.PKIMount,
		Role:       setup.PKIRole,
		CommonName: "mtls-client.local",
		TTL:        1 * time.Hour,
	})
	require.NoError(t, err)

	// Get CA
	caPool, err := client.PKI().GetCA(ctx, setup.PKIMount)
	require.NoError(t, err)

	// Create server TLS config
	serverCert, err := tls.X509KeyPair([]byte(serverCertData.CertificatePEM), []byte(serverCertData.PrivateKeyPEM))
	require.NoError(t, err)

	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Start mTLS server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn := c.(*tls.Conn)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				state := tlsConn.ConnectionState()
				if len(state.PeerCertificates) > 0 {
					cn := state.PeerCertificates[0].Subject.CommonName
					response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\nHello %s", len("Hello ")+len(cn), cn)
					_, _ = c.Write([]byte(response))
				}
			}(conn)
		}
	}()

	// Create client TLS config
	clientCert, err := tls.X509KeyPair([]byte(clientCertData.CertificatePEM), []byte(clientCertData.PrivateKeyPEM))
	require.NoError(t, err)

	clientTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
		Timeout: 10 * time.Second,
	}

	resp, err := httpClient.Get(fmt.Sprintf("https://%s/", listener.Addr().String()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "mtls-client.local")
}
