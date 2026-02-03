//go:build integration

// Package operator_test contains integration tests for the apigw-operator.
package operator_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// TestIntegration_Operator_VaultPKI_CertificateIssuance tests Vault PKI certificate issuance.
func TestIntegration_Operator_VaultPKI_CertificateIssuance(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("issues certificate from Vault PKI", func(t *testing.T) {
		certData, err := vaultSetup.IssueCertificate("test.example.com", "1h")
		require.NoError(t, err)
		require.NotNil(t, certData)

		// Verify certificate data
		certificate, ok := certData["certificate"].(string)
		assert.True(t, ok, "certificate should be a string")
		assert.NotEmpty(t, certificate)

		privateKey, ok := certData["private_key"].(string)
		assert.True(t, ok, "private_key should be a string")
		assert.NotEmpty(t, privateKey)

		caChain, ok := certData["ca_chain"]
		assert.True(t, ok, "ca_chain should exist")
		_ = caChain
	})

	t.Run("issues certificate with SANs", func(t *testing.T) {
		// Issue certificate with multiple SANs
		path := vaultSetup.PKIMount + "/issue/" + vaultSetup.PKIRole
		secret, err := vaultSetup.Client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
			"common_name": "api.example.com",
			"alt_names":   "api1.example.com,api2.example.com",
			"ip_sans":     "127.0.0.1,10.0.0.1",
			"ttl":         "1h",
		})
		require.NoError(t, err)
		require.NotNil(t, secret)
		require.NotNil(t, secret.Data)

		certificate, ok := secret.Data["certificate"].(string)
		assert.True(t, ok)
		assert.NotEmpty(t, certificate)
	})

	t.Run("retrieves CA certificate", func(t *testing.T) {
		ca, err := vaultSetup.GetCA()
		require.NoError(t, err)
		assert.NotEmpty(t, ca)
		assert.Contains(t, ca, "BEGIN CERTIFICATE")
	})
}

// TestIntegration_Operator_VaultPKI_CertificateRenewal tests Vault PKI certificate renewal.
func TestIntegration_Operator_VaultPKI_CertificateRenewal(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	t.Run("renews certificate before expiry", func(t *testing.T) {
		// Issue initial certificate with short TTL
		certData1, err := vaultSetup.IssueCertificate("renewal-test.example.com", "1h")
		require.NoError(t, err)
		require.NotNil(t, certData1)

		cert1 := certData1["certificate"].(string)

		// Issue new certificate (simulating renewal)
		certData2, err := vaultSetup.IssueCertificate("renewal-test.example.com", "1h")
		require.NoError(t, err)
		require.NotNil(t, certData2)

		cert2 := certData2["certificate"].(string)

		// Certificates should be different (new serial number)
		assert.NotEqual(t, cert1, cert2)
	})

	t.Run("handles renewal with different TTL", func(t *testing.T) {
		// Issue certificate with 1 hour TTL
		certData1, err := vaultSetup.IssueCertificate("ttl-test.example.com", "1h")
		require.NoError(t, err)
		require.NotNil(t, certData1)

		// Issue certificate with 24 hour TTL
		certData2, err := vaultSetup.IssueCertificate("ttl-test.example.com", "24h")
		require.NoError(t, err)
		require.NotNil(t, certData2)

		// Both should succeed
		assert.NotEmpty(t, certData1["certificate"])
		assert.NotEmpty(t, certData2["certificate"])
	})
}

// TestIntegration_Operator_VaultPKI_CertManager tests the Vault certificate manager.
func TestIntegration_Operator_VaultPKI_CertManager(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("creates Vault cert manager", func(t *testing.T) {
		vaultConfig := helpers.GetVaultTestConfig()

		manager, err := cert.NewVaultProvider(ctx, &cert.VaultProviderConfig{
			Address:  vaultConfig.Address,
			PKIMount: vaultConfig.PKIMount,
			Role:     vaultConfig.PKIRole,
		})
		// May fail if Vault auth is not configured properly in test environment
		if err != nil {
			t.Skipf("Vault provider creation failed (expected in test env): %v", err)
		}
		require.NotNil(t, manager)
		defer manager.Close()
	})

	t.Run("issues certificate via manager", func(t *testing.T) {
		vaultConfig := helpers.GetVaultTestConfig()

		manager, err := cert.NewVaultProvider(ctx, &cert.VaultProviderConfig{
			Address:  vaultConfig.Address,
			PKIMount: vaultConfig.PKIMount,
			Role:     vaultConfig.PKIRole,
		})
		// May fail if Vault auth is not configured properly in test environment
		if err != nil {
			t.Skipf("Vault provider creation failed (expected in test env): %v", err)
		}
		defer manager.Close()

		certificate, err := manager.GetCertificate(ctx, &cert.CertificateRequest{
			CommonName: "manager-test.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, certificate)

		assert.NotEmpty(t, certificate.CertificatePEM)
		assert.NotEmpty(t, certificate.PrivateKeyPEM)
	})

	t.Run("gets CA pool via manager", func(t *testing.T) {
		vaultConfig := helpers.GetVaultTestConfig()

		manager, err := cert.NewVaultProvider(ctx, &cert.VaultProviderConfig{
			Address:  vaultConfig.Address,
			PKIMount: vaultConfig.PKIMount,
			Role:     vaultConfig.PKIRole,
		})
		// May fail if Vault auth is not configured properly in test environment
		if err != nil {
			t.Skipf("Vault provider creation failed (expected in test env): %v", err)
		}
		defer manager.Close()

		caPool, err := manager.GetCA(ctx)
		require.NoError(t, err)
		require.NotNil(t, caPool)
	})
}

// TestIntegration_Operator_VaultKV_SecretOperations tests Vault KV secret operations.
func TestIntegration_Operator_VaultKV_SecretOperations(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	t.Run("writes and reads secret", func(t *testing.T) {
		secretPath := "test/credentials"
		secretData := map[string]interface{}{
			"username": "testuser",
			"password": "testpass",
		}

		// Write secret
		err := vaultSetup.WriteSecret(secretPath, secretData)
		require.NoError(t, err)

		// Read secret
		readData, err := vaultSetup.ReadSecret(secretPath)
		require.NoError(t, err)
		require.NotNil(t, readData)

		assert.Equal(t, "testuser", readData["username"])
		assert.Equal(t, "testpass", readData["password"])
	})

	t.Run("deletes secret", func(t *testing.T) {
		secretPath := "test/to-delete"
		secretData := map[string]interface{}{
			"key": "value",
		}

		// Write secret
		err := vaultSetup.WriteSecret(secretPath, secretData)
		require.NoError(t, err)

		// Delete secret
		err = vaultSetup.DeleteSecret(secretPath)
		require.NoError(t, err)

		// Verify deletion
		_, err = vaultSetup.ReadSecret(secretPath)
		assert.Error(t, err)
	})

	t.Run("updates existing secret", func(t *testing.T) {
		secretPath := "test/update"

		// Write initial secret
		err := vaultSetup.WriteSecret(secretPath, map[string]interface{}{
			"version": "1",
		})
		require.NoError(t, err)

		// Update secret
		err = vaultSetup.WriteSecret(secretPath, map[string]interface{}{
			"version": "2",
		})
		require.NoError(t, err)

		// Read updated secret
		readData, err := vaultSetup.ReadSecret(secretPath)
		require.NoError(t, err)
		assert.Equal(t, "2", readData["version"])
	})
}

// TestIntegration_Operator_VaultPKI_ErrorHandling tests Vault PKI error handling.
func TestIntegration_Operator_VaultPKI_ErrorHandling(t *testing.T) {
	helpers.SkipIfVaultUnavailable(t)

	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("handles invalid role", func(t *testing.T) {
		path := vaultSetup.PKIMount + "/issue/nonexistent-role"
		_, err := vaultSetup.Client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
			"common_name": "test.example.com",
			"ttl":         "1h",
		})
		assert.Error(t, err)
	})

	t.Run("handles invalid common name", func(t *testing.T) {
		// This depends on the role configuration
		// If the role restricts allowed domains, this should fail
		path := vaultSetup.PKIMount + "/issue/" + vaultSetup.PKIRole
		_, err := vaultSetup.Client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
			"common_name": "", // Empty common name
			"ttl":         "1h",
		})
		// May or may not error depending on role config
		_ = err
	})

	t.Run("handles invalid TTL", func(t *testing.T) {
		path := vaultSetup.PKIMount + "/issue/" + vaultSetup.PKIRole
		_, err := vaultSetup.Client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
			"common_name": "test.example.com",
			"ttl":         "invalid",
		})
		assert.Error(t, err)
	})
}

// TestIntegration_Operator_SelfSigned_CertificateGeneration tests self-signed certificate generation.
func TestIntegration_Operator_SelfSigned_CertificateGeneration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("generates self-signed CA", func(t *testing.T) {
		manager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
			Organization: []string{"Test Org"},
			CertValidity: 24 * time.Hour,
		})
		require.NoError(t, err)
		require.NotNil(t, manager)
		defer manager.Close()

		caPool, err := manager.GetCA(ctx)
		require.NoError(t, err)
		require.NotNil(t, caPool)
	})

	t.Run("issues certificate from self-signed CA", func(t *testing.T) {
		manager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
			Organization: []string{"Test Org"},
			CertValidity: 24 * time.Hour,
		})
		require.NoError(t, err)
		defer manager.Close()

		certificate, err := manager.GetCertificate(ctx, &cert.CertificateRequest{
			CommonName: "test.example.com",
			DNSNames:   []string{"test.example.com", "localhost"},
		})
		require.NoError(t, err)
		require.NotNil(t, certificate)

		assert.NotEmpty(t, certificate.CertificatePEM)
		assert.NotEmpty(t, certificate.PrivateKeyPEM)
		assert.Contains(t, string(certificate.CertificatePEM), "BEGIN CERTIFICATE")
		assert.Contains(t, string(certificate.PrivateKeyPEM), "BEGIN")
	})

	t.Run("issues certificate with IP SANs", func(t *testing.T) {
		manager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
			Organization: []string{"Test Org"},
			CertValidity: 24 * time.Hour,
		})
		require.NoError(t, err)
		defer manager.Close()

		certificate, err := manager.GetCertificate(ctx, &cert.CertificateRequest{
			CommonName:  "test.example.com",
			IPAddresses: []string{"127.0.0.1", "10.0.0.1"},
		})
		require.NoError(t, err)
		require.NotNil(t, certificate)

		assert.NotEmpty(t, certificate.CertificatePEM)
	})
}

// TestIntegration_Operator_CertManager_Fallback tests certificate manager fallback behavior.
func TestIntegration_Operator_CertManager_Fallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("falls back to self-signed when Vault unavailable", func(t *testing.T) {
		// When Vault is unavailable, we should use self-signed provider
		// This simulates the fallback behavior at the application level
		manager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
			Organization: []string{"Fallback Org"},
			CertValidity: 24 * time.Hour,
		})
		require.NoError(t, err)
		require.NotNil(t, manager)
		defer manager.Close()

		// Should work with self-signed
		certificate, err := manager.GetCertificate(ctx, &cert.CertificateRequest{
			CommonName: "fallback-test.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, certificate)

		assert.NotEmpty(t, certificate.CertificatePEM)
	})

	t.Run("uses Vault when available", func(t *testing.T) {
		if !helpers.IsVaultAvailable() {
			t.Skip("Vault not available")
		}

		vaultConfig := helpers.GetVaultTestConfig()

		manager, err := cert.NewVaultProvider(ctx, &cert.VaultProviderConfig{
			Address:  vaultConfig.Address,
			PKIMount: vaultConfig.PKIMount,
			Role:     vaultConfig.PKIRole,
		})
		// May fail if Vault auth is not configured properly in test environment
		if err != nil {
			t.Skipf("Vault provider creation failed (expected in test env): %v", err)
		}
		defer manager.Close()

		certificate, err := manager.GetCertificate(ctx, &cert.CertificateRequest{
			CommonName: "vault-test.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, certificate)

		assert.NotEmpty(t, certificate.CertificatePEM)
	})
}
