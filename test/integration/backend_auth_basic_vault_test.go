//go:build integration
// +build integration

package integration

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_BackendAuth_Basic_Vault(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	// Context for timeout management (used in subtests)
	_, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("backend Basic auth with Vault credentials", func(t *testing.T) {
		// Store credentials in Vault
		credPath := "backend-auth/basic-test"
		err := helpers.SetupVaultBasicAuthCredentials(t, vaultSetup, credPath, "vault-user", "vault-pass")
		require.NoError(t, err)
		defer func() {
			_ = helpers.CleanupVaultBackendCredentials(t, vaultSetup, credPath)
		}()

		// Read credentials back
		data, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)
		require.NotNil(t, data)

		assert.Equal(t, "vault-user", data["username"])
		assert.Equal(t, "vault-pass", data["password"])
	})

	t.Run("credential refresh from Vault", func(t *testing.T) {
		credPath := "backend-auth/refresh-test"

		// Store initial credentials
		err := helpers.SetupVaultBasicAuthCredentials(t, vaultSetup, credPath, "user1", "pass1")
		require.NoError(t, err)
		defer func() {
			_ = helpers.CleanupVaultBackendCredentials(t, vaultSetup, credPath)
		}()

		// Read initial credentials
		data1, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)
		assert.Equal(t, "user1", data1["username"])

		// Update credentials (simulating rotation)
		err = helpers.SetupVaultBasicAuthCredentials(t, vaultSetup, credPath, "user2", "pass2")
		require.NoError(t, err)

		// Read updated credentials
		data2, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)
		assert.Equal(t, "user2", data2["username"])
		assert.Equal(t, "pass2", data2["password"])
	})

	t.Run("error handling for missing Vault path", func(t *testing.T) {
		// Try to read non-existent path
		_, err := vaultSetup.ReadSecret("backend-auth/non-existent")
		assert.Error(t, err)
	})

	t.Run("custom username and password keys", func(t *testing.T) {
		credPath := "backend-auth/custom-keys"

		// Store credentials with custom keys
		err := vaultSetup.WriteSecret(credPath, map[string]interface{}{
			"user": "custom-user",
			"pass": "custom-pass",
		})
		require.NoError(t, err)
		defer func() {
			_ = helpers.CleanupVaultBackendCredentials(t, vaultSetup, credPath)
		}()

		// Read with custom keys
		data, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)

		// Simulate using custom key names from config
		basicConfig := &config.BackendBasicAuthConfig{
			Enabled:     true,
			VaultPath:   credPath,
			UsernameKey: "user",
			PasswordKey: "pass",
		}

		username := data[basicConfig.GetEffectiveUsernameKey()]
		password := data[basicConfig.GetEffectivePasswordKey()]

		assert.Equal(t, "custom-user", username)
		assert.Equal(t, "custom-pass", password)
	})
}

func TestIntegration_BackendAuth_Basic_HeaderInjection(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("Basic auth header injected into backend request", func(t *testing.T) {
		// Store credentials
		credPath := "backend-auth/header-test"
		username := "test-user"
		password := "test-pass"

		err := helpers.SetupVaultBasicAuthCredentials(t, vaultSetup, credPath, username, password)
		require.NoError(t, err)
		defer func() {
			_ = helpers.CleanupVaultBackendCredentials(t, vaultSetup, credPath)
		}()

		// Read credentials
		data, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)

		// Create test backend that verifies Authorization header
		var receivedAuthHeader string
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuthHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		}))
		defer backend.Close()

		// Build Basic auth header
		credentials := data["username"].(string) + ":" + data["password"].(string)
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
		authHeader := "Basic " + encoded

		// Send request with Basic auth
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL+"/api/resource", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", authHeader)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, authHeader, receivedAuthHeader)

		// Verify the header can be decoded
		assert.True(t, len(receivedAuthHeader) > 6)
		encodedPart := receivedAuthHeader[6:] // Remove "Basic "
		decoded, err := base64.StdEncoding.DecodeString(encodedPart)
		require.NoError(t, err)
		assert.Equal(t, username+":"+password, string(decoded))
	})
}

func TestIntegration_BackendAuth_Basic_VaultCaching(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	t.Run("credentials cached from Vault", func(t *testing.T) {
		credPath := "backend-auth/cache-test"

		err := helpers.SetupVaultBasicAuthCredentials(t, vaultSetup, credPath, "cached-user", "cached-pass")
		require.NoError(t, err)
		defer func() {
			_ = helpers.CleanupVaultBackendCredentials(t, vaultSetup, credPath)
		}()

		// Multiple reads should work (simulating cache behavior)
		for i := 0; i < 5; i++ {
			data, err := vaultSetup.ReadSecret(credPath)
			require.NoError(t, err)
			assert.Equal(t, "cached-user", data["username"])
			assert.Equal(t, "cached-pass", data["password"])
		}
	})
}

func TestIntegration_BackendAuth_Basic_Validation(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	t.Run("validate credentials format", func(t *testing.T) {
		credPath := "backend-auth/validation-test"

		// Store credentials with special characters
		err := helpers.SetupVaultBasicAuthCredentials(t, vaultSetup, credPath, "user@domain.com", "p@ss:word!")
		require.NoError(t, err)
		defer func() {
			_ = helpers.CleanupVaultBackendCredentials(t, vaultSetup, credPath)
		}()

		data, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)

		// Build and verify Basic auth header with special characters
		credentials := data["username"].(string) + ":" + data["password"].(string)
		encoded := base64.StdEncoding.EncodeToString([]byte(credentials))

		// Decode and verify
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		require.NoError(t, err)
		assert.Equal(t, "user@domain.com:p@ss:word!", string(decoded))
	})

	t.Run("empty credentials handling", func(t *testing.T) {
		credPath := "backend-auth/empty-test"

		// Store empty credentials
		err := vaultSetup.WriteSecret(credPath, map[string]interface{}{
			"username": "",
			"password": "",
		})
		require.NoError(t, err)
		defer func() {
			_ = helpers.CleanupVaultBackendCredentials(t, vaultSetup, credPath)
		}()

		data, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)

		// Empty credentials should still work (though not recommended)
		assert.Equal(t, "", data["username"])
		assert.Equal(t, "", data["password"])
	})
}

func TestIntegration_BackendAuth_Basic_SecretRotation(t *testing.T) {
	vaultSetup := helpers.SetupVaultForTesting(t)
	defer vaultSetup.Cleanup()

	t.Run("handle credential rotation", func(t *testing.T) {
		credPath := "backend-auth/rotation-test"

		// Initial credentials
		err := helpers.SetupVaultBasicAuthCredentials(t, vaultSetup, credPath, "old-user", "old-pass")
		require.NoError(t, err)
		defer func() {
			_ = helpers.CleanupVaultBackendCredentials(t, vaultSetup, credPath)
		}()

		// Verify initial
		data1, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)
		assert.Equal(t, "old-user", data1["username"])

		// Rotate credentials
		err = helpers.SetupVaultBasicAuthCredentials(t, vaultSetup, credPath, "new-user", "new-pass")
		require.NoError(t, err)

		// Verify rotated
		data2, err := vaultSetup.ReadSecret(credPath)
		require.NoError(t, err)
		assert.Equal(t, "new-user", data2["username"])
		assert.Equal(t, "new-pass", data2["password"])
	})
}
