package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKubernetesAuth(t *testing.T) {
	t.Run("with default mount path", func(t *testing.T) {
		auth, err := NewKubernetesAuth("test-role", "")
		require.NoError(t, err)
		assert.Equal(t, "test-role", auth.role)
		assert.Equal(t, DefaultKubernetesMountPath, auth.mountPath)
		assert.Equal(t, DefaultServiceAccountTokenPath, auth.serviceAccountPath)
		assert.Equal(t, "kubernetes", auth.Name())
	})

	t.Run("with custom mount path", func(t *testing.T) {
		auth, err := NewKubernetesAuth("test-role", "custom-kubernetes")
		require.NoError(t, err)
		assert.Equal(t, "test-role", auth.role)
		assert.Equal(t, "custom-kubernetes", auth.mountPath)
	})

	t.Run("with empty role returns error", func(t *testing.T) {
		auth, err := NewKubernetesAuth("", "")
		require.Error(t, err)
		assert.Nil(t, auth)
		assert.ErrorIs(t, err, ErrInvalidAuthConfig)
		assert.Contains(t, err.Error(), "role is required")
	})
}

func TestNewKubernetesAuthWithTokenPath(t *testing.T) {
	t.Run("with all custom values", func(t *testing.T) {
		auth, err := NewKubernetesAuthWithTokenPath("test-role", "custom-mount", "/custom/token/path")
		require.NoError(t, err)
		assert.Equal(t, "test-role", auth.role)
		assert.Equal(t, "custom-mount", auth.mountPath)
		assert.Equal(t, "/custom/token/path", auth.serviceAccountPath)
	})

	t.Run("with empty mount path uses default", func(t *testing.T) {
		auth, err := NewKubernetesAuthWithTokenPath("test-role", "", "/custom/token/path")
		require.NoError(t, err)
		assert.Equal(t, "test-role", auth.role)
		assert.Equal(t, DefaultKubernetesMountPath, auth.mountPath)
		assert.Equal(t, "/custom/token/path", auth.serviceAccountPath)
	})

	t.Run("with empty token path uses default", func(t *testing.T) {
		auth, err := NewKubernetesAuthWithTokenPath("test-role", "custom-mount", "")
		require.NoError(t, err)
		assert.Equal(t, "test-role", auth.role)
		assert.Equal(t, "custom-mount", auth.mountPath)
		assert.Equal(t, DefaultServiceAccountTokenPath, auth.serviceAccountPath)
	})

	t.Run("with both empty uses defaults", func(t *testing.T) {
		auth, err := NewKubernetesAuthWithTokenPath("test-role", "", "")
		require.NoError(t, err)
		assert.Equal(t, "test-role", auth.role)
		assert.Equal(t, DefaultKubernetesMountPath, auth.mountPath)
		assert.Equal(t, DefaultServiceAccountTokenPath, auth.serviceAccountPath)
	})

	t.Run("with empty role returns error", func(t *testing.T) {
		auth, err := NewKubernetesAuthWithTokenPath("", "custom-mount", "/custom/token/path")
		require.Error(t, err)
		assert.Nil(t, auth)
		assert.ErrorIs(t, err, ErrInvalidAuthConfig)
		assert.Contains(t, err.Error(), "role is required")
	})
}

func TestNewTokenAuth(t *testing.T) {
	t.Run("with valid token", func(t *testing.T) {
		auth, err := NewTokenAuth("test-token")
		require.NoError(t, err)
		assert.Equal(t, "test-token", auth.token)
		assert.Equal(t, "token", auth.Name())
	})

	t.Run("with empty token returns error", func(t *testing.T) {
		auth, err := NewTokenAuth("")
		require.Error(t, err)
		assert.Nil(t, auth)
		assert.ErrorIs(t, err, ErrInvalidAuthConfig)
		assert.Contains(t, err.Error(), "token is required")
	})
}

func TestNewAppRoleAuth(t *testing.T) {
	t.Run("with default mount path", func(t *testing.T) {
		auth, err := NewAppRoleAuth("role-id", "secret-id", "")
		require.NoError(t, err)
		assert.Equal(t, "role-id", auth.roleID)
		assert.Equal(t, "secret-id", auth.secretID)
		assert.Equal(t, DefaultAppRoleMountPath, auth.mountPath)
		assert.Equal(t, "approle", auth.Name())
	})

	t.Run("with custom mount path", func(t *testing.T) {
		auth, err := NewAppRoleAuth("role-id", "secret-id", "custom-approle")
		require.NoError(t, err)
		assert.Equal(t, "custom-approle", auth.mountPath)
	})

	t.Run("with empty roleID returns error", func(t *testing.T) {
		auth, err := NewAppRoleAuth("", "secret-id", "")
		require.Error(t, err)
		assert.Nil(t, auth)
		assert.ErrorIs(t, err, ErrInvalidAuthConfig)
		assert.Contains(t, err.Error(), "roleID is required")
	})

	t.Run("with empty secretID returns error", func(t *testing.T) {
		auth, err := NewAppRoleAuth("role-id", "", "")
		require.Error(t, err)
		assert.Nil(t, auth)
		assert.ErrorIs(t, err, ErrInvalidAuthConfig)
		assert.Contains(t, err.Error(), "secretID is required")
	})
}

func TestNewUserpassAuth(t *testing.T) {
	t.Run("with default mount path", func(t *testing.T) {
		auth, err := NewUserpassAuth("user", "pass", "")
		require.NoError(t, err)
		assert.Equal(t, "user", auth.username)
		assert.Equal(t, "pass", auth.password)
		assert.Equal(t, "userpass", auth.mountPath)
		assert.Equal(t, "userpass", auth.Name())
	})

	t.Run("with custom mount path", func(t *testing.T) {
		auth, err := NewUserpassAuth("user", "pass", "custom-userpass")
		require.NoError(t, err)
		assert.Equal(t, "custom-userpass", auth.mountPath)
	})

	t.Run("with empty username returns error", func(t *testing.T) {
		auth, err := NewUserpassAuth("", "pass", "")
		require.Error(t, err)
		assert.Nil(t, auth)
		assert.ErrorIs(t, err, ErrInvalidAuthConfig)
		assert.Contains(t, err.Error(), "username is required")
	})

	t.Run("with empty password returns error", func(t *testing.T) {
		auth, err := NewUserpassAuth("user", "", "")
		require.Error(t, err)
		assert.Nil(t, auth)
		assert.ErrorIs(t, err, ErrInvalidAuthConfig)
		assert.Contains(t, err.Error(), "password is required")
	})
}

// createTestVaultClient creates a Vault client configured to use the test server.
func createTestVaultClient(t *testing.T, serverURL string) *vault.Client {
	t.Helper()
	config := vault.DefaultConfig()
	config.Address = serverURL
	client, err := vault.NewClient(config)
	require.NoError(t, err)
	return client
}

// TestKubernetesAuth_Authenticate tests the KubernetesAuth.Authenticate method.
func TestKubernetesAuth_Authenticate(t *testing.T) {
	tests := []struct {
		name           string
		setupTokenFile func(t *testing.T) string
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, secret *vault.Secret)
	}{
		{
			name: "successful authentication",
			setupTokenFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				tokenPath := filepath.Join(tmpDir, "token")
				err := os.WriteFile(tokenPath, []byte("mock-jwt-token"), 0600)
				require.NoError(t, err)
				return tokenPath
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/auth/kubernetes/login", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)

				// Verify request body
				var reqBody map[string]interface{}
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				assert.NoError(t, err)
				assert.Equal(t, "test-role", reqBody["role"])
				assert.Equal(t, "mock-jwt-token", reqBody["jwt"])

				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "test-client-token",
						"renewable":      true,
						"lease_duration": 3600,
						"policies":       []string{"default", "test-policy"},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "test-client-token", secret.Auth.ClientToken)
				assert.True(t, secret.Auth.Renewable)
				assert.Equal(t, 3600, secret.Auth.LeaseDuration)
			},
		},
		{
			name: "token file not found",
			setupTokenFile: func(t *testing.T) string {
				return "/nonexistent/path/to/token"
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("server should not be called when token file is missing")
			},
			wantErr:     true,
			errContains: "failed to read service account token",
		},
		{
			name: "vault API error",
			setupTokenFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				tokenPath := filepath.Join(tmpDir, "token")
				err := os.WriteFile(tokenPath, []byte("invalid-jwt-token"), 0600)
				require.NoError(t, err)
				return tokenPath
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				response := map[string]interface{}{
					"errors": []string{"permission denied"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr:     true,
			errContains: "kubernetes auth failed",
		},
		{
			name: "with custom mount path",
			setupTokenFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				tokenPath := filepath.Join(tmpDir, "token")
				err := os.WriteFile(tokenPath, []byte("mock-jwt-token"), 0600)
				require.NoError(t, err)
				return tokenPath
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				// This will be overridden in the test case
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "custom-mount-token",
						"renewable":      false,
						"lease_duration": 1800,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "custom-mount-token", secret.Auth.ClientToken)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			tokenPath := tt.setupTokenFile(t)

			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := createTestVaultClient(t, server.URL)

			var auth *KubernetesAuth
			var authErr error
			if tt.name == "with custom mount path" {
				auth, authErr = NewKubernetesAuthWithTokenPath("test-role", "custom-k8s", tokenPath)
			} else {
				auth, authErr = NewKubernetesAuthWithTokenPath("test-role", "kubernetes", tokenPath)
			}
			require.NoError(t, authErr)

			// Act
			secret, err := auth.Authenticate(context.Background(), client)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, secret)
			}
		})
	}
}

// TestKubernetesAuth_Authenticate_CustomMountPath tests custom mount path handling.
func TestKubernetesAuth_Authenticate_CustomMountPath(t *testing.T) {
	// Arrange
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	err := os.WriteFile(tokenPath, []byte("mock-jwt-token"), 0600)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom mount path is used
		assert.Equal(t, "/v1/auth/custom-k8s-mount/login", r.URL.Path)

		response := map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "custom-mount-token",
				"renewable":      true,
				"lease_duration": 7200,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := createTestVaultClient(t, server.URL)
	auth, authErr := NewKubernetesAuthWithTokenPath("test-role", "custom-k8s-mount", tokenPath)
	require.NoError(t, authErr)

	// Act
	secret, err := auth.Authenticate(context.Background(), client)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, secret)
	assert.Equal(t, "custom-mount-token", secret.Auth.ClientToken)
}

// TestTokenAuth_Authenticate tests the TokenAuth.Authenticate method.
func TestTokenAuth_Authenticate(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, secret *vault.Secret)
	}{
		{
			name:  "successful authentication with renewable token",
			token: "test-renewable-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/auth/token/lookup-self", r.URL.Path)
				assert.Equal(t, "test-renewable-token", r.Header.Get("X-Vault-Token"))

				// Note: Vault client parses JSON numbers as json.Number, not float64
				// The code expects float64, so TTL won't be extracted from json.Number
				// This tests the actual behavior of the code
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":               "test-renewable-token",
						"ttl":              3600,
						"renewable":        true,
						"display_name":     "token",
						"creation_time":    1234567890,
						"expire_time":      "2024-01-01T00:00:00Z",
						"explicit_max_ttl": 0,
						"policies":         []string{"default", "admin"},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "test-renewable-token", secret.Auth.ClientToken)
				assert.True(t, secret.Auth.Renewable)
				// TTL is correctly parsed from both float64 and json.Number types
				assert.Equal(t, 3600, secret.Auth.LeaseDuration)
			},
		},
		{
			name:  "successful authentication with non-renewable token",
			token: "test-non-renewable-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":        "test-non-renewable-token",
						"ttl":       1800,
						"renewable": false,
						"policies":  []string{"default"},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "test-non-renewable-token", secret.Auth.ClientToken)
				assert.False(t, secret.Auth.Renewable)
				// TTL is correctly parsed from both float64 and json.Number types
				assert.Equal(t, 1800, secret.Auth.LeaseDuration)
			},
		},
		{
			name:  "token lookup failure - invalid token",
			token: "invalid-token",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				response := map[string]interface{}{
					"errors": []string{"permission denied"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr:     true,
			errContains: "token auth failed",
		},
		{
			name:  "response with missing TTL field",
			token: "token-no-ttl",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":        "token-no-ttl",
						"renewable": true,
						// TTL is missing
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "token-no-ttl", secret.Auth.ClientToken)
				assert.True(t, secret.Auth.Renewable)
				assert.Equal(t, 0, secret.Auth.LeaseDuration) // Default when TTL is missing
			},
		},
		{
			name:  "response with missing renewable field",
			token: "token-no-renewable",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"id":  "token-no-renewable",
						"ttl": float64(7200),
						// renewable is missing
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "token-no-renewable", secret.Auth.ClientToken)
				assert.False(t, secret.Auth.Renewable) // Default when renewable is missing
				// TTL is correctly parsed from both float64 and json.Number types
				assert.Equal(t, 7200, secret.Auth.LeaseDuration)
			},
		},
		{
			name:  "response with nil data",
			token: "token-nil-data",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": nil,
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "token-nil-data", secret.Auth.ClientToken)
				assert.False(t, secret.Auth.Renewable) // Default
				assert.Equal(t, 0, secret.Auth.LeaseDuration)
			},
		},
		{
			name:  "response with empty data",
			token: "token-empty-data",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "token-empty-data", secret.Auth.ClientToken)
				assert.False(t, secret.Auth.Renewable)
				assert.Equal(t, 0, secret.Auth.LeaseDuration)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := createTestVaultClient(t, server.URL)
			auth, authErr := NewTokenAuth(tt.token)
			require.NoError(t, authErr)

			// Act
			secret, err := auth.Authenticate(context.Background(), client)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, secret)
			}
		})
	}
}

// TestAppRoleAuth_Authenticate tests the AppRoleAuth.Authenticate method.
func TestAppRoleAuth_Authenticate(t *testing.T) {
	tests := []struct {
		name           string
		roleID         string
		secretID       string
		mountPath      string
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, secret *vault.Secret)
	}{
		{
			name:      "successful authentication with default mount path",
			roleID:    "test-role-id",
			secretID:  "test-secret-id",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/auth/approle/login", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)

				// Verify request body
				var reqBody map[string]interface{}
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				assert.NoError(t, err)
				assert.Equal(t, "test-role-id", reqBody["role_id"])
				assert.Equal(t, "test-secret-id", reqBody["secret_id"])

				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "approle-client-token",
						"renewable":      true,
						"lease_duration": 3600,
						"policies":       []string{"default", "approle-policy"},
						"metadata": map[string]interface{}{
							"role_name": "test-role",
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "approle-client-token", secret.Auth.ClientToken)
				assert.True(t, secret.Auth.Renewable)
				assert.Equal(t, 3600, secret.Auth.LeaseDuration)
			},
		},
		{
			name:      "successful authentication with custom mount path",
			roleID:    "custom-role-id",
			secretID:  "custom-secret-id",
			mountPath: "custom-approle",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/auth/custom-approle/login", r.URL.Path)

				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "custom-approle-token",
						"renewable":      false,
						"lease_duration": 1800,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "custom-approle-token", secret.Auth.ClientToken)
				assert.False(t, secret.Auth.Renewable)
				assert.Equal(t, 1800, secret.Auth.LeaseDuration)
			},
		},
		{
			name:      "authentication failure - invalid credentials",
			roleID:    "invalid-role-id",
			secretID:  "invalid-secret-id",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				response := map[string]interface{}{
					"errors": []string{"invalid role or secret ID"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr:     true,
			errContains: "approle auth failed",
		},
		{
			name:      "authentication failure - permission denied",
			roleID:    "role-id",
			secretID:  "secret-id",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				response := map[string]interface{}{
					"errors": []string{"permission denied"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr:     true,
			errContains: "approle auth failed",
		},
		{
			name:      "server error",
			roleID:    "role-id",
			secretID:  "secret-id",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				response := map[string]interface{}{
					"errors": []string{"internal server error"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr:     true,
			errContains: "approle auth failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := createTestVaultClient(t, server.URL)
			auth, authErr := NewAppRoleAuth(tt.roleID, tt.secretID, tt.mountPath)
			require.NoError(t, authErr)

			// Act
			secret, err := auth.Authenticate(context.Background(), client)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, secret)
			}
		})
	}
}

// TestUserpassAuth_Authenticate tests the UserpassAuth.Authenticate method.
func TestUserpassAuth_Authenticate(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		password       string
		mountPath      string
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, secret *vault.Secret)
	}{
		{
			name:      "successful authentication with default mount path",
			username:  "testuser",
			password:  "testpassword",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/auth/userpass/login/testuser", r.URL.Path)
				assert.Equal(t, http.MethodPut, r.Method)

				// Verify request body
				var reqBody map[string]interface{}
				err := json.NewDecoder(r.Body).Decode(&reqBody)
				assert.NoError(t, err)
				assert.Equal(t, "testpassword", reqBody["password"])

				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "userpass-client-token",
						"renewable":      true,
						"lease_duration": 3600,
						"policies":       []string{"default", "user-policy"},
						"metadata": map[string]interface{}{
							"username": "testuser",
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "userpass-client-token", secret.Auth.ClientToken)
				assert.True(t, secret.Auth.Renewable)
				assert.Equal(t, 3600, secret.Auth.LeaseDuration)
			},
		},
		{
			name:      "successful authentication with custom mount path",
			username:  "admin",
			password:  "adminpass",
			mountPath: "custom-userpass",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/auth/custom-userpass/login/admin", r.URL.Path)

				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "custom-userpass-token",
						"renewable":      false,
						"lease_duration": 7200,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "custom-userpass-token", secret.Auth.ClientToken)
				assert.False(t, secret.Auth.Renewable)
				assert.Equal(t, 7200, secret.Auth.LeaseDuration)
			},
		},
		{
			name:      "authentication failure - wrong password",
			username:  "testuser",
			password:  "wrongpassword",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				response := map[string]interface{}{
					"errors": []string{"invalid username or password"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr:     true,
			errContains: "userpass auth failed",
		},
		{
			name:      "authentication failure - user not found",
			username:  "nonexistent",
			password:  "password",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				response := map[string]interface{}{
					"errors": []string{"invalid username or password"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr:     true,
			errContains: "userpass auth failed",
		},
		{
			name:      "authentication failure - permission denied",
			username:  "testuser",
			password:  "testpassword",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				response := map[string]interface{}{
					"errors": []string{"permission denied"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr:     true,
			errContains: "userpass auth failed",
		},
		{
			name:      "server error",
			username:  "testuser",
			password:  "testpassword",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				response := map[string]interface{}{
					"errors": []string{"internal server error"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr:     true,
			errContains: "userpass auth failed",
		},
		{
			name:      "username with special characters",
			username:  "user@domain.com",
			password:  "password123",
			mountPath: "",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/auth/userpass/login/user@domain.com", r.URL.Path)

				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "special-user-token",
						"renewable":      true,
						"lease_duration": 3600,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *vault.Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Auth)
				assert.Equal(t, "special-user-token", secret.Auth.ClientToken)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := createTestVaultClient(t, server.URL)
			auth, authErr := NewUserpassAuth(tt.username, tt.password, tt.mountPath)
			require.NoError(t, authErr)

			// Act
			secret, err := auth.Authenticate(context.Background(), client)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, secret)
			}
		})
	}
}

// TestAuthMethod_Interface tests that all auth methods implement the AuthMethod interface.
func TestAuthMethod_Interface(t *testing.T) {
	k8sAuth, err := NewKubernetesAuth("role", "")
	require.NoError(t, err)

	tokenAuth, err := NewTokenAuth("token")
	require.NoError(t, err)

	appRoleAuth, err := NewAppRoleAuth("role-id", "secret-id", "")
	require.NoError(t, err)

	userpassAuth, err := NewUserpassAuth("user", "pass", "")
	require.NoError(t, err)

	tests := []struct {
		name       string
		authMethod AuthMethod
		wantName   string
	}{
		{
			name:       "KubernetesAuth implements AuthMethod",
			authMethod: k8sAuth,
			wantName:   "kubernetes",
		},
		{
			name:       "TokenAuth implements AuthMethod",
			authMethod: tokenAuth,
			wantName:   "token",
		},
		{
			name:       "AppRoleAuth implements AuthMethod",
			authMethod: appRoleAuth,
			wantName:   "approle",
		},
		{
			name:       "UserpassAuth implements AuthMethod",
			authMethod: userpassAuth,
			wantName:   "userpass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the Name() method returns expected value
			assert.Equal(t, tt.wantName, tt.authMethod.Name())

			// Verify the type implements AuthMethod interface
			var _ AuthMethod = tt.authMethod
		})
	}
}

// TestKubernetesAuth_Authenticate_ContextCancellation tests context cancellation handling.
func TestKubernetesAuth_Authenticate_ContextCancellation(t *testing.T) {
	// Arrange
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	err := os.WriteFile(tokenPath, []byte("mock-jwt-token"), 0600)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response - context should be cancelled before this completes
		select {
		case <-r.Context().Done():
			return
		case <-make(chan struct{}): // Block forever
		}
	}))
	defer server.Close()

	client := createTestVaultClient(t, server.URL)
	auth, authErr := NewKubernetesAuthWithTokenPath("test-role", "kubernetes", tokenPath)
	require.NoError(t, authErr)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Act
	_, err = auth.Authenticate(ctx, client)

	// Assert - should get an error due to cancelled context
	require.Error(t, err)
}

// TestKubernetesAuth_Authenticate_NilClient tests nil client handling.
func TestKubernetesAuth_Authenticate_NilClient(t *testing.T) {
	auth, err := NewKubernetesAuth("test-role", "")
	require.NoError(t, err)

	_, err = auth.Authenticate(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault client is nil")
}

// TestTokenAuth_Authenticate_NilClient tests nil client handling.
func TestTokenAuth_Authenticate_NilClient(t *testing.T) {
	auth, err := NewTokenAuth("test-token")
	require.NoError(t, err)

	_, err = auth.Authenticate(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault client is nil")
}

// TestAppRoleAuth_Authenticate_NilClient tests nil client handling.
func TestAppRoleAuth_Authenticate_NilClient(t *testing.T) {
	auth, err := NewAppRoleAuth("role-id", "secret-id", "")
	require.NoError(t, err)

	_, err = auth.Authenticate(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault client is nil")
}

// TestUserpassAuth_Authenticate_NilClient tests nil client handling.
func TestUserpassAuth_Authenticate_NilClient(t *testing.T) {
	auth, err := NewUserpassAuth("user", "pass", "")
	require.NoError(t, err)

	_, err = auth.Authenticate(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault client is nil")
}

// TestUserpassAuth_Authenticate_PathInjection tests path injection prevention.
func TestUserpassAuth_Authenticate_PathInjection(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "normal username",
			username: "testuser",
			wantErr:  false,
		},
		{
			name:     "username with email format",
			username: "user@domain.com",
			wantErr:  false,
		},
		{
			name:        "username with path traversal",
			username:    "../../../etc/passwd",
			wantErr:     true,
			errContains: "invalid username",
		},
		{
			name:        "username with slash",
			username:    "user/admin",
			wantErr:     true,
			errContains: "invalid username",
		},
		{
			name:        "username with double dots",
			username:    "user..admin",
			wantErr:     true,
			errContains: "invalid username",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewUserpassAuth(tt.username, "password", "")
			require.NoError(t, err)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "test-token",
						"renewable":      true,
						"lease_duration": 3600,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			client := createTestVaultClient(t, server.URL)
			_, err = auth.Authenticate(context.Background(), client)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
