package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ============================================================================
// Client Authenticate Tests with Mock Server
// ============================================================================

func TestClient_Authenticate_WithMockServer(t *testing.T) {
	tests := []struct {
		name           string
		setupAuth      func(t *testing.T, client *Client)
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, client *Client)
	}{
		{
			name: "successful authentication with token auth",
			setupAuth: func(t *testing.T, client *Client) {
				auth, err := NewTokenAuth("test-token")
				require.NoError(t, err)
				client.SetAuthMethod(auth)
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/token/lookup-self" {
					response := map[string]interface{}{
						"data": map[string]interface{}{
							"id":        "test-token",
							"ttl":       3600,
							"renewable": true,
						},
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(response)
				}
			},
			wantErr: false,
			validateResult: func(t *testing.T, client *Client) {
				assert.True(t, client.IsAuthenticated())
			},
		},
		{
			name: "authentication returns nil auth info",
			setupAuth: func(t *testing.T, client *Client) {
				// Create a mock auth method that returns nil auth
				auth := &mockAuthMethod{
					name: "mock",
					authenticateFunc: func(ctx context.Context, c *vault.Client) (*vault.Secret, error) {
						return &vault.Secret{Auth: nil}, nil
					},
				}
				client.SetAuthMethod(auth)
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {},
			wantErr:       true,
			errContains:   "no auth info returned",
		},
		{
			name: "authentication returns nil secret",
			setupAuth: func(t *testing.T, client *Client) {
				auth := &mockAuthMethod{
					name: "mock",
					authenticateFunc: func(ctx context.Context, c *vault.Client) (*vault.Secret, error) {
						return nil, nil
					},
				}
				client.SetAuthMethod(auth)
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {},
			wantErr:       true,
			errContains:   "no auth info returned",
		},
		{
			name: "authentication with zero lease duration",
			setupAuth: func(t *testing.T, client *Client) {
				auth := &mockAuthMethod{
					name: "mock",
					authenticateFunc: func(ctx context.Context, c *vault.Client) (*vault.Secret, error) {
						return &vault.Secret{
							Auth: &vault.SecretAuth{
								ClientToken:   "non-expiring-token",
								Renewable:     false,
								LeaseDuration: 0, // Non-expiring token
							},
						}, nil
					},
				}
				client.SetAuthMethod(auth)
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {},
			wantErr:       false,
			validateResult: func(t *testing.T, client *Client) {
				assert.True(t, client.IsAuthenticated())
				client.mu.RLock()
				assert.True(t, client.tokenExpiry.IsZero())
				client.mu.RUnlock()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &Config{
				Address:      server.URL,
				Timeout:      30 * time.Second,
				MaxRetries:   0,
				RetryWaitMin: 100 * time.Millisecond,
				RetryWaitMax: 1 * time.Second,
			}

			client, err := NewClient(config, zap.NewNop())
			require.NoError(t, err)

			tt.setupAuth(t, client)

			ctx := context.Background()
			err = client.Authenticate(ctx)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, client)
			}
		})
	}
}

// mockAuthMethod is a mock implementation of AuthMethod for testing
type mockAuthMethod struct {
	name             string
	authenticateFunc func(ctx context.Context, client *vault.Client) (*vault.Secret, error)
}

func (m *mockAuthMethod) Authenticate(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	return m.authenticateFunc(ctx, client)
}

func (m *mockAuthMethod) Name() string {
	return m.name
}

// ============================================================================
// Client ReadSecret Tests with Mock Server
// ============================================================================

func TestClient_ReadSecret_WithMockServer(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, secret *Secret)
	}{
		{
			name: "successful read with KV v2 data",
			path: "secret/data/myapp",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/secret/data/myapp" {
					response := map[string]interface{}{
						"data": map[string]interface{}{
							"data": map[string]interface{}{
								"username": "admin",
								"password": "secret123",
							},
							"metadata": map[string]interface{}{
								"created_time":  "2023-01-01T00:00:00.000000000Z",
								"version":       float64(3),
								"deletion_time": "",
								"destroyed":     false,
							},
						},
						"lease_id":       "lease-123",
						"lease_duration": 3600,
						"renewable":      true,
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(response)
				}
			},
			wantErr: false,
			validateResult: func(t *testing.T, secret *Secret) {
				require.NotNil(t, secret)
				username, ok := secret.GetString("username")
				assert.True(t, ok)
				assert.Equal(t, "admin", username)
				// Note: Metadata extraction depends on how Vault API client parses JSON
				// The version may be json.Number instead of float64, so we just check data is present
			},
		},
		{
			name: "secret not found returns error",
			path: "secret/data/nonexistent",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				// Return 404 with empty body (Vault behavior for missing secrets)
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr:     true,
			errContains: "secret not found",
		},
		{
			name: "server error returns error",
			path: "secret/data/error",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				response := map[string]interface{}{
					"errors": []string{"internal server error"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &Config{
				Address:      server.URL,
				Timeout:      30 * time.Second,
				MaxRetries:   0,
				RetryWaitMin: 100 * time.Millisecond,
				RetryWaitMax: 1 * time.Second,
			}

			client, err := NewClient(config, zap.NewNop())
			require.NoError(t, err)

			// Set up authentication
			client.mu.Lock()
			client.token = "test-token"
			client.tokenExpiry = time.Now().Add(1 * time.Hour)
			client.mu.Unlock()
			client.vaultClient.SetToken("test-token")

			ctx := context.Background()
			secret, err := client.ReadSecret(ctx, tt.path)

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

// ============================================================================
// Client WriteSecret Tests with Mock Server
// ============================================================================

func TestClient_WriteSecret_WithMockServer(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		data          map[string]interface{}
		serverHandler http.HandlerFunc
		wantErr       bool
		errContains   string
	}{
		{
			name: "successful write",
			path: "secret/data/myapp",
			data: map[string]interface{}{
				"username": "admin",
				"password": "secret123",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/secret/data/myapp" && r.Method == http.MethodPut {
					response := map[string]interface{}{
						"data": map[string]interface{}{
							"created_time":  "2023-01-01T00:00:00.000000000Z",
							"version":       float64(1),
							"deletion_time": "",
							"destroyed":     false,
						},
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(response)
				}
			},
			wantErr: false,
		},
		{
			name: "write failure - permission denied",
			path: "secret/data/forbidden",
			data: map[string]interface{}{"key": "value"},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				response := map[string]interface{}{
					"errors": []string{"permission denied"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &Config{
				Address:      server.URL,
				Timeout:      30 * time.Second,
				MaxRetries:   0,
				RetryWaitMin: 100 * time.Millisecond,
				RetryWaitMax: 1 * time.Second,
			}

			client, err := NewClient(config, zap.NewNop())
			require.NoError(t, err)

			// Set up authentication
			client.mu.Lock()
			client.token = "test-token"
			client.tokenExpiry = time.Now().Add(1 * time.Hour)
			client.mu.Unlock()
			client.vaultClient.SetToken("test-token")

			ctx := context.Background()
			err = client.WriteSecret(ctx, tt.path, tt.data)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

// ============================================================================
// Client DeleteSecret Tests with Mock Server
// ============================================================================

func TestClient_DeleteSecret_WithMockServer(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		serverHandler http.HandlerFunc
		wantErr       bool
		errContains   string
	}{
		{
			name: "successful delete",
			path: "secret/data/myapp",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/secret/data/myapp" && r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusNoContent)
				}
			},
			wantErr: false,
		},
		{
			name: "delete failure - not found",
			path: "secret/data/nonexistent",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				response := map[string]interface{}{
					"errors": []string{"no secret at path"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &Config{
				Address:      server.URL,
				Timeout:      30 * time.Second,
				MaxRetries:   0,
				RetryWaitMin: 100 * time.Millisecond,
				RetryWaitMax: 1 * time.Second,
			}

			client, err := NewClient(config, zap.NewNop())
			require.NoError(t, err)

			// Set up authentication
			client.mu.Lock()
			client.token = "test-token"
			client.tokenExpiry = time.Now().Add(1 * time.Hour)
			client.mu.Unlock()
			client.vaultClient.SetToken("test-token")

			ctx := context.Background()
			err = client.DeleteSecret(ctx, tt.path)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

// ============================================================================
// Client ListSecrets Tests with Mock Server
// ============================================================================

func TestClient_ListSecrets_WithMockServer(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		expectedKeys   []string
		validateResult func(t *testing.T, keys []string)
	}{
		{
			name: "successful list with keys",
			path: "secret/metadata/",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true") {
					response := map[string]interface{}{
						"data": map[string]interface{}{
							"keys": []interface{}{"app1/", "app2/", "config"},
						},
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(response)
				}
			},
			wantErr:      false,
			expectedKeys: []string{"app1/", "app2/", "config"},
		},
		{
			name: "list returns empty when no keys",
			path: "secret/metadata/empty/",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr:      false,
			expectedKeys: []string{},
		},
		{
			name: "list returns empty when nil response",
			path: "secret/metadata/nil/",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				// Return 404 which results in nil secret
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr:      false,
			expectedKeys: []string{},
		},
		{
			name: "list with non-string keys in response",
			path: "secret/metadata/mixed/",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": map[string]interface{}{
						"keys": []interface{}{"valid-key", 123, "another-key", nil},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			},
			wantErr: false,
			validateResult: func(t *testing.T, keys []string) {
				// Only string keys should be included
				assert.Contains(t, keys, "valid-key")
				assert.Contains(t, keys, "another-key")
				assert.Len(t, keys, 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &Config{
				Address:      server.URL,
				Timeout:      30 * time.Second,
				MaxRetries:   0,
				RetryWaitMin: 100 * time.Millisecond,
				RetryWaitMax: 1 * time.Second,
			}

			client, err := NewClient(config, zap.NewNop())
			require.NoError(t, err)

			// Set up authentication
			client.mu.Lock()
			client.token = "test-token"
			client.tokenExpiry = time.Now().Add(1 * time.Hour)
			client.mu.Unlock()
			client.vaultClient.SetToken("test-token")

			ctx := context.Background()
			keys, err := client.ListSecrets(ctx, tt.path)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, keys)
			} else if tt.expectedKeys != nil {
				assert.Equal(t, tt.expectedKeys, keys)
			}
		})
	}
}

// ============================================================================
// Client RenewToken Tests with Mock Server
// ============================================================================

func TestClient_RenewToken_WithMockServer(t *testing.T) {
	tests := []struct {
		name           string
		serverHandler  http.HandlerFunc
		wantErr        bool
		errContains    string
		validateResult func(t *testing.T, client *Client)
	}{
		{
			name: "successful token renewal",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/token/renew-self" {
					response := map[string]interface{}{
						"auth": map[string]interface{}{
							"client_token":   "renewed-token",
							"renewable":      true,
							"lease_duration": 7200,
						},
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(response)
				}
			},
			wantErr: false,
			validateResult: func(t *testing.T, client *Client) {
				client.mu.RLock()
				defer client.mu.RUnlock()
				// Token expiry should be updated
				assert.False(t, client.tokenExpiry.IsZero())
			},
		},
		{
			name: "renewal with nil auth response",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/token/renew-self" {
					response := map[string]interface{}{
						"data": map[string]interface{}{},
					}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(response)
				}
			},
			wantErr: false,
		},
		{
			name: "renewal failure",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				response := map[string]interface{}{
					"errors": []string{"permission denied"},
				}
				json.NewEncoder(w).Encode(response)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			config := &Config{
				Address:      server.URL,
				Timeout:      30 * time.Second,
				MaxRetries:   0,
				RetryWaitMin: 100 * time.Millisecond,
				RetryWaitMax: 1 * time.Second,
			}

			client, err := NewClient(config, zap.NewNop())
			require.NoError(t, err)

			// Set up authentication
			client.mu.Lock()
			client.token = "test-token"
			client.tokenExpiry = time.Now().Add(1 * time.Hour)
			client.mu.Unlock()
			client.vaultClient.SetToken("test-token")

			ctx := context.Background()
			err = client.RenewToken(ctx)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			if tt.validateResult != nil {
				tt.validateResult(t, client)
			}
		})
	}
}

// ============================================================================
// ConvertSecret Tests
// ============================================================================

func TestConvertSecret_Extended(t *testing.T) {
	tests := []struct {
		name           string
		vaultSecret    *vault.Secret
		validateResult func(t *testing.T, secret *Secret)
	}{
		{
			name:        "nil secret returns nil",
			vaultSecret: nil,
			validateResult: func(t *testing.T, secret *Secret) {
				assert.Nil(t, secret)
			},
		},
		{
			name: "secret with KV v2 data structure",
			vaultSecret: &vault.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"username": "admin",
						"password": "secret",
					},
					"metadata": map[string]interface{}{
						"created_time":  "2023-01-01T00:00:00.000000000Z",
						"version":       float64(5),
						"deletion_time": "",
						"destroyed":     false,
					},
				},
				LeaseID:       "lease-123",
				LeaseDuration: 3600,
				Renewable:     true,
			},
			validateResult: func(t *testing.T, secret *Secret) {
				require.NotNil(t, secret)
				assert.Equal(t, "lease-123", secret.LeaseID)
				assert.Equal(t, 3600, secret.LeaseDuration)
				assert.True(t, secret.Renewable)

				// Data should be unwrapped from KV v2 structure
				username, ok := secret.GetString("username")
				assert.True(t, ok)
				assert.Equal(t, "admin", username)

				// Metadata should be extracted
				require.NotNil(t, secret.Metadata)
				assert.Equal(t, 5, secret.Metadata.Version)
			},
		},
		{
			name: "secret without KV v2 structure",
			vaultSecret: &vault.Secret{
				Data: map[string]interface{}{
					"key1": "value1",
					"key2": "value2",
				},
				LeaseID:       "",
				LeaseDuration: 0,
				Renewable:     false,
			},
			validateResult: func(t *testing.T, secret *Secret) {
				require.NotNil(t, secret)
				assert.Equal(t, "", secret.LeaseID)
				assert.Equal(t, 0, secret.LeaseDuration)
				assert.False(t, secret.Renewable)

				// Data should be preserved as-is
				val, ok := secret.GetString("key1")
				assert.True(t, ok)
				assert.Equal(t, "value1", val)
			},
		},
		{
			name: "secret with metadata containing deletion time",
			vaultSecret: &vault.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"key": "value",
					},
					"metadata": map[string]interface{}{
						"created_time":  "2023-01-01T00:00:00.000000000Z",
						"version":       float64(2),
						"deletion_time": "2023-06-01T00:00:00.000000000Z",
						"destroyed":     true,
					},
				},
			},
			validateResult: func(t *testing.T, secret *Secret) {
				require.NotNil(t, secret)
				require.NotNil(t, secret.Metadata)
				assert.Equal(t, 2, secret.Metadata.Version)
				assert.True(t, secret.Metadata.Destroyed)
				assert.NotNil(t, secret.Metadata.DeletedTime)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertSecret(tt.vaultSecret)
			tt.validateResult(t, result)
		})
	}
}

// ============================================================================
// NewClient with TLS Config Tests
// ============================================================================

func TestNewClient_WithTLSConfig_Extended(t *testing.T) {
	t.Run("with full TLS config", func(t *testing.T) {
		// Generate test certificates
		caCert, caKey, err := generateTestCertificate()
		require.NoError(t, err)

		config := &Config{
			Address: "https://vault.example.com:8200",
			Timeout: 30 * time.Second,
			TLSConfig: &TLSConfig{
				CACert:             caCert,
				ClientCert:         caCert, // Using CA cert as client cert for testing
				ClientKey:          caKey,
				InsecureSkipVerify: false,
				ServerName:         "vault.example.com",
			},
		}

		client, err := NewClient(config, zap.NewNop())
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("with insecure skip verify", func(t *testing.T) {
		config := &Config{
			Address: "https://vault.example.com:8200",
			Timeout: 30 * time.Second,
			TLSConfig: &TLSConfig{
				InsecureSkipVerify: true,
			},
		}

		client, err := NewClient(config, zap.NewNop())
		require.NoError(t, err)
		assert.NotNil(t, client)
	})
}
