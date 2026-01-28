package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestAuthenticateWithToken_Success tests successful token authentication.
func TestAuthenticateWithToken_Success(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			// Vault API returns ttl as a number (not json.Number string)
			// The api.Secret struct expects numeric values for ttl
			resp := `{
				"request_id": "test-request-id",
				"lease_id": "",
				"renewable": false,
				"lease_duration": 0,
				"data": {
					"ttl": 3600
				},
				"wrap_info": null,
				"warnings": null,
				"auth": null
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithToken(context.Background())

	// Assert
	if err != nil {
		t.Errorf("authenticateWithToken() error = %v, want nil", err)
	}

	ttl := vc.tokenTTL.Load()
	if ttl != 3600 {
		t.Errorf("tokenTTL = %v, want 3600", ttl)
	}
}

// TestAuthenticateWithToken_EmptyToken tests token authentication with empty token.
func TestAuthenticateWithToken_EmptyToken(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "placeholder", // Need valid token for config validation
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)
	// Clear the token to test empty token scenario
	vc.config.Token = ""

	// Act
	err = vc.authenticateWithToken(context.Background())

	// Assert
	if err == nil {
		t.Error("authenticateWithToken() should return error for empty token")
	}

	var authErr *AuthenticationError
	if !isAuthenticationError(err, &authErr) {
		t.Errorf("authenticateWithToken() error type = %T, want *AuthenticationError", err)
	}
}

// TestAuthenticateWithToken_LookupFails tests token authentication when lookup fails.
func TestAuthenticateWithToken_LookupFails(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.WriteHeader(http.StatusForbidden)
			resp := `{"errors": ["permission denied"]}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "invalid-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithToken(context.Background())

	// Assert
	if err == nil {
		t.Error("authenticateWithToken() should return error when lookup fails")
	}
}

// TestAuthenticateWithToken_NoTTLInResponse tests token authentication with no TTL in response.
func TestAuthenticateWithToken_NoTTLInResponse(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			// Vault API response without ttl field
			resp := `{
				"request_id": "test-request-id",
				"lease_id": "",
				"renewable": false,
				"lease_duration": 0,
				"data": {
					"accessor": "test-accessor"
				},
				"wrap_info": null,
				"warnings": null,
				"auth": null
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithToken(context.Background())

	// Assert
	if err != nil {
		t.Errorf("authenticateWithToken() error = %v, want nil", err)
	}

	// TTL should remain 0 if not in response
	ttl := vc.tokenTTL.Load()
	if ttl != 0 {
		t.Errorf("tokenTTL = %v, want 0", ttl)
	}
}

// TestAuthenticateWithKubernetes_Success tests successful Kubernetes authentication.
func TestAuthenticateWithKubernetes_Success(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			// Vault API response with auth structure - use raw JSON to ensure proper types
			resp := `{
				"request_id": "test-request-id",
				"lease_id": "",
				"renewable": false,
				"lease_duration": 0,
				"data": null,
				"wrap_info": null,
				"warnings": null,
				"auth": {
					"client_token": "test-client-token",
					"accessor": "test-accessor",
					"policies": ["default"],
					"token_policies": ["default"],
					"metadata": {},
					"lease_duration": 3600,
					"renewable": true
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Create a temporary token file
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-jwt-token"), 0600); err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodKubernetes,
		Kubernetes: &KubernetesAuthConfig{
			Role:      "test-role",
			TokenPath: tokenPath,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithKubernetes(context.Background())

	// Assert
	if err != nil {
		t.Errorf("authenticateWithKubernetes() error = %v, want nil", err)
	}

	ttl := vc.tokenTTL.Load()
	if ttl != 3600 {
		t.Errorf("tokenTTL = %v, want 3600", ttl)
	}
}

// TestAuthenticateWithKubernetes_NilConfig tests Kubernetes auth with nil config.
func TestAuthenticateWithKubernetes_NilConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "placeholder",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)
	vc.config.Kubernetes = nil

	// Act
	err = vc.authenticateWithKubernetes(context.Background())

	// Assert
	if err == nil {
		t.Error("authenticateWithKubernetes() should return error for nil config")
	}
}

// TestAuthenticateWithKubernetes_TokenFileNotFound tests Kubernetes auth when token file is missing.
func TestAuthenticateWithKubernetes_TokenFileNotFound(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "placeholder",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)
	vc.config.Kubernetes = &KubernetesAuthConfig{
		Role:      "test-role",
		TokenPath: "/nonexistent/path/token",
	}

	// Act
	err = vc.authenticateWithKubernetes(context.Background())

	// Assert
	if err == nil {
		t.Error("authenticateWithKubernetes() should return error when token file not found")
	}
}

// TestAuthenticateWithKubernetes_NoAuthInResponse tests Kubernetes auth with no auth in response.
func TestAuthenticateWithKubernetes_NoAuthInResponse(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{"data": {}}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Create a temporary token file
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-jwt-token"), 0600); err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodKubernetes,
		Kubernetes: &KubernetesAuthConfig{
			Role:      "test-role",
			TokenPath: tokenPath,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithKubernetes(context.Background())

	// Assert
	if err == nil {
		t.Error("authenticateWithKubernetes() should return error when no auth in response")
	}
}

// TestAuthenticateWithKubernetes_CustomMountPath tests Kubernetes auth with custom mount path.
func TestAuthenticateWithKubernetes_CustomMountPath(t *testing.T) {
	t.Parallel()

	// Arrange
	var requestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		if r.URL.Path == "/v1/auth/custom-k8s/login" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			// Vault API response with auth structure - use raw JSON to ensure proper types
			resp := `{
				"request_id": "test-request-id",
				"lease_id": "",
				"renewable": false,
				"lease_duration": 0,
				"data": null,
				"wrap_info": null,
				"warnings": null,
				"auth": {
					"client_token": "test-client-token",
					"accessor": "test-accessor",
					"policies": ["default"],
					"token_policies": ["default"],
					"metadata": {},
					"lease_duration": 3600,
					"renewable": true
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Create a temporary token file
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-jwt-token"), 0600); err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodKubernetes,
		Kubernetes: &KubernetesAuthConfig{
			Role:      "test-role",
			MountPath: "custom-k8s",
			TokenPath: tokenPath,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithKubernetes(context.Background())

	// Assert
	if err != nil {
		t.Errorf("authenticateWithKubernetes() error = %v, want nil", err)
	}

	if requestPath != "/v1/auth/custom-k8s/login" {
		t.Errorf("request path = %v, want /v1/auth/custom-k8s/login", requestPath)
	}
}

// TestAuthenticateWithAppRole_Success tests successful AppRole authentication.
func TestAuthenticateWithAppRole_Success(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vault API uses PUT for write operations
		if r.URL.Path == "/v1/auth/approle/login" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			// Vault API response with auth structure - use raw JSON to ensure proper types
			resp := `{
				"request_id": "test-request-id",
				"lease_id": "",
				"renewable": false,
				"lease_duration": 0,
				"data": null,
				"wrap_info": null,
				"warnings": null,
				"auth": {
					"client_token": "test-client-token",
					"accessor": "test-accessor",
					"policies": ["default"],
					"token_policies": ["default"],
					"metadata": {},
					"lease_duration": 7200,
					"renewable": true
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodAppRole,
		AppRole: &AppRoleAuthConfig{
			RoleID:   "test-role-id",
			SecretID: "test-secret-id",
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithAppRole(context.Background())

	// Assert
	if err != nil {
		t.Errorf("authenticateWithAppRole() error = %v, want nil", err)
	}

	ttl := vc.tokenTTL.Load()
	if ttl != 7200 {
		t.Errorf("tokenTTL = %v, want 7200", ttl)
	}
}

// TestAuthenticateWithAppRole_NilConfig tests AppRole auth with nil config.
func TestAuthenticateWithAppRole_NilConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "placeholder",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)
	vc.config.AppRole = nil

	// Act
	err = vc.authenticateWithAppRole(context.Background())

	// Assert
	if err == nil {
		t.Error("authenticateWithAppRole() should return error for nil config")
	}
}

// TestAuthenticateWithAppRole_NoAuthInResponse tests AppRole auth with no auth in response.
func TestAuthenticateWithAppRole_NoAuthInResponse(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{"data": {}}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodAppRole,
		AppRole: &AppRoleAuthConfig{
			RoleID:   "test-role-id",
			SecretID: "test-secret-id",
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithAppRole(context.Background())

	// Assert
	if err == nil {
		t.Error("authenticateWithAppRole() should return error when no auth in response")
	}
}

// TestAuthenticateWithAppRole_CustomMountPath tests AppRole auth with custom mount path.
func TestAuthenticateWithAppRole_CustomMountPath(t *testing.T) {
	t.Parallel()

	// Arrange
	var requestPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		if r.URL.Path == "/v1/auth/custom-approle/login" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			// Vault API response with auth structure - use raw JSON to ensure proper types
			resp := `{
				"request_id": "test-request-id",
				"lease_id": "",
				"renewable": false,
				"lease_duration": 0,
				"data": null,
				"wrap_info": null,
				"warnings": null,
				"auth": {
					"client_token": "test-client-token",
					"accessor": "test-accessor",
					"policies": ["default"],
					"token_policies": ["default"],
					"metadata": {},
					"lease_duration": 7200,
					"renewable": true
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodAppRole,
		AppRole: &AppRoleAuthConfig{
			RoleID:    "test-role-id",
			SecretID:  "test-secret-id",
			MountPath: "custom-approle",
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithAppRole(context.Background())

	// Assert
	if err != nil {
		t.Errorf("authenticateWithAppRole() error = %v, want nil", err)
	}

	if requestPath != "/v1/auth/custom-approle/login" {
		t.Errorf("request path = %v, want /v1/auth/custom-approle/login", requestPath)
	}
}

// TestAuthenticateWithAppRole_AuthFails tests AppRole auth when authentication fails.
func TestAuthenticateWithAppRole_AuthFails(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" && r.Method == http.MethodPut {
			w.WriteHeader(http.StatusUnauthorized)
			resp := `{"errors": ["invalid role_id or secret_id"]}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodAppRole,
		AppRole: &AppRoleAuthConfig{
			RoleID:   "invalid-role-id",
			SecretID: "invalid-secret-id",
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithAppRole(context.Background())

	// Assert
	if err == nil {
		t.Error("authenticateWithAppRole() should return error when auth fails")
	}
}

// TestAuthenticate_UnsupportedAuthMethod tests authentication with unsupported method.
func TestAuthenticate_UnsupportedAuthMethod(t *testing.T) {
	t.Parallel()

	// Arrange
	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    "http://localhost:8200",
		AuthMethod: AuthMethodToken,
		Token:      "placeholder",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)
	vc.config.AuthMethod = AuthMethod("unsupported")

	// Act
	err = vc.Authenticate(context.Background())

	// Assert
	if err == nil {
		t.Error("Authenticate() should return error for unsupported auth method")
	}
}

// TestAuthenticate_TableDriven tests authentication with various configurations.
func TestAuthenticate_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupMock func() *httptest.Server
		setupCfg  func(serverURL string) *Config
		wantErr   bool
		wantTTL   int64
		skipClose bool
	}{
		{
			name: "token auth success",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/auth/token/lookup-self" {
						w.Header().Set("Content-Type", "application/json")
						// Use raw JSON to ensure proper numeric types
						resp := `{"data": {"ttl": 1800}}`
						_, _ = w.Write([]byte(resp))
						return
					}
					http.NotFound(w, r)
				}))
			},
			setupCfg: func(serverURL string) *Config {
				return &Config{
					Enabled:    true,
					Address:    serverURL,
					AuthMethod: AuthMethodToken,
					Token:      "test-token",
				}
			},
			wantErr: false,
			wantTTL: 1800,
		},
		{
			name: "token auth with zero TTL",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/auth/token/lookup-self" {
						w.Header().Set("Content-Type", "application/json")
						// Use raw JSON to ensure proper numeric types
						resp := `{"data": {"ttl": 0}}`
						_, _ = w.Write([]byte(resp))
						return
					}
					http.NotFound(w, r)
				}))
			},
			setupCfg: func(serverURL string) *Config {
				return &Config{
					Enabled:    true,
					Address:    serverURL,
					AuthMethod: AuthMethodToken,
					Token:      "root-token",
				}
			},
			wantErr: false,
			wantTTL: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			server := tt.setupMock()
			defer server.Close()

			cfg := tt.setupCfg(server.URL)
			logger := observability.NopLogger()

			client, err := New(cfg, logger)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if !tt.skipClose {
				defer func() { _ = client.Close() }()
			}

			// Act
			err = client.Authenticate(context.Background())

			// Assert
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				vc := client.(*vaultClient)
				if vc.tokenTTL.Load() != tt.wantTTL {
					t.Errorf("tokenTTL = %v, want %v", vc.tokenTTL.Load(), tt.wantTTL)
				}
			}
		})
	}
}

// TestReauthenticate_TableDriven tests reauthentication with various auth methods.
func TestReauthenticate_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		authMethod AuthMethod
		setupMock  func() *httptest.Server
		setupCfg   func(serverURL string) *Config
		wantErr    bool
	}{
		{
			name:       "reauthenticate with token",
			authMethod: AuthMethodToken,
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/auth/token/lookup-self" {
						w.Header().Set("Content-Type", "application/json")
						// Use raw JSON to ensure proper numeric types
						resp := `{"data": {"ttl": 3600}}`
						_, _ = w.Write([]byte(resp))
						return
					}
					http.NotFound(w, r)
				}))
			},
			setupCfg: func(serverURL string) *Config {
				return &Config{
					Enabled:    true,
					Address:    serverURL,
					AuthMethod: AuthMethodToken,
					Token:      "test-token",
				}
			},
			wantErr: false,
		},
		{
			name:       "reauthenticate with unsupported method",
			authMethod: AuthMethod("unsupported"),
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.NotFound(w, r)
				}))
			},
			setupCfg: func(serverURL string) *Config {
				return &Config{
					Enabled:    true,
					Address:    serverURL,
					AuthMethod: AuthMethodToken,
					Token:      "test-token",
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			server := tt.setupMock()
			defer server.Close()

			cfg := tt.setupCfg(server.URL)
			logger := observability.NopLogger()

			client, err := New(cfg, logger)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() { _ = client.Close() }()

			vc := client.(*vaultClient)
			vc.config.AuthMethod = tt.authMethod

			// Act
			err = vc.reauthenticate(context.Background())

			// Assert
			if (err != nil) != tt.wantErr {
				t.Errorf("reauthenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestAuthenticateWithKubernetes_AuthFails tests Kubernetes auth when authentication fails.
func TestAuthenticateWithKubernetes_AuthFails(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" && r.Method == http.MethodPut {
			w.WriteHeader(http.StatusUnauthorized)
			resp := `{"errors": ["invalid JWT"]}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Create a temporary token file
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("invalid-jwt-token"), 0600); err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodKubernetes,
		Kubernetes: &KubernetesAuthConfig{
			Role:      "test-role",
			TokenPath: tokenPath,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.authenticateWithKubernetes(context.Background())

	// Assert
	if err == nil {
		t.Error("authenticateWithKubernetes() should return error when auth fails")
	}
}

// TestAuthenticate_ConcurrentAccess tests concurrent authentication attempts.
func TestAuthenticate_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	// Arrange
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			// Use raw JSON to ensure proper numeric types
			resp := `{"data": {"ttl": 3600}}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act - run multiple concurrent authentications
	const numGoroutines = 10
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			errCh <- vc.authenticateWithToken(context.Background())
		}()
	}

	// Assert
	for i := 0; i < numGoroutines; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent authenticateWithToken() error = %v", err)
		}
	}

	if requestCount.Load() != numGoroutines {
		t.Errorf("request count = %v, want %v", requestCount.Load(), numGoroutines)
	}
}

// isAuthenticationError is a helper to check if error is AuthenticationError.
func isAuthenticationError(err error, target **AuthenticationError) bool {
	if err == nil {
		return false
	}
	authErr, ok := err.(*AuthenticationError)
	if ok && target != nil {
		*target = authErr
	}
	return ok
}

// TestExtractTTLSeconds tests the extractTTLSeconds function with various types.
func TestExtractTTLSeconds(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected int64
	}{
		{
			name:     "json.Number as int",
			input:    json.Number("3600"),
			expected: 3600,
		},
		{
			name:     "json.Number as float",
			input:    json.Number("3600.5"),
			expected: 3600,
		},
		{
			name:     "float64",
			input:    float64(7200),
			expected: 7200,
		},
		{
			name:     "int",
			input:    int(1800),
			expected: 1800,
		},
		{
			name:     "int64",
			input:    int64(900),
			expected: 900,
		},
		{
			name:     "string (unsupported)",
			input:    "3600",
			expected: 0,
		},
		{
			name:     "nil",
			input:    nil,
			expected: 0,
		},
		{
			name:     "invalid json.Number",
			input:    json.Number("invalid"),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTTLSeconds(tt.input)
			if result != tt.expected {
				t.Errorf("extractTTLSeconds(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestReauthenticate_WithKubernetes tests reauthentication with Kubernetes auth method.
func TestReauthenticate_WithKubernetes(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/kubernetes/login" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"auth": {
					"client_token": "test-client-token",
					"lease_duration": 3600,
					"renewable": true
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Create a temporary token file
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-jwt-token"), 0600); err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodKubernetes,
		Kubernetes: &KubernetesAuthConfig{
			Role:      "test-role",
			TokenPath: tokenPath,
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.reauthenticate(context.Background())

	// Assert
	if err != nil {
		t.Errorf("reauthenticate() error = %v, want nil", err)
	}
}

// TestReauthenticate_WithAppRole tests reauthentication with AppRole auth method.
func TestReauthenticate_WithAppRole(t *testing.T) {
	t.Parallel()

	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" && r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/json")
			resp := `{
				"auth": {
					"client_token": "test-client-token",
					"lease_duration": 7200,
					"renewable": true
				}
			}`
			_, _ = w.Write([]byte(resp))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	logger := observability.NopLogger()
	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodAppRole,
		AppRole: &AppRoleAuthConfig{
			RoleID:   "test-role-id",
			SecretID: "test-secret-id",
		},
	}

	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	// Act
	err = vc.reauthenticate(context.Background())

	// Assert
	if err != nil {
		t.Errorf("reauthenticate() error = %v, want nil", err)
	}
}
