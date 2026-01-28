package vault

import (
	"testing"
	"time"
)

func TestAuthMethod_String(t *testing.T) {
	tests := []struct {
		name     string
		method   AuthMethod
		expected string
	}{
		{
			name:     "token auth method",
			method:   AuthMethodToken,
			expected: "token",
		},
		{
			name:     "kubernetes auth method",
			method:   AuthMethodKubernetes,
			expected: "kubernetes",
		},
		{
			name:     "approle auth method",
			method:   AuthMethodAppRole,
			expected: "approle",
		},
		{
			name:     "unknown auth method",
			method:   AuthMethod("unknown"),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.method.String()
			if result != tt.expected {
				t.Errorf("String() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAuthMethod_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		method   AuthMethod
		expected bool
	}{
		{
			name:     "token is valid",
			method:   AuthMethodToken,
			expected: true,
		},
		{
			name:     "kubernetes is valid",
			method:   AuthMethodKubernetes,
			expected: true,
		},
		{
			name:     "approle is valid",
			method:   AuthMethodAppRole,
			expected: true,
		},
		{
			name:     "empty is invalid",
			method:   AuthMethod(""),
			expected: false,
		},
		{
			name:     "unknown is invalid",
			method:   AuthMethod("unknown"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.method.IsValid()
			if result != tt.expected {
				t.Errorf("IsValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorField  string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "disabled config is valid",
			config: &Config{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "enabled without address",
			config: &Config{
				Enabled:    true,
				AuthMethod: AuthMethodToken,
			},
			expectError: true,
			errorField:  "address",
		},
		{
			name: "invalid auth method",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethod("invalid"),
			},
			expectError: true,
			errorField:  "authMethod",
		},
		{
			name: "token auth without token",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethodToken,
			},
			expectError: true,
			errorField:  "token",
		},
		{
			name: "valid token auth",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethodToken,
				Token:      "test-token",
			},
			expectError: false,
		},
		{
			name: "kubernetes auth without config",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethodKubernetes,
			},
			expectError: true,
			errorField:  "kubernetes",
		},
		{
			name: "kubernetes auth without role",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethodKubernetes,
				Kubernetes: &KubernetesAuthConfig{},
			},
			expectError: true,
			errorField:  "kubernetes.role",
		},
		{
			name: "valid kubernetes auth",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethodKubernetes,
				Kubernetes: &KubernetesAuthConfig{
					Role: "test-role",
				},
			},
			expectError: false,
		},
		{
			name: "approle auth without config",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethodAppRole,
			},
			expectError: true,
			errorField:  "appRole",
		},
		{
			name: "approle auth without roleId",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethodAppRole,
				AppRole:    &AppRoleAuthConfig{},
			},
			expectError: true,
			errorField:  "appRole.roleId",
		},
		{
			name: "approle auth without secretId",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethodAppRole,
				AppRole: &AppRoleAuthConfig{
					RoleID: "test-role-id",
				},
			},
			expectError: true,
			errorField:  "appRole.secretId",
		},
		{
			name: "valid approle auth",
			config: &Config{
				Enabled:    true,
				Address:    "http://vault:8200",
				AuthMethod: AuthMethodAppRole,
				AppRole: &AppRoleAuthConfig{
					RoleID:   "test-role-id",
					SecretID: "test-secret-id",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVaultTLSConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *VaultTLSConfig
		expectError bool
		errorField  string
	}{
		{
			name:        "nil config is valid",
			config:      nil,
			expectError: false,
		},
		{
			name:        "empty config is valid",
			config:      &VaultTLSConfig{},
			expectError: false,
		},
		{
			name: "client cert without key",
			config: &VaultTLSConfig{
				ClientCert: "/path/to/cert.pem",
			},
			expectError: true,
			errorField:  "tls.clientKey",
		},
		{
			name: "client key without cert",
			config: &VaultTLSConfig{
				ClientKey: "/path/to/key.pem",
			},
			expectError: true,
			errorField:  "tls.clientCert",
		},
		{
			name: "valid client cert and key",
			config: &VaultTLSConfig{
				ClientCert: "/path/to/cert.pem",
				ClientKey:  "/path/to/key.pem",
			},
			expectError: false,
		},
		{
			name: "valid with CA cert",
			config: &VaultTLSConfig{
				CACert: "/path/to/ca.pem",
			},
			expectError: false,
		},
		{
			name: "valid with skip verify",
			config: &VaultTLSConfig{
				SkipVerify: true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCacheConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *CacheConfig
		expectError bool
		errorField  string
	}{
		{
			name:        "nil config is valid",
			config:      nil,
			expectError: false,
		},
		{
			name: "disabled config is valid",
			config: &CacheConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "enabled with negative TTL",
			config: &CacheConfig{
				Enabled: true,
				TTL:     -1 * time.Second,
			},
			expectError: true,
			errorField:  "cache.ttl",
		},
		{
			name: "enabled with negative maxSize",
			config: &CacheConfig{
				Enabled: true,
				MaxSize: -1,
			},
			expectError: true,
			errorField:  "cache.maxSize",
		},
		{
			name: "valid enabled config",
			config: &CacheConfig{
				Enabled: true,
				TTL:     5 * time.Minute,
				MaxSize: 1000,
			},
			expectError: false,
		},
		{
			name: "enabled with zero values is valid",
			config: &CacheConfig{
				Enabled: true,
				TTL:     0,
				MaxSize: 0,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestRetryConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *RetryConfig
		expectError bool
		errorField  string
	}{
		{
			name:        "nil config is valid",
			config:      nil,
			expectError: false,
		},
		{
			name: "negative maxRetries",
			config: &RetryConfig{
				MaxRetries: -1,
			},
			expectError: true,
			errorField:  "retry.maxRetries",
		},
		{
			name: "negative backoffBase",
			config: &RetryConfig{
				BackoffBase: -1 * time.Second,
			},
			expectError: true,
			errorField:  "retry.backoffBase",
		},
		{
			name: "negative backoffMax",
			config: &RetryConfig{
				BackoffMax: -1 * time.Second,
			},
			expectError: true,
			errorField:  "retry.backoffMax",
		},
		{
			name: "backoffBase greater than backoffMax",
			config: &RetryConfig{
				BackoffBase: 10 * time.Second,
				BackoffMax:  5 * time.Second,
			},
			expectError: true,
			errorField:  "retry.backoffBase",
		},
		{
			name: "valid config",
			config: &RetryConfig{
				MaxRetries:  3,
				BackoffBase: 100 * time.Millisecond,
				BackoffMax:  5 * time.Second,
			},
			expectError: false,
		},
		{
			name: "zero values are valid",
			config: &RetryConfig{
				MaxRetries:  0,
				BackoffBase: 0,
				BackoffMax:  0,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Error("Validate() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestKubernetesAuthConfig_GetMountPath(t *testing.T) {
	tests := []struct {
		name     string
		config   *KubernetesAuthConfig
		expected string
	}{
		{
			name:     "default mount path",
			config:   &KubernetesAuthConfig{},
			expected: "kubernetes",
		},
		{
			name: "custom mount path",
			config: &KubernetesAuthConfig{
				MountPath: "custom-kubernetes",
			},
			expected: "custom-kubernetes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetMountPath()
			if result != tt.expected {
				t.Errorf("GetMountPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestKubernetesAuthConfig_GetTokenPath(t *testing.T) {
	tests := []struct {
		name     string
		config   *KubernetesAuthConfig
		expected string
	}{
		{
			name:     "default token path",
			config:   &KubernetesAuthConfig{},
			expected: "/var/run/secrets/kubernetes.io/serviceaccount/token",
		},
		{
			name: "custom token path",
			config: &KubernetesAuthConfig{
				TokenPath: "/custom/path/token",
			},
			expected: "/custom/path/token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetTokenPath()
			if result != tt.expected {
				t.Errorf("GetTokenPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAppRoleAuthConfig_GetMountPath(t *testing.T) {
	tests := []struct {
		name     string
		config   *AppRoleAuthConfig
		expected string
	}{
		{
			name:     "default mount path",
			config:   &AppRoleAuthConfig{},
			expected: "approle",
		},
		{
			name: "custom mount path",
			config: &AppRoleAuthConfig{
				MountPath: "custom-approle",
			},
			expected: "custom-approle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetMountPath()
			if result != tt.expected {
				t.Errorf("GetMountPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCacheConfig_GetTTL(t *testing.T) {
	tests := []struct {
		name     string
		config   *CacheConfig
		expected time.Duration
	}{
		{
			name:     "default TTL when zero",
			config:   &CacheConfig{TTL: 0},
			expected: 5 * time.Minute,
		},
		{
			name:     "custom TTL",
			config:   &CacheConfig{TTL: 10 * time.Minute},
			expected: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetTTL()
			if result != tt.expected {
				t.Errorf("GetTTL() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCacheConfig_GetMaxSize(t *testing.T) {
	tests := []struct {
		name     string
		config   *CacheConfig
		expected int
	}{
		{
			name:     "default max size when zero",
			config:   &CacheConfig{MaxSize: 0},
			expected: 1000,
		},
		{
			name:     "custom max size",
			config:   &CacheConfig{MaxSize: 500},
			expected: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetMaxSize()
			if result != tt.expected {
				t.Errorf("GetMaxSize() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRetryConfig_GetMaxRetries(t *testing.T) {
	tests := []struct {
		name     string
		config   *RetryConfig
		expected int
	}{
		{
			name:     "default max retries when zero",
			config:   &RetryConfig{MaxRetries: 0},
			expected: 3,
		},
		{
			name:     "custom max retries",
			config:   &RetryConfig{MaxRetries: 5},
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetMaxRetries()
			if result != tt.expected {
				t.Errorf("GetMaxRetries() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRetryConfig_GetBackoffBase(t *testing.T) {
	tests := []struct {
		name     string
		config   *RetryConfig
		expected time.Duration
	}{
		{
			name:     "default backoff base when zero",
			config:   &RetryConfig{BackoffBase: 0},
			expected: 100 * time.Millisecond,
		},
		{
			name:     "custom backoff base",
			config:   &RetryConfig{BackoffBase: 200 * time.Millisecond},
			expected: 200 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetBackoffBase()
			if result != tt.expected {
				t.Errorf("GetBackoffBase() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRetryConfig_GetBackoffMax(t *testing.T) {
	tests := []struct {
		name     string
		config   *RetryConfig
		expected time.Duration
	}{
		{
			name:     "default backoff max when zero",
			config:   &RetryConfig{BackoffMax: 0},
			expected: 5 * time.Second,
		},
		{
			name:     "custom backoff max",
			config:   &RetryConfig{BackoffMax: 10 * time.Second},
			expected: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetBackoffMax()
			if result != tt.expected {
				t.Errorf("GetBackoffMax() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if cfg.Enabled {
		t.Error("DefaultConfig().Enabled should be false")
	}

	if cfg.AuthMethod != AuthMethodToken {
		t.Errorf("DefaultConfig().AuthMethod = %v, want %v", cfg.AuthMethod, AuthMethodToken)
	}

	if cfg.Cache == nil {
		t.Error("DefaultConfig().Cache should not be nil")
	}

	if cfg.Retry == nil {
		t.Error("DefaultConfig().Retry should not be nil")
	}
}

func TestDefaultCacheConfig(t *testing.T) {
	cfg := DefaultCacheConfig()

	if cfg == nil {
		t.Fatal("DefaultCacheConfig() returned nil")
	}

	if !cfg.Enabled {
		t.Error("DefaultCacheConfig().Enabled should be true")
	}

	if cfg.TTL != 5*time.Minute {
		t.Errorf("DefaultCacheConfig().TTL = %v, want %v", cfg.TTL, 5*time.Minute)
	}

	if cfg.MaxSize != 1000 {
		t.Errorf("DefaultCacheConfig().MaxSize = %v, want %v", cfg.MaxSize, 1000)
	}
}

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()

	if cfg == nil {
		t.Fatal("DefaultRetryConfig() returned nil")
	}

	if cfg.MaxRetries != 3 {
		t.Errorf("DefaultRetryConfig().MaxRetries = %v, want %v", cfg.MaxRetries, 3)
	}

	if cfg.BackoffBase != 100*time.Millisecond {
		t.Errorf("DefaultRetryConfig().BackoffBase = %v, want %v", cfg.BackoffBase, 100*time.Millisecond)
	}

	if cfg.BackoffMax != 5*time.Second {
		t.Errorf("DefaultRetryConfig().BackoffMax = %v, want %v", cfg.BackoffMax, 5*time.Second)
	}
}

func TestConfig_Clone(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		var cfg *Config
		clone := cfg.Clone()
		if clone != nil {
			t.Error("Clone() of nil should return nil")
		}
	})

	t.Run("full config", func(t *testing.T) {
		original := &Config{
			Enabled:    true,
			Address:    "http://vault:8200",
			Namespace:  "test-namespace",
			AuthMethod: AuthMethodKubernetes,
			Token:      "test-token",
			Kubernetes: &KubernetesAuthConfig{
				Role:      "test-role",
				MountPath: "custom-mount",
				TokenPath: "/custom/token",
			},
			AppRole: &AppRoleAuthConfig{
				RoleID:    "test-role-id",
				SecretID:  "test-secret-id",
				MountPath: "custom-approle",
			},
			TLS: &VaultTLSConfig{
				CACert:     "/path/to/ca.pem",
				CAPath:     "/path/to/ca",
				ClientCert: "/path/to/cert.pem",
				ClientKey:  "/path/to/key.pem",
				SkipVerify: true,
			},
			Cache: &CacheConfig{
				Enabled: true,
				TTL:     10 * time.Minute,
				MaxSize: 500,
			},
			Retry: &RetryConfig{
				MaxRetries:  5,
				BackoffBase: 200 * time.Millisecond,
				BackoffMax:  10 * time.Second,
			},
		}

		clone := original.Clone()

		// Verify basic fields
		if clone.Enabled != original.Enabled {
			t.Error("Clone().Enabled mismatch")
		}
		if clone.Address != original.Address {
			t.Error("Clone().Address mismatch")
		}
		if clone.Namespace != original.Namespace {
			t.Error("Clone().Namespace mismatch")
		}
		if clone.AuthMethod != original.AuthMethod {
			t.Error("Clone().AuthMethod mismatch")
		}
		if clone.Token != original.Token {
			t.Error("Clone().Token mismatch")
		}

		// Verify Kubernetes config is deep copied
		if clone.Kubernetes == original.Kubernetes {
			t.Error("Clone().Kubernetes should be a different pointer")
		}
		if clone.Kubernetes.Role != original.Kubernetes.Role {
			t.Error("Clone().Kubernetes.Role mismatch")
		}

		// Verify AppRole config is deep copied
		if clone.AppRole == original.AppRole {
			t.Error("Clone().AppRole should be a different pointer")
		}
		if clone.AppRole.RoleID != original.AppRole.RoleID {
			t.Error("Clone().AppRole.RoleID mismatch")
		}

		// Verify TLS config is deep copied
		if clone.TLS == original.TLS {
			t.Error("Clone().TLS should be a different pointer")
		}
		if clone.TLS.CACert != original.TLS.CACert {
			t.Error("Clone().TLS.CACert mismatch")
		}

		// Verify Cache config is deep copied
		if clone.Cache == original.Cache {
			t.Error("Clone().Cache should be a different pointer")
		}
		if clone.Cache.TTL != original.Cache.TTL {
			t.Error("Clone().Cache.TTL mismatch")
		}

		// Verify Retry config is deep copied
		if clone.Retry == original.Retry {
			t.Error("Clone().Retry should be a different pointer")
		}
		if clone.Retry.MaxRetries != original.Retry.MaxRetries {
			t.Error("Clone().Retry.MaxRetries mismatch")
		}

		// Verify modifying clone doesn't affect original
		clone.Address = "http://modified:8200"
		if original.Address == clone.Address {
			t.Error("Modifying clone should not affect original")
		}
	})

	t.Run("config with nil sub-configs", func(t *testing.T) {
		original := &Config{
			Enabled:    true,
			Address:    "http://vault:8200",
			AuthMethod: AuthMethodToken,
			Token:      "test-token",
		}

		clone := original.Clone()

		if clone.Kubernetes != nil {
			t.Error("Clone().Kubernetes should be nil")
		}
		if clone.AppRole != nil {
			t.Error("Clone().AppRole should be nil")
		}
		if clone.TLS != nil {
			t.Error("Clone().TLS should be nil")
		}
		if clone.Cache != nil {
			t.Error("Clone().Cache should be nil")
		}
		if clone.Retry != nil {
			t.Error("Clone().Retry should be nil")
		}
	})
}

func TestConfig_Validate_WithTLSConfig(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Address:    "http://vault:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		TLS: &VaultTLSConfig{
			ClientCert: "/path/to/cert.pem",
			// Missing ClientKey
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should return error for invalid TLS config")
	}
}

func TestConfig_Validate_WithCacheConfig(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Address:    "http://vault:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     -1 * time.Second,
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should return error for invalid cache config")
	}
}

func TestConfig_Validate_WithRetryConfig(t *testing.T) {
	cfg := &Config{
		Enabled:    true,
		Address:    "http://vault:8200",
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Retry: &RetryConfig{
			MaxRetries: -1,
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Validate() should return error for invalid retry config")
	}
}
