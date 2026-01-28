//go:build functional
// +build functional

package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/vault"
)

func TestFunctional_Vault_Config_LoadValid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		config *vault.Config
	}{
		{
			name:   "default config (disabled)",
			config: vault.DefaultConfig(),
		},
		{
			name: "token auth enabled",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
			},
		},
		{
			name: "kubernetes auth enabled",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodKubernetes,
				Kubernetes: &vault.KubernetesAuthConfig{
					Role:      "test-role",
					MountPath: "kubernetes",
				},
			},
		},
		{
			name: "approle auth enabled",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodAppRole,
				AppRole: &vault.AppRoleAuthConfig{
					RoleID:    "test-role-id",
					SecretID:  "test-secret-id",
					MountPath: "approle",
				},
			},
		},
		{
			name: "with TLS config",
			config: &vault.Config{
				Enabled:    true,
				Address:    "https://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
				TLS: &vault.VaultTLSConfig{
					CACert:     "/path/to/ca.pem",
					ClientCert: "/path/to/client.pem",
					ClientKey:  "/path/to/client-key.pem",
				},
			},
		},
		{
			name: "with cache config",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
				Cache: &vault.CacheConfig{
					Enabled: true,
					TTL:     10 * time.Minute,
					MaxSize: 500,
				},
			},
		},
		{
			name: "with retry config",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
				Retry: &vault.RetryConfig{
					MaxRetries:  5,
					BackoffBase: 200 * time.Millisecond,
					BackoffMax:  10 * time.Second,
				},
			},
		},
		{
			name: "with namespace",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				Namespace:  "my-namespace",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.config.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestFunctional_Vault_Config_LoadInvalid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		config      *vault.Config
		expectedErr string
	}{
		{
			name:        "nil config",
			config:      nil,
			expectedErr: "configuration is nil",
		},
		{
			name: "enabled without address",
			config: &vault.Config{
				Enabled:    true,
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
			},
			expectedErr: "vault address is required",
		},
		{
			name: "invalid auth method",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: "invalid",
			},
			expectedErr: "invalid auth method",
		},
		{
			name: "token auth without token",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
			},
			expectedErr: "token is required",
		},
		{
			name: "kubernetes auth without config",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodKubernetes,
			},
			expectedErr: "kubernetes configuration is required",
		},
		{
			name: "kubernetes auth without role",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodKubernetes,
				Kubernetes: &vault.KubernetesAuthConfig{},
			},
			expectedErr: "role is required",
		},
		{
			name: "approle auth without config",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodAppRole,
			},
			expectedErr: "appRole configuration is required",
		},
		{
			name: "approle auth without role ID",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodAppRole,
				AppRole: &vault.AppRoleAuthConfig{
					SecretID: "test-secret-id",
				},
			},
			expectedErr: "roleId is required",
		},
		{
			name: "approle auth without secret ID",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodAppRole,
				AppRole: &vault.AppRoleAuthConfig{
					RoleID: "test-role-id",
				},
			},
			expectedErr: "secretId is required",
		},
		{
			name: "TLS client cert without key",
			config: &vault.Config{
				Enabled:    true,
				Address:    "https://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
				TLS: &vault.VaultTLSConfig{
					ClientCert: "/path/to/client.pem",
				},
			},
			expectedErr: "client key is required",
		},
		{
			name: "TLS client key without cert",
			config: &vault.Config{
				Enabled:    true,
				Address:    "https://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
				TLS: &vault.VaultTLSConfig{
					ClientKey: "/path/to/client-key.pem",
				},
			},
			expectedErr: "client cert is required",
		},
		{
			name: "negative cache TTL",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
				Cache: &vault.CacheConfig{
					Enabled: true,
					TTL:     -1 * time.Minute,
				},
			},
			expectedErr: "TTL cannot be negative",
		},
		{
			name: "negative cache max size",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
				Cache: &vault.CacheConfig{
					Enabled: true,
					MaxSize: -1,
				},
			},
			expectedErr: "maxSize cannot be negative",
		},
		{
			name: "negative retry max retries",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
				Retry: &vault.RetryConfig{
					MaxRetries: -1,
				},
			},
			expectedErr: "maxRetries cannot be negative",
		},
		{
			name: "backoff base greater than max",
			config: &vault.Config{
				Enabled:    true,
				Address:    "http://127.0.0.1:8200",
				AuthMethod: vault.AuthMethodToken,
				Token:      "test-token",
				Retry: &vault.RetryConfig{
					BackoffBase: 10 * time.Second,
					BackoffMax:  1 * time.Second,
				},
			},
			expectedErr: "backoffBase cannot be greater than backoffMax",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.config.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestFunctional_Vault_Config_Defaults(t *testing.T) {
	t.Parallel()

	cfg := vault.DefaultConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, vault.AuthMethodToken, cfg.AuthMethod)
	assert.NotNil(t, cfg.Cache)
	assert.NotNil(t, cfg.Retry)
}

func TestFunctional_Vault_Config_DefaultCacheConfig(t *testing.T) {
	t.Parallel()

	cfg := vault.DefaultCacheConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 5*time.Minute, cfg.TTL)
	assert.Equal(t, 1000, cfg.MaxSize)
}

func TestFunctional_Vault_Config_DefaultRetryConfig(t *testing.T) {
	t.Parallel()

	cfg := vault.DefaultRetryConfig()

	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, cfg.BackoffBase)
	assert.Equal(t, 5*time.Second, cfg.BackoffMax)
}

func TestFunctional_Vault_Config_AuthMethods(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		method vault.AuthMethod
		valid  bool
	}{
		{vault.AuthMethodToken, true},
		{vault.AuthMethodKubernetes, true},
		{vault.AuthMethodAppRole, true},
		{"invalid", false},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(string(tc.method), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.valid, tc.method.IsValid())
		})
	}
}

func TestFunctional_Vault_Config_Disabled(t *testing.T) {
	t.Parallel()

	t.Run("disabled config validates without address", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.Config{
			Enabled: false,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("disabled config validates without auth method", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.Config{
			Enabled: false,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestFunctional_Vault_Config_Clone(t *testing.T) {
	t.Parallel()

	original := &vault.Config{
		Enabled:    true,
		Address:    "http://127.0.0.1:8200",
		Namespace:  "test-namespace",
		AuthMethod: vault.AuthMethodAppRole,
		Token:      "test-token",
		Kubernetes: &vault.KubernetesAuthConfig{
			Role:      "k8s-role",
			MountPath: "kubernetes",
			TokenPath: "/var/run/secrets/token",
		},
		AppRole: &vault.AppRoleAuthConfig{
			RoleID:    "role-id",
			SecretID:  "secret-id",
			MountPath: "approle",
		},
		TLS: &vault.VaultTLSConfig{
			CACert:     "/path/to/ca.pem",
			ClientCert: "/path/to/client.pem",
			ClientKey:  "/path/to/client-key.pem",
			SkipVerify: true,
		},
		Cache: &vault.CacheConfig{
			Enabled: true,
			TTL:     10 * time.Minute,
			MaxSize: 500,
		},
		Retry: &vault.RetryConfig{
			MaxRetries:  5,
			BackoffBase: 200 * time.Millisecond,
			BackoffMax:  10 * time.Second,
		},
	}

	clone := original.Clone()

	// Verify clone is not nil
	require.NotNil(t, clone)

	// Verify values are equal
	assert.Equal(t, original.Enabled, clone.Enabled)
	assert.Equal(t, original.Address, clone.Address)
	assert.Equal(t, original.Namespace, clone.Namespace)
	assert.Equal(t, original.AuthMethod, clone.AuthMethod)
	assert.Equal(t, original.Token, clone.Token)

	// Verify nested objects are cloned
	assert.NotSame(t, original.Kubernetes, clone.Kubernetes)
	assert.Equal(t, original.Kubernetes.Role, clone.Kubernetes.Role)

	assert.NotSame(t, original.AppRole, clone.AppRole)
	assert.Equal(t, original.AppRole.RoleID, clone.AppRole.RoleID)

	assert.NotSame(t, original.TLS, clone.TLS)
	assert.Equal(t, original.TLS.CACert, clone.TLS.CACert)

	assert.NotSame(t, original.Cache, clone.Cache)
	assert.Equal(t, original.Cache.TTL, clone.Cache.TTL)

	assert.NotSame(t, original.Retry, clone.Retry)
	assert.Equal(t, original.Retry.MaxRetries, clone.Retry.MaxRetries)

	// Verify modifying clone doesn't affect original
	clone.Address = "http://modified:8200"
	assert.NotEqual(t, original.Address, clone.Address)
}

func TestFunctional_Vault_Config_GetMethods(t *testing.T) {
	t.Parallel()

	t.Run("kubernetes get mount path default", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.KubernetesAuthConfig{
			Role: "test-role",
		}
		assert.Equal(t, "kubernetes", cfg.GetMountPath())
	})

	t.Run("kubernetes get mount path custom", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.KubernetesAuthConfig{
			Role:      "test-role",
			MountPath: "custom-k8s",
		}
		assert.Equal(t, "custom-k8s", cfg.GetMountPath())
	})

	t.Run("kubernetes get token path default", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.KubernetesAuthConfig{
			Role: "test-role",
		}
		assert.Equal(t, "/var/run/secrets/kubernetes.io/serviceaccount/token", cfg.GetTokenPath())
	})

	t.Run("kubernetes get token path custom", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.KubernetesAuthConfig{
			Role:      "test-role",
			TokenPath: "/custom/token/path",
		}
		assert.Equal(t, "/custom/token/path", cfg.GetTokenPath())
	})

	t.Run("approle get mount path default", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.AppRoleAuthConfig{
			RoleID:   "role-id",
			SecretID: "secret-id",
		}
		assert.Equal(t, "approle", cfg.GetMountPath())
	})

	t.Run("approle get mount path custom", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.AppRoleAuthConfig{
			RoleID:    "role-id",
			SecretID:  "secret-id",
			MountPath: "custom-approle",
		}
		assert.Equal(t, "custom-approle", cfg.GetMountPath())
	})

	t.Run("cache get TTL default", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.CacheConfig{
			Enabled: true,
		}
		assert.Equal(t, 5*time.Minute, cfg.GetTTL())
	})

	t.Run("cache get TTL custom", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.CacheConfig{
			Enabled: true,
			TTL:     10 * time.Minute,
		}
		assert.Equal(t, 10*time.Minute, cfg.GetTTL())
	})

	t.Run("cache get max size default", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.CacheConfig{
			Enabled: true,
		}
		assert.Equal(t, 1000, cfg.GetMaxSize())
	})

	t.Run("cache get max size custom", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.CacheConfig{
			Enabled: true,
			MaxSize: 500,
		}
		assert.Equal(t, 500, cfg.GetMaxSize())
	})

	t.Run("retry get max retries default", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.RetryConfig{}
		assert.Equal(t, 3, cfg.GetMaxRetries())
	})

	t.Run("retry get max retries custom", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.RetryConfig{
			MaxRetries: 5,
		}
		assert.Equal(t, 5, cfg.GetMaxRetries())
	})

	t.Run("retry get backoff base default", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.RetryConfig{}
		assert.Equal(t, 100*time.Millisecond, cfg.GetBackoffBase())
	})

	t.Run("retry get backoff base custom", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.RetryConfig{
			BackoffBase: 200 * time.Millisecond,
		}
		assert.Equal(t, 200*time.Millisecond, cfg.GetBackoffBase())
	})

	t.Run("retry get backoff max default", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.RetryConfig{}
		assert.Equal(t, 5*time.Second, cfg.GetBackoffMax())
	})

	t.Run("retry get backoff max custom", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.RetryConfig{
			BackoffMax: 10 * time.Second,
		}
		assert.Equal(t, 10*time.Second, cfg.GetBackoffMax())
	})
}

func TestFunctional_Vault_Config_Errors(t *testing.T) {
	t.Parallel()

	t.Run("vault error", func(t *testing.T) {
		t.Parallel()
		err := vault.NewVaultError("test_op", "/test/path", "test message")
		assert.Contains(t, err.Error(), "test_op")
		assert.Contains(t, err.Error(), "/test/path")
		assert.Contains(t, err.Error(), "test message")
	})

	t.Run("vault error with cause", func(t *testing.T) {
		t.Parallel()
		cause := assert.AnError
		err := vault.NewVaultErrorWithCause("test_op", "/test/path", "test message", cause)
		assert.Contains(t, err.Error(), "test message")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("authentication error", func(t *testing.T) {
		t.Parallel()
		err := vault.NewAuthenticationError("token", "invalid token")
		assert.Contains(t, err.Error(), "token")
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("configuration error", func(t *testing.T) {
		t.Parallel()
		err := vault.NewConfigurationError("address", "address is required")
		assert.Contains(t, err.Error(), "address")
		assert.Contains(t, err.Error(), "address is required")
	})

	t.Run("is retryable", func(t *testing.T) {
		t.Parallel()
		assert.True(t, vault.IsRetryable(vault.ErrVaultUnavailable))
		assert.True(t, vault.IsRetryable(vault.ErrVaultSealed))
		assert.False(t, vault.IsRetryable(vault.ErrTokenExpired))
		assert.False(t, vault.IsRetryable(vault.ErrAuthenticationFailed))
		assert.False(t, vault.IsRetryable(vault.ErrInvalidConfig))
		assert.False(t, vault.IsRetryable(nil))
	})
}

func TestFunctional_Vault_Config_VaultProviderConfig(t *testing.T) {
	t.Parallel()

	t.Run("valid provider config", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.VaultProviderConfig{
			PKIMount:    "pki",
			Role:        "test-role",
			CommonName:  "test.local",
			AltNames:    []string{"alt.local"},
			IPSANs:      []string{"127.0.0.1"},
			TTL:         24 * time.Hour,
			RenewBefore: 1 * time.Hour,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing PKI mount", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.VaultProviderConfig{
			Role:       "test-role",
			CommonName: "test.local",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PKI mount")
	})

	t.Run("missing role", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.VaultProviderConfig{
			PKIMount:   "pki",
			CommonName: "test.local",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role")
	})

	t.Run("missing common name", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.VaultProviderConfig{
			PKIMount: "pki",
			Role:     "test-role",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "common name")
	})

	t.Run("negative TTL", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.VaultProviderConfig{
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
			TTL:        -1 * time.Hour,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TTL")
	})

	t.Run("renewBefore greater than TTL", func(t *testing.T) {
		t.Parallel()
		cfg := &vault.VaultProviderConfig{
			PKIMount:    "pki",
			Role:        "test-role",
			CommonName:  "test.local",
			TTL:         1 * time.Hour,
			RenewBefore: 2 * time.Hour,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "renewBefore")
	})

	t.Run("clone provider config", func(t *testing.T) {
		t.Parallel()
		original := &vault.VaultProviderConfig{
			PKIMount:    "pki",
			Role:        "test-role",
			CommonName:  "test.local",
			AltNames:    []string{"alt1.local", "alt2.local"},
			IPSANs:      []string{"127.0.0.1", "192.168.1.1"},
			TTL:         24 * time.Hour,
			RenewBefore: 1 * time.Hour,
			CAMount:     "pki-ca",
		}

		clone := original.Clone()

		require.NotNil(t, clone)
		assert.Equal(t, original.PKIMount, clone.PKIMount)
		assert.Equal(t, original.Role, clone.Role)
		assert.Equal(t, original.CommonName, clone.CommonName)
		assert.Equal(t, original.AltNames, clone.AltNames)
		assert.Equal(t, original.IPSANs, clone.IPSANs)
		assert.Equal(t, original.TTL, clone.TTL)
		assert.Equal(t, original.RenewBefore, clone.RenewBefore)
		assert.Equal(t, original.CAMount, clone.CAMount)

		// Verify modifying clone doesn't affect original
		clone.AltNames[0] = "modified.local"
		assert.NotEqual(t, original.AltNames[0], clone.AltNames[0])
	})
}
