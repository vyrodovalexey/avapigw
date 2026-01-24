// Package vault provides HashiCorp Vault integration for the Ava API Gateway.
//
// This package enables secure secret management, PKI certificate issuance,
// encryption/decryption via Transit secrets engine, and KV secret storage.
// Vault integration is toggleable and can be enabled or disabled via configuration.
//
// # Features
//
//   - Multiple authentication methods: Token, Kubernetes, AppRole
//   - PKI secrets engine for certificate issuance and management
//   - KV secrets engine for secret storage and retrieval
//   - Transit secrets engine for encryption/decryption operations
//   - Secret caching with configurable TTL
//   - Automatic token renewal
//   - Retry with exponential backoff
//   - Prometheus metrics for monitoring
//
// # Authentication Methods
//
// The package supports three authentication methods:
//
// Token Authentication:
// Direct token authentication using a Vault token. Suitable for development
// or when tokens are managed externally.
//
//	cfg := &vault.Config{
//	    Enabled:    true,
//	    Address:    "https://vault.example.com:8200",
//	    AuthMethod: vault.AuthMethodToken,
//	    Token:      "s.xxxxx",
//	}
//
// Kubernetes Authentication:
// Uses Kubernetes ServiceAccount JWT for authentication. Ideal for workloads
// running in Kubernetes clusters.
//
//	cfg := &vault.Config{
//	    Enabled:    true,
//	    Address:    "https://vault.example.com:8200",
//	    AuthMethod: vault.AuthMethodKubernetes,
//	    Kubernetes: &vault.KubernetesAuthConfig{
//	        Role:      "my-app-role",
//	        MountPath: "kubernetes",
//	    },
//	}
//
// AppRole Authentication:
// Uses RoleID and SecretID for authentication. Suitable for automated systems
// and CI/CD pipelines.
//
//	cfg := &vault.Config{
//	    Enabled:    true,
//	    Address:    "https://vault.example.com:8200",
//	    AuthMethod: vault.AuthMethodAppRole,
//	    AppRole: &vault.AppRoleAuthConfig{
//	        RoleID:   "role-id",
//	        SecretID: "secret-id",
//	    },
//	}
//
// # PKI Secrets Engine
//
// The PKI client enables certificate issuance and management:
//
//	client, _ := vault.New(cfg, logger)
//	cert, err := client.PKI().IssueCertificate(ctx, &vault.PKIIssueOptions{
//	    Mount:      "pki",
//	    Role:       "my-role",
//	    CommonName: "example.com",
//	    AltNames:   []string{"www.example.com"},
//	    TTL:        24 * time.Hour,
//	})
//
// # KV Secrets Engine
//
// The KV client provides secret storage operations:
//
//	// Read a secret
//	secret, err := client.KV().Read(ctx, "secret", "my-app/config")
//
//	// Write a secret
//	err := client.KV().Write(ctx, "secret", "my-app/config", map[string]interface{}{
//	    "api_key": "xxx",
//	})
//
// # Transit Secrets Engine
//
// The Transit client provides encryption operations:
//
//	// Encrypt data
//	ciphertext, err := client.Transit().Encrypt(ctx, "transit", "my-key", plaintext)
//
//	// Decrypt data
//	plaintext, err := client.Transit().Decrypt(ctx, "transit", "my-key", ciphertext)
//
// # Certificate Provider
//
// The VaultProvider implements the tls.CertificateProvider interface for
// automatic certificate management:
//
//	provider, _ := vault.NewVaultProvider(client, &vault.VaultProviderConfig{
//	    PKIMount:    "pki",
//	    Role:        "my-role",
//	    CommonName:  "example.com",
//	    TTL:         24 * time.Hour,
//	    RenewBefore: 1 * time.Hour,
//	}, logger)
//
// # Caching
//
// Secret caching reduces Vault load and improves performance:
//
//	cfg := &vault.Config{
//	    // ... other config
//	    Cache: &vault.CacheConfig{
//	        Enabled: true,
//	        TTL:     5 * time.Minute,
//	    },
//	}
//
// # Retry Configuration
//
// Automatic retry with exponential backoff for transient failures:
//
//	cfg := &vault.Config{
//	    // ... other config
//	    Retry: &vault.RetryConfig{
//	        MaxRetries:  3,
//	        BackoffBase: 100 * time.Millisecond,
//	        BackoffMax:  5 * time.Second,
//	    },
//	}
//
// # Metrics
//
// The package exposes Prometheus metrics:
//
//   - gateway_vault_requests_total{operation,status}
//   - gateway_vault_request_duration_seconds
//   - gateway_vault_token_ttl_seconds
//   - gateway_vault_cache_hits_total
//   - gateway_vault_cache_misses_total
//
// # Testing
//
// For local testing, start Vault in dev mode:
//
//	vault server -dev -dev-root-token-id=myroot
//
// Configure the PKI secrets engine:
//
//	vault secrets enable pki
//	vault secrets tune -max-lease-ttl=87600h pki
//	vault write pki/root/generate/internal common_name="Test CA" ttl=87600h
//	vault write pki/roles/test-role allowed_domains="example.com" allow_subdomains=true max_ttl=72h
package vault
