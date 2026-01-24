// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

const (
	// DefaultVaultAddr is the default Vault address for testing.
	DefaultVaultAddr = "http://127.0.0.1:8200"
	// DefaultVaultToken is the default Vault token for testing.
	DefaultVaultToken = "myroot"
	// DefaultPKIMount is the default PKI mount path for testing.
	DefaultPKIMount = "pki"
	// DefaultKVMount is the default KV mount path for testing.
	DefaultKVMount = "secret"
	// DefaultPKIRole is the default PKI role for testing.
	DefaultPKIRole = "test-role"
)

// GetVaultAddr returns the Vault address from environment or default.
func GetVaultAddr() string {
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		return addr
	}
	return DefaultVaultAddr
}

// GetVaultToken returns the Vault token from environment or default.
func GetVaultToken() string {
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		return token
	}
	return DefaultVaultToken
}

// GetVaultPKIMount returns the PKI mount path from environment or default.
func GetVaultPKIMount() string {
	if mount := os.Getenv("VAULT_PKI_MOUNT"); mount != "" {
		return mount
	}
	return DefaultPKIMount
}

// GetVaultKVMount returns the KV mount path from environment or default.
func GetVaultKVMount() string {
	if mount := os.Getenv("VAULT_KV_MOUNT"); mount != "" {
		return mount
	}
	return DefaultKVMount
}

// GetVaultPKIRole returns the PKI role from environment or default.
func GetVaultPKIRole() string {
	if role := os.Getenv("VAULT_PKI_ROLE"); role != "" {
		return role
	}
	return DefaultPKIRole
}

// IsVaultAvailable checks if Vault is available.
func IsVaultAvailable() bool {
	client, err := CreateVaultClient()
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	health, err := client.Sys().HealthWithContext(ctx)
	if err != nil {
		return false
	}

	return health.Initialized && !health.Sealed
}

// SkipIfVaultUnavailable skips the test if Vault is not available.
func SkipIfVaultUnavailable(t *testing.T) {
	if !IsVaultAvailable() {
		t.Skip("Vault not available at", GetVaultAddr(), "- skipping test")
	}
}

// CreateVaultClient creates a Vault client for testing.
func CreateVaultClient() (*vault.Client, error) {
	config := vault.DefaultConfig()
	config.Address = GetVaultAddr()

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(GetVaultToken())

	return client, nil
}

// SetupVaultPKI sets up the PKI secrets engine for testing.
func SetupVaultPKI(client *vault.Client) error {
	ctx := context.Background()
	mount := GetVaultPKIMount()

	// Check if PKI is already mounted
	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	if _, ok := mounts[mount+"/"]; !ok {
		// Enable PKI secrets engine
		err = client.Sys().MountWithContext(ctx, mount, &vault.MountInput{
			Type: "pki",
			Config: vault.MountConfigInput{
				MaxLeaseTTL: "87600h",
			},
		})
		if err != nil {
			return fmt.Errorf("failed to enable PKI secrets engine: %w", err)
		}
	}

	// Generate root CA
	_, err = client.Logical().WriteWithContext(ctx, mount+"/root/generate/internal", map[string]interface{}{
		"common_name": "Test Root CA",
		"ttl":         "87600h",
	})
	if err != nil {
		// Ignore error if root already exists
		_ = err
	}

	// Configure PKI role
	_, err = client.Logical().WriteWithContext(ctx, mount+"/roles/"+GetVaultPKIRole(), map[string]interface{}{
		"allowed_domains":  "localhost,*.local,*.test",
		"allow_subdomains": true,
		"allow_localhost":  true,
		"max_ttl":          "72h",
		"allow_any_name":   true,
		"allow_ip_sans":    true,
	})
	if err != nil {
		return fmt.Errorf("failed to configure PKI role: %w", err)
	}

	return nil
}

// SetupVaultKV sets up the KV secrets engine for testing.
func SetupVaultKV(client *vault.Client) error {
	ctx := context.Background()
	mount := GetVaultKVMount()

	// Check if KV is already mounted
	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to list mounts: %w", err)
	}

	if _, ok := mounts[mount+"/"]; !ok {
		// Enable KV v2 secrets engine
		err = client.Sys().MountWithContext(ctx, mount, &vault.MountInput{
			Type: "kv-v2",
		})
		if err != nil {
			return fmt.Errorf("failed to enable KV secrets engine: %w", err)
		}
	}

	return nil
}

// CleanupVaultPKI cleans up the PKI secrets engine.
func CleanupVaultPKI(client *vault.Client) error {
	ctx := context.Background()
	mount := GetVaultPKIMount()

	// Disable PKI secrets engine
	err := client.Sys().UnmountWithContext(ctx, mount)
	if err != nil {
		// Ignore error if already unmounted
		return nil
	}

	return nil
}

// CleanupVaultKV cleans up the KV secrets engine.
func CleanupVaultKV(client *vault.Client) error {
	ctx := context.Background()
	mount := GetVaultKVMount()

	// Disable KV secrets engine
	err := client.Sys().UnmountWithContext(ctx, mount)
	if err != nil {
		// Ignore error if already unmounted
		return nil
	}

	return nil
}

// VaultTestSetup contains Vault test setup information.
type VaultTestSetup struct {
	Client    *vault.Client
	PKIMount  string
	KVMount   string
	PKIRole   string
	cleanupFn func()
}

// SetupVaultForTesting sets up Vault for integration testing.
func SetupVaultForTesting(t *testing.T) *VaultTestSetup {
	SkipIfVaultUnavailable(t)

	client, err := CreateVaultClient()
	if err != nil {
		t.Fatalf("Failed to create Vault client: %v", err)
	}

	setup := &VaultTestSetup{
		Client:   client,
		PKIMount: GetVaultPKIMount(),
		KVMount:  GetVaultKVMount(),
		PKIRole:  GetVaultPKIRole(),
	}

	// Setup PKI
	if err := SetupVaultPKI(client); err != nil {
		t.Logf("Warning: Failed to setup PKI: %v", err)
	}

	// Setup KV
	if err := SetupVaultKV(client); err != nil {
		t.Logf("Warning: Failed to setup KV: %v", err)
	}

	return setup
}

// Cleanup cleans up Vault test resources.
func (s *VaultTestSetup) Cleanup() {
	if s.cleanupFn != nil {
		s.cleanupFn()
	}
}

// WriteSecret writes a secret to KV for testing.
func (s *VaultTestSetup) WriteSecret(path string, data map[string]interface{}) error {
	ctx := context.Background()
	fullPath := fmt.Sprintf("%s/data/%s", s.KVMount, path)

	_, err := s.Client.Logical().WriteWithContext(ctx, fullPath, map[string]interface{}{
		"data": data,
	})
	return err
}

// ReadSecret reads a secret from KV for testing.
func (s *VaultTestSetup) ReadSecret(path string) (map[string]interface{}, error) {
	ctx := context.Background()
	fullPath := fmt.Sprintf("%s/data/%s", s.KVMount, path)

	secret, err := s.Client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret format")
	}

	return data, nil
}

// DeleteSecret deletes a secret from KV for testing.
func (s *VaultTestSetup) DeleteSecret(path string) error {
	ctx := context.Background()
	fullPath := fmt.Sprintf("%s/data/%s", s.KVMount, path)

	_, err := s.Client.Logical().DeleteWithContext(ctx, fullPath)
	return err
}

// IssueCertificate issues a certificate from PKI for testing.
func (s *VaultTestSetup) IssueCertificate(commonName string, ttl string) (map[string]interface{}, error) {
	ctx := context.Background()
	path := fmt.Sprintf("%s/issue/%s", s.PKIMount, s.PKIRole)

	secret, err := s.Client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"common_name": commonName,
		"ttl":         ttl,
	})
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no certificate data returned")
	}

	return secret.Data, nil
}

// GetCA returns the CA certificate from PKI for testing.
func (s *VaultTestSetup) GetCA() (string, error) {
	ctx := context.Background()
	path := fmt.Sprintf("%s/ca/pem", s.PKIMount)

	secret, err := s.Client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", err
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no CA data returned")
	}

	ca, ok := secret.Data["certificate"].(string)
	if !ok {
		return "", fmt.Errorf("invalid CA format")
	}

	return ca, nil
}

// VaultTestConfig holds Vault test configuration.
type VaultTestConfig struct {
	Address    string
	Token      string
	PKIMount   string
	KVMount    string
	PKIRole    string
	Namespace  string
	SkipVerify bool
}

// GetVaultTestConfig returns Vault test configuration from environment.
func GetVaultTestConfig() VaultTestConfig {
	return VaultTestConfig{
		Address:    GetVaultAddr(),
		Token:      GetVaultToken(),
		PKIMount:   GetVaultPKIMount(),
		KVMount:    GetVaultKVMount(),
		PKIRole:    GetVaultPKIRole(),
		Namespace:  os.Getenv("VAULT_NAMESPACE"),
		SkipVerify: os.Getenv("VAULT_SKIP_VERIFY") == "true",
	}
}

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
