//go:build e2e || integration || functional

/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package testconfig provides centralized test environment configuration
// that loads settings from environment variables instead of hardcoded values.
// This enables flexible test execution across different environments.
package testconfig

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// Default values for test configuration
const (
	// DefaultVaultAddr is the default Vault server address
	DefaultVaultAddr = "http://localhost:8200"

	// DefaultVaultRole is the default Vault Kubernetes auth role
	DefaultVaultRole = "avapigw-test"

	// DefaultK8sAPIServer is the default Kubernetes API server address
	DefaultK8sAPIServer = "https://127.0.0.1:6443"

	// DefaultKeycloakURL is the default Keycloak server URL
	DefaultKeycloakURL = "http://localhost:8080"

	// DefaultKeycloakAdmin is the default Keycloak admin username
	DefaultKeycloakAdmin = "admin"

	// DefaultKeycloakPassword is the default Keycloak admin password
	DefaultKeycloakPassword = "admin"

	// DefaultKeycloakRealm is the default test realm name
	DefaultKeycloakRealm = "avapigw-test"

	// DefaultKeycloakClientID is the default OAuth2 client ID
	DefaultKeycloakClientID = "avapigw-test-client"

	// DefaultTestNamespace is the default Kubernetes namespace for tests
	DefaultTestNamespace = "avapigw-e2e-test"

	// DefaultTimeout for test operations
	DefaultTimeout = 2 * time.Minute

	// DefaultInterval for polling
	DefaultInterval = time.Second

	// ShortTimeout for quick operations
	ShortTimeout = 30 * time.Second

	// LongTimeout for slow operations
	LongTimeout = 5 * time.Minute
)

// Environment variable names
const (
	EnvVaultAddr            = "TEST_VAULT_ADDR"
	EnvVaultToken           = "TEST_VAULT_TOKEN"
	EnvVaultRole            = "TEST_VAULT_ROLE"
	EnvK8sAPIServer         = "TEST_K8S_API_SERVER"
	EnvK8sCACert            = "TEST_K8S_CA_CERT"
	EnvKeycloakURL          = "TEST_KEYCLOAK_URL"
	EnvKeycloakAdmin        = "TEST_KEYCLOAK_ADMIN"
	EnvKeycloakPassword     = "TEST_KEYCLOAK_PASSWORD"
	EnvKeycloakRealm        = "TEST_KEYCLOAK_REALM"
	EnvKeycloakClientID     = "TEST_KEYCLOAK_CLIENT_ID"
	EnvKeycloakClientSecret = "TEST_KEYCLOAK_CLIENT_SECRET"
	EnvTestNamespace        = "TEST_NAMESPACE"
	EnvSkipE2E              = "SKIP_E2E"
	EnvSkipVaultTests       = "SKIP_VAULT_TESTS"
	EnvSkipKeycloakTests    = "SKIP_KEYCLOAK_TESTS"
)

// TestEnvConfig holds all test environment configuration loaded from environment variables.
// It provides a centralized way to manage test settings across different test suites.
type TestEnvConfig struct {
	// Vault configuration
	VaultAddr  string // Vault server address
	VaultToken string // Vault root token for setup (required for Vault tests)
	VaultRole  string // Vault Kubernetes auth role

	// Kubernetes configuration
	K8sAPIServer string // Kubernetes API server address
	K8sCACert    string // Kubernetes CA certificate (PEM format)

	// Keycloak configuration
	KeycloakURL          string // Keycloak server URL
	KeycloakAdmin        string // Keycloak admin username
	KeycloakPassword     string // Keycloak admin password
	KeycloakRealm        string // Test realm name
	KeycloakClientID     string // OAuth2 client ID
	KeycloakClientSecret string // OAuth2 client secret

	// Test configuration
	TestNamespace string // Kubernetes namespace for tests

	// Skip flags
	SkipE2E           bool // Skip E2E tests
	SkipVaultTests    bool // Skip Vault-related tests
	SkipKeycloakTests bool // Skip Keycloak-related tests
}

// LoadTestEnvConfig loads test configuration from environment variables.
// It uses default values for optional settings and leaves required fields
// empty if not provided (validation should be done separately).
func LoadTestEnvConfig() *TestEnvConfig {
	return &TestEnvConfig{
		// Vault configuration
		VaultAddr:  getEnvOrDefault(EnvVaultAddr, DefaultVaultAddr),
		VaultToken: os.Getenv(EnvVaultToken), // No default, required for Vault tests
		VaultRole:  getEnvOrDefault(EnvVaultRole, DefaultVaultRole),

		// Kubernetes configuration
		K8sAPIServer: getEnvOrDefault(EnvK8sAPIServer, DefaultK8sAPIServer),
		K8sCACert:    os.Getenv(EnvK8sCACert), // No default

		// Keycloak configuration
		KeycloakURL:          getEnvOrDefault(EnvKeycloakURL, DefaultKeycloakURL),
		KeycloakAdmin:        getEnvOrDefault(EnvKeycloakAdmin, DefaultKeycloakAdmin),
		KeycloakPassword:     getEnvOrDefault(EnvKeycloakPassword, DefaultKeycloakPassword),
		KeycloakRealm:        getEnvOrDefault(EnvKeycloakRealm, DefaultKeycloakRealm),
		KeycloakClientID:     getEnvOrDefault(EnvKeycloakClientID, DefaultKeycloakClientID),
		KeycloakClientSecret: os.Getenv(EnvKeycloakClientSecret), // No default

		// Test configuration
		TestNamespace: getEnvOrDefault(EnvTestNamespace, DefaultTestNamespace),

		// Skip flags
		SkipE2E:           getEnvBool(EnvSkipE2E, false),
		SkipVaultTests:    getEnvBool(EnvSkipVaultTests, false),
		SkipKeycloakTests: getEnvBool(EnvSkipKeycloakTests, false),
	}
}

// Validate checks that required configuration fields are set based on which tests are enabled.
// Returns an error describing any missing required configuration.
func (c *TestEnvConfig) Validate() error {
	var missingFields []string

	// Validate Vault configuration if Vault tests are not skipped
	if !c.SkipVaultTests {
		if c.VaultToken == "" {
			missingFields = append(missingFields, fmt.Sprintf("%s (Vault root token)", EnvVaultToken))
		}
	}

	// Validate Keycloak configuration if Keycloak tests are not skipped
	if !c.SkipKeycloakTests {
		if c.KeycloakClientSecret == "" {
			missingFields = append(missingFields, fmt.Sprintf("%s (Keycloak client secret)", EnvKeycloakClientSecret))
		}
	}

	if len(missingFields) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missingFields, ", "))
	}

	return nil
}

// ValidateVault checks that Vault-specific configuration is valid.
// Returns an error if Vault tests are enabled but required config is missing.
func (c *TestEnvConfig) ValidateVault() error {
	if c.SkipVaultTests {
		return nil
	}

	if c.VaultAddr == "" {
		return fmt.Errorf("vault address is required: set %s", EnvVaultAddr)
	}

	if c.VaultToken == "" {
		return fmt.Errorf("vault token is required for setup: set %s", EnvVaultToken)
	}

	return nil
}

// ValidateKeycloak checks that Keycloak-specific configuration is valid.
// Returns an error if Keycloak tests are enabled but required config is missing.
func (c *TestEnvConfig) ValidateKeycloak() error {
	if c.SkipKeycloakTests {
		return nil
	}

	if c.KeycloakURL == "" {
		return fmt.Errorf("keycloak URL is required: set %s", EnvKeycloakURL)
	}

	if c.KeycloakClientSecret == "" {
		return fmt.Errorf("keycloak client secret is required: set %s", EnvKeycloakClientSecret)
	}

	return nil
}

// NewVaultClient creates a new Vault client using the test configuration.
// Returns an error if the client cannot be created or if Vault tests are skipped.
func (c *TestEnvConfig) NewVaultClient() (*vault.Client, error) {
	if c.SkipVaultTests {
		return nil, fmt.Errorf("vault tests are skipped")
	}

	if err := c.ValidateVault(); err != nil {
		return nil, fmt.Errorf("vault configuration validation failed: %w", err)
	}

	config := vault.DefaultConfig()
	config.Address = c.VaultAddr
	config.Timeout = 30 * time.Second

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(c.VaultToken)

	return client, nil
}

// NewVaultClientWithAddress creates a new Vault client with a custom address.
// This is useful for tests that need to connect to a different Vault instance.
func (c *TestEnvConfig) NewVaultClientWithAddress(address string) (*vault.Client, error) {
	config := vault.DefaultConfig()
	config.Address = address
	config.Timeout = 30 * time.Second

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	if c.VaultToken != "" {
		client.SetToken(c.VaultToken)
	}

	return client, nil
}

// GetKeycloakTokenURL returns the token endpoint URL for Keycloak.
func (c *TestEnvConfig) GetKeycloakTokenURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.KeycloakURL, c.KeycloakRealm)
}

// GetKeycloakJWKSURL returns the JWKS endpoint URL for Keycloak.
func (c *TestEnvConfig) GetKeycloakJWKSURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.KeycloakURL, c.KeycloakRealm)
}

// GetKeycloakIssuer returns the issuer URL for Keycloak.
func (c *TestEnvConfig) GetKeycloakIssuer() string {
	return fmt.Sprintf("%s/realms/%s", c.KeycloakURL, c.KeycloakRealm)
}

// ShouldSkipE2E returns true if E2E tests should be skipped.
func (c *TestEnvConfig) ShouldSkipE2E() bool {
	return c.SkipE2E
}

// ShouldSkipVaultTests returns true if Vault-related tests should be skipped.
func (c *TestEnvConfig) ShouldSkipVaultTests() bool {
	return c.SkipVaultTests
}

// ShouldSkipKeycloakTests returns true if Keycloak-related tests should be skipped.
func (c *TestEnvConfig) ShouldSkipKeycloakTests() bool {
	return c.SkipKeycloakTests
}

// String returns a string representation of the configuration (without sensitive values).
func (c *TestEnvConfig) String() string {
	return fmt.Sprintf(
		"TestEnvConfig{VaultAddr: %q, VaultRole: %q, K8sAPIServer: %q, KeycloakURL: %q, "+
			"KeycloakRealm: %q, KeycloakClientID: %q, TestNamespace: %q, "+
			"SkipE2E: %v, SkipVaultTests: %v, SkipKeycloakTests: %v}",
		c.VaultAddr, c.VaultRole, c.K8sAPIServer, c.KeycloakURL,
		c.KeycloakRealm, c.KeycloakClientID, c.TestNamespace,
		c.SkipE2E, c.SkipVaultTests, c.SkipKeycloakTests,
	)
}

// LogConfig returns a formatted string suitable for logging configuration details.
// Sensitive values like tokens and passwords are masked.
func (c *TestEnvConfig) LogConfig() string {
	vaultTokenMasked := maskSecret(c.VaultToken)
	keycloakPasswordMasked := maskSecret(c.KeycloakPassword)
	keycloakClientSecretMasked := maskSecret(c.KeycloakClientSecret)

	return fmt.Sprintf(`Test Environment Configuration:
  Vault:
    Address: %s
    Token: %s
    Role: %s
  Kubernetes:
    API Server: %s
    CA Cert: %s
  Keycloak:
    URL: %s
    Admin: %s
    Password: %s
    Realm: %s
    Client ID: %s
    Client Secret: %s
  Test:
    Namespace: %s
  Skip Flags:
    E2E: %v
    Vault Tests: %v
    Keycloak Tests: %v`,
		c.VaultAddr, vaultTokenMasked, c.VaultRole,
		c.K8sAPIServer, maskCert(c.K8sCACert),
		c.KeycloakURL, c.KeycloakAdmin, keycloakPasswordMasked,
		c.KeycloakRealm, c.KeycloakClientID, keycloakClientSecretMasked,
		c.TestNamespace,
		c.SkipE2E, c.SkipVaultTests, c.SkipKeycloakTests,
	)
}

// getEnvOrDefault returns the environment variable value or a default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool returns the environment variable as a boolean or a default if not set.
// Accepts "true", "1", "yes" (case-insensitive) as true values.
func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	// Parse boolean value
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		// Try additional common values
		switch strings.ToLower(value) {
		case "yes", "y", "on":
			return true
		case "no", "n", "off":
			return false
		default:
			return defaultValue
		}
	}

	return parsed
}

// maskSecret masks a secret value for logging, showing only first and last characters.
func maskSecret(secret string) string {
	if secret == "" {
		return "<not set>"
	}
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:2] + "****" + secret[len(secret)-2:]
}

// maskCert masks a certificate for logging.
func maskCert(cert string) string {
	if cert == "" {
		return "<not set>"
	}
	return "<certificate present>"
}
