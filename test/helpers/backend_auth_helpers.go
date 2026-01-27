// Package helpers provides common test utilities for the API Gateway tests.
package helpers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

const (
	// DefaultBackendAuthVaultPath is the default Vault path for backend auth credentials.
	DefaultBackendAuthVaultPath = "backend-auth"
	// DefaultBackendOIDCClientID is the default OIDC client ID for backend auth.
	DefaultBackendOIDCClientID = "backend-service"
	// DefaultBackendOIDCClientSecret is the default OIDC client secret for backend auth.
	DefaultBackendOIDCClientSecret = "backend-service-secret"
)

// BackendAuthTestConfig holds backend authentication test configuration.
type BackendAuthTestConfig struct {
	VaultAddr        string
	VaultToken       string
	VaultKVMount     string
	VaultPKIMount    string
	VaultPKIRole     string
	KeycloakAddr     string
	KeycloakRealm    string
	OIDCClientID     string
	OIDCClientSecret string
	StaticJWTToken   string
	StaticUsername   string
	StaticPassword   string
}

// GetBackendAuthTestConfig returns backend auth test configuration from environment.
func GetBackendAuthTestConfig() BackendAuthTestConfig {
	return BackendAuthTestConfig{
		VaultAddr:        getEnvOrDefault("VAULT_ADDR", DefaultVaultAddr),
		VaultToken:       getEnvOrDefault("VAULT_TOKEN", DefaultVaultToken),
		VaultKVMount:     getEnvOrDefault("VAULT_KV_MOUNT", DefaultKVMount),
		VaultPKIMount:    getEnvOrDefault("VAULT_PKI_MOUNT", DefaultPKIMount),
		VaultPKIRole:     getEnvOrDefault("VAULT_PKI_ROLE", DefaultPKIRole),
		KeycloakAddr:     getEnvOrDefault("KEYCLOAK_ADDR", DefaultKeycloakAddr),
		KeycloakRealm:    getEnvOrDefault("KEYCLOAK_REALM", DefaultKeycloakRealm),
		OIDCClientID:     getEnvOrDefault("BACKEND_OIDC_CLIENT_ID", DefaultBackendOIDCClientID),
		OIDCClientSecret: getEnvOrDefault("BACKEND_OIDC_CLIENT_SECRET", DefaultBackendOIDCClientSecret),
		StaticJWTToken:   getEnvOrDefault("BACKEND_STATIC_JWT_TOKEN", "test-static-jwt-token"),
		StaticUsername:   getEnvOrDefault("BACKEND_STATIC_USERNAME", "backend-user"),
		StaticPassword:   getEnvOrDefault("BACKEND_STATIC_PASSWORD", "backend-pass"),
	}
}

// SetupVaultBackendCredentials stores test credentials in Vault for backend authentication.
func SetupVaultBackendCredentials(t *testing.T, setup *VaultTestSetup, path string, credentials map[string]interface{}) error {
	t.Helper()

	if setup == nil || setup.Client == nil {
		return fmt.Errorf("vault setup is nil")
	}

	return setup.WriteSecret(path, credentials)
}

// SetupVaultBasicAuthCredentials stores basic auth credentials in Vault.
func SetupVaultBasicAuthCredentials(t *testing.T, setup *VaultTestSetup, path, username, password string) error {
	t.Helper()

	return SetupVaultBackendCredentials(t, setup, path, map[string]interface{}{
		"username": username,
		"password": password,
	})
}

// SetupVaultJWTToken stores a JWT token in Vault.
func SetupVaultJWTToken(t *testing.T, setup *VaultTestSetup, path, token string) error {
	t.Helper()

	return SetupVaultBackendCredentials(t, setup, path, map[string]interface{}{
		"token": token,
	})
}

// SetupVaultOIDCClientSecret stores OIDC client secret in Vault.
func SetupVaultOIDCClientSecret(t *testing.T, setup *VaultTestSetup, path, clientSecret string) error {
	t.Helper()

	return SetupVaultBackendCredentials(t, setup, path, map[string]interface{}{
		"client_secret": clientSecret,
	})
}

// CleanupVaultBackendCredentials removes test credentials from Vault.
func CleanupVaultBackendCredentials(t *testing.T, setup *VaultTestSetup, path string) error {
	t.Helper()

	if setup == nil || setup.Client == nil {
		return nil
	}

	return setup.DeleteSecret(path)
}

// SetupKeycloakBackendClient creates an OIDC client in Keycloak for backend authentication.
func SetupKeycloakBackendClient(t *testing.T, setup *KeycloakTestSetup, clientID, clientSecret string) error {
	t.Helper()

	if setup == nil || setup.Client == nil {
		return fmt.Errorf("keycloak setup is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientConfig := map[string]interface{}{
		"clientId":                  clientID,
		"enabled":                   true,
		"publicClient":              false,
		"secret":                    clientSecret,
		"directAccessGrantsEnabled": false,
		"standardFlowEnabled":       false,
		"serviceAccountsEnabled":    true,
		"protocol":                  "openid-connect",
	}

	return setup.Client.CreateClient(ctx, setup.Realm, clientConfig)
}

// BackendMTLSCertificates holds mTLS certificates for backend authentication.
type BackendMTLSCertificates struct {
	CACertPEM     []byte
	CAKeyPEM      []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	TempDir       string
}

// CreateTestCertificates generates test certificates for mTLS backend authentication.
func CreateTestCertificates(t *testing.T) (*BackendMTLSCertificates, error) {
	t.Helper()

	certs := &BackendMTLSCertificates{}

	// Generate CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Backend CA"},
			CommonName:   "Test Backend Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	certs.CACertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	certs.CAKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	// Generate client certificate
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client key: %w", err)
	}

	clientSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate client serial: %w", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			Organization: []string{"Test Backend Client"},
			CommonName:   "backend-client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	certs.ClientCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	certs.ClientKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	// Generate server certificate
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	serverSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate server serial: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			Organization: []string{"Test Backend Server"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:    []string{"localhost", "*.local", "*.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	certs.ServerCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	certs.ServerKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	return certs, nil
}

// WriteToFiles writes certificates to temporary files.
func (c *BackendMTLSCertificates) WriteToFiles() error {
	tempDir, err := os.MkdirTemp("", "backend-mtls-test-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	c.TempDir = tempDir

	files := map[string][]byte{
		"ca.crt":     c.CACertPEM,
		"ca.key":     c.CAKeyPEM,
		"client.crt": c.ClientCertPEM,
		"client.key": c.ClientKeyPEM,
		"server.crt": c.ServerCertPEM,
		"server.key": c.ServerKeyPEM,
	}

	for name, data := range files {
		if err := os.WriteFile(c.TempDir+"/"+name, data, 0600); err != nil {
			return fmt.Errorf("failed to write %s: %w", name, err)
		}
	}

	return nil
}

// Cleanup removes temporary certificate files.
func (c *BackendMTLSCertificates) Cleanup() {
	if c.TempDir != "" {
		os.RemoveAll(c.TempDir)
	}
}

// CACertPath returns the path to the CA certificate file.
func (c *BackendMTLSCertificates) CACertPath() string {
	return c.TempDir + "/ca.crt"
}

// ClientCertPath returns the path to the client certificate file.
func (c *BackendMTLSCertificates) ClientCertPath() string {
	return c.TempDir + "/client.crt"
}

// ClientKeyPath returns the path to the client key file.
func (c *BackendMTLSCertificates) ClientKeyPath() string {
	return c.TempDir + "/client.key"
}

// ServerCertPath returns the path to the server certificate file.
func (c *BackendMTLSCertificates) ServerCertPath() string {
	return c.TempDir + "/server.crt"
}

// ServerKeyPath returns the path to the server key file.
func (c *BackendMTLSCertificates) ServerKeyPath() string {
	return c.TempDir + "/server.key"
}

// CircuitBreakerState represents the state of a circuit breaker.
type CircuitBreakerState string

const (
	// CircuitBreakerStateClosed indicates the circuit breaker is closed (allowing requests).
	CircuitBreakerStateClosed CircuitBreakerState = "closed"
	// CircuitBreakerStateOpen indicates the circuit breaker is open (blocking requests).
	CircuitBreakerStateOpen CircuitBreakerState = "open"
	// CircuitBreakerStateHalfOpen indicates the circuit breaker is half-open (testing).
	CircuitBreakerStateHalfOpen CircuitBreakerState = "half-open"
)

// WaitForCircuitBreakerState waits for a circuit breaker to reach a specific state.
// This is a helper function for testing circuit breaker behavior.
// The checkFn should return the current state of the circuit breaker.
func WaitForCircuitBreakerState(
	ctx context.Context,
	expectedState CircuitBreakerState,
	checkFn func() CircuitBreakerState,
	timeout time.Duration,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for circuit breaker state %s", expectedState)
		case <-ticker.C:
			if checkFn() == expectedState {
				return nil
			}
		}
	}
}

// BackendAuthTestSetup contains all setup information for backend auth tests.
type BackendAuthTestSetup struct {
	VaultSetup    *VaultTestSetup
	KeycloakSetup *KeycloakTestSetup
	Certificates  *BackendMTLSCertificates
	Config        BackendAuthTestConfig
}

// SetupBackendAuthForTesting sets up all required services for backend auth testing.
func SetupBackendAuthForTesting(t *testing.T, requireVault, requireKeycloak, requireCerts bool) *BackendAuthTestSetup {
	t.Helper()

	setup := &BackendAuthTestSetup{
		Config: GetBackendAuthTestConfig(),
	}

	if requireVault {
		setup.VaultSetup = SetupVaultForTesting(t)
	}

	if requireKeycloak {
		setup.KeycloakSetup = SetupKeycloakForTesting(t)
	}

	if requireCerts {
		certs, err := CreateTestCertificates(t)
		if err != nil {
			t.Fatalf("Failed to create test certificates: %v", err)
		}
		if err := certs.WriteToFiles(); err != nil {
			t.Fatalf("Failed to write certificates to files: %v", err)
		}
		setup.Certificates = certs
	}

	return setup
}

// Cleanup cleans up all test resources.
func (s *BackendAuthTestSetup) Cleanup() {
	if s.VaultSetup != nil {
		s.VaultSetup.Cleanup()
	}
	if s.KeycloakSetup != nil {
		s.KeycloakSetup.Cleanup()
	}
	if s.Certificates != nil {
		s.Certificates.Cleanup()
	}
}
