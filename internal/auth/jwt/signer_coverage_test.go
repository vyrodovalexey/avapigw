package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// ============================================================================
// Tests for WithVaultClient (0% -> 100%)
// ============================================================================

func TestWithVaultClient(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Vault: &VaultConfig{
			Enabled:      true,
			TransitMount: "transit",
			KeyName:      "jwt-key",
		},
	}

	mockVault := &mockVaultClient{enabled: true}

	signer, err := NewSigner(config,
		WithVaultClient(mockVault),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

// ============================================================================
// Tests for resolveKeyID (66.7% -> 100%)
// ============================================================================

func TestSigner_ResolveKeyID_EmptyOptKeyID(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	// Create signer with a specific keyID
	s, err := NewSigner(config,
		WithPrivateKey(privateKey, "default-key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	// Sign without specifying keyID in options - should use default
	token, err := s.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_SignWithOptions_CustomKeyID(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	s, err := NewSigner(config,
		WithPrivateKey(privateKey, "default-key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	// Sign with custom keyID in options
	opts := SigningOptions{
		KeyID: "custom-key-id",
	}

	token, err := s.SignWithOptions(context.Background(), claims, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

// ============================================================================
// Tests for resolveAlgorithm (80% -> 100%)
// ============================================================================

func TestSigner_ResolveAlgorithm_FromOptions(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	s, err := NewSigner(config,
		WithPrivateKey(privateKey, "key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	// Sign with algorithm specified in options
	opts := SigningOptions{
		Algorithm: "RS384",
	}

	token, err := s.SignWithOptions(context.Background(), claims, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

// ============================================================================
// Tests for setIssuer (83.3% -> 100%)
// ============================================================================

func TestSigner_SetIssuer_FromOptions(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
		Issuer:  "config-issuer",
	}

	s, err := NewSigner(config,
		WithPrivateKey(privateKey, "key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	// Claims without issuer, options with issuer
	claims := &Claims{
		Subject: "user123",
	}

	opts := SigningOptions{
		Issuer: "option-issuer",
	}

	token, err := s.SignWithOptions(context.Background(), claims, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	// The issuer should be set from options
	assert.Equal(t, "option-issuer", claims.Issuer)
}

func TestSigner_SetIssuer_ClaimsAlreadySet(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
		Issuer:  "config-issuer",
	}

	s, err := NewSigner(config,
		WithPrivateKey(privateKey, "key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	// Claims with issuer already set
	claims := &Claims{
		Subject: "user123",
		Issuer:  "claims-issuer",
	}

	opts := SigningOptions{
		Issuer: "option-issuer",
	}

	token, err := s.SignWithOptions(context.Background(), claims, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	// The issuer should remain from claims
	assert.Equal(t, "claims-issuer", claims.Issuer)
}

// ============================================================================
// Tests for setAudience (83.3% -> 100%)
// ============================================================================

func TestSigner_SetAudience_FromOptions(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled:  true,
		Audience: []string{"config-audience"},
	}

	s, err := NewSigner(config,
		WithPrivateKey(privateKey, "key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	// Claims without audience, options with audience
	claims := &Claims{
		Subject: "user123",
	}

	opts := SigningOptions{
		Audience: []string{"option-audience"},
	}

	token, err := s.SignWithOptions(context.Background(), claims, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, Audience{"option-audience"}, claims.Audience)
}

func TestSigner_SetAudience_ClaimsAlreadySet(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled:  true,
		Audience: []string{"config-audience"},
	}

	s, err := NewSigner(config,
		WithPrivateKey(privateKey, "key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	// Claims with audience already set
	claims := &Claims{
		Subject:  "user123",
		Audience: Audience{"claims-audience"},
	}

	opts := SigningOptions{
		Audience: []string{"option-audience"},
	}

	token, err := s.SignWithOptions(context.Background(), claims, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, Audience{"claims-audience"}, claims.Audience)
}

// ============================================================================
// Tests for createSignature with Vault (66.7% -> 100%)
// ============================================================================

func TestSigner_CreateSignature_WithVault(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Vault: &VaultConfig{
			Enabled:      true,
			TransitMount: "transit",
			KeyName:      "jwt-key",
		},
	}

	mockVault := &mockVaultClient{
		enabled: true,
		transit: &mockTransitClient{
			signResult: []byte("mock-signature"),
		},
	}

	s, err := NewSigner(config,
		WithVaultClient(mockVault),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := s.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_CreateSignature_WithVault_Error(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Vault: &VaultConfig{
			Enabled:      true,
			TransitMount: "transit",
			KeyName:      "jwt-key",
		},
	}

	mockVault := &mockVaultClient{
		enabled: true,
		transit: &mockTransitClient{
			signErr: errors.New("vault signing failed"),
		},
	}

	s, err := NewSigner(config,
		WithVaultClient(mockVault),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := s.Sign(context.Background(), claims)
	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "Vault signing failed")
}

func TestSigner_SignWithVault_ClientNotEnabled(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Vault: &VaultConfig{
			Enabled:      true,
			TransitMount: "transit",
			KeyName:      "jwt-key",
		},
	}

	mockVault := &mockVaultClient{
		enabled: false, // Client reports not enabled
		transit: &mockTransitClient{},
	}

	s, err := NewSigner(config,
		WithVaultClient(mockVault),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := s.Sign(context.Background(), claims)
	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "Vault client is not available")
}

// ============================================================================
// Tests for signer error paths for wrong key types
// ============================================================================

func TestSigner_SignRSAPSS_WrongKeyType(t *testing.T) {
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := &Config{Enabled: true}

	s, err := NewSigner(config,
		WithPrivateKey(ecKey, "key-id", "PS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{Subject: "user123"}

	token, err := s.Sign(context.Background(), claims)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestSigner_SignECDSA_WrongKeyType(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{Enabled: true}

	s, err := NewSigner(config,
		WithPrivateKey(rsaKey, "key-id", "ES256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{Subject: "user123"}

	token, err := s.Sign(context.Background(), claims)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestSigner_SignHMAC_WrongKeyType(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{Enabled: true}

	s, err := NewSigner(config,
		WithPrivateKey(rsaKey, "key-id", "HS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{Subject: "user123"}

	token, err := s.Sign(context.Background(), claims)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestSigner_SignEdDSA_WrongKeyType(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{Enabled: true}

	s, err := NewSigner(config,
		WithPrivateKey(rsaKey, "key-id", "EdDSA"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{Subject: "user123"}

	token, err := s.Sign(context.Background(), claims)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestSigner_SignRSA_WrongKeyType(t *testing.T) {
	t.Parallel()

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	config := &Config{Enabled: true}

	s, err := NewSigner(config,
		WithPrivateKey(edKey, "key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{Subject: "user123"}

	token, err := s.Sign(context.Background(), claims)
	assert.Error(t, err)
	assert.Empty(t, token)
}

// ============================================================================
// Mock Vault types for testing
// ============================================================================

type mockVaultClient struct {
	enabled bool
	transit *mockTransitClient
}

func (m *mockVaultClient) IsEnabled() bool                      { return m.enabled }
func (m *mockVaultClient) Authenticate(_ context.Context) error { return nil }
func (m *mockVaultClient) RenewToken(_ context.Context) error   { return nil }
func (m *mockVaultClient) Health(_ context.Context) (*vault.HealthStatus, error) {
	return &vault.HealthStatus{}, nil
}
func (m *mockVaultClient) PKI() vault.PKIClient         { return nil }
func (m *mockVaultClient) KV() vault.KVClient           { return nil }
func (m *mockVaultClient) Transit() vault.TransitClient { return m.transit }
func (m *mockVaultClient) Close() error                 { return nil }

// Ensure mockVaultClient implements vault.Client
var _ vault.Client = (*mockVaultClient)(nil)

type mockTransitClient struct {
	signResult []byte
	signErr    error
}

func (m *mockTransitClient) Encrypt(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockTransitClient) Decrypt(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockTransitClient) Sign(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return m.signResult, m.signErr
}

func (m *mockTransitClient) Verify(_ context.Context, _, _ string, _, _ []byte) (bool, error) {
	return true, nil
}

// Ensure mockTransitClient implements vault.TransitClient
var _ vault.TransitClient = (*mockTransitClient)(nil)
