package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// newNoopSignerMetrics creates a no-op metrics for testing.
func newNoopSignerMetrics() *Metrics {
	return NewMetrics("test")
}

func TestNewSigner(t *testing.T) {
	t.Parallel()

	t.Run("nil config returns error", func(t *testing.T) {
		t.Parallel()

		signer, err := NewSigner(nil)
		assert.Error(t, err)
		assert.Nil(t, signer)
	})

	t.Run("no key or vault returns error", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			Enabled: true,
		}

		signer, err := NewSigner(config)
		assert.Error(t, err)
		assert.Nil(t, signer)
	})

	t.Run("with RSA private key", func(t *testing.T) {
		t.Parallel()

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		config := &Config{
			Enabled: true,
		}

		signer, err := NewSigner(config,
			WithPrivateKey(privateKey, "test-key-id", "RS256"),
			WithSignerMetrics(newNoopSignerMetrics()),
		)
		require.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("with options", func(t *testing.T) {
		t.Parallel()

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		config := &Config{
			Enabled: true,
		}

		signer, err := NewSigner(config,
			WithPrivateKey(privateKey, "test-key-id", "RS256"),
			WithSignerLogger(observability.NopLogger()),
			WithSignerMetrics(newNoopSignerMetrics()),
		)
		require.NoError(t, err)
		assert.NotNil(t, signer)
	})
}

func TestSigner_Sign_RS256(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled:  true,
		Issuer:   "test-issuer",
		Audience: []string{"test-audience"},
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Token should have 3 parts
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3)
}

func TestSigner_Sign_RS384(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "RS384"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_RS512(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "RS512"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_PS256(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "PS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_PS384(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "PS384"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_PS512(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "PS512"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_ES256(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "ES256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_ES384(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "ES384"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_ES512(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "ES512"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_HS256(t *testing.T) {
	t.Parallel()

	secret := []byte("super-secret-key-at-least-32-bytes-long")

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(secret, "test-key-id", "HS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_HS384(t *testing.T) {
	t.Parallel()

	secret := []byte("super-secret-key-at-least-48-bytes-long-for-hs384")

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(secret, "test-key-id", "HS384"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_HS512(t *testing.T) {
	t.Parallel()

	secret := []byte("super-secret-key-at-least-64-bytes-long-for-hs512-algorithm-test")

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(secret, "test-key-id", "HS512"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_EdDSA(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "EdDSA"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_SignWithOptions(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	opts := SigningOptions{
		Algorithm:   "RS256",
		KeyID:       "custom-key-id",
		ExpiresIn:   time.Hour,
		NotBefore:   time.Now(),
		Issuer:      "custom-issuer",
		Audience:    []string{"custom-audience"},
		GenerateJTI: true,
	}

	token, err := signer.SignWithOptions(context.Background(), claims, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_WrongKeyType(t *testing.T) {
	t.Parallel()

	// Use ECDSA key with RSA algorithm
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(ecdsaKey, "test-key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestSigner_Sign_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "UNSUPPORTED"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestSigner_Sign_DefaultAlgorithm(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled: true,
	}

	// Create signer without specifying algorithm
	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", ""),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	claims := &Claims{
		Subject: "user123",
	}

	// Should use RS256 as default
	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigner_Sign_ClaimsFromConfig(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	config := &Config{
		Enabled:  true,
		Issuer:   "config-issuer",
		Audience: []string{"config-audience"},
	}

	signer, err := NewSigner(config,
		WithPrivateKey(privateKey, "test-key-id", "RS256"),
		WithSignerMetrics(newNoopSignerMetrics()),
	)
	require.NoError(t, err)

	// Claims without issuer/audience should use config values
	claims := &Claims{
		Subject: "user123",
	}

	token, err := signer.Sign(context.Background(), claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestSigningOptions_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	opts := SigningOptions{
		Algorithm:   "RS256",
		KeyID:       "key-123",
		ExpiresIn:   time.Hour,
		NotBefore:   now,
		Issuer:      "test-issuer",
		Audience:    []string{"aud1", "aud2"},
		GenerateJTI: true,
	}

	assert.Equal(t, "RS256", opts.Algorithm)
	assert.Equal(t, "key-123", opts.KeyID)
	assert.Equal(t, time.Hour, opts.ExpiresIn)
	assert.Equal(t, now, opts.NotBefore)
	assert.Equal(t, "test-issuer", opts.Issuer)
	assert.Equal(t, []string{"aud1", "aud2"}, opts.Audience)
	assert.True(t, opts.GenerateJTI)
}
