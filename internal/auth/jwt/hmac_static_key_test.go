// HMAC static key tests: raw shared secrets configured via
// authentication.jwt.secret must be usable for HS256/HS384/HS512
// validation, while asymmetric algorithms keep requiring JWK/PEM material.
package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// signHMACToken hand-crafts a JWT signed with the given HMAC hash and
// secret. kid is omitted from the header when empty, matching the common
// shape of HMAC tokens issued with a single shared secret.
func signHMACToken(
	t *testing.T, alg string, hashFunc func() hash.Hash, secret, kid string, claims map[string]any,
) string {
	t.Helper()

	header := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	mac := hmac.New(hashFunc, []byte(secret))
	mac.Write([]byte(signingInput))

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func futureClaims() map[string]any {
	return map[string]any{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

func TestParseStaticKey_HMACRawSecret(t *testing.T) {
	t.Parallel()

	for _, alg := range []string{AlgHS256, AlgHS384, AlgHS512} {
		key, err := parseStaticKey(StaticKey{
			KeyID:     "default",
			Algorithm: alg,
			Key:       "my-raw-shared-secret",
		})
		require.NoError(t, err, "raw secret must be accepted for %s", alg)

		secret, ok := key.([]byte)
		require.True(t, ok, "HMAC key must be a byte slice for %s", alg)
		assert.Equal(t, []byte("my-raw-shared-secret"), secret)
	}
}

func TestParseStaticKey_HMACJWKOctKey(t *testing.T) {
	t.Parallel()

	rawSecret := []byte("oct-jwk-secret-material")
	jwkKey, err := jwk.FromRaw(rawSecret)
	require.NoError(t, err)
	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	key, err := parseStaticKey(StaticKey{
		KeyID:     "oct-key",
		Algorithm: AlgHS256,
		Key:       string(jwkJSON),
	})
	require.NoError(t, err)

	secret, ok := key.([]byte)
	require.True(t, ok)
	assert.Equal(t, rawSecret, secret)
}

func TestParseStaticKey_HMACAsymmetricJWKRejected(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwkKey, err := jwk.FromRaw(rsaKey.Public())
	require.NoError(t, err)
	jwkJSON, err := json.Marshal(jwkKey)
	require.NoError(t, err)

	_, err = parseStaticKey(StaticKey{
		KeyID:     "asym",
		Algorithm: AlgHS256,
		Key:       string(jwkJSON),
	})
	require.Error(t, err, "asymmetric JWK must be rejected for HMAC algorithms")
	assert.Contains(t, err.Error(), "symmetric")
}

func TestParseStaticKey_NonHMACRawSecretRejected(t *testing.T) {
	t.Parallel()

	_, err := parseStaticKey(StaticKey{
		KeyID:     "default",
		Algorithm: AlgRS256,
		Key:       "raw-secret-is-not-a-public-key",
	})
	require.Error(t, err, "raw secrets must be rejected for asymmetric algorithms")
	assert.Contains(t, err.Error(), "RS256 requires a JWK or PEM key")
}

func TestParseHMACKey_EmptySecretRejected(t *testing.T) {
	t.Parallel()

	// jwk.FromRaw rejects empty symmetric key material; the error must be
	// wrapped with the algorithm for actionable configuration diagnostics.
	_, err := parseHMACKey(StaticKey{KeyID: "empty", Algorithm: AlgHS256}, []byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to construct symmetric key for HS256")
}

func TestStaticKeySet_EmptyKid_SingleKeyFallback(t *testing.T) {
	t.Parallel()

	ks, err := NewStaticKeySet([]StaticKey{
		{KeyID: "default", Algorithm: AlgHS256, Key: "shared-secret"},
	}, observability.NopLogger())
	require.NoError(t, err)

	// Empty kid with exactly one key resolves to that key.
	key, err := ks.GetKey(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, []byte("shared-secret"), key)

	// Explicit unknown kid still fails.
	_, err = ks.GetKey(context.Background(), "other")
	require.Error(t, err)
}

func TestStaticKeySet_EmptyKid_MultipleKeysAmbiguous(t *testing.T) {
	t.Parallel()

	ks, err := NewStaticKeySet([]StaticKey{
		{KeyID: "k1", Algorithm: AlgHS256, Key: "secret-1"},
		{KeyID: "k2", Algorithm: AlgHS256, Key: "secret-2"},
	}, observability.NopLogger())
	require.NoError(t, err)

	_, err = ks.GetKey(context.Background(), "")
	require.Error(t, err, "empty kid with multiple keys is ambiguous and must fail")
}

func TestValidateKeyAlgorithm_HMACRequiresSymmetricKey(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Asymmetric key material must never be usable as an HMAC secret
	// (algorithm-confusion defense).
	err = validateKeyAlgorithm(rsaKey.Public(), AlgHS256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symmetric")

	// Symmetric byte-slice keys pass.
	assert.NoError(t, validateKeyAlgorithm([]byte("secret"), AlgHS256))
}

// TestValidator_HMACSecret_EndToEnd validates the full acceptance flow:
// a config with an HS256 static secret authenticates a token signed with
// that secret (without a kid header) and rejects a token signed with a
// different secret.
func TestValidator_HMACSecret_EndToEnd(t *testing.T) {
	t.Parallel()

	const secret = "route-level-hmac-secret"

	cfg := &Config{
		Enabled:    true,
		Algorithms: []string{AlgHS256},
		StaticKeys: []StaticKey{
			{KeyID: "default", Algorithm: AlgHS256, Key: secret},
		},
	}

	v, err := NewValidator(cfg, WithValidatorLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Token signed with the configured secret validates.
	token := signHMACToken(t, AlgHS256, sha256.New, secret, "", futureClaims())
	claims, err := v.Validate(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "user-1", claims.Subject)

	// Token signed with the wrong secret is rejected.
	forged := signHMACToken(t, AlgHS256, sha256.New, "wrong-secret", "", futureClaims())
	_, err = v.Validate(context.Background(), forged)
	require.Error(t, err)

	// Token with an explicit matching kid also validates.
	withKid := signHMACToken(t, AlgHS256, sha256.New, secret, "default", futureClaims())
	_, err = v.Validate(context.Background(), withKid)
	require.NoError(t, err)
}

// TestValidator_HMACSecret_HS384And512 covers the remaining HMAC variants.
func TestValidator_HMACSecret_HS384And512(t *testing.T) {
	t.Parallel()

	cases := []struct {
		alg      string
		hashFunc func() hash.Hash
	}{
		{AlgHS384, sha512.New384},
		{AlgHS512, sha512.New},
	}

	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			t.Parallel()

			const secret = "another-shared-secret"
			cfg := &Config{
				Enabled:    true,
				Algorithms: []string{tc.alg},
				StaticKeys: []StaticKey{
					{KeyID: "default", Algorithm: tc.alg, Key: secret},
				},
			}

			v, err := NewValidator(cfg, WithValidatorLogger(observability.NopLogger()))
			require.NoError(t, err)

			token := signHMACToken(t, tc.alg, tc.hashFunc, secret, "", futureClaims())
			_, err = v.Validate(context.Background(), token)
			require.NoError(t, err)
		})
	}
}
