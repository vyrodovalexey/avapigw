// End-to-end coverage for the authentication.jwt.secret configuration
// path: a gateway config carrying a raw HMAC secret must produce an
// authenticator that accepts tokens signed with that secret and rejects
// everything else.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// signHS256Token hand-crafts an HS256 JWT without a kid header, matching
// tokens issued against a single shared secret.
func signHS256Token(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// newHMACAuthMiddleware builds the HTTP auth middleware from a gateway
// authentication config with an HS256 shared secret.
func newHMACAuthMiddleware(t *testing.T, secret string) func(http.Handler) http.Handler {
	t.Helper()

	gatewayCfg := &config.AuthenticationConfig{
		Enabled: true,
		JWT: &config.JWTAuthConfig{
			Enabled:   true,
			Secret:    secret,
			Algorithm: "HS256",
		},
	}

	authCfg, err := ConvertFromGatewayConfig(gatewayCfg)
	require.NoError(t, err)
	require.NotNil(t, authCfg)

	authenticator, err := NewAuthenticator(authCfg,
		WithAuthenticatorLogger(observability.NopLogger()),
	)
	require.NoError(t, err,
		"HS256 with a raw shared secret must construct an authenticator")

	return authenticator.HTTPMiddleware()
}

func TestHMACSecretFlow_ValidTokenAuthenticates(t *testing.T) {
	t.Parallel()

	const secret = "gateway-config-hmac-secret"
	mw := newHMACAuthMiddleware(t, secret)

	var seenSubject string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if identity, ok := IdentityFromContext(r.Context()); ok && identity != nil {
			seenSubject = identity.Subject
		}
		w.WriteHeader(http.StatusOK)
	}))

	token := signHS256Token(t, secret, map[string]any{
		"sub": "hmac-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "hmac-user", seenSubject)
}

func TestHMACSecretFlow_WrongSecretRejected(t *testing.T) {
	t.Parallel()

	mw := newHMACAuthMiddleware(t, "the-real-secret")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	forged := signHS256Token(t, "attacker-secret", map[string]any{
		"sub": "mallory",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHMACSecretFlow_MissingTokenRejected(t *testing.T) {
	t.Parallel()

	mw := newHMACAuthMiddleware(t, "the-real-secret")

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/data", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
