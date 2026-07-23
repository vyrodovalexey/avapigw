package auth

// Tests for T3.D1 (review M11/L9): IdP discovery/token responses are read
// through bounded readers, and error bodies embedded in provider errors are
// truncated.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// oversizeHandler streams more than maxIDPResponseBytes.
func oversizeHandler() http.HandlerFunc {
	chunk := strings.Repeat("x", 64*1024)
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for written := 0; written < maxIDPResponseBytes+len(chunk); written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}
}

func newOIDCTestProvider(t *testing.T, issuerURL string) *JWTProvider {
	t.Helper()

	provider, err := NewJWTProvider("test", &config.BackendJWTAuthConfig{
		Enabled:     true,
		TokenSource: TokenSourceOIDC,
		OIDC: &config.BackendOIDCConfig{
			IssuerURL:    issuerURL,
			ClientID:     "client",
			ClientSecret: "secret",
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close() })
	return provider
}

// TestDiscoverTokenEndpoint_OversizeRejected verifies oversize discovery
// documents are rejected.
func TestDiscoverTokenEndpoint_OversizeRejected(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(oversizeHandler())
	defer server.Close()

	provider := newOIDCTestProvider(t, server.URL)

	_, err := provider.discoverTokenEndpoint(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read discovery document")
}

// TestRequestOIDCToken_OversizeRejected verifies oversize token responses
// are rejected.
func TestRequestOIDCToken_OversizeRejected(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(oversizeHandler())
	defer server.Close()

	provider := newOIDCTestProvider(t, server.URL)

	_, _, err := provider.requestOIDCToken(context.Background(), server.URL, "secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read token response")
}

// TestRequestOIDCToken_ErrorBodyTruncated verifies the IdP error body
// embedded in the provider error string is capped (L9).
func TestRequestOIDCToken_ErrorBodyTruncated(t *testing.T) {
	t.Parallel()

	hugeErrorBody := strings.Repeat("e", 64*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(hugeErrorBody))
	}))
	defer server.Close()

	provider := newOIDCTestProvider(t, server.URL)

	_, _, err := provider.requestOIDCToken(context.Background(), server.URL, "secret")
	require.Error(t, err)
	assert.Less(t, len(err.Error()), maxIDPErrorBodyBytes+512,
		"IdP error body embedded in the provider error must be truncated")
	assert.Contains(t, err.Error(), "...(truncated)")
}
