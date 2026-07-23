package oidc

// Tests for T3.D1 (review M11): OIDC discovery documents are read through a
// bounded reader — oversize bodies are rejected.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/httputil"
)

// TestDiscoveryClient_OversizeResponseRejected verifies a discovery body
// exceeding the read limit fails with a clear error.
func TestDiscoveryClient_OversizeResponseRejected(t *testing.T) {
	t.Parallel()

	chunk := strings.Repeat("x", 64*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for written := 0; written < maxDiscoveryResponseBytes+len(chunk); written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	client, err := NewDiscoveryClient(&Config{
		Enabled: true,
		Providers: []ProviderConfig{{
			Name:         "big",
			Issuer:       "https://issuer.example.com",
			DiscoveryURL: server.URL,
			ClientID:     "client-id",
		}},
	})
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.GetDiscovery(context.Background(), "big")
	require.Error(t, err, "oversize discovery document must be rejected")
	assert.ErrorIs(t, err, httputil.ErrResponseTooLarge)
}
