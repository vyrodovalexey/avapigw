package external

// Tests for T3.D1 (review M11): OPA decision responses are read through a
// bounded reader — oversize bodies are rejected instead of inflating
// gateway memory.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/httputil"
)

// TestOPAClient_Authorize_OversizeResponseRejected verifies an OPA body
// exceeding the read limit fails the authorization with a clear error.
func TestOPAClient_Authorize_OversizeResponseRejected(t *testing.T) {
	t.Parallel()

	chunk := strings.Repeat("x", 64*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		// Stream > maxOPAResponseBytes.
		for written := 0; written < maxOPAResponseBytes+len(chunk); written += len(chunk) {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	client, err := NewOPAClient(&OPAConfig{URL: server.URL, Policy: "authz/allow"}, 30*time.Second,
		WithOPARetryConfig(RetryConfig{
			MaxRetries:        0,
			InitialBackoff:    time.Millisecond,
			MaxBackoff:        time.Millisecond,
			BackoffMultiplier: 1,
		}),
	)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Authorize(context.Background(), &OPAInput{
		Resource: "/api", Action: "GET",
	})
	require.Error(t, err, "oversize OPA response must be rejected")
	assert.ErrorIs(t, err, httputil.ErrResponseTooLarge)
}

// TestOPAClient_Authorize_NormalResponseUnaffected pins the happy path:
// regular-size responses flow through the bounded reader untouched.
func TestOPAClient_Authorize_NormalResponseUnaffected(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(HeaderContentType, ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true, "decision_id": "d-1"}`))
	}))
	defer server.Close()

	client, err := NewOPAClient(&OPAConfig{URL: server.URL}, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	result, err := client.Authorize(context.Background(), &OPAInput{Resource: "/api", Action: "GET"})
	require.NoError(t, err)
	assert.True(t, result.Allow)
}
