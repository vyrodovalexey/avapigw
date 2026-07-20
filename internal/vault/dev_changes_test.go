package vault

// Tests for T3.C1 (review M6) and T3.C2 (review M7):
//   - authenticateWithToken must honor the caller's context (the startup
//     auth timeout bounds the token lookup);
//   - KV List must retry transient failures with exponential backoff like
//     its Read/Write/Delete siblings.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestAuthenticateWithToken_HonorsContextCancellation verifies the token
// TTL lookup is bounded by the caller's context: a canceled context must
// abort the lookup instead of hanging on the Vault API default timeout.
func TestAuthenticateWithToken_HonorsContextCancellation(t *testing.T) {
	t.Parallel()

	requestStarted := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-release // hang until the test finishes
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	defer close(release)

	client, err := New(&Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-requestStarted
		cancel()
	}()

	start := time.Now()
	err = vc.authenticateWithToken(ctx)
	elapsed := time.Since(start)

	require.Error(t, err, "canceled context must abort the token lookup")
	assert.Less(t, elapsed, 10*time.Second,
		"lookup must abort on ctx cancellation, not wait for the API default timeout")
}

// TestAuthenticateWithToken_AlreadyCanceledContext verifies a pre-canceled
// context fails fast without any network wait.
func TestAuthenticateWithToken_AlreadyCanceledContext(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(&Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	vc := client.(*vaultClient)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = vc.authenticateWithToken(ctx)
	require.Error(t, err)
}

// TestKVList_RetriesTransientErrors verifies List routes through
// executeWithRetry: transient 5xx responses are retried with backoff and
// the call eventually succeeds.
func TestKVList_RetriesTransientErrors(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) <= 2 {
			// Transient server error: retryable.
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"keys":["one","two"]}}`))
	}))
	defer server.Close()

	client, err := New(&Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Retry: &RetryConfig{
			MaxRetries:  3,
			BackoffBase: time.Millisecond,
			BackoffMax:  5 * time.Millisecond,
		},
	}, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	keys, err := client.KV().List(context.Background(), "secret", "apps")
	require.NoError(t, err, "transient errors must be retried")
	assert.Equal(t, []string{"one", "two"}, keys)
	assert.GreaterOrEqual(t, attempts.Load(), int32(3),
		"expected at least 3 attempts (2 transient failures + success)")
}

// TestKVList_ExhaustedRetriesFail verifies List surfaces the error after
// the retry budget is exhausted.
func TestKVList_ExhaustedRetriesFail(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client, err := New(&Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
		Retry: &RetryConfig{
			MaxRetries:  2,
			BackoffBase: time.Millisecond,
			BackoffMax:  5 * time.Millisecond,
		},
	}, observability.NopLogger())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.KV().List(context.Background(), "secret", "apps")
	require.Error(t, err)
	assert.Greater(t, attempts.Load(), int32(1), "expected retries before failure")
}
