package jwt

// Tests for T3.D2 (review M3): JWKSKeySet.Close must not hang when Start
// was never called (or failed) and double-Close must not panic; and for
// T3.D1 (review M11): oversize JWKS responses are rejected.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/httputil"
)

// closeWithTimeout runs Close in a goroutine and fails the test if it does
// not return within the deadline (regression net for the pre-fix hang).
func closeWithTimeout(t *testing.T, ks *JWKSKeySet, timeout time.Duration) {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- ks.Close() }()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(timeout):
		t.Fatal("Close() did not return in time (pre-fix hang regression)")
	}
}

func TestJWKSKeySet_CloseWithoutStart_ReturnsImmediately(t *testing.T) {
	t.Parallel()

	ks, err := NewJWKSKeySet("https://idp.example.com/jwks")
	require.NoError(t, err)

	closeWithTimeout(t, ks, 2*time.Second)
}

func TestJWKSKeySet_DoubleClose_NoPanic(t *testing.T) {
	t.Parallel()

	ks, err := NewJWKSKeySet("https://idp.example.com/jwks")
	require.NoError(t, err)

	closeWithTimeout(t, ks, 2*time.Second)
	// Second close must be a safe no-op (pre-fix: close of closed channel).
	closeWithTimeout(t, ks, 2*time.Second)
}

func TestJWKSKeySet_CloseAfterFailedStart_ReturnsImmediately(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL,
		WithRetryConfig(RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond,
			MaxInterval: time.Millisecond, Multiplier: 1}),
	)
	require.NoError(t, err)

	require.Error(t, ks.Start(context.Background()), "initial fetch must fail")

	// Start failed → no refresh loop is running → Close must not block on
	// stoppedCh.
	closeWithTimeout(t, ks, 2*time.Second)
}

func TestJWKSKeySet_StartCloseLifecycle(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL)
	require.NoError(t, err)

	require.NoError(t, ks.Start(context.Background()))
	// Idempotent second Start must not launch a duplicate refresh loop.
	require.NoError(t, ks.Start(context.Background()))

	closeWithTimeout(t, ks, 2*time.Second)

	// Start after Close is rejected.
	assert.Error(t, ks.Start(context.Background()))
}

// TestJWKSKeySet_ConcurrentClose_Race exercises concurrent Close callers
// (run with -race) — exactly one goroutine may wait for the loop, the rest
// must return immediately without panicking.
func TestJWKSKeySet_ConcurrentClose_Race(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL)
	require.NoError(t, err)
	require.NoError(t, ks.Start(context.Background()))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, ks.Close())
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Close() calls did not all return")
	}
}

// TestJWKSKeySet_OversizeResponseRejected covers the T3.D1 bound: a JWKS
// body over the read limit is rejected as a fetch error.
func TestJWKSKeySet_OversizeResponseRejected(t *testing.T) {
	t.Parallel()

	huge := `{"keys":[` + strings.Repeat(`{"kty":"oct","k":"`+strings.Repeat("A", 4096)+`"},`, 3000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Stream > maxJWKSResponseBytes of data.
		for written := 0; written < maxJWKSResponseBytes+4096; written += len(huge) {
			if _, err := w.Write([]byte(huge)); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	ks, err := NewJWKSKeySet(server.URL,
		WithRetryConfig(RetryConfig{MaxAttempts: 1, InitialInterval: time.Millisecond,
			MaxInterval: time.Millisecond, Multiplier: 1}),
	)
	require.NoError(t, err)
	defer func() { _ = ks.Close() }()

	fetchErr := ks.Start(context.Background())
	require.Error(t, fetchErr, "oversize JWKS response must be rejected")
	assert.ErrorIs(t, fetchErr, httputil.ErrResponseTooLarge)
}
