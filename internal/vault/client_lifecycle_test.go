package vault

// Lifecycle/regression tests for WP6 (channel-replacement races).
//
// Authenticate replaces stopCh/stoppedCh per token-renewal-goroutine
// generation. These tests verify the generation capture pattern: a goroutine
// only ever observes and closes ITS OWN generation's channels, so a stranded
// goroutine (left behind by a timed-out wait) exits correctly on its own
// closed stop channel and never touches a newer generation's channels.
//
// All tests are expected to run under -race (the race detector is the primary
// acceptance signal for the field-read races that were fixed).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// waitClosedTimeout is the bounded wait used when asserting a channel closes.
const waitClosedTimeout = 3 * time.Second

// shortCloseTimeout is injected into vc.closeTimeout (test seam, mirrors the
// backend/health stopTimeout pattern) by tests that deliberately wait out the
// bounded goroutine-shutdown timeout, so they don't pay the real 5s
// DefaultCloseTimeout. Lower-bound elapsed assertions stay deterministic:
// time.After never fires early.
const shortCloseTimeout = 250 * time.Millisecond

// newTokenLookupServer returns a mock Vault server answering
// /v1/auth/token/lookup-self with a long TTL so Authenticate succeeds and the
// renewal loop starts but never ticks during the test.
func newTokenLookupServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data": {"ttl": 3600}}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

// newTestVaultClient creates an enabled vault client pointed at the given address.
func newTestVaultClient(t *testing.T, address string) *vaultClient {
	t.Helper()
	client, err := New(&Config{
		Enabled:    true,
		Address:    address,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}, observability.NopLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	vc, ok := client.(*vaultClient)
	if !ok {
		t.Fatal("client should be *vaultClient")
	}
	return vc
}

// currentRenewalChannels reads the current generation's channels under the lock.
func currentRenewalChannels(vc *vaultClient) (chan struct{}, chan struct{}) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return vc.stopCh, vc.stoppedCh
}

// assertClosed fails the test if ch does not close within waitClosedTimeout.
func assertClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		// Channel closed as expected.
	case <-time.After(waitClosedTimeout):
		t.Fatalf("%s was not closed within %v", what, waitClosedTimeout)
	}
}

// assertNotClosed fails the test if ch is already closed.
func assertNotClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s must not be closed", what)
	default:
		// Channel still open as expected.
	}
}

// TestVaultClient_Authenticate_ReauthWhileRenewalLoopRuns verifies that a
// second Authenticate stops the previous renewal goroutine generation and
// starts a new one on fresh channels, with no data race on the channel fields
// (run under -race) and no stranded goroutine.
func TestVaultClient_Authenticate_ReauthWhileRenewalLoopRuns(t *testing.T) {
	t.Parallel()

	server := newTokenLookupServer(t)
	vc := newTestVaultClient(t, server.URL)

	if err := vc.Authenticate(context.Background()); err != nil {
		t.Fatalf("first Authenticate() error = %v", err)
	}
	gen1Stop, gen1Stopped := currentRenewalChannels(vc)

	// Re-authenticate while the first generation's renewal loop is running.
	if err := vc.Authenticate(context.Background()); err != nil {
		t.Fatalf("second Authenticate() error = %v", err)
	}

	// The first generation must have exited by signaling ITS OWN stoppedCh.
	assertClosed(t, gen1Stopped, "generation-1 stoppedCh")

	gen2Stop, gen2Stopped := currentRenewalChannels(vc)
	if gen1Stop == gen2Stop || gen1Stopped == gen2Stopped {
		t.Fatal("second Authenticate() must install fresh generation channels")
	}
	assertNotClosed(t, gen2Stopped, "generation-2 stoppedCh")

	// Close stops the second generation cleanly.
	if err := vc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertClosed(t, gen2Stopped, "generation-2 stoppedCh after Close")
}

// TestVaultClient_Authenticate_TimeoutPath_StrandedGenerationExits forces the
// wait-timeout branch in Authenticate (the previous goroutine appears stuck)
// and verifies that:
//   - Authenticate proceeds after the bounded close timeout and starts a
//     fresh generation on new channels;
//   - the replaced goroutine still exits on its own generation's stop channel
//     and closes its own stoppedCh (never the new generation's);
//   - shutdown afterwards is clean.
func TestVaultClient_Authenticate_TimeoutPath_StrandedGenerationExits(t *testing.T) {
	t.Parallel()

	server := newTokenLookupServer(t)
	vc := newTestVaultClient(t, server.URL)
	vc.closeTimeout = shortCloseTimeout // Seam: avoid the real 5s wait.

	if err := vc.Authenticate(context.Background()); err != nil {
		t.Fatalf("first Authenticate() error = %v", err)
	}
	_, gen1Stopped := currentRenewalChannels(vc)

	// Simulate a stuck previous goroutine: swap the stoppedCh field with a
	// dummy that never closes. The real generation-1 goroutine still holds
	// its own captured stoppedCh (generation capture pattern).
	vc.mu.Lock()
	vc.stoppedCh = make(chan struct{})
	vc.mu.Unlock()

	start := time.Now()
	if err := vc.Authenticate(context.Background()); err != nil {
		t.Fatalf("second Authenticate() error = %v", err)
	}
	elapsed := time.Since(start)

	// The wait must have hit the bounded-timeout branch (time.After cannot
	// fire before its duration, so the lower bound is deterministic).
	if elapsed < shortCloseTimeout {
		t.Errorf("Authenticate() returned after %v, expected to wait ~%v for the stuck goroutine",
			elapsed, shortCloseTimeout)
	}

	// The "stuck" goroutine actually received the stop signal for its own
	// generation and must have closed its own captured stoppedCh.
	assertClosed(t, gen1Stopped, "generation-1 stoppedCh")

	// The new generation must be running on fresh channels.
	_, gen2Stopped := currentRenewalChannels(vc)
	assertNotClosed(t, gen2Stopped, "generation-2 stoppedCh")

	if err := vc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertClosed(t, gen2Stopped, "generation-2 stoppedCh after Close")
}

// TestVaultClient_CloseDuringAuthenticateWait_NoDoubleClose covers the
// Close-vs-Authenticate interleaving: Close runs while Authenticate is
// waiting for a (seemingly stuck) previous generation. There must be no
// double close of any channel and Authenticate must observe the closed
// client instead of spawning a new renewal goroutine (TOCTOU re-check).
func TestVaultClient_CloseDuringAuthenticateWait_NoDoubleClose(t *testing.T) {
	t.Parallel()

	server := newTokenLookupServer(t)
	vc := newTestVaultClient(t, server.URL)
	// Seam: shrink the bounded wait, but keep it wide enough (1s) that Close
	// reliably runs while Authenticate is still parked in its wait window.
	vc.closeTimeout = time.Second

	if err := vc.Authenticate(context.Background()); err != nil {
		t.Fatalf("first Authenticate() error = %v", err)
	}
	_, gen1Stopped := currentRenewalChannels(vc)

	// Make the second Authenticate wait the full timeout.
	vc.mu.Lock()
	vc.stoppedCh = make(chan struct{})
	vc.mu.Unlock()

	authErrCh := make(chan error, 1)
	go func() {
		authErrCh <- vc.Authenticate(context.Background())
	}()

	// Let Authenticate reach its bounded wait, then close the client.
	assertClosed(t, gen1Stopped, "generation-1 stoppedCh")
	closeStart := time.Now()
	if err := vc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// The renewal goroutine was already signaled by Authenticate, so Close
	// must not wait the full bounded timeout on it.
	if closeElapsed := time.Since(closeStart); closeElapsed >= vc.closeTimeout {
		t.Errorf("Close() took %v, expected to return without waiting for renewal", closeElapsed)
	}

	select {
	case err := <-authErrCh:
		if !errors.Is(err, ErrClientClosed) {
			t.Errorf("Authenticate() during Close error = %v, want ErrClientClosed", err)
		}
	case <-time.After(vc.closeTimeout + waitClosedTimeout):
		t.Fatal("Authenticate() did not return after Close()")
	}
}

// TestVaultClient_TokenRenewalLoop_GenerationCapture runs two renewal-loop
// generations side by side (simulating a stranded generation coexisting with
// its replacement) and verifies full channel isolation between generations.
func TestVaultClient_TokenRenewalLoop_GenerationCapture(t *testing.T) {
	t.Parallel()

	vc := newTestVaultClient(t, "http://localhost:8200")
	// Ensure the loop keeps running (renewal interval > 0) but never ticks
	// during the test (interval is minutes).
	vc.tokenTTL.Store(3600)

	gen1Stop := make(chan struct{})
	gen1Stopped := make(chan struct{})
	gen2Stop := make(chan struct{})
	gen2Stopped := make(chan struct{})

	go vc.tokenRenewalLoop(gen1Stop, gen1Stopped)
	go vc.tokenRenewalLoop(gen2Stop, gen2Stopped)

	// Stopping generation 1 must terminate ONLY generation 1.
	close(gen1Stop)
	assertClosed(t, gen1Stopped, "generation-1 stoppedCh")
	assertNotClosed(t, gen2Stopped, "generation-2 stoppedCh")

	// Generation 2 exits on its own channel.
	close(gen2Stop)
	assertClosed(t, gen2Stopped, "generation-2 stoppedCh")
}

// TestVaultClient_Close_WithoutRenewalLoop_ReturnsPromptly locks in the
// behavior that Close does not wait DefaultCloseTimeout when no renewal
// goroutine was ever started (Authenticate never called).
func TestVaultClient_Close_WithoutRenewalLoop_ReturnsPromptly(t *testing.T) {
	t.Parallel()

	vc := newTestVaultClient(t, "http://localhost:8200")

	start := time.Now()
	if err := vc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Errorf("Close() without renewal loop took %v, expected prompt return", elapsed)
	}
}

// TestVaultClient_Authenticate_ClosedDuringAuthCall covers the closed
// re-check at the top of the renewal-goroutine section: Close() runs while
// the authentication HTTP call is still in flight, so Authenticate must
// return ErrClientClosed instead of spawning a renewal goroutine on a closed
// client.
func TestVaultClient_Authenticate_ClosedDuringAuthCall(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	requestStarted := make(chan struct{})
	var startedOnce sync.Once

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			startedOnce.Do(func() { close(requestStarted) })
			<-release // Hold the auth call until Close() completed.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data": {"ttl": 3600}}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	vc := newTestVaultClient(t, server.URL)

	authErrCh := make(chan error, 1)
	go func() {
		authErrCh <- vc.Authenticate(context.Background())
	}()

	assertClosed(t, requestStarted, "auth request start signal")
	if err := vc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	close(release)

	select {
	case err := <-authErrCh:
		if !errors.Is(err, ErrClientClosed) {
			t.Errorf("Authenticate() error = %v, want ErrClientClosed", err)
		}
	case <-time.After(waitClosedTimeout):
		t.Fatal("Authenticate() did not return after Close()")
	}
}

// TestVaultClient_Close_TimeoutWaitingForStuckRenewal covers Close's bounded
// wait: when the renewal goroutine does not signal its stoppedCh within the
// close timeout, Close must log a warning and return instead of hanging
// forever.
func TestVaultClient_Close_TimeoutWaitingForStuckRenewal(t *testing.T) {
	t.Parallel()

	vc := newTestVaultClient(t, "http://localhost:8200")
	vc.closeTimeout = shortCloseTimeout // Seam: avoid the real 5s wait.

	// Simulate a stuck renewal goroutine: mark the generation as running
	// without any goroutine that would ever close stoppedCh.
	vc.mu.Lock()
	vc.renewalStarted = true
	vc.mu.Unlock()

	start := time.Now()
	if err := vc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed < shortCloseTimeout {
		t.Errorf("Close() returned after %v, expected to wait ~%v for the stuck goroutine",
			elapsed, shortCloseTimeout)
	}
}
