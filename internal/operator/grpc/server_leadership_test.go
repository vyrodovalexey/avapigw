// Package grpc — tests for the leadership-gated store readiness wait (C2):
// on a non-leader replica the controllers never run and the store stays
// empty, so the bounded seed-timeout fallback must never fire before leader
// election; gated RPCs park until elected (or until their context ends).
package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLeadershipTestServer returns a gated server with the given seed timeout
// and its (initially open) leadership signal channel.
func newLeadershipTestServer(t *testing.T, seedTimeout time.Duration) (*Server, chan struct{}) {
	t.Helper()
	_, srv := newGatedTestService(t, seedTimeout)
	elected := make(chan struct{})
	srv.SetLeadershipSignal(elected)
	return srv, elected
}

// TestWaitForStoreSeeded_NotElected_ParksPastSeedTimeout verifies that a
// non-leader parks well past the configured seed timeout: the timeout clock
// must not start before election, so the empty-store fallback cannot fire.
func TestWaitForStoreSeeded_NotElected_ParksPastSeedTimeout(t *testing.T) {
	srv, _ := newLeadershipTestServer(t, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	start := time.Now()
	seeded, reason := srv.WaitForStoreSeeded(ctx, 100*time.Millisecond)
	elapsed := time.Since(start)

	assert.False(t, seeded)
	assert.Equal(t, seedReasonAwaitingLeadership, reason)
	assert.GreaterOrEqual(t, elapsed, 300*time.Millisecond,
		"non-leader must park past the seed timeout (clock starts at election)")
}

// TestWaitForStoreSeeded_TimeoutClockStartsAtElection verifies that the
// bounded seed wait begins only once the replica is elected: with a 100ms
// timeout and election at +200ms, the timeout fallback fires at ~300ms.
func TestWaitForStoreSeeded_TimeoutClockStartsAtElection(t *testing.T) {
	srv, elected := newLeadershipTestServer(t, 100*time.Millisecond)

	go func() {
		time.Sleep(200 * time.Millisecond)
		close(elected)
	}()

	start := time.Now()
	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 100*time.Millisecond)
	elapsed := time.Since(start)

	assert.False(t, seeded)
	assert.Equal(t, seedReasonTimeout, reason)
	assert.GreaterOrEqual(t, elapsed, 300*time.Millisecond,
		"seed timeout must be measured from election, not from RPC arrival")
}

// TestWaitForStoreSeeded_ElectedUpfront_BoundedWaitUnchanged verifies that an
// already-elected replica (closed signal — also the leader-election-disabled
// case) keeps the pre-existing bounded-wait semantics.
func TestWaitForStoreSeeded_ElectedUpfront_BoundedWaitUnchanged(t *testing.T) {
	srv, elected := newLeadershipTestServer(t, time.Second)
	close(elected)

	start := time.Now()
	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 100*time.Millisecond)

	assert.False(t, seeded)
	assert.Equal(t, seedReasonTimeout, reason)
	// Generous upper bound (the op takes ~100ms): this only proves the wait
	// stayed BOUNDED instead of parking indefinitely, so wide headroom keeps
	// the assertion meaningful without wobbling on a saturated CI box.
	assert.Less(t, time.Since(start), 3*time.Second,
		"elected replica must keep the bounded wait")
}

// TestWaitForStoreSeeded_SeededWhileAwaitingLeadership verifies that a seed
// mark landing during the leadership wait releases the caller immediately.
func TestWaitForStoreSeeded_SeededWhileAwaitingLeadership(t *testing.T) {
	srv, _ := newLeadershipTestServer(t, time.Second)

	go func() {
		time.Sleep(50 * time.Millisecond)
		srv.MarkStoreSeeded()
	}()

	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 5*time.Second)
	assert.True(t, seeded)
	assert.Equal(t, seedReasonSeeded, reason)
}

// TestWaitForStoreSeeded_ElectedThenSeeded verifies the leader happy path:
// election followed by the seed mark releases the wait with reason seeded.
func TestWaitForStoreSeeded_ElectedThenSeeded(t *testing.T) {
	srv, elected := newLeadershipTestServer(t, 5*time.Second)

	go func() {
		time.Sleep(50 * time.Millisecond)
		close(elected)
		time.Sleep(50 * time.Millisecond)
		srv.MarkStoreSeeded()
	}()

	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 5*time.Second)
	assert.True(t, seeded)
	assert.Equal(t, seedReasonSeeded, reason)
	assert.True(t, srv.StoreSeeded())
}

// TestWaitForStoreSeeded_NilLeadershipSignal_GatingDisabled verifies that
// explicitly wiring a nil signal leaves leadership gating off (standalone
// servers keep the original bounded-wait behavior).
func TestWaitForStoreSeeded_NilLeadershipSignal_GatingDisabled(t *testing.T) {
	_, srv := newGatedTestService(t, time.Second)
	srv.SetLeadershipSignal(nil)

	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 50*time.Millisecond)
	assert.False(t, seeded)
	assert.Equal(t, seedReasonTimeout, reason)
}

// TestWaitForStoreSeeded_NonLeader_RevisionDoesNotOpenGate verifies that an
// advanced store revision cannot substitute for election: the revision
// fallback belongs to the post-election bounded wait only.
func TestWaitForStoreSeeded_NonLeader_RevisionDoesNotOpenGate(t *testing.T) {
	srv, _ := newLeadershipTestServer(t, 100*time.Millisecond)

	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "r1", "default", []byte(`{}`)))

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	seeded, reason := srv.WaitForStoreSeeded(ctx, 100*time.Millisecond)
	assert.False(t, seeded)
	assert.Equal(t, seedReasonAwaitingLeadership, reason,
		"revision advance must not bypass the leadership gate")
}

// TestWaitForStoreSeeded_AlreadySeeded_SkipsLeadershipWait verifies the
// fast path: a seeded store answers immediately even while un-elected.
func TestWaitForStoreSeeded_AlreadySeeded_SkipsLeadershipWait(t *testing.T) {
	srv, _ := newLeadershipTestServer(t, time.Second)
	srv.MarkStoreSeeded()

	start := time.Now()
	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 5*time.Second)

	assert.True(t, seeded)
	assert.Equal(t, seedReasonSeeded, reason)
	// Generous upper bound (the fast path returns immediately): proves the
	// call did not park on the (never-closed) leadership gate while staying
	// robust against CI scheduling stalls.
	assert.Less(t, time.Since(start), 3*time.Second)
}
