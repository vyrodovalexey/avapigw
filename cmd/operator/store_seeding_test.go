// Package main contains unit tests for the gRPC configuration store seeding
// logic that gates initial snapshots until the controllers' first reconcile
// pass has populated the store (BUG: empty FULL_SYNC on gateway connect after
// operator restart).
package main

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"
)

// fakeCacheSyncWaiter implements cacheSyncWaiter for tests.
type fakeCacheSyncWaiter struct {
	result bool
	delay  time.Duration
}

func (f *fakeCacheSyncWaiter) WaitForCacheSync(ctx context.Context) bool {
	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(f.delay):
		}
	}
	return f.result
}

// newSeedTestServer creates a gRPC server with an isolated metrics registry
// and the store readiness gate armed, mirroring production wiring.
func newSeedTestServer(t *testing.T) *operatorgrpc.Server {
	t.Helper()
	server, err := operatorgrpc.NewServerWithRegistry(
		&operatorgrpc.ServerConfig{Port: 0},
		prometheus.NewRegistry(),
	)
	require.NoError(t, err)
	server.EnableStoreReadinessGate()
	return server
}

// electedNow returns a closed channel simulating a replica that already won
// leader election (or runs with leader election disabled, where
// controller-runtime closes Elected() at manager start).
func electedNow() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func TestCountExpectedConfigResources(t *testing.T) {
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&avapigwv1alpha1.APIRoute{ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default"}},
			&avapigwv1alpha1.APIRoute{ObjectMeta: metav1.ObjectMeta{Name: "r2", Namespace: "default"}},
			&avapigwv1alpha1.Backend{ObjectMeta: metav1.ObjectMeta{Name: "b1", Namespace: "default"}},
			&avapigwv1alpha1.GRPCRoute{ObjectMeta: metav1.ObjectMeta{Name: "g1", Namespace: "default"}},
			&avapigwv1alpha1.GRPCBackend{ObjectMeta: metav1.ObjectMeta{Name: "gb1", Namespace: "default"}},
			&avapigwv1alpha1.GraphQLRoute{ObjectMeta: metav1.ObjectMeta{Name: "q1", Namespace: "default"}},
			&avapigwv1alpha1.GraphQLBackend{ObjectMeta: metav1.ObjectMeta{Name: "qb1", Namespace: "default"}},
		).
		Build()

	total := countExpectedConfigResources(context.Background(), fakeClient)
	assert.Equal(t, 7, total)
}

func TestCountExpectedConfigResources_Empty(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	total := countExpectedConfigResources(context.Background(), fakeClient)
	assert.Equal(t, 0, total)
}

func TestWaitForStoreCount_ZeroExpected(t *testing.T) {
	server := newSeedTestServer(t)

	// Zero expected resources → immediately complete (legitimately empty cluster).
	assert.True(t, waitForStoreCount(context.Background(), server, 0))
}

func TestWaitForStoreCount_ReachedAfterApplies(t *testing.T) {
	server := newSeedTestServer(t)

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = server.ApplyAPIRoute(context.Background(), "r1", "default", []byte(`{}`))
		_ = server.ApplyBackend(context.Background(), "b1", "default", []byte(`{}`))
	}()

	assert.True(t, waitForStoreCount(context.Background(), server, 2))
	assert.Equal(t, 2, server.StoreResourceCount())
}

func TestWaitForStoreCount_ContextCanceled(t *testing.T) {
	server := newSeedTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	assert.False(t, waitForStoreCount(ctx, server, 5))
}

func TestSeedGRPCStore_MarksSeededAfterCacheSyncAndReconcile(t *testing.T) {
	server := newSeedTestServer(t)
	assert.False(t, server.StoreSeeded())

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&avapigwv1alpha1.APIRoute{ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default"}},
		).
		Build()

	// Simulate the reconciler applying the resource shortly after cache sync.
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = server.ApplyAPIRoute(context.Background(), "r1", "default", []byte(`{}`))
	}()

	seedGRPCStore(context.Background(), server, electedNow(), &fakeCacheSyncWaiter{result: true}, fakeClient)

	assert.True(t, server.StoreSeeded(), "store must be marked seeded after reconcile pass")
	assert.Equal(t, 1, server.StoreResourceCount())
}

func TestSeedGRPCStore_EmptyCluster_MarksSeededImmediately(t *testing.T) {
	server := newSeedTestServer(t)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	start := time.Now()
	seedGRPCStore(context.Background(), server, electedNow(), &fakeCacheSyncWaiter{result: true}, fakeClient)

	assert.True(t, server.StoreSeeded(),
		"legitimately empty cluster must be marked seeded without waiting")
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestSeedGRPCStore_CacheSyncCanceled_SkipsSeedMark(t *testing.T) {
	server := newSeedTestServer(t)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	seedGRPCStore(context.Background(), server, electedNow(), &fakeCacheSyncWaiter{result: false}, fakeClient)

	assert.False(t, server.StoreSeeded(),
		"seed mark must be skipped when cache sync is canceled (shutdown path)")
}

func TestStartStoreSeedingBackground_NilServer(t *testing.T) {
	// A nil gRPC server (gRPC disabled) must be a no-op and must not panic.
	// The manager argument is not touched when the server is nil.
	assert.NotPanics(t, func() {
		startStoreSeedingBackground(context.Background(), nil, nil)
	})
}

// ============================================================================
// Leadership gating (C2): non-leader replicas must never open the seed gate
// with an empty store — controllers only run on the elected leader.
// ============================================================================

// runSeedGRPCStore runs seedGRPCStore in a goroutine and returns its
// completion channel so tests can assert parking and unblocking behavior.
func runSeedGRPCStore(
	ctx context.Context,
	server *operatorgrpc.Server,
	elected <-chan struct{},
	sync *fakeCacheSyncWaiter,
	reader client.Reader,
) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		seedGRPCStore(ctx, server, elected, sync, reader)
	}()
	return done
}

func TestSeedGRPCStore_NonLeader_ParksAndNeverSeeds(t *testing.T) {
	server := newSeedTestServer(t)

	// A populated cluster whose resources will never reconcile locally:
	// on a non-leader the controllers do not run.
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&avapigwv1alpha1.APIRoute{ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default"}},
		).
		Build()

	elected := make(chan struct{}) // never closed — replica stays non-leader
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := runSeedGRPCStore(ctx, server, elected, &fakeCacheSyncWaiter{result: true}, fakeClient)

	// Within the observation window the goroutine must stay parked on the
	// election gate: no seed mark and no timeout fallback (the bounded
	// reconcile-wait clock must not even start pre-election).
	select {
	case <-done:
		t.Fatal("seedGRPCStore must park on a non-leader, not return")
	case <-time.After(300 * time.Millisecond):
	}
	assert.False(t, server.StoreSeeded(),
		"non-leader must never mark the (empty) store seeded")

	// Shutdown while parked → returns promptly WITHOUT marking seeded.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("seedGRPCStore must return promptly on shutdown while parked")
	}
	assert.False(t, server.StoreSeeded(),
		"shutdown before election must not mark the store seeded")
}

func TestSeedGRPCStore_SeedsAfterElection(t *testing.T) {
	server := newSeedTestServer(t)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&avapigwv1alpha1.APIRoute{ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default"}},
		).
		Build()

	elected := make(chan struct{})
	done := runSeedGRPCStore(
		context.Background(), server, elected, &fakeCacheSyncWaiter{result: true}, fakeClient,
	)

	// Not seeded while awaiting election.
	time.Sleep(100 * time.Millisecond)
	assert.False(t, server.StoreSeeded(), "must not seed before election")

	// Simulate the controllers populating the store, then win the election:
	// seeding must proceed through cache sync + reconcile wait and mark
	// the store seeded.
	require.NoError(t, server.ApplyAPIRoute(context.Background(), "r1", "default", []byte(`{}`)))
	close(elected)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("seedGRPCStore must complete after election")
	}
	assert.True(t, server.StoreSeeded(), "store must be seeded once elected and reconciled")
	assert.Equal(t, 1, server.StoreResourceCount())
}

func TestSeedGRPCStore_ShutdownDuringReconcileWait_SkipsSeedMark(t *testing.T) {
	server := newSeedTestServer(t)

	// One expected resource that is never applied → the bounded reconcile
	// wait blocks until the context is canceled (operator shutdown).
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&avapigwv1alpha1.APIRoute{ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "default"}},
		).
		Build()

	ctx, cancel := context.WithCancel(context.Background())
	done := runSeedGRPCStore(ctx, server, electedNow(), &fakeCacheSyncWaiter{result: true}, fakeClient)

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("seedGRPCStore must return promptly on shutdown during the reconcile wait")
	}
	assert.False(t, server.StoreSeeded(),
		"shutdown during the reconcile wait must not mark the store seeded")
}

func TestStartStoreSeedingBackground_NonLeaderManager_WiresGateAndParks(t *testing.T) {
	// Full wiring test with a REAL (unstarted) manager: an unstarted manager
	// is exactly a non-elected replica — its Elected() channel is open. The
	// seeding goroutine must park (store never seeded) and the manager's
	// election signal must be wired into the server's readiness gate so
	// gated RPCs park too instead of hitting the seed-timeout fallback.
	server := newSeedTestServer(t)
	mgr := newTestManager(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startStoreSeedingBackground(ctx, server, mgr)

	time.Sleep(300 * time.Millisecond)
	assert.False(t, server.StoreSeeded(),
		"store must not be seeded while the manager is not elected")

	// A gated RPC wait must report awaiting-leadership (not the timeout
	// fallback) when its context ends on a non-leader.
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer waitCancel()
	seeded, reason := server.WaitForStoreSeeded(waitCtx, 50*time.Millisecond)
	assert.False(t, seeded)
	assert.Equal(t, "awaiting_leadership", reason)
}
