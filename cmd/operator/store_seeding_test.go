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

	seedGRPCStore(context.Background(), server, &fakeCacheSyncWaiter{result: true}, fakeClient)

	assert.True(t, server.StoreSeeded(), "store must be marked seeded after reconcile pass")
	assert.Equal(t, 1, server.StoreResourceCount())
}

func TestSeedGRPCStore_EmptyCluster_MarksSeededImmediately(t *testing.T) {
	server := newSeedTestServer(t)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	start := time.Now()
	seedGRPCStore(context.Background(), server, &fakeCacheSyncWaiter{result: true}, fakeClient)

	assert.True(t, server.StoreSeeded(),
		"legitimately empty cluster must be marked seeded without waiting")
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestSeedGRPCStore_CacheSyncCanceled_SkipsSeedMark(t *testing.T) {
	server := newSeedTestServer(t)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	seedGRPCStore(context.Background(), server, &fakeCacheSyncWaiter{result: false}, fakeClient)

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
