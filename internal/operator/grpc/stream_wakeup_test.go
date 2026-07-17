// Package grpc contains regression tests for the StreamConfiguration
// lost-wakeup bug (config changes landing during an in-flight Send) and for
// the store readiness gate that prevents empty initial snapshots after
// operator restart.
package grpc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/metadata"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// ============================================================================
// Blocking stream mock — simulates a slow gateway during Send
// ============================================================================

// blockingFirstSendStream blocks the FIRST Send call until release is closed,
// creating the exact window in which a store change used to be lost: the
// change notification fires while the stream goroutine is inside Send, and a
// naive re-subscription afterwards would obtain a fresh channel and stall.
type blockingFirstSendStream struct {
	ctx     context.Context
	entered chan struct{} // closed when the first Send begins
	release chan struct{} // the first Send returns when this is closed

	mu      sync.Mutex
	first   bool
	updates []*operatorv1alpha1.ConfigurationUpdate
}

func newBlockingFirstSendStream(ctx context.Context) *blockingFirstSendStream {
	return &blockingFirstSendStream{
		ctx:     ctx,
		entered: make(chan struct{}),
		release: make(chan struct{}),
		first:   true,
	}
}

func (m *blockingFirstSendStream) Send(update *operatorv1alpha1.ConfigurationUpdate) error {
	m.mu.Lock()
	isFirst := m.first
	m.first = false
	m.mu.Unlock()

	if isFirst {
		close(m.entered)
		<-m.release
	}

	m.mu.Lock()
	m.updates = append(m.updates, update)
	m.mu.Unlock()
	return nil
}

func (m *blockingFirstSendStream) updateCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.updates)
}

func (m *blockingFirstSendStream) getUpdates() []*operatorv1alpha1.ConfigurationUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*operatorv1alpha1.ConfigurationUpdate, len(m.updates))
	copy(cp, m.updates)
	return cp
}

func (m *blockingFirstSendStream) Context() context.Context     { return m.ctx }
func (m *blockingFirstSendStream) SetHeader(metadata.MD) error  { return nil }
func (m *blockingFirstSendStream) SendHeader(metadata.MD) error { return nil }
func (m *blockingFirstSendStream) SetTrailer(metadata.MD)       {}
func (m *blockingFirstSendStream) SendMsg(interface{}) error    { return nil } //nolint:revive // interface{} required by grpc.ServerStream
func (m *blockingFirstSendStream) RecvMsg(interface{}) error    { return nil } //nolint:revive // interface{} required by grpc.ServerStream

// ============================================================================
// BUG 1 regression — lost config-change wakeup during in-flight Send
// ============================================================================

// TestStreamConfiguration_ChangeDuringInFlightSend_NotLost verifies that a
// store change applied while stream.Send is in flight is pushed as the next
// snapshot WITHOUT requiring another store change to wake the loop.
func TestStreamConfiguration_ChangeDuringInFlightSend_NotLost(t *testing.T) {
	svc, srv := newTestService(t)

	// Seed one resource so the initial snapshot is non-trivial.
	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "route1", "default", []byte(`{"path":"/api"}`)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := newBlockingFirstSendStream(ctx)
	req := &operatorv1alpha1.StreamConfigurationRequest{SessionId: "wakeup-session"}

	var wg sync.WaitGroup
	wg.Add(1)
	var streamErr error
	go func() {
		defer wg.Done()
		streamErr = svc.StreamConfiguration(req, stream)
	}()

	// Wait until the initial Send is in flight (blocked).
	select {
	case <-stream.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("initial Send did not start")
	}

	// Apply a store change WHILE the Send is blocked. This closes and
	// replaces the notification channel — the window in which the old
	// re-subscribe-after-send loop lost the wakeup.
	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "route2", "default", []byte(`{"path":"/api/v2"}`)))

	// Unblock the in-flight Send. No further store changes are made.
	close(stream.release)

	// The change applied during the Send must be pushed as the next snapshot
	// without needing another NotifyConfigChanged.
	require.Eventually(t, func() bool {
		return stream.updateCount() >= 2
	}, 2*time.Second, 10*time.Millisecond,
		"snapshot for the change applied during the in-flight Send must be pushed")

	updates := stream.getUpdates()
	assert.Equal(t, int32(1), updates[0].Snapshot.GetTotalResources(), "initial snapshot has 1 resource")
	second := updates[1]
	assert.Equal(t, operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC, second.Type)
	require.NotNil(t, second.Snapshot)
	assert.Equal(t, int32(2), second.Snapshot.GetTotalResources(),
		"second snapshot must include the resource applied during the in-flight Send")

	cancel()
	wg.Wait()
	assert.NoError(t, streamErr)
}

// TestStreamConfiguration_MultipleChangesDuringInFlightSend verifies that
// several changes landing during one in-flight Send are coalesced into the
// next pushed snapshot (no change is lost, no stall).
func TestStreamConfiguration_MultipleChangesDuringInFlightSend(t *testing.T) {
	svc, srv := newTestService(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := newBlockingFirstSendStream(ctx)
	req := &operatorv1alpha1.StreamConfigurationRequest{SessionId: "multi-wakeup-session"}

	var wg sync.WaitGroup
	wg.Add(1)
	var streamErr error
	go func() {
		defer wg.Done()
		streamErr = svc.StreamConfiguration(req, stream)
	}()

	select {
	case <-stream.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("initial Send did not start")
	}

	// Two changes while the Send is blocked — each swaps the broadcast channel.
	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "route1", "default", []byte(`{"path":"/a"}`)))
	require.NoError(t, srv.ApplyBackend(context.Background(), "backend1", "default", []byte(`{"host":"b"}`)))

	close(stream.release)

	require.Eventually(t, func() bool {
		updates := stream.getUpdates()
		if len(updates) < 2 {
			return false
		}
		last := updates[len(updates)-1]
		return last.Snapshot.GetTotalResources() == 2
	}, 2*time.Second, 10*time.Millisecond,
		"all changes applied during the in-flight Send must be pushed")

	cancel()
	wg.Wait()
	assert.NoError(t, streamErr)
}

// TestConfigChangeSignal_PairsChannelAndRevision verifies the subscription
// invariants used by the stream loop.
func TestConfigChangeSignal_PairsChannelAndRevision(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ch1, rev1 := srv.ConfigChangeSignal()
	assert.Equal(t, uint64(0), rev1)
	assert.Equal(t, uint64(0), srv.ConfigRevision())

	srv.NotifyConfigChanged()

	// The channel obtained before the broadcast must be closed and the
	// revision must have advanced.
	select {
	case <-ch1:
	default:
		t.Fatal("channel obtained before broadcast was not closed")
	}
	assert.Equal(t, uint64(1), srv.ConfigRevision())

	ch2, rev2 := srv.ConfigChangeSignal()
	assert.Equal(t, uint64(1), rev2)
	select {
	case <-ch2:
		t.Fatal("fresh channel must not be closed before the next broadcast")
	default:
	}
}

// ============================================================================
// BUG 2 — store readiness gate (operator side)
// ============================================================================

// newGatedTestService creates a service whose server has the store readiness
// gate armed and a custom seed timeout.
func newGatedTestService(t *testing.T, seedTimeout time.Duration) (*configurationServiceImpl, *Server) {
	t.Helper()
	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{StoreSeedTimeout: seedTimeout}, reg)
	require.NoError(t, err)
	srv.EnableStoreReadinessGate()
	svc := &configurationServiceImpl{
		server: srv,
		tracer: otel.Tracer(tracerName),
	}
	return svc, srv
}

func TestWaitForStoreSeeded_GateDisabled(t *testing.T) {
	_, srv := newTestService(t)

	seeded, reason := srv.WaitForStoreSeeded(context.Background(), time.Second)
	assert.True(t, seeded)
	assert.Equal(t, seedReasonGateDisabled, reason)
	assert.True(t, srv.StoreSeeded(), "unarmed gate reports seeded")
}

func TestWaitForStoreSeeded_MarkStoreSeeded(t *testing.T) {
	_, srv := newGatedTestService(t, time.Second)

	assert.False(t, srv.StoreSeeded())

	go func() {
		time.Sleep(50 * time.Millisecond)
		srv.MarkStoreSeeded()
	}()

	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 2*time.Second)
	assert.True(t, seeded)
	assert.Equal(t, seedReasonSeeded, reason)
	assert.True(t, srv.StoreSeeded())

	// Idempotent.
	srv.MarkStoreSeeded()
	seeded, reason = srv.WaitForStoreSeeded(context.Background(), time.Second)
	assert.True(t, seeded)
	assert.Equal(t, seedReasonSeeded, reason)
}

// TestWaitForStoreSeeded_RevisionAdvance_FallbackOnlyAfterTimeout verifies the
// strict-seeded gating: an advanced revision alone does NOT open the gate
// early (partial snapshots wiped route sets during operator restarts); it is
// honored only as the fallback once the bounded wait expires.
func TestWaitForStoreSeeded_RevisionAdvance_FallbackOnlyAfterTimeout(t *testing.T) {
	_, srv := newGatedTestService(t, time.Second)

	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "r1", "default", []byte(`{}`)))

	// The revision has advanced, but the gate must stay closed for the full
	// bounded wait: only the timeout fallback serves the partial store.
	start := time.Now()
	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 300*time.Millisecond)
	elapsed := time.Since(start)

	assert.True(t, seeded)
	assert.Equal(t, seedReasonRevision, reason)
	assert.GreaterOrEqual(t, elapsed, 300*time.Millisecond,
		"revision_advanced must not open the gate before the bounded wait expires")
}

// TestWaitForStoreSeeded_SeededBeatsRevision verifies that the seed mark
// unblocks the wait immediately even when the revision advanced first.
func TestWaitForStoreSeeded_SeededBeatsRevision(t *testing.T) {
	_, srv := newGatedTestService(t, time.Second)

	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "r1", "default", []byte(`{}`)))
	go func() {
		time.Sleep(50 * time.Millisecond)
		srv.MarkStoreSeeded()
	}()

	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 5*time.Second)
	assert.True(t, seeded)
	assert.Equal(t, seedReasonSeeded, reason)
}

func TestWaitForStoreSeeded_Timeout(t *testing.T) {
	_, srv := newGatedTestService(t, time.Second)

	start := time.Now()
	seeded, reason := srv.WaitForStoreSeeded(context.Background(), 100*time.Millisecond)
	assert.False(t, seeded)
	assert.Equal(t, seedReasonTimeout, reason)
	assert.Less(t, time.Since(start), time.Second, "wait must be bounded by the timeout")
}

func TestWaitForStoreSeeded_ContextCanceled(t *testing.T) {
	_, srv := newGatedTestService(t, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	seeded, reason := srv.WaitForStoreSeeded(ctx, 5*time.Second)
	assert.False(t, seeded)
	assert.Equal(t, seedReasonCanceled, reason)
}

func TestWaitForStoreSeeded_DeadlineCap(t *testing.T) {
	_, srv := newGatedTestService(t, time.Second)

	// Deadline closer than the safety margin → immediate timeout decision.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	seeded, reason := srv.WaitForStoreSeeded(ctx, 10*time.Second)
	assert.False(t, seeded)
	assert.Equal(t, seedReasonTimeout, reason)
	assert.Less(t, time.Since(start), 400*time.Millisecond,
		"wait must be capped below the caller's deadline")
}

// TestStreamConfiguration_GatedInitialSnapshot verifies that with the gate
// armed and an empty store, the stream parks — INCLUDING through partial
// applies (revision advances) — and the first pushed snapshot contains the
// complete configuration present at the seed mark (never a partial wipe).
func TestStreamConfiguration_GatedInitialSnapshot(t *testing.T) {
	svc, srv := newGatedTestService(t, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := &safeMockServerStream{ctx: ctx}
	req := &operatorv1alpha1.StreamConfigurationRequest{SessionId: "gated-session"}

	var wg sync.WaitGroup
	wg.Add(1)
	var streamErr error
	go func() {
		defer wg.Done()
		streamErr = svc.StreamConfiguration(req, stream)
	}()

	// While the store is empty and unseeded, no snapshot may be sent.
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 0, stream.updateCount(), "stream must park until the store is seeded")

	// A partial apply advances the revision but must NOT open the gate:
	// the initial reconcile pass is still in flight.
	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "r1", "default", []byte(`{"path":"/api"}`)))
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 0, stream.updateCount(),
		"stream must stay parked on revision advance alone (partial snapshot)")

	// A second apply completes the reconcile pass; the seed mark opens the gate.
	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "r2", "default", []byte(`{"path":"/api/v2"}`)))
	srv.MarkStoreSeeded()

	require.Eventually(t, func() bool {
		return stream.updateCount() >= 1
	}, 2*time.Second, 10*time.Millisecond, "initial snapshot should be sent after seeding")

	updates := stream.getUpdates()
	assert.Equal(t, int32(2), updates[0].Snapshot.GetTotalResources(),
		"initial snapshot must include the fully seeded store, not a partial one")

	cancel()
	wg.Wait()
	assert.NoError(t, streamErr)
}

// TestStreamConfiguration_GateTimeout_ProceedsWithLoggedDecision verifies the
// bounded-wait behavior: when seeding never happens, the stream proceeds after
// the timeout instead of blocking forever.
func TestStreamConfiguration_GateTimeout_ProceedsWithLoggedDecision(t *testing.T) {
	svc, _ := newGatedTestService(t, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := &safeMockServerStream{ctx: ctx}
	req := &operatorv1alpha1.StreamConfigurationRequest{SessionId: "gate-timeout-session"}

	var wg sync.WaitGroup
	wg.Add(1)
	var streamErr error
	go func() {
		defer wg.Done()
		streamErr = svc.StreamConfiguration(req, stream)
	}()

	require.Eventually(t, func() bool {
		return stream.updateCount() >= 1
	}, 2*time.Second, 10*time.Millisecond, "stream must proceed after the bounded wait")

	cancel()
	wg.Wait()
	assert.NoError(t, streamErr)
}

// TestRegisterGateway_GatedInitialConfig verifies that RegisterGateway waits
// for the store seed mark before returning the initial configuration.
func TestRegisterGateway_GatedInitialConfig(t *testing.T) {
	svc, srv := newGatedTestService(t, 5*time.Second)

	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "pre", "default", []byte(`{"path":"/pre"}`)))
	// The seed mark (not the advanced revision) opens the gate; registration
	// must return the fully seeded configuration immediately afterwards.
	srv.MarkStoreSeeded()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := svc.RegisterGateway(ctx, &operatorv1alpha1.RegisterGatewayRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{Name: "gw", Namespace: "default"},
	})
	require.NoError(t, err)
	require.True(t, resp.Success)
	require.NotNil(t, resp.InitialConfig)
	assert.Equal(t, int32(1), resp.InitialConfig.GetTotalResources())
}

// TestGetConfiguration_GateTimeout verifies GetConfiguration proceeds after
// the bounded wait when the store never seeds.
func TestGetConfiguration_GateTimeout(t *testing.T) {
	svc, _ := newGatedTestService(t, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	snapshot, err := svc.GetConfiguration(ctx, &operatorv1alpha1.GetConfigurationRequest{})
	require.NoError(t, err)
	require.NotNil(t, snapshot)
	assert.Equal(t, int32(0), snapshot.GetTotalResources())
}

// TestStoreResourceCount verifies the aggregate store count used in seeding
// decisions.
func TestStoreResourceCount(t *testing.T) {
	_, srv := newTestService(t)
	assert.Equal(t, 0, srv.StoreResourceCount())

	ctx := context.Background()
	require.NoError(t, srv.ApplyAPIRoute(ctx, "r1", "default", []byte(`{}`)))
	require.NoError(t, srv.ApplyGRPCRoute(ctx, "g1", "default", []byte(`{}`)))
	require.NoError(t, srv.ApplyGraphQLRoute(ctx, "q1", "default", []byte(`{}`)))
	require.NoError(t, srv.ApplyBackend(ctx, "b1", "default", []byte(`{}`)))
	require.NoError(t, srv.ApplyGRPCBackend(ctx, "gb1", "default", []byte(`{}`)))
	require.NoError(t, srv.ApplyGraphQLBackend(ctx, "qb1", "default", []byte(`{}`)))

	assert.Equal(t, 6, srv.StoreResourceCount())
	assert.Equal(t, uint64(6), srv.ConfigRevision())
}
