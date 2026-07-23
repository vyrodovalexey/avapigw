// Package grpc contains regression tests for graceful shutdown with live
// configuration streams (the shutdown signal) and for the gateway registry
// staleness reaper.
package grpc

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// ============================================================================
// Shutdown signal — service level
// ============================================================================

// TestStreamConfiguration_TerminatesOnShutdownSignal verifies that a
// long-lived configuration stream returns promptly when server shutdown
// begins, instead of pinning GracefulStop until the shutdown timeout.
func TestStreamConfiguration_TerminatesOnShutdownSignal(t *testing.T) {
	svc, srv := newTestService(t)

	require.NoError(t, srv.ApplyAPIRoute(context.Background(), "route1", "default", []byte(`{"path":"/api"}`)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := newBlockingFirstSendStream(ctx)
	close(stream.release) // do not block sends in this test

	done := make(chan error, 1)
	go func() {
		done <- svc.StreamConfiguration(
			&operatorv1alpha1.StreamConfigurationRequest{SessionId: "shutdown-session"}, stream)
	}()

	// Wait for the initial snapshot so the stream is parked in its select.
	require.Eventually(t, func() bool { return stream.updateCount() >= 1 },
		2*time.Second, 10*time.Millisecond, "initial snapshot not sent")

	srv.signalShutdown()

	select {
	case err := <-done:
		assert.NoError(t, err, "stream should terminate cleanly on shutdown")
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not terminate on shutdown signal")
	}
}

// TestShutdownSignal_ClosedOnStop verifies the shutdown channel semantics:
// closed exactly once, observable by multiple listeners, idempotent.
func TestShutdownSignal_ClosedOnStop(t *testing.T) {
	server := newIsolatedTestServer(t)

	select {
	case <-server.ShutdownSignal():
		t.Fatal("shutdown signal must not fire before Stop")
	default:
	}

	require.NoError(t, server.StopWithContext(context.Background()))

	select {
	case <-server.ShutdownSignal():
	default:
		t.Fatal("shutdown signal must fire after Stop")
	}

	// Idempotent: a second stop (already closed) must not panic and must
	// return immediately.
	assert.NoError(t, server.StopWithContext(context.Background()))
	server.signalShutdown() // direct double-signal is safe too
}

// ============================================================================
// StopWithContext — mutex must NOT be held across the graceful wait
// ============================================================================

// blockerServiceDesc returns a hand-rolled gRPC service whose single unary
// method blocks until release is closed, keeping GracefulStop waiting on an
// active RPC for as long as the test needs.
func blockerServiceDesc(entered, release chan struct{}) *grpc.ServiceDesc {
	var once sync.Once
	return &grpc.ServiceDesc{
		ServiceName: "avapigw.test.Blocker",
		HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Block",
			Handler: func(_ interface{}, _ context.Context,
				_ func(interface{}) error, _ grpc.UnaryServerInterceptor,
			) (interface{}, error) {
				once.Do(func() { close(entered) })
				<-release
				return &emptypb.Empty{}, nil
			},
		}},
	}
}

// TestStopWithContext_MutexReleasedDuringGracefulWait is the H3 regression
// test: while GracefulStop is draining an active RPC, configuration
// operations (Apply*) must not be blocked on the server state mutex — the
// old implementation held s.mu across the entire graceful wait.
func TestStopWithContext_MutexReleasedDuringGracefulWait(t *testing.T) {
	server := newIsolatedTestServer(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	entered := make(chan struct{})
	release := make(chan struct{})

	grpcSrv := grpc.NewServer()
	grpcSrv.RegisterService(blockerServiceDesc(entered, release), struct{}{})
	go func() { _ = grpcSrv.Serve(listener) }()

	server.mu.Lock()
	server.grpcServer = grpcSrv
	server.mu.Unlock()

	conn, err := grpc.NewClient(listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Start the blocking RPC so GracefulStop has something to wait for.
	rpcDone := make(chan error, 1)
	go func() {
		rpcDone <- conn.Invoke(context.Background(),
			"/avapigw.test.Blocker/Block", &emptypb.Empty{}, &emptypb.Empty{})
	}()

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("blocking RPC did not start")
	}

	// Begin shutdown; the graceful wait now blocks on the active RPC.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	stopDone := make(chan error, 1)
	go func() { stopDone <- server.StopWithContext(stopCtx) }()

	// While the graceful wait is in progress, an Apply must complete
	// promptly: the state mutex must not be held across the wait.
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer applyCancel()
	assert.NoError(t, server.ApplyAPIRoute(applyCtx, "during-stop", "default", []byte(`{}`)),
		"Apply must not be blocked by an in-progress graceful shutdown")

	// Release the RPC; graceful shutdown must now complete promptly.
	close(release)
	select {
	case err := <-stopDone:
		assert.NoError(t, err, "graceful shutdown should complete once RPCs drain")
	case <-time.After(5 * time.Second):
		t.Fatal("StopWithContext did not complete after RPCs drained")
	}
	<-rpcDone
}

// TestStopWithContext_LiveConfigStream_PromptGracefulShutdown is the
// end-to-end H3 regression test: with a REAL gateway configuration stream
// connected (long-lived by design), StopWithContext must complete a GRACEFUL
// shutdown promptly — the shutdown signal makes the stream return — instead
// of burning the whole graceful-shutdown window and force-stopping.
func TestStopWithContext_LiveConfigStream_PromptGracefulShutdown(t *testing.T) {
	port := getFreePort(t)
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{Port: port}, reg)
	require.NoError(t, err)

	require.NoError(t, server.ApplyAPIRoute(context.Background(), "r1", "default", []byte(`{"path":"/api"}`)))

	serveCtx, serveCancel := context.WithCancel(context.Background())
	defer serveCancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Start(serveCtx) }()

	conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	client := operatorv1alpha1.NewConfigurationServiceClient(conn)
	streamCtx, streamCancel := context.WithCancel(context.Background())
	defer streamCancel()

	var stream grpc.ServerStreamingClient[operatorv1alpha1.ConfigurationUpdate]
	require.Eventually(t, func() bool {
		stream, err = client.StreamConfiguration(streamCtx,
			&operatorv1alpha1.StreamConfigurationRequest{SessionId: "live"})
		return err == nil
	}, 5*time.Second, 50*time.Millisecond, "could not open configuration stream")

	// Receive the initial FULL_SYNC so the stream is established end-to-end.
	update, err := stream.Recv()
	require.NoError(t, err)
	require.NotNil(t, update.GetSnapshot())

	// Graceful stop with a generous deadline: MUST finish promptly (the
	// stream is signaled), NOT by exhausting the deadline into force-stop.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer stopCancel()

	start := time.Now()
	err = server.StopWithContext(stopCtx)
	elapsed := time.Since(start)

	assert.NoError(t, err, "shutdown must be graceful, not forced")
	assert.Less(t, elapsed, 5*time.Second,
		"graceful shutdown must complete promptly with a live config stream")

	// The server-side stream handler returned; the client observes EOF or a
	// transport error, never a hang.
	_, recvErr := stream.Recv()
	assert.Error(t, recvErr, "client stream must be terminated by server shutdown")
}

// TestStopWithContext_RecordsShutdownDurationMetric verifies the graceful
// path observes the shutdown duration histogram.
func TestStopWithContext_RecordsShutdownDurationMetric(t *testing.T) {
	reg := prometheus.NewRegistry()
	server, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)
	server.grpcServer = grpc.NewServer()

	require.NoError(t, server.StopWithContext(context.Background()))

	count := testutil.CollectAndCount(server.metrics.shutdownDuration,
		"avapigw_operator_grpc_shutdown_duration_seconds")
	assert.Equal(t, 1, count, "graceful shutdown must record the duration histogram")
}

// ============================================================================
// Store-seed gate — shutdown unparks gated RPCs
// ============================================================================

// TestWaitForStoreSeeded_Shutdown_BoundedWait verifies a gated RPC parked in
// the bounded seed wait unparks immediately on shutdown.
func TestWaitForStoreSeeded_Shutdown_BoundedWait(t *testing.T) {
	server := newIsolatedTestServer(t)
	server.EnableStoreReadinessGate()

	go func() {
		time.Sleep(50 * time.Millisecond)
		server.signalShutdown()
	}()

	start := time.Now()
	seeded, reason := server.WaitForStoreSeeded(context.Background(), 10*time.Second)
	assert.False(t, seeded)
	assert.Equal(t, seedReasonShutdown, reason)
	assert.Less(t, time.Since(start), 5*time.Second, "shutdown must unpark the seed wait promptly")
}

// TestWaitForStoreSeeded_Shutdown_LeadershipPark verifies a gated RPC parked
// on the leadership signal (non-leader replica) unparks on shutdown.
func TestWaitForStoreSeeded_Shutdown_LeadershipPark(t *testing.T) {
	server := newIsolatedTestServer(t)
	server.EnableStoreReadinessGate()
	server.SetLeadershipSignal(make(chan struct{})) // never elected

	go func() {
		time.Sleep(50 * time.Millisecond)
		server.signalShutdown()
	}()

	seeded, reason := server.WaitForStoreSeeded(context.Background(), 10*time.Second)
	assert.False(t, seeded)
	assert.Equal(t, seedReasonShutdown, reason)
}

// ============================================================================
// Gateway registry staleness reaper
// ============================================================================

// backdateGateway rewinds a registered gateway's lastSeen by age.
func backdateGateway(t *testing.T, s *Server, name, namespace string, age time.Duration) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, gw := range s.gateways {
		if gw.name == name && gw.namespace == namespace {
			gw.lastSeen = time.Now().Add(-age)
			return
		}
	}
	t.Fatalf("gateway %s/%s not registered", namespace, name)
}

// TestReapStaleGateways_RemovesOnlyStale verifies TTL-based reaping removes
// exactly the stale registrations and updates the active-gateways gauge and
// reap counter.
func TestReapStaleGateways_RemovesOnlyStale(t *testing.T) {
	server := newIsolatedTestServer(t)

	server.RegisterGateway("fresh", "default")
	server.RegisterGateway("stale", "default")
	backdateGateway(t, server, "stale", "default", 10*time.Minute)

	reaped := server.reapStaleGateways(DefaultGatewayStaleTTL)

	assert.Equal(t, 1, reaped)
	assert.Equal(t, 1, server.GetGatewayCount())
	assert.InDelta(t, 1.0, testutil.ToFloat64(server.metrics.reapedGateways), 0.001)
	assert.InDelta(t, 1.0, testutil.ToFloat64(server.metrics.activeGateways), 0.001)
}

// TestReapStaleGateways_FreshHeartbeatSurvives verifies a gateway whose
// heartbeat is fresh is never reaped.
func TestReapStaleGateways_FreshHeartbeatSurvives(t *testing.T) {
	server := newIsolatedTestServer(t)

	server.RegisterGateway("gw", "default")
	server.UpdateGatewayHeartbeat("gw", "default")

	assert.Zero(t, server.reapStaleGateways(DefaultGatewayStaleTTL))
	assert.Equal(t, 1, server.GetGatewayCount())
}

// TestStartGatewayReaper_ReapsInBackground verifies the background loop
// (with default-overriding interval/TTL) removes a disappeared gateway.
func TestStartGatewayReaper_ReapsInBackground(t *testing.T) {
	server := newIsolatedTestServer(t)

	server.RegisterGateway("ghost", "default")
	backdateGateway(t, server, "ghost", "default", time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.StartGatewayReaper(ctx, 10*time.Millisecond, 50*time.Millisecond)

	assert.Eventually(t, func() bool { return server.GetGatewayCount() == 0 },
		2*time.Second, 10*time.Millisecond, "stale gateway was not reaped by the background loop")
}

// TestStartGatewayReaper_StopsOnShutdown verifies the reaper loop exits on
// server shutdown without reaping afterwards. The loop goroutine signals
// completion through a done channel, so the "no sweep runs anymore"
// verification is deterministic: after loopDone is closed the loop has
// provably returned (the select may serve one pending tick before observing
// the shutdown channel, which the bounded wait absorbs).
func TestStartGatewayReaper_StopsOnShutdown(t *testing.T) {
	server := newIsolatedTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		server.runGatewayReaper(ctx, 5*time.Millisecond, time.Hour)
	}()

	server.signalShutdown()
	select {
	case <-loopDone:
	case <-time.After(10 * time.Second):
		t.Fatal("reaper loop did not exit on shutdown signal")
	}

	// The loop has exited: a stale gateway registered now can never be
	// swept, no matter how long the test would wait.
	server.RegisterGateway("late", "default")
	backdateGateway(t, server, "late", "default", 2*time.Hour)

	assert.Equal(t, 1, server.GetGatewayCount(), "reaper must not run after shutdown")
}

// TestStartGatewayReaper_StopsOnContextCancel verifies the reaper loop also
// exits on context cancellation (the other select arm).
func TestStartGatewayReaper_StopsOnContextCancel(t *testing.T) {
	server := newIsolatedTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		server.runGatewayReaper(ctx, 5*time.Millisecond, time.Hour)
	}()

	cancel()
	select {
	case <-loopDone:
	case <-time.After(10 * time.Second):
		t.Fatal("reaper loop did not exit on context cancellation")
	}

	server.RegisterGateway("late", "default")
	backdateGateway(t, server, "late", "default", 2*time.Hour)

	assert.Equal(t, 1, server.GetGatewayCount(), "reaper must not run after context cancellation")
}

// TestReapStaleGateways_ReRegisterAfterReap verifies a reaped gateway can
// re-register (reconnect after a partition) and the active-gateways gauge
// stays consistent across reap → re-register → sweep.
func TestReapStaleGateways_ReRegisterAfterReap(t *testing.T) {
	server := newIsolatedTestServer(t)

	server.RegisterGateway("gw", "default")
	backdateGateway(t, server, "gw", "default", 10*time.Minute)
	require.Equal(t, 1, server.reapStaleGateways(DefaultGatewayStaleTTL))
	require.Zero(t, server.GetGatewayCount())
	assert.InDelta(t, 0.0, testutil.ToFloat64(server.metrics.activeGateways), 0.001,
		"gauge must drop to zero after the reap")

	// The same gateway name/namespace re-registers.
	server.RegisterGateway("gw", "default")
	assert.Equal(t, 1, server.GetGatewayCount())
	assert.InDelta(t, 1.0, testutil.ToFloat64(server.metrics.activeGateways), 0.001,
		"re-registration must restore the gauge")

	// The fresh registration survives the next sweep; gauge unchanged.
	assert.Zero(t, server.reapStaleGateways(DefaultGatewayStaleTTL))
	assert.Equal(t, 1, server.GetGatewayCount())
	assert.InDelta(t, 1.0, testutil.ToFloat64(server.metrics.activeGateways), 0.001)
}

// TestReapStaleGateways_HeartbeatAfterTTLElapsedPreventsReap verifies a
// heartbeat arriving after the TTL has already elapsed (live stream, late
// heartbeat) refreshes lastSeen so the gateway is never reaped.
func TestReapStaleGateways_HeartbeatAfterTTLElapsedPreventsReap(t *testing.T) {
	server := newIsolatedTestServer(t)

	server.RegisterGateway("gw", "default")
	backdateGateway(t, server, "gw", "default", 10*time.Minute) // beyond TTL

	// The heartbeat lands before the sweep.
	server.UpdateGatewayHeartbeat("gw", "default")

	assert.Zero(t, server.reapStaleGateways(DefaultGatewayStaleTTL),
		"a gateway whose heartbeat refreshed lastSeen must not be reaped")
	assert.Equal(t, 1, server.GetGatewayCount())
}

// TestHeartbeatRPC_KeepsGatewayAliveThroughSweeps verifies the service-level
// Heartbeat RPC path updates lastSeen: a streaming gateway that keeps
// heartbeating survives sweeps even when its original registration time is
// far beyond the TTL.
func TestHeartbeatRPC_KeepsGatewayAliveThroughSweeps(t *testing.T) {
	svc, server := newTestService(t)

	server.RegisterGateway("live", "default")
	backdateGateway(t, server, "live", "default", 10*time.Minute)

	for i := 0; i < 3; i++ {
		resp, err := svc.Heartbeat(context.Background(), &operatorv1alpha1.HeartbeatRequest{
			Gateway: &operatorv1alpha1.GatewayInfo{Name: "live", Namespace: "default"},
		})
		require.NoError(t, err)
		require.True(t, resp.GetAcknowledged())

		assert.Zero(t, server.reapStaleGateways(DefaultGatewayStaleTTL),
			"sweep %d must not reap a gateway with a fresh heartbeat", i)
		assert.Equal(t, 1, server.GetGatewayCount())
	}
}

// TestStartGatewayReaper_DefaultsApplied covers the default interval/TTL
// path (0,0) — the loop must start and remain harmless for fresh gateways.
func TestStartGatewayReaper_DefaultsApplied(t *testing.T) {
	server := newIsolatedTestServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	server.StartGatewayReaper(ctx, 0, 0)
	server.RegisterGateway("gw", "default")

	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, 1, server.GetGatewayCount())
	cancel()
}
