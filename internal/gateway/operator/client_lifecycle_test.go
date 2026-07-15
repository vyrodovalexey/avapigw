// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

// Lifecycle/regression tests for WP6 (channel-replacement races).
//
// Start replaces stopCh/stoppedCh/wg per background-goroutine generation.
// These tests verify the generation capture pattern: after a timed-out Stop
// leaves a goroutine behind, a subsequent Start installs fresh channels for
// the new generation while the stranded goroutine still exits on ITS OWN
// (already closed) generation stop channel.
//
// All tests are expected to run under -race.

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// fakeLifecycleServer is a plain (mutex-free across RPCs) ConfigurationService
// implementation. The shared testify mock serializes all RPCs behind one
// mutex, which would deadlock scenarios where one stream must stay blocked
// while another stream and heartbeats proceed.
type fakeLifecycleServer struct {
	operatorv1alpha1.UnimplementedConfigurationServiceServer

	// sendUpdateOnFirstStream makes the first established stream deliver a
	// single configuration update before blocking.
	sendUpdateOnFirstStream bool

	streamCount atomic.Int32
}

func (s *fakeLifecycleServer) RegisterGateway(
	_ context.Context, _ *operatorv1alpha1.RegisterGatewayRequest,
) (*operatorv1alpha1.RegisterGatewayResponse, error) {
	return &operatorv1alpha1.RegisterGatewayResponse{
		Success:           true,
		SessionId:         "lifecycle-session",
		HeartbeatInterval: durationpb.New(30 * time.Second),
	}, nil
}

func (s *fakeLifecycleServer) StreamConfiguration(
	_ *operatorv1alpha1.StreamConfigurationRequest,
	stream operatorv1alpha1.ConfigurationService_StreamConfigurationServer,
) error {
	if s.streamCount.Add(1) == 1 && s.sendUpdateOnFirstStream {
		if err := stream.Send(&operatorv1alpha1.ConfigurationUpdate{
			Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
			Version:  "v1",
			Sequence: 1,
		}); err != nil {
			return err
		}
	}
	// Mimic a healthy long-lived stream until the client goes away.
	<-stream.Context().Done()
	return nil
}

func (s *fakeLifecycleServer) Heartbeat(
	_ context.Context, _ *operatorv1alpha1.HeartbeatRequest,
) (*operatorv1alpha1.HeartbeatResponse, error) {
	return &operatorv1alpha1.HeartbeatResponse{Acknowledged: true}, nil
}

func (s *fakeLifecycleServer) AcknowledgeConfiguration(
	_ context.Context, _ *operatorv1alpha1.AcknowledgeConfigurationRequest,
) (*operatorv1alpha1.AcknowledgeConfigurationResponse, error) {
	return &operatorv1alpha1.AcknowledgeConfigurationResponse{Received: true}, nil
}

// startFakeLifecycleServer starts the fake gRPC server and returns its address.
func startFakeLifecycleServer(t *testing.T, fake *fakeLifecycleServer) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, fake)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)

	return listener.Addr().String()
}

// clientGeneration captures the lifecycle primitives of the client's current
// goroutine generation under the client's lock.
func clientGeneration(c *Client) (stopCh, stoppedCh chan struct{}, wg *sync.WaitGroup) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stopCh, c.stoppedCh, c.wg
}

// TestClient_StopTimeout_ThenStart_GenerationCapture reproduces the WP6
// scenario end to end:
//  1. a configuration-apply handler blocks, so Stop() times out and leaves
//     the generation-1 stream goroutine stranded;
//  2. Start() installs a fresh generation on new channels and connects;
//  3. once unblocked, the stranded goroutine exits on its own captured
//     (closed) generation-1 stop channel without disturbing generation 2.
func TestClient_StopTimeout_ThenStart_GenerationCapture(t *testing.T) {
	t.Parallel()

	fake := &fakeLifecycleServer{sendUpdateOnFirstStream: true}
	address := startFakeLifecycleServer(t, fake)

	gate := make(chan struct{})
	handlerEntered := make(chan struct{})
	client, err := NewClient(&Config{
		Enabled:           true,
		Address:           address,
		GatewayName:       "test-gateway",
		GatewayNamespace:  "default",
		HeartbeatInterval: 50 * time.Millisecond,
	},
		WithMetricsRegistry(prometheus.NewRegistry()),
		WithConfigUpdateHandler(func(_ context.Context, _ *operatorv1alpha1.ConfigurationUpdate) error {
			close(handlerEntered)
			// Deliberately ignore ctx: simulates a slow config apply that
			// outlives Stop's bounded wait.
			<-gate
			return nil
		}),
	)
	require.NoError(t, err)
	// Seam (mirrors backend/health stopTimeout): avoid the real 5s bounded
	// wait; time.After never fires early, so the elapsed lower bound holds.
	client.stopTimeout = 500 * time.Millisecond

	require.NoError(t, client.Start(context.Background()))

	// Wait until the generation-1 stream goroutine is stuck in the handler.
	select {
	case <-handlerEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("configuration update never reached the blocking handler")
	}

	gen1Stop, gen1Stopped, gen1WG := clientGeneration(client)

	// Stop must hit its bounded-wait timeout because the stream goroutine is
	// stuck in the handler, and still return cleanly.
	stopStart := time.Now()
	require.NoError(t, client.Stop())
	stopElapsed := time.Since(stopStart)
	assert.GreaterOrEqual(t, stopElapsed, client.stopTimeout,
		"Stop should have waited out its bounded timeout for the stuck goroutine")

	// Stop signaled generation 1 (stopCh closed) and external waiters
	// (stoppedCh closed) despite the timeout.
	select {
	case <-gen1Stop:
	default:
		t.Fatal("generation-1 stopCh must be closed by Stop")
	}
	select {
	case <-gen1Stopped:
	default:
		t.Fatal("generation-1 stoppedCh must be closed by Stop")
	}

	// Restart: generation 2 must run on fresh channels.
	require.NoError(t, client.Start(context.Background()))
	gen2Stop, gen2Stopped, gen2WG := clientGeneration(client)
	assert.NotEqual(t, gen1Stop, gen2Stop, "Start must install a fresh stop channel")
	assert.NotEqual(t, gen1Stopped, gen2Stopped, "Start must install a fresh stopped channel")
	assert.NotSame(t, gen1WG, gen2WG, "Start must install a fresh WaitGroup")

	require.Eventually(t, client.IsConnected, 2*time.Second, 10*time.Millisecond,
		"restarted client must reconnect")
	require.Eventually(t, func() bool { return fake.streamCount.Load() >= 2 },
		2*time.Second, 10*time.Millisecond, "generation-2 stream must be established")

	// Unblock the stranded generation-1 goroutine. It must exit on its own
	// captured (closed) generation-1 stop channel.
	close(gate)
	gen1Drained := make(chan struct{})
	go func() {
		gen1WG.Wait()
		close(gen1Drained)
	}()
	select {
	case <-gen1Drained:
	case <-time.After(5 * time.Second):
		t.Fatal("stranded generation-1 goroutine did not exit on its captured stop channel")
	}

	// Generation 2 must be unaffected by generation 1 draining.
	time.Sleep(200 * time.Millisecond)
	assert.True(t, client.IsConnected(), "generation-2 loops must keep running")
	select {
	case <-gen2Stopped:
		t.Fatal("generation-2 stoppedCh must not be closed by generation-1 shutdown")
	default:
	}

	// Second Stop is clean and prompt: nothing is stuck anymore.
	stopStart = time.Now()
	require.NoError(t, client.Stop())
	assert.Less(t, time.Since(stopStart), client.stopTimeout,
		"second Stop must not run into the timeout")
	assert.False(t, client.IsConnected())
}

// TestClient_NilServiceClient_Guards verifies that RPC helpers called on a
// client whose connection was torn down (c.client == nil, e.g. a goroutine
// stranded past a timed-out Stop) fail gracefully with ErrNotConnected
// instead of panicking on a nil service client.
func TestClient_NilServiceClient_Guards(t *testing.T) {
	t.Parallel()

	client, err := NewClient(&Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}, WithMetricsRegistry(prometheus.NewRegistry()))
	require.NoError(t, err)

	ctx := context.Background()

	err = client.register(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRegistrationFailed)
	assert.ErrorIs(t, err, ErrNotConnected)

	err = client.streamConfiguration(ctx, client.stopCh)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotConnected)

	// Fire-and-forget helpers must not panic without a connection.
	client.sendAcknowledgment(ctx, "v1", true, "", time.Millisecond)
	client.sendHeartbeat(ctx)

	// GetConfiguration checks the connected flag first; force it true to
	// exercise the nil-service-client guard behind it.
	client.connected.Store(true)
	snapshot, err := client.GetConfiguration(ctx)
	assert.Nil(t, snapshot)
	assert.ErrorIs(t, err, ErrNotConnected)
}

// TestClient_Restart_CleanCycle verifies the fast path Start -> Stop ->
// Start -> Stop cycle: every generation gets fresh channels, stops promptly,
// and the started-state error contract is preserved.
func TestClient_Restart_CleanCycle(t *testing.T) {
	t.Parallel()

	fake := &fakeLifecycleServer{}
	address := startFakeLifecycleServer(t, fake)

	client, err := NewClient(&Config{
		Enabled:           true,
		Address:           address,
		GatewayName:       "test-gateway",
		GatewayNamespace:  "default",
		HeartbeatInterval: 50 * time.Millisecond,
	}, WithMetricsRegistry(prometheus.NewRegistry()))
	require.NoError(t, err)

	// Cycle 1
	require.NoError(t, client.Start(context.Background()))
	assert.ErrorIs(t, client.Start(context.Background()), ErrAlreadyStarted)
	_, gen1Stopped, _ := clientGeneration(client)
	require.Eventually(t, client.IsConnected, 2*time.Second, 10*time.Millisecond)

	stopStart := time.Now()
	require.NoError(t, client.Stop())
	assert.Less(t, time.Since(stopStart), clientStopTimeout, "clean Stop must not time out")
	select {
	case <-gen1Stopped:
	default:
		t.Fatal("generation-1 stoppedCh must be closed after Stop")
	}

	// Cycle 2
	require.NoError(t, client.Start(context.Background()))
	_, gen2Stopped, _ := clientGeneration(client)
	assert.NotEqual(t, gen1Stopped, gen2Stopped, "restart must use fresh channels")
	require.Eventually(t, client.IsConnected, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, client.Stop())
	assert.ErrorIs(t, client.Stop(), ErrNotStarted)
	select {
	case <-gen2Stopped:
	default:
		t.Fatal("generation-2 stoppedCh must be closed after Stop")
	}
}
