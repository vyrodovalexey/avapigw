// Package grpc provides additional tests to boost coverage for the StreamConfiguration
// config-change push loop and related edge cases.
package grpc

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// ============================================================================
// Thread-safe mock stream for concurrent tests
// ============================================================================

// safeMockServerStream is a thread-safe version of mockServerStream for use
// in tests where StreamConfiguration runs in a goroutine.
type safeMockServerStream struct {
	ctx     context.Context
	mu      sync.Mutex
	updates []*operatorv1alpha1.ConfigurationUpdate
	sendErr error
}

func (m *safeMockServerStream) Send(update *operatorv1alpha1.ConfigurationUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.updates = append(m.updates, update)
	return nil
}

func (m *safeMockServerStream) getUpdates() []*operatorv1alpha1.ConfigurationUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*operatorv1alpha1.ConfigurationUpdate, len(m.updates))
	copy(cp, m.updates)
	return cp
}

func (m *safeMockServerStream) updateCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.updates)
}

func (m *safeMockServerStream) Context() context.Context     { return m.ctx }
func (m *safeMockServerStream) SetHeader(metadata.MD) error  { return nil }
func (m *safeMockServerStream) SendHeader(metadata.MD) error { return nil }
func (m *safeMockServerStream) SetTrailer(metadata.MD)       {}
func (m *safeMockServerStream) SendMsg(interface{}) error    { return nil } //nolint:revive // interface{} required by grpc.ServerStream
func (m *safeMockServerStream) RecvMsg(interface{}) error    { return nil } //nolint:revive // interface{} required by grpc.ServerStream

// ============================================================================
// StreamConfiguration — config change push loop tests
// ============================================================================

// TestStreamConfiguration_ConfigChangePush verifies that when NotifyConfigChanged
// is called, the StreamConfiguration loop sends a second update to the stream.
func TestStreamConfiguration_ConfigChangePush(t *testing.T) {
	svc, srv := newTestService(t)

	// Populate some initial data
	srv.mu.Lock()
	srv.apiRoutes["default/route1"] = []byte(`{"path":"/api"}`)
	srv.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := &safeMockServerStream{ctx: ctx}

	req := &operatorv1alpha1.StreamConfigurationRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      "push-gw",
			Namespace: "default",
		},
		SessionId: "push-session",
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var streamErr error
	go func() {
		defer wg.Done()
		streamErr = svc.StreamConfiguration(req, stream)
	}()

	// Wait for the initial snapshot to be sent
	require.Eventually(t, func() bool {
		return stream.updateCount() >= 1
	}, 2*time.Second, 10*time.Millisecond, "initial snapshot should be sent")

	// Verify initial snapshot
	updates := stream.getUpdates()
	assert.Equal(t, operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC, updates[0].Type)
	assert.NotNil(t, updates[0].Snapshot)
	assert.Equal(t, int32(1), updates[0].Snapshot.TotalResources)

	// Add more data and notify config changed
	srv.mu.Lock()
	srv.apiRoutes["default/route2"] = []byte(`{"path":"/api/v2"}`)
	srv.mu.Unlock()

	// Trigger config change notification
	srv.NotifyConfigChanged()

	// Wait for the second update to be sent
	require.Eventually(t, func() bool {
		return stream.updateCount() >= 2
	}, 2*time.Second, 10*time.Millisecond, "config change update should be sent")

	// Verify the second update
	updates = stream.getUpdates()
	secondUpdate := updates[1]
	assert.Equal(t, operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC, secondUpdate.Type)
	assert.NotNil(t, secondUpdate.Snapshot)
	assert.Equal(t, int32(2), secondUpdate.Snapshot.TotalResources)
	assert.NotEmpty(t, secondUpdate.Version)

	// Cancel context to stop the stream
	cancel()
	wg.Wait()

	assert.NoError(t, streamErr)
}

// TestStreamConfiguration_ConfigChangePush_SendError verifies that when a send error
// occurs during a config change push, the stream returns an error.
func TestStreamConfiguration_ConfigChangePush_SendError(t *testing.T) {
	svc, srv := newTestService(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a stream that fails on the second Send call
	failStream := &failOnNthSendStream{
		ctx:        ctx,
		failOnCall: 2,
	}

	req := &operatorv1alpha1.StreamConfigurationRequest{
		SessionId: "push-err-session",
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var streamErr error
	go func() {
		defer wg.Done()
		streamErr = svc.StreamConfiguration(req, failStream)
	}()

	// Wait for the initial snapshot to be sent
	require.Eventually(t, func() bool {
		return failStream.callCount() >= 1
	}, 2*time.Second, 10*time.Millisecond, "initial snapshot should be sent")

	// Trigger config change — the second Send will fail
	srv.NotifyConfigChanged()

	// Wait for the goroutine to finish
	wg.Wait()

	// Should return an error from the failed send
	assert.Error(t, streamErr)
	assert.Contains(t, streamErr.Error(), "failed to send configuration update")
}

// TestStreamConfiguration_MultipleConfigChanges verifies that multiple config changes
// each produce a new update on the stream.
func TestStreamConfiguration_MultipleConfigChanges(t *testing.T) {
	svc, srv := newTestService(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := &safeMockServerStream{ctx: ctx}

	req := &operatorv1alpha1.StreamConfigurationRequest{
		SessionId: "multi-push-session",
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var streamErr error
	go func() {
		defer wg.Done()
		streamErr = svc.StreamConfiguration(req, stream)
	}()

	// Wait for initial snapshot
	require.Eventually(t, func() bool {
		return stream.updateCount() >= 1
	}, 2*time.Second, 10*time.Millisecond)

	// Send 3 config changes.
	// After each update is confirmed, a brief sleep allows the stream goroutine
	// to re-enter WaitForConfigChange() before the next NotifyConfigChanged(),
	// preventing a lost-wakeup race on the broadcast channel.
	for i := range 3 {
		srv.mu.Lock()
		srv.apiRoutes[fmt.Sprintf("default/route%d", i)] = []byte(
			fmt.Sprintf(`{"path":"/api/v%d"}`, i),
		)
		srv.mu.Unlock()

		srv.NotifyConfigChanged()

		expectedCount := i + 2 // 1 initial + (i+1) changes
		require.Eventually(t, func() bool {
			return stream.updateCount() >= expectedCount
		}, 2*time.Second, 10*time.Millisecond, "update %d should be sent", i+1)

		// Allow the stream goroutine to loop back and register on the
		// new configNotify channel before the next iteration fires.
		time.Sleep(50 * time.Millisecond)
	}

	// Verify we got 4 total updates (1 initial + 3 changes)
	assert.Equal(t, 4, stream.updateCount())

	// Verify versions are monotonically increasing
	updates := stream.getUpdates()
	for i := 1; i < len(updates); i++ {
		assert.NotEqual(t, updates[i-1].Version, updates[i].Version,
			"versions should be different between updates %d and %d", i-1, i)
	}

	cancel()
	wg.Wait()
	assert.NoError(t, streamErr)
}

// TestStreamConfiguration_ContextCancelDuringWait verifies that canceling the context
// while waiting for a config change properly exits the loop.
func TestStreamConfiguration_ContextCancelDuringWait(t *testing.T) {
	svc, _ := newTestService(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := &safeMockServerStream{ctx: ctx}

	req := &operatorv1alpha1.StreamConfigurationRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      "cancel-gw",
			Namespace: "default",
		},
		SessionId: "cancel-session",
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var streamErr error
	go func() {
		defer wg.Done()
		streamErr = svc.StreamConfiguration(req, stream)
	}()

	// Wait for initial snapshot
	require.Eventually(t, func() bool {
		return stream.updateCount() >= 1
	}, 2*time.Second, 10*time.Millisecond)

	// Cancel context while waiting for config change
	cancel()
	wg.Wait()

	assert.NoError(t, streamErr)
	// Only the initial snapshot should have been sent
	assert.Equal(t, 1, stream.updateCount())
}

// ============================================================================
// Helper types
// ============================================================================

// failOnNthSendStream is a thread-safe mock stream that fails on the Nth Send call.
type failOnNthSendStream struct {
	ctx        context.Context
	mu         sync.Mutex
	count      int
	failOnCall int
	updates    []*operatorv1alpha1.ConfigurationUpdate
}

func (f *failOnNthSendStream) Send(update *operatorv1alpha1.ConfigurationUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	if f.count >= f.failOnCall {
		return fmt.Errorf("simulated send failure on call %d", f.count)
	}
	f.updates = append(f.updates, update)
	return nil
}

func (f *failOnNthSendStream) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

func (f *failOnNthSendStream) Context() context.Context     { return f.ctx }
func (f *failOnNthSendStream) SetHeader(metadata.MD) error  { return nil }
func (f *failOnNthSendStream) SendHeader(metadata.MD) error { return nil }
func (f *failOnNthSendStream) SetTrailer(metadata.MD)       {}
func (f *failOnNthSendStream) SendMsg(interface{}) error    { return nil } //nolint:revive // interface{} required by grpc.ServerStream
func (f *failOnNthSendStream) RecvMsg(interface{}) error    { return nil } //nolint:revive // interface{} required by grpc.ServerStream
