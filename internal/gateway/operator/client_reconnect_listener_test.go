// Package operator contains tests for the client's reconnect listener: it
// must fire on every successful registration BEFORE the initial snapshot is
// applied, so listeners can arm the snapshot regression window.
package operator

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// startReconnectMockServer starts a mock operator returning a successful
// registration carrying an initial snapshot.
func startReconnectMockServer(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.RegisterGatewayResponse{
			Success:           true,
			SessionId:         "reconnect-session",
			HeartbeatInterval: durationpb.New(30 * time.Second),
			InitialConfig: &operatorv1alpha1.ConfigurationSnapshot{
				Version: "initial",
			},
		}, nil,
	)

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	return listener.Addr().String()
}

// TestClient_ReconnectListener_FiredBeforeInitialSnapshot verifies the
// listener fires on successful registration and strictly before the initial
// snapshot handler.
func TestClient_ReconnectListener_FiredBeforeInitialSnapshot(t *testing.T) {
	addr := startReconnectMockServer(t)

	var order []string
	var listenerCalls atomic.Int32

	cfg := &Config{
		Enabled:          true,
		Address:          addr,
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg,
		WithReconnectListener(func() {
			listenerCalls.Add(1)
			order = append(order, "reconnect")
		}),
		WithSnapshotHandler(func(_ context.Context, _ *operatorv1alpha1.ConfigurationSnapshot) error {
			order = append(order, "snapshot")
			return nil
		}),
	)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, client.Connect(ctx))
	require.NoError(t, client.register(ctx))

	assert.Equal(t, int32(1), listenerCalls.Load(), "listener must fire once per registration")
	require.Len(t, order, 2)
	assert.Equal(t, []string{"reconnect", "snapshot"}, order,
		"the reconnect signal must precede the initial snapshot application")

	// A re-registration (reconnect) fires the listener again.
	require.NoError(t, client.register(ctx))
	assert.Equal(t, int32(2), listenerCalls.Load(), "listener must fire on every re-registration")

	client.mu.Lock()
	if client.conn != nil {
		_ = client.conn.Close()
		client.conn = nil
		client.client = nil
	}
	client.mu.Unlock()
}

// TestClient_ReconnectListener_NilSafe verifies registration works without a
// listener configured.
func TestClient_ReconnectListener_NilSafe(t *testing.T) {
	addr := startReconnectMockServer(t)

	cfg := &Config{
		Enabled:          true,
		Address:          addr,
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, client.Connect(ctx))
	require.NoError(t, client.register(ctx))
	assert.True(t, client.IsConnected())

	client.mu.Lock()
	if client.conn != nil {
		_ = client.conn.Close()
		client.conn = nil
		client.client = nil
	}
	client.mu.Unlock()
}
