// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

// Tests for the reconnect connection-leak fix (C4): every Connect must close
// the previous grpc.ClientConn before replacing it, so repeated reconnect
// attempts never accumulate live connections (goroutines/sockets), and the
// Connect/Stop paths never double-close the same connection.
package operator

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/protobuf/types/known/durationpb"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// currentConn returns the client's current connection under the read lock.
func currentConn(c *Client) *grpc.ClientConn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}

// TestClient_Connect_ClosesPreviousConnection verifies that N sequential
// Connect calls leave exactly one live connection: every predecessor is
// closed (connectivity.Shutdown) when it is replaced.
func TestClient_Connect_ClosesPreviousConnection(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "127.0.0.1:0", // grpc.NewClient is lazy; no server needed
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	const attempts = 5
	conns := make([]*grpc.ClientConn, 0, attempts)

	for i := 0; i < attempts; i++ {
		require.NoError(t, client.Connect(context.Background()), "connect %d", i)
		conn := currentConn(client)
		require.NotNil(t, conn, "connect %d must install a connection", i)
		conns = append(conns, conn)
	}

	t.Cleanup(func() {
		_ = conns[len(conns)-1].Close()
	})

	// Every connection except the newest must have been closed on replacement.
	for i := 0; i < attempts-1; i++ {
		assert.Equal(t, connectivity.Shutdown, conns[i].GetState(),
			"connection %d must be closed when replaced by connect %d", i, i+1)
	}
	assert.NotEqual(t, connectivity.Shutdown, conns[attempts-1].GetState(),
		"the newest connection must remain live")

	// Each replacement produced a distinct ClientConn.
	seen := make(map[*grpc.ClientConn]struct{}, attempts)
	for _, conn := range conns {
		seen[conn] = struct{}{}
	}
	assert.Len(t, seen, attempts, "every Connect must create a fresh connection")
}

// TestClient_Connect_PreviousAlreadyClosed_LogsAndProceeds verifies Connect
// tolerates a previous connection that was already closed elsewhere: the
// close error is logged (not returned) and the new connection is installed.
func TestClient_Connect_PreviousAlreadyClosed_LogsAndProceeds(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "127.0.0.1:0",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	require.NoError(t, client.Connect(context.Background()))
	first := currentConn(client)
	require.NotNil(t, first)
	require.NoError(t, first.Close())

	// Second Connect finds an already-closed predecessor: Close returns an
	// error, which must be swallowed (logged) and the swap must proceed.
	require.NoError(t, client.Connect(context.Background()))
	second := currentConn(client)
	require.NotNil(t, second)
	assert.NotSame(t, first, second)
	assert.NotEqual(t, connectivity.Shutdown, second.GetState())

	t.Cleanup(func() {
		_ = second.Close()
	})
}

// TestClient_ReconnectThenStop_NoDoubleClose exercises the full lifecycle
// under -race: Start (connect + register), reconnects that replace-and-close
// the live connection, then Stop closing the final one. The same ClientConn
// is never closed twice: Connect closes only the conn it replaces, and Stop
// closes the current conn and nils the field.
func TestClient_ReconnectThenStop_NoDoubleClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.RegisterGatewayResponse{
			Success:           true,
			SessionId:         "leak-test-session",
			HeartbeatInterval: durationpb.New(30 * time.Second),
		}, nil,
	)
	mockServer.On("StreamConfiguration", mock.Anything, mock.Anything).Return(nil)
	mockServer.On("Heartbeat", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.HeartbeatResponse{Acknowledged: true}, nil,
	)

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	require.NoError(t, client.Start(context.Background()))

	first := currentConn(client)
	require.NotNil(t, first)

	// Simulate reconnect attempts replacing the live connection.
	require.NoError(t, client.Connect(context.Background()))
	second := currentConn(client)
	require.NoError(t, client.Connect(context.Background()))
	third := currentConn(client)

	assert.Equal(t, connectivity.Shutdown, first.GetState(),
		"first connection must be closed by the first reconnect")
	assert.Equal(t, connectivity.Shutdown, second.GetState(),
		"second connection must be closed by the second reconnect")
	assert.NotEqual(t, connectivity.Shutdown, third.GetState(),
		"current connection must be live before Stop")

	require.NoError(t, client.Stop())

	assert.Nil(t, currentConn(client), "Stop must clear the connection")
	assert.Equal(t, connectivity.Shutdown, third.GetState(),
		"Stop must close the current connection")
}
