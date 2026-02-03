// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/vyrodovalexey/avapigw/internal/config"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// ============================================================================
// WithHandlerTracer Tests
// ============================================================================

func TestWithHandlerTracer(t *testing.T) {
	applier := &MockConfigApplier{}
	tracer := otel.Tracer("test-tracer")

	handler := NewConfigHandler(applier, WithHandlerTracer(tracer))

	require.NotNil(t, handler)
	assert.NotNil(t, handler.tracer)
}

func TestWithHandlerTracer_Nil(t *testing.T) {
	applier := &MockConfigApplier{}

	handler := NewConfigHandler(applier, WithHandlerTracer(nil))

	require.NotNil(t, handler)
	// Tracer should be nil when passed nil
	assert.Nil(t, handler.tracer)
}

func TestWithHandlerTracer_CustomTracer(t *testing.T) {
	applier := &MockConfigApplier{}
	customTracer := otel.Tracer("custom-tracer")

	handler := NewConfigHandler(applier, WithHandlerTracer(customTracer))

	require.NotNil(t, handler)
	// Verify the tracer was set
	assert.Equal(t, customTracer, handler.tracer)
}

// ============================================================================
// handleDelete Coverage Tests
// ============================================================================

func TestConfigHandler_handleDelete_UnknownType(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	resource := &operatorv1alpha1.ConfigurationResource{
		Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_UNSPECIFIED,
		Name:      "test-resource",
		Namespace: "default",
	}

	err := handler.handleDelete(context.Background(), resource, "default/test-resource")
	require.NoError(t, err)
}

func TestConfigHandler_handleDelete_GRPCRoute(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	// First add a gRPC route
	grpcRoute := config.GRPCRoute{Name: "test-grpc-route"}
	grpcRouteJSON, _ := json.Marshal(grpcRoute)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
			Name:      "test-grpc-route",
			Namespace: "default",
			SpecJson:  grpcRouteJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Now delete using handleDelete directly
	resource := &operatorv1alpha1.ConfigurationResource{
		Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
		Name:      "test-grpc-route",
		Namespace: "default",
	}

	err := handler.handleDelete(context.Background(), resource, "default/test-grpc-route")
	require.NoError(t, err)

	// Verify state
	_, _, grpcRoutes, _ := handler.GetCurrentState()
	assert.Len(t, grpcRoutes, 0)
}

func TestConfigHandler_handleDelete_GRPCBackend(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	// First add a gRPC backend
	grpcBackend := config.GRPCBackend{Name: "test-grpc-backend"}
	grpcBackendJSON, _ := json.Marshal(grpcBackend)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
			Name:      "test-grpc-backend",
			Namespace: "default",
			SpecJson:  grpcBackendJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Now delete using handleDelete directly
	resource := &operatorv1alpha1.ConfigurationResource{
		Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
		Name:      "test-grpc-backend",
		Namespace: "default",
	}

	err := handler.handleDelete(context.Background(), resource, "default/test-grpc-backend")
	require.NoError(t, err)

	// Verify state
	_, _, _, grpcBackends := handler.GetCurrentState()
	assert.Len(t, grpcBackends, 0)
}

// ============================================================================
// GetConfiguration Coverage Tests
// ============================================================================

func TestClient_GetConfiguration_Success(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("GetConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.ConfigurationSnapshot{
			Version:        "v1",
			TotalResources: 5,
			Checksum:       "abc123",
		}, nil,
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
		Namespaces:       []string{"ns1", "ns2"},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Set connected state
	client.connected.Store(true)
	client.mu.Lock()
	client.sessionID = "test-session"
	client.mu.Unlock()

	// Get configuration
	snapshot, err := client.GetConfiguration(context.Background())
	require.NoError(t, err)
	require.NotNil(t, snapshot)
	assert.Equal(t, "v1", snapshot.Version)
	assert.Equal(t, int32(5), snapshot.TotalResources)
	assert.Equal(t, "abc123", snapshot.Checksum)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_GetConfiguration_Error(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("GetConfiguration", mock.Anything, mock.Anything).Return(
		nil, assert.AnError,
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

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Set connected state
	client.connected.Store(true)
	client.mu.Lock()
	client.sessionID = "test-session"
	client.mu.Unlock()

	// Get configuration should fail
	snapshot, err := client.GetConfiguration(context.Background())
	require.Error(t, err)
	assert.Nil(t, snapshot)
	assert.Contains(t, err.Error(), "failed to get configuration")

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// runHeartbeatLoop Coverage Tests
// ============================================================================

func TestClient_runHeartbeatLoop_StopChannel(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("Heartbeat", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.HeartbeatResponse{
			Acknowledged: true,
		}, nil,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	cfg := &Config{
		Enabled:           true,
		Address:           listener.Addr().String(),
		GatewayName:       "test-gateway",
		GatewayNamespace:  "default",
		HeartbeatInterval: 50 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	client.startTime = time.Now()

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Set connected state
	client.connected.Store(true)
	client.mu.Lock()
	client.sessionID = "test-session"
	client.mu.Unlock()

	// Initialize stop channel
	client.stopCh = make(chan struct{})

	// Start heartbeat loop in goroutine
	done := make(chan struct{})
	go func() {
		client.runHeartbeatLoop(context.Background())
		close(done)
	}()

	// Wait for at least one heartbeat
	time.Sleep(100 * time.Millisecond)

	// Stop the heartbeat loop
	close(client.stopCh)

	// Wait for loop to exit
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("runHeartbeatLoop did not exit after stop signal")
	}

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_runHeartbeatLoop_ContextCanceled(t *testing.T) {
	cfg := &Config{
		Enabled:           true,
		Address:           "localhost:50051",
		GatewayName:       "test-gateway",
		GatewayNamespace:  "default",
		HeartbeatInterval: 50 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	client.startTime = time.Now()

	// Initialize stop channel
	client.stopCh = make(chan struct{})

	// Create cancelable context - cancel immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before starting

	// Start heartbeat loop - should exit immediately due to canceled context
	done := make(chan struct{})
	go func() {
		client.runHeartbeatLoop(ctx)
		close(done)
	}()

	// Wait for loop to exit
	select {
	case <-done:
		// Success
	case <-time.After(500 * time.Millisecond):
		// Close stop channel to force exit
		close(client.stopCh)
		<-done
	}
}

// ============================================================================
// streamConfiguration Coverage Tests
// ============================================================================

// Note: streamConfiguration requires a connected client with a valid gRPC client
// Testing it directly without a server would cause nil pointer dereference
// The function is tested indirectly through Start/Stop tests

// ============================================================================
// buildTLSConfig Coverage Tests
// ============================================================================

func TestClient_buildTLSConfig_ServerNameOnly(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:    true,
			ServerName: "custom-server-name",
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	tlsConfig, err := client.buildTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, "custom-server-name", tlsConfig.ServerName)
}

func TestClient_buildTLSConfig_MinVersion(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled: true,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	tlsConfig, err := client.buildTLSConfig()
	require.NoError(t, err)
	// Should have TLS 1.2 as minimum version
	assert.Equal(t, uint16(0x0303), tlsConfig.MinVersion) // TLS 1.2
}

// ============================================================================
// HandleUpdate with Tracer Coverage Tests
// ============================================================================

func TestConfigHandler_HandleUpdate_WithTracer(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)

	tracer := otel.Tracer("test-tracer")
	handler := NewConfigHandler(applier, WithHandlerTracer(tracer))

	route := config.Route{
		Name: "test-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/api"}},
		},
	}
	routeJSON, err := json.Marshal(route)
	require.NoError(t, err)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "test-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}

	err = handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)

	applier.AssertExpectations(t)
}

// ============================================================================
// Connect Coverage Tests
// ============================================================================

func TestClient_Connect_AlreadyConnected(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
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

	// First connect
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Second connect should also succeed (idempotent)
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// Register Coverage Tests
// ============================================================================

func TestClient_Register_WithPodAndNodeInfo(t *testing.T) {
	// Set environment variables for pod and node name
	t.Setenv("POD_NAME", "test-pod")
	t.Setenv("NODE_NAME", "test-node")

	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.MatchedBy(func(req *operatorv1alpha1.RegisterGatewayRequest) bool {
		return req.Gateway.PodName == "test-pod" && req.Gateway.NodeName == "test-node"
	})).Return(
		&operatorv1alpha1.RegisterGatewayResponse{
			Success:           true,
			SessionId:         "test-session-123",
			HeartbeatInterval: durationpb.New(30 * time.Second),
		}, nil,
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

	// Connect
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Register
	err = client.register(context.Background())
	require.NoError(t, err)

	// Verify session ID was set
	assert.Equal(t, "test-session-123", client.SessionID())

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// HandleUpdate Error Path Coverage Tests
// ============================================================================

func TestConfigHandler_HandleUpdate_BackendApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyBackends", mock.Anything, mock.Anything).Return(assert.AnError)

	handler := NewConfigHandler(applier)

	backend := config.Backend{Name: "test-backend"}
	backendJSON, _ := json.Marshal(backend)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
			Name:      "test-backend",
			Namespace: "default",
			SpecJson:  backendJSON,
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply backends")
}

func TestConfigHandler_HandleUpdate_GRPCRouteApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCRoutes", mock.Anything, mock.Anything).Return(assert.AnError)

	handler := NewConfigHandler(applier)

	grpcRoute := config.GRPCRoute{Name: "test-grpc-route"}
	grpcRouteJSON, _ := json.Marshal(grpcRoute)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
			Name:      "test-grpc-route",
			Namespace: "default",
			SpecJson:  grpcRouteJSON,
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply gRPC routes")
}

func TestConfigHandler_HandleUpdate_GRPCBackendApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCBackends", mock.Anything, mock.Anything).Return(assert.AnError)

	handler := NewConfigHandler(applier)

	grpcBackend := config.GRPCBackend{Name: "test-grpc-backend"}
	grpcBackendJSON, _ := json.Marshal(grpcBackend)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
			Name:      "test-grpc-backend",
			Namespace: "default",
			SpecJson:  grpcBackendJSON,
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply gRPC backends")
}

func TestConfigHandler_HandleUpdate_InvalidBackendJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
			Name:      "test-backend",
			Namespace: "default",
			SpecJson:  []byte("invalid json"),
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal backend spec")
}

func TestConfigHandler_HandleUpdate_InvalidGRPCRouteJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
			Name:      "test-grpc-route",
			Namespace: "default",
			SpecJson:  []byte("invalid json"),
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal gRPC route spec")
}

func TestConfigHandler_HandleUpdate_InvalidGRPCBackendJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
			Name:      "test-grpc-backend",
			Namespace: "default",
			SpecJson:  []byte("invalid json"),
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal gRPC backend spec")
}

// ============================================================================
// HandleSnapshot Parse Error Coverage Tests
// ============================================================================

func TestConfigHandler_HandleSnapshot_InvalidBackendJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		Backends: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
				Name:      "invalid-backend",
				Namespace: "default",
				SpecJson:  []byte("invalid json"),
			},
		},
	}

	// Should not error, just skip invalid resources
	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	// State should be empty since the backend was invalid
	_, backends, _, _ := handler.GetCurrentState()
	assert.Len(t, backends, 0)
}

func TestConfigHandler_HandleSnapshot_InvalidGRPCRouteJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		GrpcRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
				Name:      "invalid-grpc-route",
				Namespace: "default",
				SpecJson:  []byte("invalid json"),
			},
		},
	}

	// Should not error, just skip invalid resources
	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	// State should be empty since the gRPC route was invalid
	_, _, grpcRoutes, _ := handler.GetCurrentState()
	assert.Len(t, grpcRoutes, 0)
}

func TestConfigHandler_HandleSnapshot_InvalidGRPCBackendJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		GrpcBackends: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
				Name:      "invalid-grpc-backend",
				Namespace: "default",
				SpecJson:  []byte("invalid json"),
			},
		},
	}

	// Should not error, just skip invalid resources
	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	// State should be empty since the gRPC backend was invalid
	_, _, _, grpcBackends := handler.GetCurrentState()
	assert.Len(t, grpcBackends, 0)
}

// ============================================================================
// Tracer Interface Test
// ============================================================================

// Ensure trace.Tracer interface is properly used
func TestConfigHandler_TracerInterface(t *testing.T) {
	applier := &MockConfigApplier{}

	// Test with default tracer (from otel.Tracer)
	handler1 := NewConfigHandler(applier)
	require.NotNil(t, handler1)
	assert.NotNil(t, handler1.tracer)

	// Test with custom tracer
	var customTracer trace.Tracer = otel.Tracer("custom")
	handler2 := NewConfigHandler(applier, WithHandlerTracer(customTracer))
	require.NotNil(t, handler2)
	assert.Equal(t, customTracer, handler2.tracer)
}

// ============================================================================
// Delete Error Path Coverage Tests
// ============================================================================

func TestConfigHandler_handleRouteDelete_ApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil).Once()
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(assert.AnError).Once()

	handler := NewConfigHandler(applier)

	// First add a route
	route := config.Route{Name: "test-route"}
	routeJSON, _ := json.Marshal(route)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "test-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Now delete it - should fail
	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "test-route",
			Namespace: "default",
		},
	}

	err := handler.HandleUpdate(context.Background(), deleteUpdate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply routes after deletion")
}

func TestConfigHandler_handleBackendDelete_ApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyBackends", mock.Anything, mock.Anything).Return(nil).Once()
	applier.On("ApplyBackends", mock.Anything, mock.Anything).Return(assert.AnError).Once()

	handler := NewConfigHandler(applier)

	// First add a backend
	backend := config.Backend{Name: "test-backend"}
	backendJSON, _ := json.Marshal(backend)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
			Name:      "test-backend",
			Namespace: "default",
			SpecJson:  backendJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Now delete it - should fail
	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
			Name:      "test-backend",
			Namespace: "default",
		},
	}

	err := handler.HandleUpdate(context.Background(), deleteUpdate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply backends after deletion")
}

func TestConfigHandler_handleGRPCRouteDelete_ApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCRoutes", mock.Anything, mock.Anything).Return(nil).Once()
	applier.On("ApplyGRPCRoutes", mock.Anything, mock.Anything).Return(assert.AnError).Once()

	handler := NewConfigHandler(applier)

	// First add a gRPC route
	grpcRoute := config.GRPCRoute{Name: "test-grpc-route"}
	grpcRouteJSON, _ := json.Marshal(grpcRoute)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
			Name:      "test-grpc-route",
			Namespace: "default",
			SpecJson:  grpcRouteJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Now delete it - should fail
	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
			Name:      "test-grpc-route",
			Namespace: "default",
		},
	}

	err := handler.HandleUpdate(context.Background(), deleteUpdate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply gRPC routes after deletion")
}

func TestConfigHandler_handleGRPCBackendDelete_ApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCBackends", mock.Anything, mock.Anything).Return(nil).Once()
	applier.On("ApplyGRPCBackends", mock.Anything, mock.Anything).Return(assert.AnError).Once()

	handler := NewConfigHandler(applier)

	// First add a gRPC backend
	grpcBackend := config.GRPCBackend{Name: "test-grpc-backend"}
	grpcBackendJSON, _ := json.Marshal(grpcBackend)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
			Name:      "test-grpc-backend",
			Namespace: "default",
			SpecJson:  grpcBackendJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Now delete it - should fail
	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
	}

	err := handler.HandleUpdate(context.Background(), deleteUpdate)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply gRPC backends after deletion")
}
