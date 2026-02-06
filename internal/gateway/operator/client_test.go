// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// MockConfigurationServiceServer is a mock gRPC server for testing.
type MockConfigurationServiceServer struct {
	operatorv1alpha1.UnimplementedConfigurationServiceServer
	mock.Mock
	mu sync.Mutex
}

func (m *MockConfigurationServiceServer) RegisterGateway(
	ctx context.Context, req *operatorv1alpha1.RegisterGatewayRequest,
) (*operatorv1alpha1.RegisterGatewayResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*operatorv1alpha1.RegisterGatewayResponse), args.Error(1)
}

func (m *MockConfigurationServiceServer) StreamConfiguration(
	req *operatorv1alpha1.StreamConfigurationRequest,
	stream operatorv1alpha1.ConfigurationService_StreamConfigurationServer,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(req, stream)
	return args.Error(0)
}

func (m *MockConfigurationServiceServer) GetConfiguration(
	ctx context.Context, req *operatorv1alpha1.GetConfigurationRequest,
) (*operatorv1alpha1.ConfigurationSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*operatorv1alpha1.ConfigurationSnapshot), args.Error(1)
}

func (m *MockConfigurationServiceServer) Heartbeat(
	ctx context.Context, req *operatorv1alpha1.HeartbeatRequest,
) (*operatorv1alpha1.HeartbeatResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*operatorv1alpha1.HeartbeatResponse), args.Error(1)
}

func (m *MockConfigurationServiceServer) AcknowledgeConfiguration(
	ctx context.Context, req *operatorv1alpha1.AcknowledgeConfigurationRequest,
) (*operatorv1alpha1.AcknowledgeConfigurationResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*operatorv1alpha1.AcknowledgeConfigurationResponse), args.Error(1)
}

// MockStatusProvider is a mock implementation of StatusProvider.
type MockStatusProvider struct {
	mock.Mock
}

func (m *MockStatusProvider) GetActiveConnections() int64 {
	args := m.Called()
	return args.Get(0).(int64)
}

func (m *MockStatusProvider) GetRequestsPerSecond() float64 {
	args := m.Called()
	return args.Get(0).(float64)
}

func (m *MockStatusProvider) GetErrorRate() float64 {
	args := m.Called()
	return args.Get(0).(float64)
}

func (m *MockStatusProvider) GetMemoryBytes() int64 {
	args := m.Called()
	return args.Get(0).(int64)
}

func (m *MockStatusProvider) GetCPUUsage() float64 {
	args := m.Called()
	return args.Get(0).(float64)
}

func (m *MockStatusProvider) IsHealthy() bool {
	args := m.Called()
	return args.Bool(0)
}

func TestNewClient_NilConfig(t *testing.T) {
	client, err := NewClient(nil)
	require.Error(t, err)
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestNewClient_ValidConfig(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Equal(t, cfg, client.config)
	assert.NotNil(t, client.metrics)
}

func TestNewClient_DisabledConfig(t *testing.T) {
	cfg := &Config{
		Enabled: false,
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestNewClient_InvalidConfig(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		// Missing required fields
	}

	client, err := NewClient(cfg)
	require.Error(t, err)
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestNewClient_WithOptions(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	registry := prometheus.NewRegistry()
	statusProvider := &MockStatusProvider{}

	client, err := NewClient(cfg,
		WithLogger(nil),
		WithMetricsRegistry(registry),
		WithStatusProvider(statusProvider),
		WithConfigUpdateHandler(func(ctx context.Context, update *operatorv1alpha1.ConfigurationUpdate) error {
			return nil
		}),
		WithSnapshotHandler(func(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error {
			return nil
		}),
	)

	require.NoError(t, err)
	require.NotNil(t, client)
	assert.NotNil(t, client.statusProvider)
	assert.NotNil(t, client.onConfigUpdate)
	assert.NotNil(t, client.onSnapshot)
}

func TestClient_IsConnected(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Initially not connected
	assert.False(t, client.IsConnected())

	// Set connected
	client.connected.Store(true)
	assert.True(t, client.IsConnected())

	// Set disconnected
	client.connected.Store(false)
	assert.False(t, client.IsConnected())
}

func TestClient_SessionID(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Initially empty
	assert.Empty(t, client.SessionID())

	// Set session ID
	client.mu.Lock()
	client.sessionID = "test-session-123"
	client.mu.Unlock()

	assert.Equal(t, "test-session-123", client.SessionID())
}

func TestClient_SetConfigUpdateHandler(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	handler := func(ctx context.Context, update *operatorv1alpha1.ConfigurationUpdate) error {
		return nil
	}

	client.SetConfigUpdateHandler(handler)
	assert.NotNil(t, client.onConfigUpdate)
}

func TestClient_SetSnapshotHandler(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	handler := func(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error {
		return nil
	}

	client.SetSnapshotHandler(handler)
	assert.NotNil(t, client.onSnapshot)
}

func TestClient_Stop_NotStarted(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	err = client.Stop()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotStarted)
}

func TestClient_Start_AlreadyStarted(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Simulate already started
	client.started.Store(true)

	err = client.Start(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadyStarted)
}

func TestClient_CalculateBackoff(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		ReconnectBackoff: BackoffConfig{
			InitialInterval: 1 * time.Second,
			MaxInterval:     30 * time.Second,
			Multiplier:      2.0,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	tests := []struct {
		name     string
		attempts int
		expected time.Duration
	}{
		{
			name:     "first attempt",
			attempts: 1,
			expected: 1 * time.Second,
		},
		{
			name:     "second attempt",
			attempts: 2,
			expected: 2 * time.Second,
		},
		{
			name:     "third attempt",
			attempts: 3,
			expected: 4 * time.Second,
		},
		{
			name:     "capped at max",
			attempts: 10,
			expected: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.reconnectAttempts = tt.attempts
			backoff := client.calculateBackoff()
			assert.Equal(t, tt.expected, backoff)
		})
	}
}

func TestClient_BuildGatewayStatus(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	client.startTime = time.Now().Add(-1 * time.Hour)

	// Test without status provider
	status := client.buildGatewayStatus(time.Now())
	assert.Equal(t, operatorv1alpha1.HealthState_HEALTH_STATE_HEALTHY, status.Health)
	assert.NotNil(t, status.Uptime)

	// Test with status provider
	statusProvider := &MockStatusProvider{}
	statusProvider.On("GetActiveConnections").Return(int64(100))
	statusProvider.On("GetRequestsPerSecond").Return(float64(50.5))
	statusProvider.On("GetErrorRate").Return(float64(0.01))
	statusProvider.On("GetMemoryBytes").Return(int64(1024 * 1024 * 100))
	statusProvider.On("GetCPUUsage").Return(float64(0.25))
	statusProvider.On("IsHealthy").Return(true)

	client.statusProvider = statusProvider

	status = client.buildGatewayStatus(time.Now())
	assert.Equal(t, operatorv1alpha1.HealthState_HEALTH_STATE_HEALTHY, status.Health)
	assert.Equal(t, int64(100), status.ActiveConnections)
	assert.Equal(t, float64(50.5), status.RequestsPerSecond)
	assert.Equal(t, float64(0.01), status.ErrorRate)
	assert.Equal(t, int64(1024*1024*100), status.MemoryBytes)
	assert.Equal(t, float64(0.25), status.CpuUsage)

	statusProvider.AssertExpectations(t)
}

func TestClient_BuildGatewayStatus_Unhealthy(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)
	client.startTime = time.Now()

	statusProvider := &MockStatusProvider{}
	statusProvider.On("GetActiveConnections").Return(int64(0))
	statusProvider.On("GetRequestsPerSecond").Return(float64(0))
	statusProvider.On("GetErrorRate").Return(float64(0.5))
	statusProvider.On("GetMemoryBytes").Return(int64(0))
	statusProvider.On("GetCPUUsage").Return(float64(0))
	statusProvider.On("IsHealthy").Return(false)

	client.statusProvider = statusProvider

	status := client.buildGatewayStatus(time.Now())
	assert.Equal(t, operatorv1alpha1.HealthState_HEALTH_STATE_DEGRADED, status.Health)

	statusProvider.AssertExpectations(t)
}

func TestClient_GetConfiguration_NotConnected(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	snapshot, err := client.GetConfiguration(context.Background())
	require.Error(t, err)
	assert.Nil(t, snapshot)
	assert.ErrorIs(t, err, ErrNotConnected)
}

// Integration test with mock server
func TestClient_ConnectAndRegister(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
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

	// Create client
	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Connect
	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Verify connection was established
	assert.NotNil(t, client.conn)
	assert.NotNil(t, client.client)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_Connect_WithTLS(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Build dial options should work with TLS config
	opts, err := client.buildDialOptions()
	require.NoError(t, err)
	assert.NotEmpty(t, opts)
}

func TestClient_Connect_WithoutTLS(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Build dial options should work without TLS
	opts, err := client.buildDialOptions()
	require.NoError(t, err)
	assert.NotEmpty(t, opts)
}

func TestWithLogger(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	// When nil is passed, the client should still have a logger (NopLogger is set in NewClient)
	_, err := NewClient(cfg, WithLogger(nil))
	require.NoError(t, err)
	// Logger is set to nil by the option, but NewClient doesn't override it
	// The default is set before options are applied
}

func TestWithTracer(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	// When nil is passed, the tracer is set to nil
	client, err := NewClient(cfg, WithTracer(nil))
	require.NoError(t, err)
	// Tracer is set to nil by the option
	_ = client
}

func TestClient_StartAndStop(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.RegisterGatewayResponse{
			Success:           true,
			SessionId:         "test-session-123",
			HeartbeatInterval: durationpb.New(30 * time.Second),
		}, nil,
	)
	mockServer.On("StreamConfiguration", mock.Anything, mock.Anything).Return(nil).Maybe()
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

	// Create client with short heartbeat interval for testing
	cfg := &Config{
		Enabled:           true,
		Address:           listener.Addr().String(),
		GatewayName:       "test-gateway",
		GatewayNamespace:  "default",
		HeartbeatInterval: 100 * time.Millisecond,
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Start client
	ctx := context.Background()
	err = client.Start(ctx)
	require.NoError(t, err)

	// Verify started
	assert.True(t, client.started.Load())
	assert.True(t, client.IsConnected())
	assert.Equal(t, "test-session-123", client.SessionID())

	// Wait a bit for heartbeat
	time.Sleep(150 * time.Millisecond)

	// Stop client
	err = client.Stop()
	require.NoError(t, err)

	// Verify stopped
	assert.False(t, client.started.Load())
	assert.False(t, client.IsConnected())
}

func TestClient_HandleUpdate(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{
			Received: true,
		}, nil,
	).Maybe()

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

	handlerCalled := false
	client, err := NewClient(cfg, WithConfigUpdateHandler(func(ctx context.Context, update *operatorv1alpha1.ConfigurationUpdate) error {
		handlerCalled = true
		return nil
	}))
	require.NoError(t, err)

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
	}

	err = client.handleUpdate(context.Background(), update)
	require.NoError(t, err)
	assert.True(t, handlerCalled)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_HandleUpdate_FullSync(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{
			Received: true,
		}, nil,
	).Maybe()

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

	snapshotHandlerCalled := false
	client, err := NewClient(cfg, WithSnapshotHandler(func(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error {
		snapshotHandlerCalled = true
		return nil
	}))
	require.NoError(t, err)

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC,
		Version:  "v1",
		Sequence: 1,
		Snapshot: &operatorv1alpha1.ConfigurationSnapshot{
			Version: "v1",
		},
	}

	err = client.handleUpdate(context.Background(), update)
	require.NoError(t, err)
	assert.True(t, snapshotHandlerCalled)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_HandleUpdate_Heartbeat(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{
			Received: true,
		}, nil,
	).Maybe()

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

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_HEARTBEAT,
		Version:  "v1",
		Sequence: 1,
	}

	// Should not error
	err = client.handleUpdate(context.Background(), update)
	require.NoError(t, err)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_HandleUpdate_OutOfOrder(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{
			Received: true,
		}, nil,
	).Maybe()

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

	handlerCalled := false
	client, err := NewClient(cfg, WithConfigUpdateHandler(func(ctx context.Context, update *operatorv1alpha1.ConfigurationUpdate) error {
		handlerCalled = true
		return nil
	}))
	require.NoError(t, err)

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Set last applied sequence
	client.mu.Lock()
	client.lastAppliedSequence = 10
	client.mu.Unlock()

	// Send update with lower sequence
	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 5, // Lower than lastAppliedSequence
	}

	err = client.handleUpdate(context.Background(), update)
	require.NoError(t, err)
	// Handler should not be called for out-of-order updates
	assert.False(t, handlerCalled)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_HandleSnapshot(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	handlerCalled := false
	client, err := NewClient(cfg, WithSnapshotHandler(func(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error {
		handlerCalled = true
		return nil
	}))
	require.NoError(t, err)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 0,
	}

	err = client.handleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)
	assert.True(t, handlerCalled)
}

func TestClient_HandleSnapshot_NoHandler(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 0,
	}

	// Should not error even without handler
	err = client.handleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)
}

// Test that client properly uses insecure credentials when TLS is disabled
func TestClient_BuildDialOptions_Insecure(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS:              nil, // No TLS
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	opts, err := client.buildDialOptions()
	require.NoError(t, err)
	assert.NotEmpty(t, opts)
}

// Test connection to a non-existent server
func TestClient_Connect_Failure(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:59999", // Non-existent port
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Connect should succeed (lazy connection)
	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// But the connection won't actually work until we try to use it
	assert.NotNil(t, client.conn)
}

// Test that Start fails when connection fails during registration
func TestClient_Start_RegistrationFailure(t *testing.T) {
	// Start mock server that rejects registration
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.RegisterGatewayResponse{
			Success:      false,
			ErrorMessage: "registration rejected",
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

	// Pre-connect
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	client.conn = conn
	client.client = operatorv1alpha1.NewConfigurationServiceClient(conn)

	// Start should fail due to registration rejection
	err = client.Start(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRegistrationFailed)
}

// ============================================================================
// sendHeartbeat Tests
// ============================================================================

func TestClient_SendHeartbeat_Success(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("Heartbeat", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.HeartbeatResponse{
			Acknowledged:    true,
			ShouldReconnect: false,
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
	client.startTime = time.Now()

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Set connected state
	client.connected.Store(true)
	client.mu.Lock()
	client.sessionID = "test-session"
	client.mu.Unlock()

	// Send heartbeat
	client.sendHeartbeat(context.Background())

	// Verify heartbeat was called
	mockServer.AssertCalled(t, "Heartbeat", mock.Anything, mock.Anything)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_SendHeartbeat_ShouldReconnect(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("Heartbeat", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.HeartbeatResponse{
			Acknowledged:    true,
			ShouldReconnect: true,
			Message:         "please reconnect",
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
	client.startTime = time.Now()

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Set connected state
	client.connected.Store(true)
	client.mu.Lock()
	client.sessionID = "test-session"
	client.mu.Unlock()

	// Send heartbeat
	client.sendHeartbeat(context.Background())

	// Verify connected state was set to false due to ShouldReconnect
	assert.False(t, client.IsConnected())

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_SendHeartbeat_Error(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("Heartbeat", mock.Anything, mock.Anything).Return(
		nil, errors.New("heartbeat failed"),
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
	client.startTime = time.Now()

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)

	// Set connected state
	client.connected.Store(true)
	client.mu.Lock()
	client.sessionID = "test-session"
	client.mu.Unlock()

	// Send heartbeat - should not panic on error
	client.sendHeartbeat(context.Background())

	// Verify heartbeat was called
	mockServer.AssertCalled(t, "Heartbeat", mock.Anything, mock.Anything)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

func TestClient_SendHeartbeat_WithStatusProvider(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("Heartbeat", mock.Anything, mock.MatchedBy(func(req *operatorv1alpha1.HeartbeatRequest) bool {
		// Verify status is populated from status provider
		return req.Status != nil &&
			req.Status.ActiveConnections == 100 &&
			req.Status.RequestsPerSecond == 50.0
	})).Return(
		&operatorv1alpha1.HeartbeatResponse{
			Acknowledged: true,
		}, nil,
	)

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	// Create status provider mock
	statusProvider := &MockStatusProvider{}
	statusProvider.On("GetActiveConnections").Return(int64(100))
	statusProvider.On("GetRequestsPerSecond").Return(float64(50.0))
	statusProvider.On("GetErrorRate").Return(float64(0.01))
	statusProvider.On("GetMemoryBytes").Return(int64(1024 * 1024))
	statusProvider.On("GetCPUUsage").Return(float64(0.25))
	statusProvider.On("IsHealthy").Return(true)

	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg, WithStatusProvider(statusProvider))
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

	// Send heartbeat
	client.sendHeartbeat(context.Background())

	// Verify status provider was called
	statusProvider.AssertExpectations(t)

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// reconnectWithBackoff Tests
// ============================================================================

func TestClient_ReconnectWithBackoff_StopChannel(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:59999", // Non-existent
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		ReconnectBackoff: BackoffConfig{
			InitialInterval: 10 * time.Millisecond,
			MaxInterval:     100 * time.Millisecond,
			Multiplier:      2.0,
			MaxRetries:      0, // Unlimited
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Initialize stop channel
	client.stopCh = make(chan struct{})

	// Start reconnect in goroutine
	resultCh := make(chan bool, 1)
	go func() {
		resultCh <- client.reconnectWithBackoff(context.Background())
	}()

	// Close stop channel to signal stop
	time.Sleep(50 * time.Millisecond)
	close(client.stopCh)

	// Wait for result
	select {
	case result := <-resultCh:
		assert.False(t, result, "reconnectWithBackoff should return false when stopped")
	case <-time.After(2 * time.Second):
		t.Error("reconnectWithBackoff did not return after stop signal")
	}
}

func TestClient_ReconnectWithBackoff_MaxRetries(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:59999", // Non-existent
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		ReconnectBackoff: BackoffConfig{
			InitialInterval: 1 * time.Millisecond,
			MaxInterval:     10 * time.Millisecond,
			Multiplier:      1.5,
			MaxRetries:      2, // Only 2 retries
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Initialize stop channel
	client.stopCh = make(chan struct{})

	// Start reconnect
	result := client.reconnectWithBackoff(context.Background())

	// Should return false after max retries
	assert.False(t, result, "reconnectWithBackoff should return false after max retries")
	assert.Equal(t, 3, client.reconnectAttempts, "should have attempted 3 times (initial + 2 retries)")
}

func TestClient_ReconnectWithBackoff_Success(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("RegisterGateway", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.RegisterGatewayResponse{
			Success:           true,
			SessionId:         "new-session",
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
		ReconnectBackoff: BackoffConfig{
			InitialInterval: 1 * time.Millisecond,
			MaxInterval:     10 * time.Millisecond,
			Multiplier:      1.5,
			MaxRetries:      5,
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// Initialize stop channel
	client.stopCh = make(chan struct{})
	client.reconnectAttempts = 0

	// Start reconnect
	result := client.reconnectWithBackoff(context.Background())

	// Should return true on successful reconnection
	assert.True(t, result, "reconnectWithBackoff should return true on success")
	assert.Equal(t, 0, client.reconnectAttempts, "reconnectAttempts should be reset to 0")
	assert.True(t, client.IsConnected(), "client should be connected")

	// Clean up
	if client.conn != nil {
		client.conn.Close()
	}
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

func TestClient_BuildTLSConfig_WithCertFiles(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:    true,
			CertFile:   "/nonexistent/cert.pem",
			KeyFile:    "/nonexistent/key.pem",
			ServerName: "test-server",
		},
	}

	// NewClient should fail with non-existent cert files during validation
	_, err := NewClient(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certFile not found")
}

func TestClient_BuildTLSConfig_WithCAFile(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled: true,
			CAFile:  "/nonexistent/ca.pem",
		},
	}

	// NewClient should fail with non-existent CA file during validation
	_, err := NewClient(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "caFile not found")
}

func TestClient_BuildTLSConfig_InsecureSkipVerify(t *testing.T) {
	cfg := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
			ServerName:         "test-server",
		},
	}

	client, err := NewClient(cfg)
	require.NoError(t, err)

	// buildTLSConfig should succeed with InsecureSkipVerify
	tlsConfig, err := client.buildTLSConfig()
	require.NoError(t, err)
	assert.True(t, tlsConfig.InsecureSkipVerify)
	assert.Equal(t, "test-server", tlsConfig.ServerName)
}
