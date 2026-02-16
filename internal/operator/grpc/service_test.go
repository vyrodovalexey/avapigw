// Package grpc provides comprehensive tests for the ConfigurationService gRPC implementation.
package grpc

import (
	"context"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// newTestService creates a configurationServiceImpl backed by a fresh server with its own registry.
func newTestService(t *testing.T) (*configurationServiceImpl, *Server) {
	t.Helper()
	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)
	svc := &configurationServiceImpl{
		server: srv,
		tracer: otel.Tracer(tracerName),
	}
	return svc, srv
}

// ============================================================================
// RegisterGateway Tests
// ============================================================================

func TestRegisterGateway_ValidRequest(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	req := &operatorv1alpha1.RegisterGatewayRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      "test-gw",
			Namespace: "default",
		},
	}

	resp, err := svc.RegisterGateway(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.SessionId)
	assert.NotNil(t, resp.InitialConfig)
	assert.NotNil(t, resp.HeartbeatInterval)
	assert.Equal(t, defaultHeartbeatInterval.Seconds(), resp.HeartbeatInterval.AsDuration().Seconds())

	// Verify gateway was registered on the server
	assert.Equal(t, 1, srv.GetGatewayCount())
}

func TestRegisterGateway_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// A nil request still has GetGateway() == nil
	req := &operatorv1alpha1.RegisterGatewayRequest{}

	resp, err := svc.RegisterGateway(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, resp.Success)
	assert.Equal(t, "gateway info is required", resp.ErrorMessage)
}

func TestRegisterGateway_MissingGatewayInfo(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	req := &operatorv1alpha1.RegisterGatewayRequest{
		Gateway: nil,
	}

	resp, err := svc.RegisterGateway(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, resp.Success)
	assert.Contains(t, resp.ErrorMessage, "gateway info is required")
}

func TestRegisterGateway_WithPopulatedMaps(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	// Populate server maps
	srv.mu.Lock()
	srv.apiRoutes["default/route1"] = []byte(`{"path":"/api"}`)
	srv.backends["default/backend1"] = []byte(`{"host":"svc"}`)
	srv.mu.Unlock()

	req := &operatorv1alpha1.RegisterGatewayRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      "test-gw",
			Namespace: "default",
		},
	}

	resp, err := svc.RegisterGateway(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.NotNil(t, resp.InitialConfig)
	assert.Equal(t, int32(2), resp.InitialConfig.TotalResources)
}

// ============================================================================
// GetConfiguration Tests
// ============================================================================

func TestGetConfiguration_EmptyMaps(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	req := &operatorv1alpha1.GetConfigurationRequest{}

	snapshot, err := svc.GetConfiguration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	assert.Equal(t, int32(0), snapshot.TotalResources)
	assert.Empty(t, snapshot.ApiRoutes)
	assert.Empty(t, snapshot.GrpcRoutes)
	assert.Empty(t, snapshot.Backends)
	assert.Empty(t, snapshot.GrpcBackends)
	assert.NotEmpty(t, snapshot.Checksum)
	assert.NotEmpty(t, snapshot.Version)
	assert.NotNil(t, snapshot.Timestamp)
}

func TestGetConfiguration_PopulatedMaps(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	// Populate all four map types
	srv.mu.Lock()
	srv.apiRoutes["default/route1"] = []byte(`{"path":"/api"}`)
	srv.apiRoutes["default/route2"] = []byte(`{"path":"/v2"}`)
	srv.grpcRoutes["default/grpc1"] = []byte(`{"service":"svc"}`)
	srv.backends["default/be1"] = []byte(`{"host":"be1"}`)
	srv.grpcBackends["default/gbe1"] = []byte(`{"host":"gbe1"}`)
	srv.mu.Unlock()

	req := &operatorv1alpha1.GetConfigurationRequest{}

	snapshot, err := svc.GetConfiguration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	assert.Equal(t, int32(5), snapshot.TotalResources)
	assert.Len(t, snapshot.ApiRoutes, 2)
	assert.Len(t, snapshot.GrpcRoutes, 1)
	assert.Len(t, snapshot.Backends, 1)
	assert.Len(t, snapshot.GrpcBackends, 1)
}

func TestGetConfiguration_WithGatewayInfo(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	req := &operatorv1alpha1.GetConfigurationRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      "my-gw",
			Namespace: "prod",
		},
	}

	snapshot, err := svc.GetConfiguration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, snapshot)
}

func TestGetConfiguration_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Empty request (no gateway info)
	req := &operatorv1alpha1.GetConfigurationRequest{}

	snapshot, err := svc.GetConfiguration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, snapshot)
}

// ============================================================================
// Heartbeat Tests
// ============================================================================

func TestHeartbeat_ValidRequest(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	// Register a gateway first
	srv.RegisterGateway("hb-gw", "default")

	req := &operatorv1alpha1.HeartbeatRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      "hb-gw",
			Namespace: "default",
		},
		SessionId: "session-123",
	}

	resp, err := svc.Heartbeat(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Acknowledged)
	assert.NotNil(t, resp.ServerTime)
}

func TestHeartbeat_NilGatewayInfo(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	req := &operatorv1alpha1.HeartbeatRequest{
		SessionId: "session-456",
	}

	resp, err := svc.Heartbeat(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Acknowledged)
	assert.NotNil(t, resp.ServerTime)
}

func TestHeartbeat_EmptyRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	req := &operatorv1alpha1.HeartbeatRequest{}

	resp, err := svc.Heartbeat(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Acknowledged)
}

// ============================================================================
// AcknowledgeConfiguration Tests
// ============================================================================

func TestAcknowledgeConfiguration_Success(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	req := &operatorv1alpha1.AcknowledgeConfigurationRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      "ack-gw",
			Namespace: "default",
		},
		SessionId:     "session-789",
		ConfigVersion: "42",
		Success:       true,
	}

	resp, err := svc.AcknowledgeConfiguration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Received)
	assert.NotNil(t, resp.ServerTime)
}

func TestAcknowledgeConfiguration_Failure(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	req := &operatorv1alpha1.AcknowledgeConfigurationRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      "ack-gw",
			Namespace: "default",
		},
		SessionId:     "session-fail",
		ConfigVersion: "43",
		Success:       false,
		ErrorMessage:  "config apply failed",
	}

	resp, err := svc.AcknowledgeConfiguration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Received)
	assert.NotNil(t, resp.ServerTime)
}

func TestAcknowledgeConfiguration_NilGateway(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	req := &operatorv1alpha1.AcknowledgeConfigurationRequest{
		SessionId:     "session-nil",
		ConfigVersion: "44",
		Success:       true,
	}

	resp, err := svc.AcknowledgeConfiguration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Received)
}

func TestAcknowledgeConfiguration_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Empty request
	req := &operatorv1alpha1.AcknowledgeConfigurationRequest{}

	resp, err := svc.AcknowledgeConfiguration(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Received)
}

// ============================================================================
// StreamConfiguration Tests
// ============================================================================

// mockServerStream implements grpc.ServerStreamingServer[operatorv1alpha1.ConfigurationUpdate]
// for testing StreamConfiguration.
type mockServerStream struct {
	grpc.ServerStream
	ctx     context.Context
	updates []*operatorv1alpha1.ConfigurationUpdate
	sendErr error
}

func (m *mockServerStream) Send(update *operatorv1alpha1.ConfigurationUpdate) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.updates = append(m.updates, update)
	return nil
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockServerStream) SendHeader(metadata.MD) error { return nil }
func (m *mockServerStream) SetTrailer(metadata.MD)       {}
func (m *mockServerStream) SendMsg(interface{}) error    { return nil }
func (m *mockServerStream) RecvMsg(interface{}) error    { return nil }

func TestStreamConfiguration_InitialSendAndClose(t *testing.T) {
	svc, srv := newTestService(t)

	// Populate some data
	srv.mu.Lock()
	srv.apiRoutes["default/route1"] = []byte(`{"path":"/api"}`)
	srv.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())

	stream := &mockServerStream{
		ctx: ctx,
	}

	req := &operatorv1alpha1.StreamConfigurationRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      "stream-gw",
			Namespace: "default",
		},
		SessionId: "stream-session",
	}

	// Cancel context immediately after a short delay to unblock <-ctx.Done()
	go func() {
		cancel()
	}()

	err := svc.StreamConfiguration(req, stream)
	// Should return nil (context canceled is handled gracefully)
	assert.NoError(t, err)

	// Verify initial snapshot was sent
	require.Len(t, stream.updates, 1)
	update := stream.updates[0]
	assert.Equal(t, operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC, update.Type)
	assert.NotEmpty(t, update.Version)
	assert.NotNil(t, update.Timestamp)
	assert.NotNil(t, update.Snapshot)
	assert.Equal(t, int32(1), update.Snapshot.TotalResources)
}

func TestStreamConfiguration_SendError(t *testing.T) {
	svc, _ := newTestService(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream := &mockServerStream{
		ctx:     ctx,
		sendErr: fmt.Errorf("send failed"),
	}

	req := &operatorv1alpha1.StreamConfigurationRequest{
		SessionId: "stream-err",
	}

	err := svc.StreamConfiguration(req, stream)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send initial snapshot")
}

func TestStreamConfiguration_NilGateway(t *testing.T) {
	svc, _ := newTestService(t)

	ctx, cancel := context.WithCancel(context.Background())

	stream := &mockServerStream{
		ctx: ctx,
	}

	req := &operatorv1alpha1.StreamConfigurationRequest{
		SessionId: "stream-nil-gw",
	}

	go func() {
		cancel()
	}()

	err := svc.StreamConfiguration(req, stream)
	assert.NoError(t, err)
	require.Len(t, stream.updates, 1)
}

// ============================================================================
// buildSnapshot Tests
// ============================================================================

func TestBuildSnapshot_EmptyMaps(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	snapshot, err := svc.buildSnapshot(ctx)
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	assert.Equal(t, int32(0), snapshot.TotalResources)
	assert.Empty(t, snapshot.ApiRoutes)
	assert.Empty(t, snapshot.GrpcRoutes)
	assert.Empty(t, snapshot.Backends)
	assert.Empty(t, snapshot.GrpcBackends)
	assert.NotEmpty(t, snapshot.Checksum)
	assert.NotEmpty(t, snapshot.Version)
	assert.NotNil(t, snapshot.Timestamp)
}

func TestBuildSnapshot_AllTypes(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	// Populate all four map types
	srv.mu.Lock()
	srv.apiRoutes["ns/api1"] = []byte(`{"api":"route1"}`)
	srv.apiRoutes["ns/api2"] = []byte(`{"api":"route2"}`)
	srv.grpcRoutes["ns/grpc1"] = []byte(`{"grpc":"route1"}`)
	srv.backends["ns/be1"] = []byte(`{"backend":"be1"}`)
	srv.backends["ns/be2"] = []byte(`{"backend":"be2"}`)
	srv.backends["ns/be3"] = []byte(`{"backend":"be3"}`)
	srv.grpcBackends["ns/gbe1"] = []byte(`{"grpcbackend":"gbe1"}`)
	srv.mu.Unlock()

	snapshot, err := svc.buildSnapshot(ctx)
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	assert.Equal(t, int32(7), snapshot.TotalResources)
	assert.Len(t, snapshot.ApiRoutes, 2)
	assert.Len(t, snapshot.GrpcRoutes, 1)
	assert.Len(t, snapshot.Backends, 3)
	assert.Len(t, snapshot.GrpcBackends, 1)
	assert.NotEmpty(t, snapshot.Checksum)
}

func TestBuildSnapshot_OnlyAPIRoutes(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	srv.mu.Lock()
	srv.apiRoutes["ns/api1"] = []byte(`{"api":"route1"}`)
	srv.mu.Unlock()

	snapshot, err := svc.buildSnapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), snapshot.TotalResources)
	assert.Len(t, snapshot.ApiRoutes, 1)
	assert.Empty(t, snapshot.GrpcRoutes)
	assert.Empty(t, snapshot.Backends)
	assert.Empty(t, snapshot.GrpcBackends)
}

func TestBuildSnapshot_OnlyGRPCRoutes(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	srv.mu.Lock()
	srv.grpcRoutes["ns/grpc1"] = []byte(`{"grpc":"route1"}`)
	srv.mu.Unlock()

	snapshot, err := svc.buildSnapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), snapshot.TotalResources)
	assert.Len(t, snapshot.GrpcRoutes, 1)
}

func TestBuildSnapshot_OnlyBackends(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	srv.mu.Lock()
	srv.backends["ns/be1"] = []byte(`{"backend":"be1"}`)
	srv.mu.Unlock()

	snapshot, err := svc.buildSnapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), snapshot.TotalResources)
	assert.Len(t, snapshot.Backends, 1)
}

func TestBuildSnapshot_OnlyGRPCBackends(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	srv.mu.Lock()
	srv.grpcBackends["ns/gbe1"] = []byte(`{"grpcbackend":"gbe1"}`)
	srv.mu.Unlock()

	snapshot, err := svc.buildSnapshot(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), snapshot.TotalResources)
	assert.Len(t, snapshot.GrpcBackends, 1)
}

// ============================================================================
// buildConfigResource Tests
// ============================================================================

func TestBuildConfigResource(t *testing.T) {
	tests := []struct {
		name         string
		resourceType operatorv1alpha1.ResourceType
		key          string
		data         []byte
	}{
		{
			name:         "API route resource",
			resourceType: operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			key:          "default/my-route",
			data:         []byte(`{"path":"/api"}`),
		},
		{
			name:         "gRPC route resource",
			resourceType: operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
			key:          "prod/grpc-route",
			data:         []byte(`{"service":"svc"}`),
		},
		{
			name:         "backend resource",
			resourceType: operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
			key:          "staging/backend",
			data:         []byte(`{"host":"backend-svc"}`),
		},
		{
			name:         "gRPC backend resource",
			resourceType: operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
			key:          "dev/grpc-backend",
			data:         []byte(`{"host":"grpc-svc"}`),
		},
		{
			name:         "empty data",
			resourceType: operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			key:          "ns/empty",
			data:         []byte{},
		},
		{
			name:         "nil data",
			resourceType: operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
			key:          "ns/nil",
			data:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource := buildConfigResource(tt.resourceType, tt.key, tt.data)

			require.NotNil(t, resource)
			assert.Equal(t, tt.resourceType, resource.Type)
			assert.Equal(t, tt.key, resource.Name)
			assert.Equal(t, tt.data, resource.SpecJson)
		})
	}
}

// ============================================================================
// computeSnapshotChecksum Tests
// ============================================================================

func TestComputeSnapshotChecksum(t *testing.T) {
	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "1",
		TotalResources: 0,
	}

	checksum, err := computeSnapshotChecksum(snapshot)
	require.NoError(t, err)
	assert.NotEmpty(t, checksum)
	assert.Len(t, checksum, 64) // SHA-256 hex string is 64 chars
}

func TestComputeSnapshotChecksum_Deterministic(t *testing.T) {
	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "42",
		TotalResources: 2,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:     operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
				Name:     "ns/route1",
				SpecJson: []byte(`{"path":"/api"}`),
			},
		},
		Backends: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:     operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
				Name:     "ns/be1",
				SpecJson: []byte(`{"host":"svc"}`),
			},
		},
	}

	checksum1, err := computeSnapshotChecksum(snapshot)
	require.NoError(t, err)
	checksum2, err := computeSnapshotChecksum(snapshot)
	require.NoError(t, err)

	assert.Equal(t, checksum1, checksum2, "checksum should be deterministic for the same input")
}

func TestComputeSnapshotChecksum_DifferentInputs(t *testing.T) {
	snapshot1 := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "1",
		TotalResources: 0,
	}
	snapshot2 := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "2",
		TotalResources: 1,
	}

	checksum1, err := computeSnapshotChecksum(snapshot1)
	require.NoError(t, err)
	checksum2, err := computeSnapshotChecksum(snapshot2)
	require.NoError(t, err)

	assert.NotEqual(t, checksum1, checksum2, "different inputs should produce different checksums")
}

func TestComputeSnapshotChecksum_NilSnapshot(t *testing.T) {
	// nil snapshot should still produce a valid checksum (json.Marshal of nil returns "null")
	checksum, err := computeSnapshotChecksum(nil)
	require.NoError(t, err)
	// proto.Marshal of nil returns empty bytes, json.Marshal returns "null"
	// Either way, it should not panic and should return something
	assert.NotEmpty(t, checksum)
}

// ============================================================================
// registerConfigurationService Tests
// ============================================================================

func TestRegisterConfigurationService(t *testing.T) {
	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	grpcSrv := grpc.NewServer()
	defer grpcSrv.Stop()

	// Should not panic
	registerConfigurationService(grpcSrv, srv)

	// Verify the service was registered by checking the service info
	info := grpcSrv.GetServiceInfo()
	assert.Contains(t, info, "avapigw.operator.v1alpha1.ConfigurationService")
}

// ============================================================================
// Table-Driven RegisterGateway Tests
// ============================================================================

func TestRegisterGateway_TableDriven(t *testing.T) {
	tests := []struct {
		name            string
		req             *operatorv1alpha1.RegisterGatewayRequest
		expectSuccess   bool
		expectError     bool
		expectErrSubstr string
	}{
		{
			name: "valid gateway",
			req: &operatorv1alpha1.RegisterGatewayRequest{
				Gateway: &operatorv1alpha1.GatewayInfo{
					Name:      "gw1",
					Namespace: "ns1",
				},
			},
			expectSuccess: true,
		},
		{
			name:          "nil gateway info",
			req:           &operatorv1alpha1.RegisterGatewayRequest{},
			expectSuccess: false,
		},
		{
			name: "empty name and namespace",
			req: &operatorv1alpha1.RegisterGatewayRequest{
				Gateway: &operatorv1alpha1.GatewayInfo{
					Name:      "",
					Namespace: "",
				},
			},
			expectSuccess: true, // empty name/namespace is allowed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			ctx := context.Background()

			resp, err := svc.RegisterGateway(ctx, tt.req)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tt.expectSuccess, resp.Success)
		})
	}
}

// ============================================================================
// Table-Driven AcknowledgeConfiguration Tests
// ============================================================================

func TestAcknowledgeConfiguration_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		req     *operatorv1alpha1.AcknowledgeConfigurationRequest
		success bool
	}{
		{
			name: "success with gateway",
			req: &operatorv1alpha1.AcknowledgeConfigurationRequest{
				Gateway: &operatorv1alpha1.GatewayInfo{
					Name:      "gw1",
					Namespace: "ns1",
				},
				SessionId:     "s1",
				ConfigVersion: "v1",
				Success:       true,
			},
			success: true,
		},
		{
			name: "failure with gateway",
			req: &operatorv1alpha1.AcknowledgeConfigurationRequest{
				Gateway: &operatorv1alpha1.GatewayInfo{
					Name:      "gw2",
					Namespace: "ns2",
				},
				SessionId:     "s2",
				ConfigVersion: "v2",
				Success:       false,
				ErrorMessage:  "apply failed",
			},
			success: false,
		},
		{
			name: "success without gateway",
			req: &operatorv1alpha1.AcknowledgeConfigurationRequest{
				SessionId:     "s3",
				ConfigVersion: "v3",
				Success:       true,
			},
			success: true,
		},
		{
			name:    "empty request",
			req:     &operatorv1alpha1.AcknowledgeConfigurationRequest{},
			success: false, // GetSuccess() returns false for empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			ctx := context.Background()

			resp, err := svc.AcknowledgeConfiguration(ctx, tt.req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.True(t, resp.Received)
			assert.NotNil(t, resp.ServerTime)
		})
	}
}

// ============================================================================
// Snapshot Resource Verification Tests
// ============================================================================

func TestBuildSnapshot_ResourceContent(t *testing.T) {
	svc, srv := newTestService(t)
	ctx := context.Background()

	expectedData := []byte(`{"path":"/api/v1"}`)
	srv.mu.Lock()
	srv.apiRoutes["default/my-route"] = expectedData
	srv.mu.Unlock()

	snapshot, err := svc.buildSnapshot(ctx)
	require.NoError(t, err)
	require.Len(t, snapshot.ApiRoutes, 1)

	resource := snapshot.ApiRoutes[0]
	assert.Equal(t, operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE, resource.Type)
	assert.Equal(t, "default/my-route", resource.Name)
	assert.True(t, proto.Equal(
		&operatorv1alpha1.ConfigurationResource{
			Type:     operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:     "default/my-route",
			SpecJson: expectedData,
		},
		resource,
	))
}

// ============================================================================
// Constants and Defaults Tests
// ============================================================================

func TestDefaultHeartbeatInterval(t *testing.T) {
	assert.Equal(t, float64(30), defaultHeartbeatInterval.Seconds())
}

func TestTracerName(t *testing.T) {
	assert.Equal(t, "avapigw-operator/grpc", tracerName)
}
