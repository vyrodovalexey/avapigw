// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// MockConfigApplier is a mock implementation of ConfigApplier.
type MockConfigApplier struct {
	mock.Mock
}

func (m *MockConfigApplier) ApplyRoutes(ctx context.Context, routes []config.Route) error {
	args := m.Called(ctx, routes)
	return args.Error(0)
}

func (m *MockConfigApplier) ApplyBackends(ctx context.Context, backends []config.Backend) error {
	args := m.Called(ctx, backends)
	return args.Error(0)
}

func (m *MockConfigApplier) ApplyGRPCRoutes(ctx context.Context, routes []config.GRPCRoute) error {
	args := m.Called(ctx, routes)
	return args.Error(0)
}

func (m *MockConfigApplier) ApplyGRPCBackends(ctx context.Context, backends []config.GRPCBackend) error {
	args := m.Called(ctx, backends)
	return args.Error(0)
}

func (m *MockConfigApplier) ApplyFullConfig(ctx context.Context, cfg *config.GatewayConfig) error {
	args := m.Called(ctx, cfg)
	return args.Error(0)
}

func TestNewConfigHandler(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	require.NotNil(t, handler)
	assert.NotNil(t, handler.applier)
	assert.NotNil(t, handler.routes)
	assert.NotNil(t, handler.backends)
	assert.NotNil(t, handler.grpcRoutes)
	assert.NotNil(t, handler.grpcBackends)
}

func TestNewConfigHandler_WithOptions(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier,
		WithHandlerLogger(nil), // Will use NopLogger
	)

	require.NotNil(t, handler)
}

func TestConfigHandler_HandleUpdate_NilResource(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: nil,
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)
}

func TestConfigHandler_HandleUpdate_Added_Route(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

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

	// Verify state
	routes, _, _, _ := handler.GetCurrentState()
	assert.Len(t, routes, 1)
	assert.Equal(t, "test-route", routes[0].Name)
}

func TestConfigHandler_HandleUpdate_Modified_Route(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	route := config.Route{
		Name: "test-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/api/v2"}},
		},
	}
	routeJSON, err := json.Marshal(route)
	require.NoError(t, err)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_MODIFIED,
		Version:  "v2",
		Sequence: 2,
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

func TestConfigHandler_HandleUpdate_Deleted_Route(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)

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

	// Now delete it
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
	require.NoError(t, err)

	// Verify state
	routes, _, _, _ := handler.GetCurrentState()
	assert.Len(t, routes, 0)
}

func TestConfigHandler_HandleUpdate_Backend(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	backend := config.Backend{
		Name: "test-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 8080},
		},
	}
	backendJSON, err := json.Marshal(backend)
	require.NoError(t, err)

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

	err = handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)

	applier.AssertExpectations(t)

	// Verify state
	_, backends, _, _ := handler.GetCurrentState()
	assert.Len(t, backends, 1)
	assert.Equal(t, "test-backend", backends[0].Name)
}

func TestConfigHandler_HandleUpdate_Deleted_Backend(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyBackends", mock.Anything, mock.Anything).Return(nil)

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

	// Now delete it
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
	require.NoError(t, err)

	// Verify state
	_, backends, _, _ := handler.GetCurrentState()
	assert.Len(t, backends, 0)
}

func TestConfigHandler_HandleUpdate_GRPCRoute(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	grpcRoute := config.GRPCRoute{
		Name: "test-grpc-route",
		Match: []config.GRPCRouteMatch{
			{Service: &config.StringMatch{Exact: "myservice"}},
		},
	}
	grpcRouteJSON, err := json.Marshal(grpcRoute)
	require.NoError(t, err)

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

	err = handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)

	applier.AssertExpectations(t)

	// Verify state
	_, _, grpcRoutes, _ := handler.GetCurrentState()
	assert.Len(t, grpcRoutes, 1)
	assert.Equal(t, "test-grpc-route", grpcRoutes[0].Name)
}

func TestConfigHandler_HandleUpdate_Deleted_GRPCRoute(t *testing.T) {
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

	// Now delete it
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
	require.NoError(t, err)

	// Verify state
	_, _, grpcRoutes, _ := handler.GetCurrentState()
	assert.Len(t, grpcRoutes, 0)
}

func TestConfigHandler_HandleUpdate_GRPCBackend(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	grpcBackend := config.GRPCBackend{
		Name: "test-grpc-backend",
		Hosts: []config.BackendHost{
			{Address: "localhost", Port: 50051},
		},
	}
	grpcBackendJSON, err := json.Marshal(grpcBackend)
	require.NoError(t, err)

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

	err = handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)

	applier.AssertExpectations(t)

	// Verify state
	_, _, _, grpcBackends := handler.GetCurrentState()
	assert.Len(t, grpcBackends, 1)
	assert.Equal(t, "test-grpc-backend", grpcBackends[0].Name)
}

func TestConfigHandler_HandleUpdate_Deleted_GRPCBackend(t *testing.T) {
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

	// Now delete it
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
	require.NoError(t, err)

	// Verify state
	_, _, _, grpcBackends := handler.GetCurrentState()
	assert.Len(t, grpcBackends, 0)
}

func TestConfigHandler_HandleUpdate_FullSync(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	route := config.Route{Name: "route1"}
	routeJSON, _ := json.Marshal(route)

	backend := config.Backend{Name: "backend1"}
	backendJSON, _ := json.Marshal(backend)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 2,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
				Name:      "route1",
				Namespace: "default",
				SpecJson:  routeJSON,
			},
		},
		Backends: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
				Name:      "backend1",
				Namespace: "default",
				SpecJson:  backendJSON,
			},
		},
	}

	// Call HandleSnapshot directly since HandleUpdate with FULL_SYNC calls HandleSnapshot
	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	applier.AssertExpectations(t)
}

func TestConfigHandler_HandleSnapshot(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	route := config.Route{Name: "route1"}
	routeJSON, _ := json.Marshal(route)

	backend := config.Backend{Name: "backend1"}
	backendJSON, _ := json.Marshal(backend)

	grpcRoute := config.GRPCRoute{Name: "grpc-route1"}
	grpcRouteJSON, _ := json.Marshal(grpcRoute)

	grpcBackend := config.GRPCBackend{Name: "grpc-backend1"}
	grpcBackendJSON, _ := json.Marshal(grpcBackend)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 4,
		Checksum:       "abc123",
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
				Name:      "route1",
				Namespace: "default",
				SpecJson:  routeJSON,
			},
		},
		Backends: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
				Name:      "backend1",
				Namespace: "default",
				SpecJson:  backendJSON,
			},
		},
		GrpcRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
				Name:      "grpc-route1",
				Namespace: "default",
				SpecJson:  grpcRouteJSON,
			},
		},
		GrpcBackends: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
				Name:      "grpc-backend1",
				Namespace: "default",
				SpecJson:  grpcBackendJSON,
			},
		},
	}

	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	applier.AssertExpectations(t)

	// Verify state
	routes, backends, grpcRoutes, grpcBackends := handler.GetCurrentState()
	assert.Len(t, routes, 1)
	assert.Len(t, backends, 1)
	assert.Len(t, grpcRoutes, 1)
	assert.Len(t, grpcBackends, 1)
}

func TestConfigHandler_HandleSnapshot_Empty(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 0,
	}

	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	// Verify state is empty
	routes, backends, grpcRoutes, grpcBackends := handler.GetCurrentState()
	assert.Len(t, routes, 0)
	assert.Len(t, backends, 0)
	assert.Len(t, grpcRoutes, 0)
	assert.Len(t, grpcBackends, 0)
}

func TestConfigHandler_HandleSnapshot_ClearsExistingState(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	// First add some routes
	route := config.Route{Name: "old-route"}
	routeJSON, _ := json.Marshal(route)

	addUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "old-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}
	_ = handler.HandleUpdate(context.Background(), addUpdate)

	// Verify old route exists
	routes, _, _, _ := handler.GetCurrentState()
	assert.Len(t, routes, 1)

	// Now apply a snapshot with different routes
	newRoute := config.Route{Name: "new-route"}
	newRouteJSON, _ := json.Marshal(newRoute)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v2",
		TotalResources: 1,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
				Name:      "new-route",
				Namespace: "default",
				SpecJson:  newRouteJSON,
			},
		},
	}

	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	// Verify old route is gone and new route exists
	routes, _, _, _ = handler.GetCurrentState()
	assert.Len(t, routes, 1)
	assert.Equal(t, "new-route", routes[0].Name)
}

func TestConfigHandler_HandleUpdate_ApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(errors.New("apply failed"))

	handler := NewConfigHandler(applier)

	route := config.Route{Name: "test-route"}
	routeJSON, _ := json.Marshal(route)

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

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply routes")
}

func TestConfigHandler_HandleUpdate_InvalidJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "test-route",
			Namespace: "default",
			SpecJson:  []byte("invalid json"),
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal route spec")
}

func TestConfigHandler_HandleUpdate_UnknownResourceType(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_UNSPECIFIED,
			Name:      "test-resource",
			Namespace: "default",
			SpecJson:  []byte("{}"),
		},
	}

	// Should not error, just log warning
	err := handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)
}

func TestConfigHandler_HandleUpdate_Heartbeat(t *testing.T) {
	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_HEARTBEAT,
		Version:  "v1",
		Sequence: 1,
	}

	// Should not error
	err := handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)
}

func TestConfigHandler_HandleSnapshot_ApplierError(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(errors.New("apply failed"))

	handler := NewConfigHandler(applier)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 0,
	}

	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to apply full configuration")
}

func TestConfigHandler_HandleSnapshot_NilApplier(t *testing.T) {
	handler := NewConfigHandler(nil)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 0,
	}

	// Should not error with nil applier
	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)
}

func TestConfigHandler_HandleUpdate_NilApplier(t *testing.T) {
	handler := NewConfigHandler(nil)

	route := config.Route{Name: "test-route"}
	routeJSON, _ := json.Marshal(route)

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

	// Should not error with nil applier
	err := handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)

	// State should still be updated
	routes, _, _, _ := handler.GetCurrentState()
	assert.Len(t, routes, 1)
}

func TestConfigHandler_GetCurrentState(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)
	applier.On("ApplyBackends", mock.Anything, mock.Anything).Return(nil)
	applier.On("ApplyGRPCRoutes", mock.Anything, mock.Anything).Return(nil)
	applier.On("ApplyGRPCBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	// Add various resources
	route := config.Route{Name: "route1"}
	routeJSON, _ := json.Marshal(route)
	_ = handler.HandleUpdate(context.Background(), &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "route1",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	})

	backend := config.Backend{Name: "backend1"}
	backendJSON, _ := json.Marshal(backend)
	_ = handler.HandleUpdate(context.Background(), &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND,
			Name:      "backend1",
			Namespace: "default",
			SpecJson:  backendJSON,
		},
	})

	grpcRoute := config.GRPCRoute{Name: "grpc-route1"}
	grpcRouteJSON, _ := json.Marshal(grpcRoute)
	_ = handler.HandleUpdate(context.Background(), &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v3",
		Sequence: 3,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE,
			Name:      "grpc-route1",
			Namespace: "default",
			SpecJson:  grpcRouteJSON,
		},
	})

	grpcBackend := config.GRPCBackend{Name: "grpc-backend1"}
	grpcBackendJSON, _ := json.Marshal(grpcBackend)
	_ = handler.HandleUpdate(context.Background(), &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v4",
		Sequence: 4,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND,
			Name:      "grpc-backend1",
			Namespace: "default",
			SpecJson:  grpcBackendJSON,
		},
	})

	// Get current state
	routes, backends, grpcRoutes, grpcBackends := handler.GetCurrentState()

	assert.Len(t, routes, 1)
	assert.Len(t, backends, 1)
	assert.Len(t, grpcRoutes, 1)
	assert.Len(t, grpcBackends, 1)

	assert.Equal(t, "route1", routes[0].Name)
	assert.Equal(t, "backend1", backends[0].Name)
	assert.Equal(t, "grpc-route1", grpcRoutes[0].Name)
	assert.Equal(t, "grpc-backend1", grpcBackends[0].Name)
}

func TestResourceKey(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		resName   string
		expected  string
	}{
		{
			name:      "with namespace",
			namespace: "default",
			resName:   "my-resource",
			expected:  "default/my-resource",
		},
		{
			name:      "without namespace",
			namespace: "",
			resName:   "my-resource",
			expected:  "my-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourceKey(tt.namespace, tt.resName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigHandler_HandleSnapshot_InvalidJSON(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
				Name:      "invalid-route",
				Namespace: "default",
				SpecJson:  []byte("invalid json"),
			},
		},
	}

	// Should not error, just skip invalid resources
	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	// State should be empty since the route was invalid
	routes, _, _, _ := handler.GetCurrentState()
	assert.Len(t, routes, 0)
}
