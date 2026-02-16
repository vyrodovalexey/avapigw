// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// ============================================================
// WithCacheInvalidator option tests
// ============================================================

func TestWithCacheInvalidator_SetsInvalidator(t *testing.T) {
	t.Parallel()

	called := false
	invalidator := CacheInvalidator(func() {
		called = true
	})

	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

	require.NotNil(t, handler.cacheInvalidator)

	// Call the invalidator to verify it was set correctly
	handler.cacheInvalidator()
	assert.True(t, called)
}

func TestWithCacheInvalidator_NilInvalidator(t *testing.T) {
	t.Parallel()

	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier, WithCacheInvalidator(nil))

	assert.Nil(t, handler.cacheInvalidator)
}

// ============================================================
// invalidateCache tests
// ============================================================

func TestConfigHandler_InvalidateCache_WithInvalidator(t *testing.T) {
	t.Parallel()

	var callCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&callCount, 1)
	})

	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

	handler.invalidateCache()
	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount))

	handler.invalidateCache()
	assert.Equal(t, int32(2), atomic.LoadInt32(&callCount))
}

func TestConfigHandler_InvalidateCache_NilInvalidator_NoPanic(t *testing.T) {
	t.Parallel()

	applier := &MockConfigApplier{}
	handler := NewConfigHandler(applier)

	// Should not panic with nil invalidator
	assert.NotPanics(t, func() {
		handler.invalidateCache()
	})
}

func TestConfigHandler_InvalidateCache_DefaultHandler_NoPanic(t *testing.T) {
	t.Parallel()

	handler := NewConfigHandler(nil)

	// Should not panic with nil applier and nil invalidator
	assert.NotPanics(t, func() {
		handler.invalidateCache()
	})
}

// ============================================================
// Integration: Config updates trigger cache invalidation
// ============================================================

func TestConfigHandler_RouteUpdate_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

	route := config.Route{Name: "test-route"}
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

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}

func TestConfigHandler_RouteDelete_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

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

	// Reset counter
	atomic.StoreInt32(&invalidateCount, 0)

	// Delete the route
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

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}

func TestConfigHandler_BackendUpdate_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

	backend := config.Backend{Name: "test-backend"}
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

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}

func TestConfigHandler_BackendDelete_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

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

	atomic.StoreInt32(&invalidateCount, 0)

	// Delete the backend
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

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}

func TestConfigHandler_GRPCRouteUpdate_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

	grpcRoute := config.GRPCRoute{Name: "test-grpc-route"}
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

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}

func TestConfigHandler_GRPCBackendUpdate_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

	grpcBackend := config.GRPCBackend{Name: "test-grpc-backend"}
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

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}

func TestConfigHandler_Snapshot_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 0,
	}

	err := handler.HandleSnapshot(context.Background(), snapshot)
	require.NoError(t, err)

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}

func TestConfigHandler_FullSync_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

	route := config.Route{Name: "route1"}
	routeJSON, _ := json.Marshal(route)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
				Name:      "route1",
				Namespace: "default",
				SpecJson:  routeJSON,
			},
		},
	}

	// HandleUpdate with FULL_SYNC requires a non-nil Resource to pass the nil check,
	// or we can call HandleSnapshot directly which is what FULL_SYNC delegates to.
	// The HandleUpdate method checks update.Resource == nil and returns early,
	// so for FULL_SYNC we need to provide a resource or call HandleSnapshot directly.
	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC,
		Version:  "v1",
		Sequence: 1,
		Snapshot: snapshot,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "route1",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}

	err := handler.HandleUpdate(context.Background(), update)
	require.NoError(t, err)

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}

func TestConfigHandler_GRPCRouteDelete_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

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

	atomic.StoreInt32(&invalidateCount, 0)

	// Delete the gRPC route
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

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}

func TestConfigHandler_GRPCBackendDelete_TriggersCacheInvalidation(t *testing.T) {
	t.Parallel()

	var invalidateCount int32
	invalidator := CacheInvalidator(func() {
		atomic.AddInt32(&invalidateCount, 1)
	})

	applier := &MockConfigApplier{}
	applier.On("ApplyGRPCBackends", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier, WithCacheInvalidator(invalidator))

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

	atomic.StoreInt32(&invalidateCount, 0)

	// Delete the gRPC backend
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

	assert.Equal(t, int32(1), atomic.LoadInt32(&invalidateCount))
}
