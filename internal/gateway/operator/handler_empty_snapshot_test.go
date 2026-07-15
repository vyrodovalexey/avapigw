// Package operator contains tests for the empty-snapshot safeguard: a
// non-empty running configuration must never be wiped by an EMPTY FULL_SYNC
// snapshot (operator-restart protection).
package operator

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// seedHandlerWithRoute seeds the handler with one running route via an
// incremental update so the safeguard sees a non-empty running configuration.
func seedHandlerWithRoute(t *testing.T, handler *ConfigHandler) {
	t.Helper()

	route := config.Route{Name: "running-route"}
	routeJSON, err := json.Marshal(route)
	require.NoError(t, err)

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "running-route",
			Namespace: "default",
			SpecJson:  routeJSON,
		},
	}
	require.NoError(t, handler.HandleUpdate(context.Background(), update))

	routes, _, _, _, _, _ := handler.GetCurrentState()
	require.Len(t, routes, 1)
}

// TestConfigHandler_HandleSnapshot_EmptyDoesNotWipeRunningConfig is the
// regression test for the operator-restart wipe: an empty FULL_SYNC while a
// non-empty configuration is running must be skipped (last-known-good kept).
func TestConfigHandler_HandleSnapshot_EmptyDoesNotWipeRunningConfig(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)
	// ApplyFullConfig must NOT be invoked for the skipped empty snapshot;
	// no expectation is registered so an unexpected call fails the test.

	handler := NewConfigHandler(applier)
	seedHandlerWithRoute(t, handler)

	emptySnapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "restart-0",
		TotalResources: 0,
	}

	err := handler.HandleSnapshot(context.Background(), emptySnapshot)
	require.NoError(t, err, "skipping an empty snapshot must not be an error")

	// The running configuration must be untouched.
	routes, _, _, _, _, _ := handler.GetCurrentState()
	require.Len(t, routes, 1)
	assert.Equal(t, "running-route", routes[0].Name)

	applier.AssertNotCalled(t, "ApplyFullConfig", mock.Anything, mock.Anything)
}

// TestConfigHandler_HandleSnapshot_NonEmptyStillReplaces verifies the
// safeguard does not interfere with legitimate non-empty snapshots.
func TestConfigHandler_HandleSnapshot_NonEmptyStillReplaces(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)
	seedHandlerWithRoute(t, handler)

	newRoute := config.Route{Name: "replacement-route"}
	newRouteJSON, err := json.Marshal(newRoute)
	require.NoError(t, err)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v2",
		TotalResources: 1,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
				Name:      "replacement-route",
				Namespace: "default",
				SpecJson:  newRouteJSON,
			},
		},
	}

	require.NoError(t, handler.HandleSnapshot(context.Background(), snapshot))

	routes, _, _, _, _, _ := handler.GetCurrentState()
	require.Len(t, routes, 1)
	assert.Equal(t, "replacement-route", routes[0].Name)
	applier.AssertCalled(t, "ApplyFullConfig", mock.Anything, mock.Anything)
}

// TestConfigHandler_HandleSnapshot_EmptyOnEmptyStateApplies verifies an empty
// snapshot on an empty running configuration is applied normally (fresh
// gateway start against a legitimately empty cluster).
func TestConfigHandler_HandleSnapshot_EmptyOnEmptyStateApplies(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)

	emptySnapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 0,
	}

	require.NoError(t, handler.HandleSnapshot(context.Background(), emptySnapshot))
	applier.AssertCalled(t, "ApplyFullConfig", mock.Anything, mock.Anything)
}

// TestConfigHandler_HandleSnapshot_MiscountedEmptySnapshotStillSkipped
// verifies the safeguard inspects the resource slices, not the
// TotalResources counter.
func TestConfigHandler_HandleSnapshot_MiscountedEmptySnapshotStillSkipped(t *testing.T) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)

	handler := NewConfigHandler(applier)
	seedHandlerWithRoute(t, handler)

	// Claims resources but carries none.
	miscounted := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v2",
		TotalResources: 5,
	}

	require.NoError(t, handler.HandleSnapshot(context.Background(), miscounted))

	routes, _, _, _, _, _ := handler.GetCurrentState()
	require.Len(t, routes, 1, "running configuration must be retained")
	applier.AssertNotCalled(t, "ApplyFullConfig", mock.Anything, mock.Anything)
}

// TestSnapshotIsEmpty exercises the emptiness predicate across resource types.
func TestSnapshotIsEmpty(t *testing.T) {
	res := []*operatorv1alpha1.ConfigurationResource{{Name: "x"}}

	tests := []struct {
		name     string
		snapshot *operatorv1alpha1.ConfigurationSnapshot
		want     bool
	}{
		{"empty", &operatorv1alpha1.ConfigurationSnapshot{}, true},
		{"api routes", &operatorv1alpha1.ConfigurationSnapshot{ApiRoutes: res}, false},
		{"backends", &operatorv1alpha1.ConfigurationSnapshot{Backends: res}, false},
		{"grpc routes", &operatorv1alpha1.ConfigurationSnapshot{GrpcRoutes: res}, false},
		{"grpc backends", &operatorv1alpha1.ConfigurationSnapshot{GrpcBackends: res}, false},
		{"graphql routes", &operatorv1alpha1.ConfigurationSnapshot{GraphqlRoutes: res}, false},
		{"graphql backends", &operatorv1alpha1.ConfigurationSnapshot{GraphqlBackends: res}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, snapshotIsEmpty(tt.snapshot))
		})
	}
}

// TestConfigHandler_HasRunningConfig exercises the running-config predicate
// for every resource type map.
func TestConfigHandler_HasRunningConfig(t *testing.T) {
	handler := NewConfigHandler(nil)
	assert.False(t, handler.hasRunningConfig())

	handler.mu.Lock()
	handler.backends["default/b1"] = &config.Backend{Name: "b1"}
	handler.mu.Unlock()
	assert.True(t, handler.hasRunningConfig())

	handler.mu.Lock()
	handler.backends = map[string]*config.Backend{}
	handler.grpcRoutes["default/g1"] = &config.GRPCRoute{Name: "g1"}
	handler.mu.Unlock()
	assert.True(t, handler.hasRunningConfig())

	handler.mu.Lock()
	handler.grpcRoutes = map[string]*config.GRPCRoute{}
	handler.graphqlBackends["default/qb1"] = &config.GraphQLBackend{Name: "qb1"}
	handler.mu.Unlock()
	assert.True(t, handler.hasRunningConfig())
}
