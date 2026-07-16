// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

// Package operator tests for snapshot/incremental state-key symmetry (C6):
// FULL_SYNC snapshots must key handler state by the SAME composite
// namespace/name key incremental updates use, so a snapshot-seeded resource
// can be modified or deleted by subsequent incremental updates; plus the
// WP2 interplay tests: per-type-empty snapshots apply while the all-empty
// guard and the regression window keep protecting operator restarts.
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

// namespacedRouteResource marshals a config.Route into a namespaced resource.
func namespacedRouteResource(t *testing.T, namespace, name string) *operatorv1alpha1.ConfigurationResource {
	t.Helper()
	routeJSON, err := json.Marshal(config.Route{Name: name})
	require.NoError(t, err)
	return &operatorv1alpha1.ConfigurationResource{
		Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
		Name:      name,
		Namespace: namespace,
		SpecJson:  routeJSON,
	}
}

// newKeySymmetryHandler returns a handler with a permissive applier.
func newKeySymmetryHandler() (*ConfigHandler, *MockConfigApplier) {
	applier := &MockConfigApplier{}
	applier.On("ApplyRoutes", mock.Anything, mock.Anything).Return(nil)
	applier.On("ApplyGraphQLRoutes", mock.Anything, mock.Anything).Return(nil)
	applier.On("ApplyFullConfig", mock.Anything, mock.Anything).Return(nil)
	return NewConfigHandler(applier), applier
}

// TestConfigHandler_SnapshotThenIncrementalDelete_KeySymmetry is the C6
// regression test: a resource seeded by FULL_SYNC must be deletable by a
// subsequent incremental DELETE carrying the same namespace/name.
func TestConfigHandler_SnapshotThenIncrementalDelete_KeySymmetry(t *testing.T) {
	handler, _ := newKeySymmetryHandler()
	ctx := context.Background()

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			namespacedRouteResource(t, "prod", "orders-route"),
		},
	}
	require.NoError(t, handler.HandleSnapshot(ctx, snapshot))

	routes, _, _, _, _, _ := handler.GetCurrentState()
	require.Len(t, routes, 1)

	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "orders-route",
			Namespace: "prod",
		},
	}
	require.NoError(t, handler.HandleUpdate(ctx, deleteUpdate))

	routes, _, _, _, _, _ = handler.GetCurrentState()
	assert.Empty(t, routes,
		"incremental DELETE must remove the snapshot-seeded resource (key symmetry)")
}

// TestConfigHandler_SnapshotThenIncrementalModify_NoDuplicate verifies an
// incremental MODIFY after a FULL_SYNC replaces the snapshot-seeded entry
// instead of adding a duplicate under a differently shaped key.
func TestConfigHandler_SnapshotThenIncrementalModify_NoDuplicate(t *testing.T) {
	handler, _ := newKeySymmetryHandler()
	ctx := context.Background()

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			namespacedRouteResource(t, "prod", "orders-route"),
		},
	}
	require.NoError(t, handler.HandleSnapshot(ctx, snapshot))

	modified := config.Route{Name: "orders-route", Timeout: config.Duration(5000000000)}
	modifiedJSON, err := json.Marshal(modified)
	require.NoError(t, err)

	modifyUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_MODIFIED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
			Name:      "orders-route",
			Namespace: "prod",
			SpecJson:  modifiedJSON,
		},
	}
	require.NoError(t, handler.HandleUpdate(ctx, modifyUpdate))

	routes, _, _, _, _, _ := handler.GetCurrentState()
	require.Len(t, routes, 1,
		"incremental MODIFY must replace the snapshot-seeded entry, not duplicate it")
	assert.Equal(t, modified.Timeout, routes[0].Timeout)
}

// TestConfigHandler_SnapshotGraphQLThenIncrementalDelete_KeySymmetry mirrors
// the C6 key-symmetry check for the GraphQL route state map.
func TestConfigHandler_SnapshotGraphQLThenIncrementalDelete_KeySymmetry(t *testing.T) {
	handler, _ := newKeySymmetryHandler()
	ctx := context.Background()

	gqlJSON, err := json.Marshal(config.GraphQLRoute{Name: "gql-route"})
	require.NoError(t, err)

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 1,
		GraphqlRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
				Name:      "gql-route",
				Namespace: "prod",
				SpecJson:  gqlJSON,
			},
		},
	}
	require.NoError(t, handler.HandleSnapshot(ctx, snapshot))

	_, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	require.Len(t, graphqlRoutes, 1)

	deleteUpdate := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_DELETED,
		Version:  "v2",
		Sequence: 2,
		Resource: &operatorv1alpha1.ConfigurationResource{
			Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
			Name:      "gql-route",
			Namespace: "prod",
		},
	}
	require.NoError(t, handler.HandleUpdate(ctx, deleteUpdate))

	_, _, _, _, graphqlRoutes, _ = handler.GetCurrentState()
	assert.Empty(t, graphqlRoutes)
}

// graphqlRouteResource marshals a GraphQL route spec into a snapshot resource.
func graphqlRouteResource(t *testing.T, name string, spec config.GraphQLRoute) *operatorv1alpha1.ConfigurationResource {
	t.Helper()
	specJSON, err := json.Marshal(spec)
	require.NoError(t, err)
	return &operatorv1alpha1.ConfigurationResource{
		Type:     operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
		Name:     name,
		SpecJson: specJSON,
	}
}

// TestConfigHandler_PartialEmptySnapshotApplies_WithinWindow is the WP2
// interplay test: within the post-reconnect window, a snapshot whose TOTAL
// count does not regress must apply even when ONE type became empty — the
// per-type empty clears while other types stay served.
func TestConfigHandler_PartialEmptySnapshotApplies_WithinWindow(t *testing.T) {
	handler, applier := newKeySymmetryHandler()
	ctx := context.Background()

	// Seed: 2 HTTP routes + 1 GraphQL route (3 total).
	seed := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "seed",
		TotalResources: 3,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			namespacedRouteResource(t, "", "http-a"),
			namespacedRouteResource(t, "", "http-b"),
		},
		GraphqlRoutes: []*operatorv1alpha1.ConfigurationResource{
			graphqlRouteResource(t, "gql-a", config.GraphQLRoute{Name: "gql-a"}),
		},
	}
	require.NoError(t, handler.HandleSnapshot(ctx, seed))
	require.Equal(t, 3, handler.runningResourceCount())

	handler.MarkReconnected()

	// Non-regressing total (3), GraphQL type now empty.
	next := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v2",
		TotalResources: 3,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			namespacedRouteResource(t, "", "http-a"),
			namespacedRouteResource(t, "", "http-b"),
			namespacedRouteResource(t, "", "http-c"),
		},
	}
	require.NoError(t, handler.HandleSnapshot(ctx, next))

	routes, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	assert.Len(t, routes, 3, "populated type must be applied")
	assert.Empty(t, graphqlRoutes, "per-type empty must clear within a non-regressing snapshot")
	applier.AssertNumberOfCalls(t, "ApplyFullConfig", 2)
}

// TestConfigHandler_PartialEmptyRegressingSnapshotDeferred_WithinWindow
// verifies the regression window still defers a snapshot whose per-type
// emptiness ALSO shrinks the total resource count (operator-restart
// protection remains intact).
func TestConfigHandler_PartialEmptyRegressingSnapshotDeferred_WithinWindow(t *testing.T) {
	handler, applier := newKeySymmetryHandler()
	ctx := context.Background()

	seed := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "seed",
		TotalResources: 3,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			namespacedRouteResource(t, "", "http-a"),
			namespacedRouteResource(t, "", "http-b"),
		},
		GraphqlRoutes: []*operatorv1alpha1.ConfigurationResource{
			graphqlRouteResource(t, "gql-a", config.GraphQLRoute{Name: "gql-a"}),
		},
	}
	require.NoError(t, handler.HandleSnapshot(ctx, seed))

	handler.MarkReconnected()

	// Regressing total (2 < 3) with the GraphQL type empty: deferred.
	regressing := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "partial",
		TotalResources: 2,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			namespacedRouteResource(t, "", "http-a"),
			namespacedRouteResource(t, "", "http-b"),
		},
	}
	require.NoError(t, handler.HandleSnapshot(ctx, regressing))

	_, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	assert.Len(t, graphqlRoutes, 1,
		"regressing snapshot within the window must be deferred (LKG kept)")
	applier.AssertNumberOfCalls(t, "ApplyFullConfig", 1)
}

// TestConfigHandler_CollectSorted_DeterministicOrder verifies collected
// slices are ordered by composite state key so route loading, apply logs,
// and diffs are reproducible regardless of map iteration order.
func TestConfigHandler_CollectSorted_DeterministicOrder(t *testing.T) {
	handler, _ := newKeySymmetryHandler()
	ctx := context.Background()

	for _, name := range []string{"zulu", "alpha", "mike"} {
		routeJSON, err := json.Marshal(config.Route{Name: name})
		require.NoError(t, err)
		require.NoError(t, handler.HandleUpdate(ctx, &operatorv1alpha1.ConfigurationUpdate{
			Type: operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
			Resource: &operatorv1alpha1.ConfigurationResource{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
				Name:      name,
				Namespace: "default",
				SpecJson:  routeJSON,
			},
		}))
	}

	routes, _, _, _, _, _ := handler.GetCurrentState()
	require.Len(t, routes, 3)
	assert.Equal(t, "alpha", routes[0].Name)
	assert.Equal(t, "mike", routes[1].Name)
	assert.Equal(t, "zulu", routes[2].Name)
}

// TestConfigHandler_CollectGraphQLRoutes_SpecificityOrder verifies GraphQL
// routes are collected in the SAME specificity order the data-plane router
// establishes in LoadRoutes (shared exported priority function).
func TestConfigHandler_CollectGraphQLRoutes_SpecificityOrder(t *testing.T) {
	handler, _ := newKeySymmetryHandler()
	ctx := context.Background()

	specs := []config.GraphQLRoute{
		{Name: "generic"},
		{
			Name:  "path-exact",
			Match: []config.GraphQLRouteMatch{{Path: &config.StringMatch{Exact: "/graphql"}}},
		},
		{
			Name:  "op-type",
			Match: []config.GraphQLRouteMatch{{OperationType: "query"}},
		},
	}

	for i := range specs {
		specJSON, err := json.Marshal(specs[i])
		require.NoError(t, err)
		require.NoError(t, handler.HandleUpdate(ctx, &operatorv1alpha1.ConfigurationUpdate{
			Type: operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
			Resource: &operatorv1alpha1.ConfigurationResource{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRAPHQL_ROUTE,
				Name:      specs[i].Name,
				Namespace: "default",
				SpecJson:  specJSON,
			},
		}))
	}

	_, _, _, _, graphqlRoutes, _ := handler.GetCurrentState()
	require.Len(t, graphqlRoutes, 3)
	assert.Equal(t, "path-exact", graphqlRoutes[0].Name, "most specific first")
	assert.Equal(t, "op-type", graphqlRoutes[1].Name)
	assert.Equal(t, "generic", graphqlRoutes[2].Name, "catch-all last")
}

// TestConfigHandler_SnapshotUndecodableResourceSkipped verifies undecodable
// snapshot resources are skipped (logged) while valid siblings apply.
func TestConfigHandler_SnapshotUndecodableResourceSkipped(t *testing.T) {
	handler, _ := newKeySymmetryHandler()

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        "v1",
		TotalResources: 2,
		ApiRoutes: []*operatorv1alpha1.ConfigurationResource{
			{
				Type:      operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE,
				Name:      "broken",
				Namespace: "default",
				SpecJson:  []byte("not json"),
			},
			namespacedRouteResource(t, "default", "valid-route"),
		},
	}
	require.NoError(t, handler.HandleSnapshot(context.Background(), snapshot))

	routes, _, _, _, _, _ := handler.GetCurrentState()
	require.Len(t, routes, 1)
	assert.Equal(t, "valid-route", routes[0].Name)
}
