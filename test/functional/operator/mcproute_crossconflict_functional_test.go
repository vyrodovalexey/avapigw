//go:build functional

// Package operator_test contains functional tests for the apigw-operator.
//
// This file black-boxes the MCPRoute admission webhook (webhook.MCPRouteValidator)
// through its public ValidateCreate/ValidateUpdate API, mirroring the existing
// APIRoute<->GraphQLRoute cross-route conflict functional tests. It asserts the
// MCPRoute<->APIRoute and MCPRoute<->GraphQLRoute cross-kind admission rules:
// colliding path.exact/prefix (identical specificity) is denied, while
// non-colliding or different-specificity combinations are admitted (the data
// plane orders them deterministically).
package operator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// mcpRouteWith builds a namespaced MCPRoute with a single path match block (or a
// catch-all MCPRoute when match is nil) fanning out to a single upstream.
func mcpRouteWith(name string, match *avapigwv1alpha1.MCPRouteMatch) *avapigwv1alpha1.MCPRoute {
	route := &avapigwv1alpha1.MCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       avapigwv1alpha1.MCPRouteSpec{Upstreams: []string{"mcp-backend"}},
	}
	if match != nil {
		route.Spec.Match = []avapigwv1alpha1.MCPRouteMatch{*match}
	}
	return route
}

// mcpPathMatch is a small helper for a path-only MCPRouteMatch.
func mcpPathMatch(sm *avapigwv1alpha1.StringMatch) *avapigwv1alpha1.MCPRouteMatch {
	return &avapigwv1alpha1.MCPRouteMatch{Path: sm}
}

// TestFunctional_Webhook_MCPRouteAPIRouteCrossConflict tests that creating an
// MCPRoute that collides with an existing APIRoute is rejected, while
// non-colliding / different-specificity combinations are admitted. This mirrors
// TestFunctional_Webhook_APIRouteGraphQLCrossConflict for the MCP analogue.
func TestFunctional_Webhook_MCPRouteAPIRouteCrossConflict(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	t.Run("MCPRoute identical exact path as APIRoute exact path rejected", func(t *testing.T) {
		t.Parallel()

		existingAPI := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "api-route-exact", Namespace: "default"},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Exact: "/mcp"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "rest-backend", Port: 8080}, Weight: 100},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingAPI).Build()
		dc := webhook.NewDuplicateCheckerWithContext(context.Background(), fakeClient)
		validator := &webhook.MCPRouteValidator{Client: fakeClient, DuplicateChecker: dc}

		// Identical exact path → identical specificity → genuine cross-kind
		// duplicate that admission must reject.
		conflicting := mcpRouteWith("mcp-route-conflict",
			mcpPathMatch(&avapigwv1alpha1.StringMatch{Exact: "/mcp"}))

		_, err := validator.ValidateCreate(context.Background(), conflicting)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")
		assert.Contains(t, err.Error(), "APIRoute")
	})

	t.Run("MCPRoute identical prefix as APIRoute prefix rejected", func(t *testing.T) {
		t.Parallel()

		existingAPI := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "api-route-prefix", Namespace: "default"},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/mcp"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "rest-backend", Port: 8080}, Weight: 100},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingAPI).Build()
		dc := webhook.NewDuplicateCheckerWithContext(context.Background(), fakeClient)
		validator := &webhook.MCPRouteValidator{Client: fakeClient, DuplicateChecker: dc}

		conflicting := mcpRouteWith("mcp-route-prefix-conflict",
			mcpPathMatch(&avapigwv1alpha1.StringMatch{Prefix: "/mcp"}))

		_, err := validator.ValidateCreate(context.Background(), conflicting)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")
		assert.Contains(t, err.Error(), "APIRoute")
	})

	t.Run("MCPRoute exact path coexists with broader APIRoute prefix", func(t *testing.T) {
		t.Parallel()

		existingAPI := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "api-route-catchall", Namespace: "default"},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "rest-backend", Port: 8080}, Weight: 100},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingAPI).Build()
		dc := webhook.NewDuplicateCheckerWithContext(context.Background(), fakeClient)
		validator := &webhook.MCPRouteValidator{Client: fakeClient, DuplicateChecker: dc}

		// Exact vs prefix is different specificity: the data plane orders
		// them deterministically, so admission must allow the combination.
		nonConflicting := mcpRouteWith("mcp-route-exact",
			mcpPathMatch(&avapigwv1alpha1.StringMatch{Exact: "/mcp"}))

		_, err := validator.ValidateCreate(context.Background(), nonConflicting)
		require.NoError(t, err,
			"MCPRoute exact path must coexist with a broader APIRoute prefix (different specificity)")
	})

	t.Run("MCPRoute on a different path coexists with APIRoute", func(t *testing.T) {
		t.Parallel()

		existingAPI := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "api-route-safe", Namespace: "default"},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "rest-backend", Port: 8080}, Weight: 100},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingAPI).Build()
		dc := webhook.NewDuplicateCheckerWithContext(context.Background(), fakeClient)
		validator := &webhook.MCPRouteValidator{Client: fakeClient, DuplicateChecker: dc}

		nonConflicting := mcpRouteWith("mcp-route-distinct",
			mcpPathMatch(&avapigwv1alpha1.StringMatch{Exact: "/mcp"}))

		_, err := validator.ValidateCreate(context.Background(), nonConflicting)
		require.NoError(t, err,
			"MCPRoute on a distinct path must coexist with an unrelated APIRoute")
	})
}

// TestFunctional_Webhook_MCPRouteGraphQLCrossConflict tests that creating an
// MCPRoute that collides with an existing GraphQLRoute is rejected, while
// non-colliding / different-specificity combinations are admitted. This mirrors
// TestFunctional_Webhook_GraphQLRouteAPIRouteCrossConflict for the MCP analogue.
func TestFunctional_Webhook_MCPRouteGraphQLCrossConflict(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	t.Run("MCPRoute identical exact path as GraphQLRoute exact path rejected", func(t *testing.T) {
		t.Parallel()

		existingGraphQL := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "graphql-route-exact", Namespace: "default"},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "graphql-backend", Port: 8821}, Weight: 100},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingGraphQL).Build()
		dc := webhook.NewDuplicateCheckerWithContext(context.Background(), fakeClient)
		validator := &webhook.MCPRouteValidator{Client: fakeClient, DuplicateChecker: dc}

		conflicting := mcpRouteWith("mcp-route-gql-conflict",
			mcpPathMatch(&avapigwv1alpha1.StringMatch{Exact: "/mcp"}))

		_, err := validator.ValidateCreate(context.Background(), conflicting)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")
		assert.Contains(t, err.Error(), "GraphQLRoute")
	})

	t.Run("MCPRoute identical prefix as GraphQLRoute prefix rejected", func(t *testing.T) {
		t.Parallel()

		existingGraphQL := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "graphql-route-prefix", Namespace: "default"},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{Path: &avapigwv1alpha1.StringMatch{Prefix: "/mcp"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "graphql-backend", Port: 8821}, Weight: 100},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingGraphQL).Build()
		dc := webhook.NewDuplicateCheckerWithContext(context.Background(), fakeClient)
		validator := &webhook.MCPRouteValidator{Client: fakeClient, DuplicateChecker: dc}

		conflicting := mcpRouteWith("mcp-route-gql-prefix-conflict",
			mcpPathMatch(&avapigwv1alpha1.StringMatch{Prefix: "/mcp"}))

		_, err := validator.ValidateCreate(context.Background(), conflicting)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")
		assert.Contains(t, err.Error(), "GraphQLRoute")
	})

	t.Run("MCPRoute exact path coexists with more specific GraphQLRoute exact path", func(t *testing.T) {
		t.Parallel()

		existingGraphQL := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "graphql-route-nested", Namespace: "default"},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp/graphql"}},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{Destination: avapigwv1alpha1.Destination{Host: "graphql-backend", Port: 8821}, Weight: 100},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingGraphQL).Build()
		dc := webhook.NewDuplicateCheckerWithContext(context.Background(), fakeClient)
		validator := &webhook.MCPRouteValidator{Client: fakeClient, DuplicateChecker: dc}

		// Distinct exact paths never collide.
		nonConflicting := mcpRouteWith("mcp-route-exact",
			mcpPathMatch(&avapigwv1alpha1.StringMatch{Exact: "/mcp"}))

		_, err := validator.ValidateCreate(context.Background(), nonConflicting)
		require.NoError(t, err,
			"MCPRoute exact path must coexist with a GraphQLRoute on a distinct exact path")
	})
}

// TestFunctional_Webhook_MCPRouteUpdateCrossConflict tests that updating an
// MCPRoute onto an identical-specificity path duplicate of an APIRoute is
// rejected, while the pre-update non-colliding spec was admissible. This mirrors
// TestFunctional_Webhook_CrossCRDUpdateConflict for the MCP analogue.
func TestFunctional_Webhook_MCPRouteUpdateCrossConflict(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	existingAPI := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "api-route-existing", Namespace: "default"},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Exact: "/mcp"}},
			},
			Route: []avapigwv1alpha1.RouteDestination{
				{Destination: avapigwv1alpha1.Destination{Host: "rest-backend", Port: 8080}, Weight: 100},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingAPI).Build()
	dc := webhook.NewDuplicateCheckerWithContext(context.Background(), fakeClient)
	validator := &webhook.MCPRouteValidator{Client: fakeClient, DuplicateChecker: dc}

	// The old MCPRoute is on a non-colliding path and is admissible.
	oldMCP := mcpRouteWith("mcp-route-updating",
		mcpPathMatch(&avapigwv1alpha1.StringMatch{Exact: "/mcp-safe"}))
	_, err := validator.ValidateCreate(context.Background(), oldMCP)
	require.NoError(t, err, "the pre-update non-colliding MCPRoute must be admissible")

	// The update moves it onto the APIRoute's exact path: identical
	// specificity → genuine cross-kind duplicate the update webhook rejects.
	newMCP := oldMCP.DeepCopy()
	newMCP.Spec.Match[0].Path = &avapigwv1alpha1.StringMatch{Exact: "/mcp"}

	_, err = validator.ValidateUpdate(context.Background(), oldMCP, newMCP)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path conflict")
	assert.Contains(t, err.Error(), "APIRoute")
}
