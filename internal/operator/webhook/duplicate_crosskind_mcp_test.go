// Package webhook contains regression tests for the MCPRoute cross-route
// conflict detection (requirement B): same-kind duplicate detection, the two
// MCP↔APIRoute and MCP↔GraphQLRoute cross-conflict checks in BOTH directions,
// the overlap primitives, and the cache/list-error/deletion branches.
package webhook

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// errListClient wraps a fake client whose List always returns an error, used
// to exercise the "failed to list ..." error arms.
func newListErrorChecker(t *testing.T) *DuplicateChecker {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errors.New("boom: list failed")
			},
		}).
		Build()
	return NewDuplicateChecker(fakeClient)
}

// newMCPRoute builds a namespaced MCPRoute with a single match block.
func newMCPRoute(name, namespace string, match *avapigwv1alpha1.MCPRouteMatch) *avapigwv1alpha1.MCPRoute {
	route := &avapigwv1alpha1.MCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       avapigwv1alpha1.MCPRouteSpec{Upstreams: []string{"mcp-backend"}},
	}
	if match != nil {
		route.Spec.Match = []avapigwv1alpha1.MCPRouteMatch{*match}
	}
	return route
}

// ============================================================================
// 2.1 CheckMCPRouteDuplicate
// ============================================================================

func TestCheckMCPRouteDuplicate(t *testing.T) {
	t.Parallel()

	exactMCP := &avapigwv1alpha1.MCPRouteMatch{
		Path:    &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
		Method:  "tools/call",
		Headers: []avapigwv1alpha1.HeaderMatch{{Name: "X-Env", Exact: "prod"}},
	}

	tests := []struct {
		name         string
		existing     *avapigwv1alpha1.MCPRoute
		candidate    *avapigwv1alpha1.MCPRoute
		wantConflict bool
	}{
		{
			name:         "identical exact path + same method + compatible headers → conflict",
			existing:     newMCPRoute("existing", "default", exactMCP),
			candidate:    newMCPRoute("candidate", "default", exactMCP),
			wantConflict: true,
		},
		{
			name:     "different exact path → ok",
			existing: newMCPRoute("existing", "default", exactMCP),
			candidate: newMCPRoute("candidate", "default", &avapigwv1alpha1.MCPRouteMatch{
				Path: &avapigwv1alpha1.StringMatch{Exact: "/other"}, Method: "tools/call",
			}),
			wantConflict: false,
		},
		{
			name:     "same path different method → ok",
			existing: newMCPRoute("existing", "default", exactMCP),
			candidate: newMCPRoute("candidate", "default", &avapigwv1alpha1.MCPRouteMatch{
				Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}, Method: "resources/read",
			}),
			wantConflict: false,
		},
		{
			name:     "same path disjoint header values → ok",
			existing: newMCPRoute("existing", "default", exactMCP),
			candidate: newMCPRoute("candidate", "default", &avapigwv1alpha1.MCPRouteMatch{
				Path:    &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
				Method:  "tools/call",
				Headers: []avapigwv1alpha1.HeaderMatch{{Name: "X-Env", Exact: "dev"}},
			}),
			wantConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			checker := newCrossKindChecker(t, tt.existing)
			err := checker.CheckMCPRouteDuplicate(context.Background(), tt.candidate)
			if tt.wantConflict {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "conflicts with existing route(s)")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckMCPRouteDuplicate_NilClient(t *testing.T) {
	t.Parallel()
	checker := NewDuplicateChecker(nil)
	err := checker.CheckMCPRouteDuplicate(context.Background(),
		newMCPRoute("candidate", "default", &avapigwv1alpha1.MCPRouteMatch{
			Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}))
	require.NoError(t, err)
}

func TestCheckMCPRouteDuplicate_ListError(t *testing.T) {
	t.Parallel()
	checker := newListErrorChecker(t)
	err := checker.CheckMCPRouteDuplicate(context.Background(),
		newMCPRoute("candidate", "default", &avapigwv1alpha1.MCPRouteMatch{
			Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list MCPRoutes")
}

func TestCheckMCPRouteDuplicate_IsBeingDeletedSkipped(t *testing.T) {
	t.Parallel()

	existing := newMCPRoute("existing", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})
	now := metav1.Now()
	existing.DeletionTimestamp = &now
	existing.Finalizers = []string{"avapigw.io/finalizer"}

	checker := newCrossKindChecker(t, existing)
	candidate := newMCPRoute("candidate", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})

	// The existing route is being deleted → skipped → no conflict.
	err := checker.CheckMCPRouteDuplicate(context.Background(), candidate)
	require.NoError(t, err)
}

func TestCheckMCPRouteDuplicate_CacheHit(t *testing.T) {
	t.Parallel()

	existing := newMCPRoute("existing", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})

	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	checker := NewDuplicateChecker(fakeClient,
		WithCacheEnabled(true), WithCacheTTL(10*time.Second))
	t.Cleanup(checker.Stop)

	candidate := newMCPRoute("candidate", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})

	// First call populates cache and detects conflict.
	err := checker.CheckMCPRouteDuplicate(context.Background(), candidate)
	require.Error(t, err)
	// Second call is served from cache and detects the same conflict.
	err = checker.CheckMCPRouteDuplicate(context.Background(), candidate)
	require.Error(t, err)
}

// TestCheckMCPRouteDuplicate_CatchAllTopology drives the catch-all arms of
// mcpRoutesOverlap: two match-less routes conflict; a catch-all vs a route
// with matches does not.
func TestCheckMCPRouteDuplicate_CatchAllTopology(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		existing     *avapigwv1alpha1.MCPRoute
		candidate    *avapigwv1alpha1.MCPRoute
		wantConflict bool
	}{
		{
			name:         "two catch-alls conflict",
			existing:     newMCPRoute("existing", "default", nil),
			candidate:    newMCPRoute("candidate", "default", nil),
			wantConflict: true,
		},
		{
			name:     "catch-all vs matched route coexist",
			existing: newMCPRoute("existing", "default", nil),
			candidate: newMCPRoute("candidate", "default", &avapigwv1alpha1.MCPRouteMatch{
				Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}),
			wantConflict: false,
		},
		{
			name: "matched route vs catch-all coexist",
			existing: newMCPRoute("existing", "default", &avapigwv1alpha1.MCPRouteMatch{
				Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}),
			candidate:    newMCPRoute("candidate", "default", nil),
			wantConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			checker := newCrossKindChecker(t, tt.existing)
			err := checker.CheckMCPRouteDuplicate(context.Background(), tt.candidate)
			if tt.wantConflict {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// 2.2 / 2.4 CheckMCPRouteCrossConflictsWithAPIRoute + reverse
// ============================================================================

func TestCheckMCPRouteCrossConflictsWithAPIRoute_Topology(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		mcpPath      *avapigwv1alpha1.StringMatch // nil → catch-all
		apiURI       *avapigwv1alpha1.URIMatch    // nil → catch-all
		wantConflict bool
	}{
		{
			name:         "exact /mcp vs exact /mcp → conflict",
			mcpPath:      &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
			apiURI:       &avapigwv1alpha1.URIMatch{Exact: "/mcp"},
			wantConflict: true,
		},
		{
			name:         "identical prefixes → conflict",
			mcpPath:      &avapigwv1alpha1.StringMatch{Prefix: "/mcp"},
			apiURI:       &avapigwv1alpha1.URIMatch{Prefix: "/mcp"},
			wantConflict: true,
		},
		{
			name:         "exact vs prefix → no conflict",
			mcpPath:      &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
			apiURI:       &avapigwv1alpha1.URIMatch{Prefix: "/"},
			wantConflict: false,
		},
		{
			name:         "regex vs exact → no conflict",
			mcpPath:      &avapigwv1alpha1.StringMatch{Regex: "^/mcp$"},
			apiURI:       &avapigwv1alpha1.URIMatch{Exact: "/mcp"},
			wantConflict: false,
		},
		{
			name:         "mcp catch-all → no conflict",
			mcpPath:      nil,
			apiURI:       &avapigwv1alpha1.URIMatch{Exact: "/mcp"},
			wantConflict: false,
		},
		{
			name:         "api catch-all → no conflict",
			mcpPath:      &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
			apiURI:       nil,
			wantConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Direction 1: MCPRoute vs existing APIRoute.
			existingAPI := newAPIRoute("existing-api", "default", tt.apiURI)
			checker1 := newCrossKindChecker(t, existingAPI)
			var mcpMatch *avapigwv1alpha1.MCPRouteMatch
			if tt.mcpPath != nil {
				mcpMatch = &avapigwv1alpha1.MCPRouteMatch{Path: tt.mcpPath}
			}
			mcpRoute := newMCPRoute("new-mcp", "default", mcpMatch)

			err := checker1.CheckMCPRouteCrossConflictsWithAPIRoute(context.Background(), mcpRoute)
			if tt.wantConflict {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "has path conflict with APIRoute:")
			} else {
				require.NoError(t, err)
			}

			// Direction 2 (reverse): APIRoute vs existing MCPRoute.
			existingMCP := newMCPRoute("existing-mcp", "default", mcpMatch)
			checker2 := newCrossKindChecker(t, existingMCP)
			apiRoute := newAPIRoute("new-api", "default", tt.apiURI)

			err = checker2.CheckAPIRouteCrossConflictsWithMCP(context.Background(), apiRoute)
			if tt.wantConflict {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "has path conflict with MCPRoute:")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckMCPRouteCrossConflictsWithAPIRoute_NilClient(t *testing.T) {
	t.Parallel()
	checker := NewDuplicateChecker(nil)
	require.NoError(t, checker.CheckMCPRouteCrossConflictsWithAPIRoute(context.Background(),
		newMCPRoute("mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
			Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})))
}

func TestCheckMCPRouteCrossConflictsWithAPIRoute_ListError(t *testing.T) {
	t.Parallel()
	checker := newListErrorChecker(t)
	err := checker.CheckMCPRouteCrossConflictsWithAPIRoute(context.Background(),
		newMCPRoute("mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
			Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list APIRoutes")
}

func TestCheckMCPRouteCrossConflictsWithAPIRoute_IsBeingDeletedSkipped(t *testing.T) {
	t.Parallel()

	existingAPI := newAPIRoute("existing-api", "default", &avapigwv1alpha1.URIMatch{Exact: "/mcp"})
	now := metav1.Now()
	existingAPI.DeletionTimestamp = &now
	existingAPI.Finalizers = []string{"avapigw.io/finalizer"}

	checker := newCrossKindChecker(t, existingAPI)
	mcpRoute := newMCPRoute("mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})
	require.NoError(t, checker.CheckMCPRouteCrossConflictsWithAPIRoute(context.Background(), mcpRoute))
}

func TestCheckMCPRouteCrossConflictsWithAPIRoute_CacheHit(t *testing.T) {
	t.Parallel()

	existingAPI := newAPIRoute("existing-api", "default", &avapigwv1alpha1.URIMatch{Exact: "/mcp"})
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingAPI).Build()

	checker := NewDuplicateChecker(fakeClient, WithCacheEnabled(true), WithCacheTTL(10*time.Second))
	t.Cleanup(checker.Stop)

	mcpRoute := newMCPRoute("mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})
	require.Error(t, checker.CheckMCPRouteCrossConflictsWithAPIRoute(context.Background(), mcpRoute))
	require.Error(t, checker.CheckMCPRouteCrossConflictsWithAPIRoute(context.Background(), mcpRoute))
}

func TestCheckAPIRouteCrossConflictsWithMCP_NilClient(t *testing.T) {
	t.Parallel()
	checker := NewDuplicateChecker(nil)
	require.NoError(t, checker.CheckAPIRouteCrossConflictsWithMCP(context.Background(),
		newAPIRoute("api", "default", &avapigwv1alpha1.URIMatch{Exact: "/mcp"})))
}

func TestCheckAPIRouteCrossConflictsWithMCP_ListError(t *testing.T) {
	t.Parallel()
	checker := newListErrorChecker(t)
	err := checker.CheckAPIRouteCrossConflictsWithMCP(context.Background(),
		newAPIRoute("api", "default", &avapigwv1alpha1.URIMatch{Exact: "/mcp"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list MCPRoutes")
}

func TestCheckAPIRouteCrossConflictsWithMCP_IsBeingDeletedSkipped(t *testing.T) {
	t.Parallel()

	existingMCP := newMCPRoute("existing-mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})
	now := metav1.Now()
	existingMCP.DeletionTimestamp = &now
	existingMCP.Finalizers = []string{"avapigw.io/finalizer"}

	checker := newCrossKindChecker(t, existingMCP)
	apiRoute := newAPIRoute("api", "default", &avapigwv1alpha1.URIMatch{Exact: "/mcp"})
	require.NoError(t, checker.CheckAPIRouteCrossConflictsWithMCP(context.Background(), apiRoute))
}

func TestCheckAPIRouteCrossConflictsWithMCP_CacheHit(t *testing.T) {
	t.Parallel()

	existingMCP := newMCPRoute("existing-mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingMCP).Build()

	checker := NewDuplicateChecker(fakeClient, WithCacheEnabled(true), WithCacheTTL(10*time.Second))
	t.Cleanup(checker.Stop)

	apiRoute := newAPIRoute("api", "default", &avapigwv1alpha1.URIMatch{Exact: "/mcp"})
	require.Error(t, checker.CheckAPIRouteCrossConflictsWithMCP(context.Background(), apiRoute))
	require.Error(t, checker.CheckAPIRouteCrossConflictsWithMCP(context.Background(), apiRoute))
}

// ============================================================================
// 2.3 / 2.5 CheckMCPRouteCrossConflictsWithGraphQL + reverse
// ============================================================================

func TestCheckMCPRouteCrossConflictsWithGraphQL_Topology(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		mcpPath      *avapigwv1alpha1.StringMatch
		gqlPath      *avapigwv1alpha1.StringMatch
		wantConflict bool
	}{
		{
			name:         "exact /mcp vs exact /mcp → conflict",
			mcpPath:      &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
			gqlPath:      &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
			wantConflict: true,
		},
		{
			name:         "identical prefixes → conflict",
			mcpPath:      &avapigwv1alpha1.StringMatch{Prefix: "/a"},
			gqlPath:      &avapigwv1alpha1.StringMatch{Prefix: "/a"},
			wantConflict: true,
		},
		{
			name:         "exact vs prefix → no conflict",
			mcpPath:      &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
			gqlPath:      &avapigwv1alpha1.StringMatch{Prefix: "/"},
			wantConflict: false,
		},
		{
			name:         "mcp catch-all → no conflict",
			mcpPath:      nil,
			gqlPath:      &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
			wantConflict: false,
		},
		{
			name:         "gql catch-all → no conflict",
			mcpPath:      &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
			gqlPath:      nil,
			wantConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Direction 1: MCPRoute vs existing GraphQLRoute.
			existingGQL := newCrossKindGraphQLRoute("existing-gql", "default", tt.gqlPath)
			checker1 := newCrossKindChecker(t, existingGQL)
			var mcpMatch *avapigwv1alpha1.MCPRouteMatch
			if tt.mcpPath != nil {
				mcpMatch = &avapigwv1alpha1.MCPRouteMatch{Path: tt.mcpPath}
			}
			mcpRoute := newMCPRoute("new-mcp", "default", mcpMatch)

			err := checker1.CheckMCPRouteCrossConflictsWithGraphQL(context.Background(), mcpRoute)
			if tt.wantConflict {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "has path conflict with GraphQLRoute:")
			} else {
				require.NoError(t, err)
			}

			// Direction 2 (reverse): GraphQLRoute vs existing MCPRoute.
			existingMCP := newMCPRoute("existing-mcp", "default", mcpMatch)
			checker2 := newCrossKindChecker(t, existingMCP)
			gqlRoute := newCrossKindGraphQLRoute("new-gql", "default", tt.gqlPath)

			err = checker2.CheckGraphQLRouteCrossConflictsWithMCP(context.Background(), gqlRoute)
			if tt.wantConflict {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "has path conflict with MCPRoute:")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckMCPRouteCrossConflictsWithGraphQL_NilClient(t *testing.T) {
	t.Parallel()
	checker := NewDuplicateChecker(nil)
	require.NoError(t, checker.CheckMCPRouteCrossConflictsWithGraphQL(context.Background(),
		newMCPRoute("mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
			Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})))
}

func TestCheckMCPRouteCrossConflictsWithGraphQL_ListError(t *testing.T) {
	t.Parallel()
	checker := newListErrorChecker(t)
	err := checker.CheckMCPRouteCrossConflictsWithGraphQL(context.Background(),
		newMCPRoute("mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
			Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list GraphQLRoutes")
}

func TestCheckMCPRouteCrossConflictsWithGraphQL_CacheHit(t *testing.T) {
	t.Parallel()

	existingGQL := newCrossKindGraphQLRoute("existing-gql", "default",
		&avapigwv1alpha1.StringMatch{Exact: "/mcp"})
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingGQL).Build()

	checker := NewDuplicateChecker(fakeClient, WithCacheEnabled(true), WithCacheTTL(10*time.Second))
	t.Cleanup(checker.Stop)

	mcpRoute := newMCPRoute("mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"}})
	require.Error(t, checker.CheckMCPRouteCrossConflictsWithGraphQL(context.Background(), mcpRoute))
	require.Error(t, checker.CheckMCPRouteCrossConflictsWithGraphQL(context.Background(), mcpRoute))
}

func TestCheckGraphQLRouteCrossConflictsWithMCP_NilClient(t *testing.T) {
	t.Parallel()
	checker := NewDuplicateChecker(nil)
	require.NoError(t, checker.CheckGraphQLRouteCrossConflictsWithMCP(context.Background(),
		newCrossKindGraphQLRoute("gql", "default", &avapigwv1alpha1.StringMatch{Exact: "/mcp"})))
}

func TestCheckGraphQLRouteCrossConflictsWithMCP_ListError(t *testing.T) {
	t.Parallel()
	checker := newListErrorChecker(t)
	err := checker.CheckGraphQLRouteCrossConflictsWithMCP(context.Background(),
		newCrossKindGraphQLRoute("gql", "default", &avapigwv1alpha1.StringMatch{Exact: "/mcp"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list MCPRoutes")
}

func TestCheckGraphQLRouteCrossConflictsWithMCP_IsBeingDeletedSkipped(t *testing.T) {
	t.Parallel()

	existingMCP := newMCPRoute("existing-mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Prefix: "/a"}})
	now := metav1.Now()
	existingMCP.DeletionTimestamp = &now
	existingMCP.Finalizers = []string{"avapigw.io/finalizer"}

	checker := newCrossKindChecker(t, existingMCP)
	gqlRoute := newCrossKindGraphQLRoute("gql", "default", &avapigwv1alpha1.StringMatch{Prefix: "/a"})
	require.NoError(t, checker.CheckGraphQLRouteCrossConflictsWithMCP(context.Background(), gqlRoute))
}

func TestCheckGraphQLRouteCrossConflictsWithMCP_CacheHit(t *testing.T) {
	t.Parallel()

	existingMCP := newMCPRoute("existing-mcp", "default", &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Prefix: "/a"}})
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingMCP).Build()

	checker := NewDuplicateChecker(fakeClient, WithCacheEnabled(true), WithCacheTTL(10*time.Second))
	t.Cleanup(checker.Stop)

	gqlRoute := newCrossKindGraphQLRoute("gql", "default", &avapigwv1alpha1.StringMatch{Prefix: "/a"})
	require.Error(t, checker.CheckGraphQLRouteCrossConflictsWithMCP(context.Background(), gqlRoute))
	require.Error(t, checker.CheckGraphQLRouteCrossConflictsWithMCP(context.Background(), gqlRoute))
}

// ============================================================================
// 2.6 mcpHeaderValuesCompatible matrix + mcpHeaderSetsCompatible
// ============================================================================

func TestMCPHeaderValuesCompatible(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b avapigwv1alpha1.HeaderMatch
		want bool
	}{
		{"exact==exact match", avapigwv1alpha1.HeaderMatch{Exact: "x"}, avapigwv1alpha1.HeaderMatch{Exact: "x"}, true},
		{"exact!=exact mismatch", avapigwv1alpha1.HeaderMatch{Exact: "x"}, avapigwv1alpha1.HeaderMatch{Exact: "y"}, false},
		{"exact has prefix", avapigwv1alpha1.HeaderMatch{Exact: "prod-1"}, avapigwv1alpha1.HeaderMatch{Prefix: "prod"}, true},
		{"exact lacks prefix", avapigwv1alpha1.HeaderMatch{Exact: "dev-1"}, avapigwv1alpha1.HeaderMatch{Prefix: "prod"}, false},
		{"prefix vs exact match", avapigwv1alpha1.HeaderMatch{Prefix: "prod"}, avapigwv1alpha1.HeaderMatch{Exact: "prod-1"}, true},
		{"prefix vs exact mismatch", avapigwv1alpha1.HeaderMatch{Prefix: "prod"}, avapigwv1alpha1.HeaderMatch{Exact: "dev-1"}, false},
		{"nested prefixes", avapigwv1alpha1.HeaderMatch{Prefix: "prod"}, avapigwv1alpha1.HeaderMatch{Prefix: "prod-eu"}, true},
		{"disjoint prefixes", avapigwv1alpha1.HeaderMatch{Prefix: "prod"}, avapigwv1alpha1.HeaderMatch{Prefix: "dev"}, false},
		{"regex default compatible", avapigwv1alpha1.HeaderMatch{Regex: "^x$"}, avapigwv1alpha1.HeaderMatch{Regex: "^y$"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, b := tt.a, tt.b
			assert.Equal(t, tt.want, mcpHeaderValuesCompatible(&a, &b))
		})
	}
}

func TestMCPHeaderSetsCompatible(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b []avapigwv1alpha1.HeaderMatch
		want bool
	}{
		{
			name: "different names are independent",
			a:    []avapigwv1alpha1.HeaderMatch{{Name: "X-A", Exact: "1"}},
			b:    []avapigwv1alpha1.HeaderMatch{{Name: "X-B", Exact: "2"}},
			want: true,
		},
		{
			name: "same name case-insensitive disjoint values → incompatible",
			a:    []avapigwv1alpha1.HeaderMatch{{Name: "X-Env", Exact: "prod"}},
			b:    []avapigwv1alpha1.HeaderMatch{{Name: "x-env", Exact: "dev"}},
			want: false,
		},
		{
			name: "same name compatible values",
			a:    []avapigwv1alpha1.HeaderMatch{{Name: "X-Env", Exact: "prod-1"}},
			b:    []avapigwv1alpha1.HeaderMatch{{Name: "X-Env", Prefix: "prod"}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, mcpHeaderSetsCompatible(tt.a, tt.b))
		})
	}
}

// TestMCPStringMatchesIdentical drives all arms of mcpStringMatchesIdentical,
// including the one-catch-all/one-concrete arm that returns false.
func TestMCPStringMatchesIdentical(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b *avapigwv1alpha1.StringMatch
		want bool
	}{
		{"both catch-all (nil)", nil, nil, true},
		{"both catch-all (empty)", &avapigwv1alpha1.StringMatch{}, &avapigwv1alpha1.StringMatch{}, true},
		{"a catch-all, b concrete", nil, &avapigwv1alpha1.StringMatch{Exact: "/a"}, false},
		{"a concrete, b catch-all", &avapigwv1alpha1.StringMatch{Exact: "/a"}, nil, false},
		{"identical exacts", &avapigwv1alpha1.StringMatch{Exact: "/a"}, &avapigwv1alpha1.StringMatch{Exact: "/a"}, true},
		{"different exacts", &avapigwv1alpha1.StringMatch{Exact: "/a"}, &avapigwv1alpha1.StringMatch{Exact: "/b"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, mcpStringMatchesIdentical(tt.a, tt.b))
		})
	}
}

// TestMCPMatchConditionsOverlap_NameDivergence exercises the name-divergence
// early return in mcpMatchConditionsOverlap (identical path, one named / one
// not → not a duplicate).
func TestMCPMatchConditionsOverlap_NameDivergence(t *testing.T) {
	t.Parallel()

	checker := &DuplicateChecker{}
	a := &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
		Name: &avapigwv1alpha1.StringMatch{Exact: "toolA"},
	}
	b := &avapigwv1alpha1.MCPRouteMatch{
		Path: &avapigwv1alpha1.StringMatch{Exact: "/mcp"},
		// no Name → catch-all name
	}
	assert.False(t, checker.mcpMatchConditionsOverlap(a, b))
}

// ============================================================================
// 2.7 mcpMethodsOverlap
// ============================================================================

func TestMCPMethodsOverlap(t *testing.T) {
	t.Parallel()

	checker := &DuplicateChecker{}
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"empty a matches all", "", "tools/call", true},
		{"empty b matches all", "tools/call", "", true},
		{"both empty", "", "", true},
		{"case-insensitive equal", "tools/call", "TOOLS/CALL", true},
		{"distinct methods", "tools/call", "resources/read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, checker.mcpMethodsOverlap(tt.a, tt.b))
		})
	}
}

// ============================================================================
// 3.1 overlap parity: MCP↔API / MCP↔GraphQL agree with the shared rule and
// symmetric wrappers delegate correctly.
// ============================================================================

func TestMCPPathsOverlapParity(t *testing.T) {
	t.Parallel()

	checker := &DuplicateChecker{}

	cases := []struct {
		name        string
		mcpPath     *avapigwv1alpha1.StringMatch
		apiURI      *avapigwv1alpha1.URIMatch
		gqlPath     *avapigwv1alpha1.StringMatch
		wantOverlap bool
	}{
		{"exact==exact", &avapigwv1alpha1.StringMatch{Exact: "/a"}, &avapigwv1alpha1.URIMatch{Exact: "/a"}, &avapigwv1alpha1.StringMatch{Exact: "/a"}, true},
		{"prefix==prefix", &avapigwv1alpha1.StringMatch{Prefix: "/a"}, &avapigwv1alpha1.URIMatch{Prefix: "/a"}, &avapigwv1alpha1.StringMatch{Prefix: "/a"}, true},
		{"exact-vs-prefix", &avapigwv1alpha1.StringMatch{Exact: "/a"}, &avapigwv1alpha1.URIMatch{Prefix: "/a"}, &avapigwv1alpha1.StringMatch{Prefix: "/a"}, false},
		{"regex", &avapigwv1alpha1.StringMatch{Regex: "^/a$"}, &avapigwv1alpha1.URIMatch{Exact: "/a"}, &avapigwv1alpha1.StringMatch{Exact: "/a"}, false},
		{"nil mcp path", nil, &avapigwv1alpha1.URIMatch{Exact: "/a"}, &avapigwv1alpha1.StringMatch{Exact: "/a"}, false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mcpMatch := &avapigwv1alpha1.MCPRouteMatch{Path: tt.mcpPath}
			apiMatch := &avapigwv1alpha1.RouteMatch{URI: tt.apiURI}
			gqlMatch := &avapigwv1alpha1.GraphQLRouteMatch{Path: tt.gqlPath}

			expected := tt.wantOverlap
			if tt.mcpPath == nil {
				expected = false
			}

			assert.Equal(t, expected, checker.mcpRouteAndAPIRoutePathsOverlap(mcpMatch, apiMatch))
			assert.Equal(t, expected, checker.mcpRouteAndGraphQLRoutePathsOverlap(mcpMatch, gqlMatch))

			// Symmetric wrappers delegate to the same computation.
			mcpRoute := &avapigwv1alpha1.MCPRoute{Spec: avapigwv1alpha1.MCPRouteSpec{
				Match: []avapigwv1alpha1.MCPRouteMatch{*mcpMatch}}}
			apiRoute := &avapigwv1alpha1.APIRoute{Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{*apiMatch}}}
			gqlRoute := &avapigwv1alpha1.GraphQLRoute{Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{*gqlMatch}}}

			assert.Equal(t,
				checker.mcpRouteAndAPIRouteOverlap(mcpRoute, apiRoute),
				checker.apiRouteAndMCPRouteOverlap(apiRoute, mcpRoute))
			assert.Equal(t,
				checker.mcpRouteAndGraphQLRouteOverlap(mcpRoute, gqlRoute),
				checker.graphqlRouteAndMCPRouteOverlap(gqlRoute, mcpRoute))
		})
	}
}

// ============================================================================
// pathMatchesIdenticalSpecificity table (explicit)
// ============================================================================

func TestPathMatchesIdenticalSpecificity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                             string
		aExact, aPrefix, bExact, bPrefix string
		want                             bool
	}{
		{"exact==exact", "/a", "", "/a", "", true},
		{"exact!=exact", "/a", "", "/b", "", false},
		{"prefix==prefix", "", "/a", "", "/a", true},
		{"prefix!=prefix", "", "/a", "", "/b", false},
		{"exact vs prefix", "/a", "", "", "/a", false},
		{"prefix vs exact", "", "/a", "/a", "", false},
		{"all empty", "", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want,
				pathMatchesIdenticalSpecificity(tt.aExact, tt.aPrefix, tt.bExact, tt.bPrefix))
		})
	}
}

// ============================================================================
// 4.1 metrics label includes "mcproute"
// ============================================================================

func TestInitDuplicateVecMetrics_IncludesMCPRoute(t *testing.T) {
	InitDuplicateVecMetrics()

	dm := getDuplicateMetrics()
	// The mcproute label must be pre-populated on the duplicate-check vectors.
	assert.NotPanics(t, func() {
		dm.checkTotal.WithLabelValues(resTypeMCPRoute, "namespace", "ok")
		dm.cacheHits.WithLabelValues(resTypeMCPRoute)
		dm.cacheMisses.WithLabelValues(resTypeMCPRoute)
	})
	assert.Equal(t, "mcproute", resTypeMCPRoute)
}

// ============================================================================
// 4.2 resourceCache MCP slot lifecycle
// ============================================================================

func TestResourceCache_MCPSlotLifecycle(t *testing.T) {
	t.Parallel()

	rc := newResourceCache()
	require.NotNil(t, rc.mcpRoutes, "newResourceCache should initialize mcpRoutes")

	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	checker := NewDuplicateChecker(fakeClient, WithCacheEnabled(true))
	t.Cleanup(checker.Stop)

	checker.cache.mu.Lock()
	checker.cache.mcpRoutes["mcproute:default"] = &avapigwv1alpha1.MCPRouteList{}
	checker.cache.mu.Unlock()

	checker.InvalidateCache()

	checker.cache.mu.RLock()
	got := len(checker.cache.mcpRoutes)
	checker.cache.mu.RUnlock()
	assert.Equal(t, 0, got, "InvalidateCache should clear mcpRoutes")
}
