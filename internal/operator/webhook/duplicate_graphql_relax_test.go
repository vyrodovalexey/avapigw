// Package webhook contains regression tests for the GraphQL same-kind
// overlap relaxation: only identical-specificity match blocks with
// overlapping match values are admission conflicts, mirroring the sorted
// GraphQL data-plane router (internal/graphql/router). Parity tests pin the
// webhook's block scoring to the router's exported Specificity and verify
// admitted pairs resolve deterministically in the router.
package webhook

import (
	"context"
	"net/http/httptest"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/config"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
)

// newGraphQLRouteWithMatches builds a GraphQLRoute with the given match blocks.
func newGraphQLRouteWithMatches(name string, matches ...avapigwv1alpha1.GraphQLRouteMatch) *avapigwv1alpha1.GraphQLRoute {
	return &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       avapigwv1alpha1.GraphQLRouteSpec{Match: matches},
	}
}

// TestCheckGraphQLRouteDuplicate_SpecificityTopology is the WP5b regression
// table: different-specificity overlaps are admitted (the sorted router
// resolves them deterministically), identical-specificity overlapping
// values are still rejected.
//
//nolint:maintidx // Exhaustive semantics table for all match dimensions.
func TestCheckGraphQLRouteDuplicate_SpecificityTopology(t *testing.T) {
	exact := func(v string) *avapigwv1alpha1.StringMatch {
		return &avapigwv1alpha1.StringMatch{Exact: v}
	}
	prefix := func(v string) *avapigwv1alpha1.StringMatch {
		return &avapigwv1alpha1.StringMatch{Prefix: v}
	}
	regex := func(v string) *avapigwv1alpha1.StringMatch {
		return &avapigwv1alpha1.StringMatch{Regex: v}
	}

	tests := []struct {
		name      string
		existing  *avapigwv1alpha1.GraphQLRoute
		candidate *avapigwv1alpha1.GraphQLRoute
		wantErr   bool
	}{
		{
			// The fixture pair shape: graphql-basic (exact /graphql, no
			// opType, spec 1000) vs do04-graphql-route (exact /graphql +
			// operationType query, spec 1200).
			name: "opType-specific vs generic admitted (generic exists first)",
			existing: newGraphQLRouteWithMatches("generic",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			candidate: newGraphQLRouteWithMatches("typed",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationType: "query"}),
			wantErr: false,
		},
		{
			name: "opType-specific vs generic admitted (typed exists first)",
			existing: newGraphQLRouteWithMatches("typed",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationType: "query"}),
			candidate: newGraphQLRouteWithMatches("generic",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			wantErr: false,
		},
		{
			name: "identical exact path and opType rejected",
			existing: newGraphQLRouteWithMatches("first",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationType: "query"}),
			candidate: newGraphQLRouteWithMatches("second",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationType: "query"}),
			wantErr: true,
		},
		{
			name: "identical exact path without opTypes rejected",
			existing: newGraphQLRouteWithMatches("first",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			candidate: newGraphQLRouteWithMatches("second",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			wantErr: true,
		},
		{
			name: "same exact path with different opTypes admitted (disjoint values)",
			existing: newGraphQLRouteWithMatches("queries",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationType: "query"}),
			candidate: newGraphQLRouteWithMatches("mutations",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationType: "mutation"}),
			// Admitted: equal specificity but disjoint operation types —
			// no request carries both a query and a mutation.
			wantErr: false,
		},
		{
			name:      "both catch-all rejected",
			existing:  newGraphQLRouteWithMatches("first"),
			candidate: newGraphQLRouteWithMatches("second"),
			wantErr:   true,
		},
		{
			name:     "catch-all vs specific admitted (catch-all exists first)",
			existing: newGraphQLRouteWithMatches("catch-all"),
			candidate: newGraphQLRouteWithMatches("specific",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			wantErr: false,
		},
		{
			name: "catch-all vs specific admitted (specific exists first)",
			existing: newGraphQLRouteWithMatches("specific",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			candidate: newGraphQLRouteWithMatches("catch-all"),
			wantErr:   false,
		},
		{
			name: "nested prefixes admitted (longest-prefix specificity)",
			existing: newGraphQLRouteWithMatches("wide",
				avapigwv1alpha1.GraphQLRouteMatch{Path: prefix("/graphql")}),
			candidate: newGraphQLRouteWithMatches("narrow",
				avapigwv1alpha1.GraphQLRouteMatch{Path: prefix("/graphql/v2")}),
			wantErr: false,
		},
		{
			name: "exact vs prefix on same path admitted (different specificity)",
			existing: newGraphQLRouteWithMatches("by-prefix",
				avapigwv1alpha1.GraphQLRouteMatch{Path: prefix("/graphql")}),
			candidate: newGraphQLRouteWithMatches("by-exact",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			wantErr: false,
		},
		{
			name: "identical prefixes rejected",
			existing: newGraphQLRouteWithMatches("first",
				avapigwv1alpha1.GraphQLRouteMatch{Path: prefix("/graphql")}),
			candidate: newGraphQLRouteWithMatches("second",
				avapigwv1alpha1.GraphQLRouteMatch{Path: prefix("/graphql")}),
			wantErr: true,
		},
		{
			name: "same path different exact opNames admitted (disjoint values)",
			existing: newGraphQLRouteWithMatches("get-user",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationName: exact("GetUser")}),
			candidate: newGraphQLRouteWithMatches("get-order",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationName: exact("GetOrder")}),
			wantErr: false,
		},
		{
			name: "same path identical exact opNames rejected",
			existing: newGraphQLRouteWithMatches("first",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationName: exact("GetUser")}),
			candidate: newGraphQLRouteWithMatches("second",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationName: exact("GetUser")}),
			wantErr: true,
		},
		{
			name: "opName-specific vs generic on same path admitted (different specificity)",
			existing: newGraphQLRouteWithMatches("generic",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			candidate: newGraphQLRouteWithMatches("named",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql"), OperationName: exact("GetUser")}),
			wantErr: false,
		},
		{
			// Same specificity (1010 each), same path, header constraints on
			// the SAME name with disjoint exact values: no request satisfies
			// both — admitted. (Header semantics: value overlap.)
			name: "same specificity disjoint header values admitted",
			existing: newGraphQLRouteWithMatches("tenant-a",
				avapigwv1alpha1.GraphQLRouteMatch{
					Path:    exact("/graphql"),
					Headers: []avapigwv1alpha1.GraphQLHeaderMatch{{Name: "X-Tenant", Exact: "a"}},
				}),
			candidate: newGraphQLRouteWithMatches("tenant-b",
				avapigwv1alpha1.GraphQLRouteMatch{
					Path:    exact("/graphql"),
					Headers: []avapigwv1alpha1.GraphQLHeaderMatch{{Name: "X-Tenant", Exact: "b"}},
				}),
			wantErr: false,
		},
		{
			// Same specificity, header constraints on DIFFERENT names: one
			// request can carry both headers, so both blocks can match the
			// same request — rejected.
			name: "same specificity different header names rejected",
			existing: newGraphQLRouteWithMatches("by-tenant",
				avapigwv1alpha1.GraphQLRouteMatch{
					Path:    exact("/graphql"),
					Headers: []avapigwv1alpha1.GraphQLHeaderMatch{{Name: "X-Tenant", Exact: "a"}},
				}),
			candidate: newGraphQLRouteWithMatches("by-region",
				avapigwv1alpha1.GraphQLRouteMatch{
					Path:    exact("/graphql"),
					Headers: []avapigwv1alpha1.GraphQLHeaderMatch{{Name: "X-Region", Exact: "eu"}},
				}),
			wantErr: true,
		},
		{
			// Regex intersection is undecidable; mirroring the APIRoute and
			// gRPC checkers, regex pairs are admitted (the router orders
			// equal-specificity routes deterministically by name).
			name: "identical path regexes admitted (documented regex semantics)",
			existing: newGraphQLRouteWithMatches("first",
				avapigwv1alpha1.GraphQLRouteMatch{Path: regex("^/graphql/.*")}),
			candidate: newGraphQLRouteWithMatches("second",
				avapigwv1alpha1.GraphQLRouteMatch{Path: regex("^/graphql/.*")}),
			wantErr: false,
		},
		{
			// Multi-block: the second block of the candidate duplicates the
			// existing single-block route — still detected pairwise.
			name: "duplicate hidden in second match block rejected",
			existing: newGraphQLRouteWithMatches("existing",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			candidate: newGraphQLRouteWithMatches("multi",
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/other")},
				avapigwv1alpha1.GraphQLRouteMatch{Path: exact("/graphql")}),
			wantErr: true,
		},
	}

	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.existing.DeepCopy()).
				Build()
			checker := NewDuplicateChecker(c)

			err := checker.CheckGraphQLRouteDuplicate(context.Background(), tt.candidate)
			if tt.wantErr && err == nil {
				t.Error("CheckGraphQLRouteDuplicate() expected conflict error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("CheckGraphQLRouteDuplicate() expected admission, got %v", err)
			}
		})
	}
}

// TestGraphQLMatchSpecificity_ParityWithRouterWeights pins the webhook's
// CRD-to-config conversion and block scoring to the GraphQL router's
// authoritative Specificity weights. The expected values restate the
// documented weight table so a router weight change surfaces here as an
// explicit semantic decision, and the direct comparison with
// graphqlrouter.Specificity guards the conversion itself.
func TestGraphQLMatchSpecificity_ParityWithRouterWeights(t *testing.T) {
	tests := []struct {
		name     string
		match    avapigwv1alpha1.GraphQLRouteMatch
		expected int
	}{
		{"empty block (catch-all)", avapigwv1alpha1.GraphQLRouteMatch{}, 0},
		{
			"exact path",
			avapigwv1alpha1.GraphQLRouteMatch{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
			1000,
		},
		{
			"prefix path gains length",
			avapigwv1alpha1.GraphQLRouteMatch{Path: &avapigwv1alpha1.StringMatch{Prefix: "/graphql"}},
			500 + len("/graphql"),
		},
		{
			"regex path",
			avapigwv1alpha1.GraphQLRouteMatch{Path: &avapigwv1alpha1.StringMatch{Regex: "^/g.*"}},
			100,
		},
		{
			"exact path with operation type",
			avapigwv1alpha1.GraphQLRouteMatch{
				Path:          &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
				OperationType: "query",
			},
			1200,
		},
		{
			"exact path with exact operation name",
			avapigwv1alpha1.GraphQLRouteMatch{
				Path:          &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
				OperationName: &avapigwv1alpha1.StringMatch{Exact: "GetUser"},
			},
			1500,
		},
		{
			"prefix operation name gains length",
			avapigwv1alpha1.GraphQLRouteMatch{
				OperationName: &avapigwv1alpha1.StringMatch{Prefix: "Get"},
			},
			250 + len("Get"),
		},
		{
			"regex operation name",
			avapigwv1alpha1.GraphQLRouteMatch{
				OperationName: &avapigwv1alpha1.StringMatch{Regex: "^Get.*"},
			},
			50,
		},
		{
			"headers add ten each",
			avapigwv1alpha1.GraphQLRouteMatch{
				Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
				Headers: []avapigwv1alpha1.GraphQLHeaderMatch{
					{Name: "X-Tenant", Exact: "a"},
					{Name: "X-Region", Prefix: "eu"},
				},
			},
			1020,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := graphqlMatchSpecificity(&tt.match)
			if got != tt.expected {
				t.Errorf("graphqlMatchSpecificity() = %d, want %d", got, tt.expected)
			}

			// Direct parity with the router's exported scorer on the
			// converted config route.
			routerScore := graphqlrouter.Specificity(&config.GraphQLRoute{
				Match: []config.GraphQLRouteMatch{graphqlMatchToConfig(&tt.match)},
			})
			if got != routerScore {
				t.Errorf("graphqlMatchSpecificity() = %d, router Specificity = %d — conversion drift",
					got, routerScore)
			}
		})
	}
}

// TestGraphQLDataplaneParity_SpecificityOrdering verifies the data-plane
// half of the relaxation invariant: pairs the webhook now admits are
// resolved by the GraphQL router to a single deterministic winner regardless
// of load order.
func TestGraphQLDataplaneParity_SpecificityOrdering(t *testing.T) {
	generic := config.GraphQLRoute{
		Name: "generic",
		Match: []config.GraphQLRouteMatch{
			{Path: &config.StringMatch{Exact: "/graphql"}},
		},
	}
	typed := config.GraphQLRoute{
		Name: "typed",
		Match: []config.GraphQLRouteMatch{
			{Path: &config.StringMatch{Exact: "/graphql"}, OperationType: "query"},
		},
	}

	loadOrders := [][]config.GraphQLRoute{
		{generic, typed},
		{typed, generic},
	}

	for _, order := range loadOrders {
		r := graphqlrouter.New()
		if err := r.LoadRoutes(order); err != nil {
			t.Fatalf("LoadRoutes() error = %v", err)
		}

		// A query on /graphql matches both routes; the operationType-
		// specific route (1200) must deterministically beat the generic
		// one (1000).
		req := httptest.NewRequest("POST", "/graphql", nil)
		result := r.Match(req, &graphqlrouter.GraphQLRequest{Query: "query { user }"})
		if result == nil {
			t.Fatal("Match() returned nil for a query on /graphql")
		}
		if result.Route.Name != "typed" {
			t.Errorf("load order %s,%s: query must hit the operationType-specific route, got %q",
				order[0].Name, order[1].Name, result.Route.Name)
		}

		// A mutation only matches the generic route.
		result = r.Match(req, &graphqlrouter.GraphQLRequest{Query: "mutation { addUser }"})
		if result == nil {
			t.Fatal("Match() returned nil for a mutation on /graphql")
		}
		if result.Route.Name != "generic" {
			t.Errorf("load order %s,%s: mutation must fall back to the generic route, got %q",
				order[0].Name, order[1].Name, result.Route.Name)
		}
	}
}

// TestGraphQLBasicVsDo04FixturePair_Admitted documents the verdict for the
// fixture pair that motivated the relaxation: graphql-basic (exact /graphql,
// no operationType, specificity 1000) and do04-graphql-route (exact /graphql
// + operationType query, specificity 1200) no longer conflict even in the
// SAME namespace — the router deterministically routes queries to the typed
// route and everything else on /graphql to the generic one.
func TestGraphQLBasicVsDo04FixturePair_Admitted(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	graphqlBasic := newGraphQLRouteWithMatches("graphql-basic",
		avapigwv1alpha1.GraphQLRouteMatch{
			Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
		})
	do04Route := newGraphQLRouteWithMatches("do04-graphql-route",
		avapigwv1alpha1.GraphQLRouteMatch{
			Path:          &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
			OperationType: "query",
		})

	// Both directions admit.
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(graphqlBasic.DeepCopy()).Build()
	if err := NewDuplicateChecker(c).CheckGraphQLRouteDuplicate(context.Background(), do04Route); err != nil {
		t.Errorf("do04-graphql-route must be admitted alongside graphql-basic, got: %v", err)
	}

	c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(do04Route.DeepCopy()).Build()
	if err := NewDuplicateChecker(c).CheckGraphQLRouteDuplicate(context.Background(), graphqlBasic); err != nil {
		t.Errorf("graphql-basic must be admitted alongside do04-graphql-route, got: %v", err)
	}
}
