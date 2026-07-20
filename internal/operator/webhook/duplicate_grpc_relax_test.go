// Package webhook contains regression tests for the gRPC same-kind overlap
// relaxation: only identical-specificity match blocks whose values can
// cover the same request (service/method/authority/metadata, mirroring the
// GraphQL checker) are admission conflicts. Data-plane parity tests pin the
// invariant that the webhook rejects exactly what the gRPC router cannot
// deterministically order by specificity.
package webhook

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcrouter "github.com/vyrodovalexey/avapigw/internal/grpc/router"
)

// newGRPCRouteMatch builds a GRPCRoute with a single service/method match.
// Passing nil for both service and method produces a match-less catch-all.
func newGRPCRouteMatch(name string, service, method *avapigwv1alpha1.StringMatch) *avapigwv1alpha1.GRPCRoute {
	route := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
	}
	if service != nil || method != nil {
		route.Spec.Match = []avapigwv1alpha1.GRPCRouteMatch{{Service: service, Method: method}}
	}
	return route
}

// TestCheckGRPCRouteDuplicate_SpecificityTopology is the regression table
// for the gRPC same-kind relaxation: nested (different-specificity) prefixes
// are admitted because the gRPC router orders them deterministically, while
// identical-specificity duplicates are still rejected.
func TestCheckGRPCRouteDuplicate_SpecificityTopology(t *testing.T) {
	exact := func(v string) *avapigwv1alpha1.StringMatch {
		return &avapigwv1alpha1.StringMatch{Exact: v}
	}
	prefix := func(v string) *avapigwv1alpha1.StringMatch {
		return &avapigwv1alpha1.StringMatch{Prefix: v}
	}

	tests := []struct {
		name      string
		existing  *avapigwv1alpha1.GRPCRoute
		candidate *avapigwv1alpha1.GRPCRoute
		wantErr   bool
	}{
		{
			name:      "nested prefix services admitted (longest-prefix specificity)",
			existing:  newGRPCRouteMatch("wide", prefix("com.example"), nil),
			candidate: newGRPCRouteMatch("narrow", prefix("com.example.user"), nil),
			wantErr:   false,
		},
		{
			name:      "nested prefix services admitted (reverse direction)",
			existing:  newGRPCRouteMatch("narrow", prefix("com.example.user"), nil),
			candidate: newGRPCRouteMatch("wide", prefix("com.example"), nil),
			wantErr:   false,
		},
		{
			name:      "identical prefix services still rejected",
			existing:  newGRPCRouteMatch("first", prefix("com.example"), nil),
			candidate: newGRPCRouteMatch("second", prefix("com.example"), nil),
			wantErr:   true,
		},
		{
			name:      "identical exact service and method still rejected",
			existing:  newGRPCRouteMatch("first", exact("svc.v1.User"), exact("Get")),
			candidate: newGRPCRouteMatch("second", exact("svc.v1.User"), exact("Get")),
			wantErr:   true,
		},
		{
			name:      "method-disjoint same exact service admitted",
			existing:  newGRPCRouteMatch("get", exact("svc.v1.User"), exact("Get")),
			candidate: newGRPCRouteMatch("create", exact("svc.v1.User"), exact("Create")),
			wantErr:   false,
		},
		{
			// A method condition adds +500 specificity: the router serves
			// the method-specific route first and the nil-method route as
			// the service fallback — deterministic, not a conflict. (A
			// nil-method route must not block a whole service.)
			name:      "same exact service with method catch-all admitted (specificity ordering)",
			existing:  newGRPCRouteMatch("all-methods", exact("svc.v1.User"), nil),
			candidate: newGRPCRouteMatch("one-method", exact("svc.v1.User"), exact("Get")),
			wantErr:   false,
		},
		{
			name:      "two nil-method routes on same exact service still rejected",
			existing:  newGRPCRouteMatch("all-methods", exact("svc.v1.User"), nil),
			candidate: newGRPCRouteMatch("all-methods-2", exact("svc.v1.User"), nil),
			wantErr:   true,
		},
		{
			name:      "nested method prefixes on same exact service admitted",
			existing:  newGRPCRouteMatch("wide-method", exact("svc.v1.User"), prefix("Get")),
			candidate: newGRPCRouteMatch("narrow-method", exact("svc.v1.User"), prefix("GetUser")),
			wantErr:   false,
		},
		{
			name:      "identical method prefixes on same exact service rejected",
			existing:  newGRPCRouteMatch("first", exact("svc.v1.User"), prefix("Get")),
			candidate: newGRPCRouteMatch("second", exact("svc.v1.User"), prefix("Get")),
			wantErr:   true,
		},
		{
			name:      "identical prefix services with disjoint exact methods admitted",
			existing:  newGRPCRouteMatch("get", prefix("com.example"), exact("Get")),
			candidate: newGRPCRouteMatch("create", prefix("com.example"), exact("Create")),
			wantErr:   false,
		},
		{
			name:      "identical prefix services with identical exact methods rejected",
			existing:  newGRPCRouteMatch("first", prefix("com.example"), exact("Get")),
			candidate: newGRPCRouteMatch("second", prefix("com.example"), exact("Get")),
			wantErr:   true,
		},
		{
			name:      "exact vs prefix service admitted (different match types)",
			existing:  newGRPCRouteMatch("by-prefix", prefix("com.example"), nil),
			candidate: newGRPCRouteMatch("by-exact", exact("com.example.user.UserService"), nil),
			wantErr:   false,
		},
		{
			// Catch-all (specificity 0) vs specific route: ordered
			// deterministically by the router (specific first) — admitted,
			// mirroring the GraphQL and APIRoute checkers.
			name:      "match-less catch-all vs specific route admitted (specificity ordering)",
			existing:  newGRPCRouteMatch("catch-all", nil, nil),
			candidate: newGRPCRouteMatch("specific", exact("svc.v1.User"), exact("Get")),
			wantErr:   false,
		},
		{
			name:      "two match-less catch-alls still rejected",
			existing:  newGRPCRouteMatch("catch-all", nil, nil),
			candidate: newGRPCRouteMatch("catch-all-2", nil, nil),
			wantErr:   true,
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

			err := checker.CheckGRPCRouteDuplicate(context.Background(), tt.candidate)
			if tt.wantErr && err == nil {
				t.Error("CheckGRPCRouteDuplicate() expected conflict error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("CheckGRPCRouteDuplicate() expected admission, got %v", err)
			}
		})
	}
}

// newGRPCRouteMetadata builds a GRPCRoute with a single match carrying
// service, method, and metadata conditions.
func newGRPCRouteMetadata(
	name string, service, method *avapigwv1alpha1.StringMatch,
	metadata ...avapigwv1alpha1.MetadataMatch,
) *avapigwv1alpha1.GRPCRoute {
	route := newGRPCRouteMatch(name, service, method)
	if len(route.Spec.Match) == 0 {
		route.Spec.Match = []avapigwv1alpha1.GRPCRouteMatch{{}}
	}
	route.Spec.Match[0].Metadata = metadata
	return route
}

// TestCheckGRPCRouteDuplicate_MetadataDiscriminators is the regression
// table for the metadata-awareness fix, mirroring the GraphQL checker's
// header semantics: routes on the same service/method that are
// discriminated by metadata matchers are NOT duplicates (the router orders
// them by +10-per-metadata specificity, and equal-specificity blocks with
// provably disjoint metadata values never cover the same request), while
// identical metadata blocks remain true duplicates.
func TestCheckGRPCRouteDuplicate_MetadataDiscriminators(t *testing.T) {
	exact := func(v string) *avapigwv1alpha1.StringMatch {
		return &avapigwv1alpha1.StringMatch{Exact: v}
	}
	meta := func(name, exactValue string) avapigwv1alpha1.MetadataMatch {
		return avapigwv1alpha1.MetadataMatch{Name: name, Exact: exactValue}
	}

	tests := []struct {
		name      string
		existing  *avapigwv1alpha1.GRPCRoute
		candidate *avapigwv1alpha1.GRPCRoute
		wantErr   bool
	}{
		{
			// The scenario the perf suite hit: same service/method with
			// disjoint metadata discriminators must be admissible.
			name: "metadata-discriminated same service/method admitted",
			existing: newGRPCRouteMetadata("scenario-basic",
				exact("svc.v1.User"), exact("Get"), meta("x-scenario", "basic")),
			candidate: newGRPCRouteMetadata("scenario-cached",
				exact("svc.v1.User"), exact("Get"), meta("x-scenario", "cached")),
			wantErr: false,
		},
		{
			// Metadata adds +10 specificity: a metadata-specific route and
			// a generic route on the same service/method are ordered
			// deterministically — admitted.
			name: "metadata-specific vs generic same service/method admitted",
			existing: newGRPCRouteMetadata("generic",
				exact("svc.v1.User"), exact("Get")),
			candidate: newGRPCRouteMetadata("with-metadata",
				exact("svc.v1.User"), exact("Get"), meta("x-scenario", "basic")),
			wantErr: false,
		},
		{
			name: "identical metadata blocks still rejected",
			existing: newGRPCRouteMetadata("first",
				exact("svc.v1.User"), exact("Get"), meta("x-scenario", "basic")),
			candidate: newGRPCRouteMetadata("second",
				exact("svc.v1.User"), exact("Get"), meta("x-scenario", "basic")),
			wantErr: true,
		},
		{
			// Same key, one exact vs one prefix the exact carries: some
			// request (x-scenario: cached-v2) satisfies both and both
			// blocks score... exact and prefix metadata weigh the same
			// (+10), so the specificity gate passes and the value overlap
			// applies — rejected.
			name: "compatible metadata constraints on same key rejected",
			existing: newGRPCRouteMetadata("by-prefix",
				exact("svc.v1.User"), exact("Get"),
				avapigwv1alpha1.MetadataMatch{Name: "x-scenario", Prefix: "cached"}),
			candidate: newGRPCRouteMetadata("by-exact",
				exact("svc.v1.User"), exact("Get"), meta("x-scenario", "cached-v2")),
			wantErr: true,
		},
		{
			// Conditions on DIFFERENT metadata keys are independent — one
			// request can carry both — so the blocks overlap: rejected.
			name: "disjoint metadata keys on same service/method rejected",
			existing: newGRPCRouteMetadata("by-key-a",
				exact("svc.v1.User"), exact("Get"), meta("x-a", "1")),
			candidate: newGRPCRouteMetadata("by-key-b",
				exact("svc.v1.User"), exact("Get"), meta("x-b", "2")),
			wantErr: true,
		},
		{
			// Nil-method route + metadata-differentiated method routes:
			// the full perf-suite topology (grpc-cached style) must load.
			name: "nil-method route coexists with metadata-discriminated method route",
			existing: newGRPCRouteMetadata("grpc-cached",
				exact("svc.v1.User"), nil, meta("x-cache", "on")),
			candidate: newGRPCRouteMetadata("grpc-basic",
				exact("svc.v1.User"), exact("Get")),
			wantErr: false,
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

			err := checker.CheckGRPCRouteDuplicate(context.Background(), tt.candidate)
			if tt.wantErr && err == nil {
				t.Error("CheckGRPCRouteDuplicate() expected conflict error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("CheckGRPCRouteDuplicate() expected admission, got %v", err)
			}
		})
	}
}

// TestGRPCDataplaneParity_MetadataDiscriminatedDeterministic verifies the
// data-plane half of the metadata relaxation: metadata-discriminated routes
// the webhook now admits are resolved by the gRPC router per request
// metadata, with the generic route as the deterministic fallback.
func TestGRPCDataplaneParity_MetadataDiscriminatedDeterministic(t *testing.T) {
	const fullMethod = "/svc.v1.User/Get"

	r := grpcrouter.New()
	addGRPCRouterRoute(t, r, "generic", config.GRPCRouteMatch{
		Service: &config.StringMatch{Exact: "svc.v1.User"},
		Method:  &config.StringMatch{Exact: "Get"},
	})
	addGRPCRouterRoute(t, r, "scenario-cached", config.GRPCRouteMatch{
		Service:  &config.StringMatch{Exact: "svc.v1.User"},
		Method:   &config.StringMatch{Exact: "Get"},
		Metadata: []config.MetadataMatch{{Name: "x-scenario", Exact: "cached"}},
	})

	withMeta := metadata.Pairs("x-scenario", "cached")
	result, err := r.Match(fullMethod, withMeta)
	if err != nil {
		t.Fatalf("Match(%s) with metadata error = %v", fullMethod, err)
	}
	if result.Route.Name != "scenario-cached" {
		t.Errorf("router must pick the metadata-discriminated route for matching metadata, got %q",
			result.Route.Name)
	}

	result, err = r.Match(fullMethod, metadata.MD{})
	if err != nil {
		t.Fatalf("Match(%s) without metadata error = %v", fullMethod, err)
	}
	if result.Route.Name != "generic" {
		t.Errorf("router must fall back to the generic route without metadata, got %q", result.Route.Name)
	}
}

// TestGRPCRouterSpecificity_ParityWithWebhookConversion pins the
// webhook-side specificity scoring to the router's exported Specificity so
// the two cannot drift.
func TestGRPCRouterSpecificity_ParityWithWebhookConversion(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }

	tests := []struct {
		name     string
		match    avapigwv1alpha1.GRPCRouteMatch
		expected int
	}{
		{name: "empty catch-all block", match: avapigwv1alpha1.GRPCRouteMatch{}, expected: 0},
		{
			name: "exact service",
			match: avapigwv1alpha1.GRPCRouteMatch{
				Service: &avapigwv1alpha1.StringMatch{Exact: "svc.v1.User"},
			},
			expected: 1000,
		},
		{
			name: "prefix service scores 500 plus length",
			match: avapigwv1alpha1.GRPCRouteMatch{
				Service: &avapigwv1alpha1.StringMatch{Prefix: "com.example"},
			},
			expected: 500 + len("com.example"),
		},
		{
			name: "exact service and method with metadata and withoutHeaders",
			match: avapigwv1alpha1.GRPCRouteMatch{
				Service: &avapigwv1alpha1.StringMatch{Exact: "svc.v1.User"},
				Method:  &avapigwv1alpha1.StringMatch{Exact: "Get"},
				Metadata: []avapigwv1alpha1.MetadataMatch{
					{Name: "x-scenario", Exact: "basic"},
					{Name: "x-tenant", Present: boolPtr(true)},
				},
				WithoutHeaders: []string{"x-legacy"},
			},
			expected: 1000 + 500 + 2*10 + 5,
		},
		{
			name: "authority adds 100",
			match: avapigwv1alpha1.GRPCRouteMatch{
				Service:   &avapigwv1alpha1.StringMatch{Regex: "^svc\\..*$"},
				Authority: &avapigwv1alpha1.StringMatch{Exact: "api.example.com"},
			},
			expected: 100 + 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := grpcMatchSpecificity(&tt.match)
			if got != tt.expected {
				t.Errorf("grpcMatchSpecificity() = %d, want %d", got, tt.expected)
			}

			routerScore := grpcrouter.Specificity(config.GRPCRoute{
				Match: []config.GRPCRouteMatch{grpcMatchToConfig(&tt.match)},
			})
			if got != routerScore {
				t.Errorf("grpcMatchSpecificity() = %d, router Specificity = %d — conversion drift",
					got, routerScore)
			}
		})
	}
}

// addGRPCRouterRoute adds a single-match route to the data-plane router.
func addGRPCRouterRoute(t *testing.T, r *grpcrouter.Router, name string, match config.GRPCRouteMatch) {
	t.Helper()
	if err := r.AddRoute(config.GRPCRoute{
		Name:  name,
		Match: []config.GRPCRouteMatch{match},
	}); err != nil {
		t.Fatalf("AddRoute(%s) error = %v", name, err)
	}
}

// TestGRPCDataplaneParity_NestedPrefixesDeterministic verifies the data
// plane half of the relaxation invariant: nested-prefix configurations the
// webhook now admits are resolved by the gRPC router to a single
// deterministic winner regardless of load order.
func TestGRPCDataplaneParity_NestedPrefixesDeterministic(t *testing.T) {
	const fullMethod = "/com.example.user.UserService/GetUser"

	// Load orders are permuted to prove determinism is due to the
	// priority sort, not insertion order.
	loadOrders := [][]string{
		{"wide", "narrow"},
		{"narrow", "wide"},
	}
	matches := map[string]config.GRPCRouteMatch{
		"wide":   {Service: &config.StringMatch{Prefix: "com.example"}},
		"narrow": {Service: &config.StringMatch{Prefix: "com.example.user"}},
	}

	for _, order := range loadOrders {
		r := grpcrouter.New()
		for _, name := range order {
			addGRPCRouterRoute(t, r, name, matches[name])
		}

		result, err := r.Match(fullMethod, metadata.MD{})
		if err != nil {
			t.Fatalf("Match(%s) error = %v", fullMethod, err)
		}
		if result.Route.Name != "narrow" {
			t.Errorf("load order %v: router must pick the most specific prefix route, got %q",
				order, result.Route.Name)
		}
	}
}

// TestGRPCDataplaneParity_NestedMethodPrefixesDeterministic mirrors the
// method-prefix relaxation: on the same exact service, nested method
// prefixes resolve deterministically to the longer prefix.
func TestGRPCDataplaneParity_NestedMethodPrefixesDeterministic(t *testing.T) {
	const fullMethod = "/svc.v1.User/GetUserProfile"

	r := grpcrouter.New()
	// Load the less specific route first on purpose.
	addGRPCRouterRoute(t, r, "wide-method", config.GRPCRouteMatch{
		Service: &config.StringMatch{Exact: "svc.v1.User"},
		Method:  &config.StringMatch{Prefix: "Get"},
	})
	addGRPCRouterRoute(t, r, "narrow-method", config.GRPCRouteMatch{
		Service: &config.StringMatch{Exact: "svc.v1.User"},
		Method:  &config.StringMatch{Prefix: "GetUser"},
	})

	result, err := r.Match(fullMethod, metadata.MD{})
	if err != nil {
		t.Fatalf("Match(%s) error = %v", fullMethod, err)
	}
	if result.Route.Name != "narrow-method" {
		t.Errorf("router must pick the most specific method prefix route, got %q", result.Route.Name)
	}
}

// TestGRPCDataplaneParity_IdenticalPrefixesAmbiguous pins the negative half
// of the invariant: identical prefixes produce identical router priorities,
// so the data plane cannot order them deterministically — exactly the case
// the webhook still rejects.
func TestGRPCDataplaneParity_IdenticalPrefixesAmbiguous(t *testing.T) {
	r := grpcrouter.New()
	addGRPCRouterRoute(t, r, "first", config.GRPCRouteMatch{
		Service: &config.StringMatch{Prefix: "com.example"},
	})
	addGRPCRouterRoute(t, r, "second", config.GRPCRouteMatch{
		Service: &config.StringMatch{Prefix: "com.example"},
	})

	first, ok := r.GetRoute("first")
	if !ok {
		t.Fatal("GetRoute(first) not found")
	}
	second, ok := r.GetRoute("second")
	if !ok {
		t.Fatal("GetRoute(second) not found")
	}
	if first.Priority != second.Priority {
		t.Errorf("identical prefixes must have identical priorities (ambiguous), got %d vs %d",
			first.Priority, second.Priority)
	}
}
