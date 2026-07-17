// Package webhook contains regression tests for the gRPC same-kind overlap
// relaxation: only identical-specificity match conditions (same match type
// with the same service/method values) are admission conflicts, mirroring
// the APIRoute semantics. Data-plane parity tests pin the invariant that the
// webhook rejects exactly what the gRPC router cannot deterministically
// order by specificity.
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
			name:      "same exact service with method catch-all still rejected",
			existing:  newGRPCRouteMatch("all-methods", exact("svc.v1.User"), nil),
			candidate: newGRPCRouteMatch("one-method", exact("svc.v1.User"), exact("Get")),
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
			name:      "match-less catch-all still conflicts with any route",
			existing:  newGRPCRouteMatch("catch-all", nil, nil),
			candidate: newGRPCRouteMatch("specific", exact("svc.v1.User"), exact("Get")),
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
