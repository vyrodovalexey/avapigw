// Package webhook contains regression tests for the catch-all topology bug:
// with a catch-all APIRoute (prefix "/") present, other routes must remain
// admittable, the catch-all itself must be re-admittable on update, and true
// duplicates must still be rejected.
package webhook

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// newAPIRoute builds an APIRoute with a single URI match.
func newAPIRoute(name, namespace string, uri *avapigwv1alpha1.URIMatch, methods ...string) *avapigwv1alpha1.APIRoute {
	route := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	if uri != nil {
		route.Spec.Match = []avapigwv1alpha1.RouteMatch{{URI: uri, Methods: methods}}
	}
	return route
}

// TestCheckAPIRouteDuplicate_CatchAllTopology is the regression table test for
// the catch-all overlap bug fixed to mirror the data-plane router precedence
// (exact > longest prefix > regex; see internal/router calculatePriority).
func TestCheckAPIRouteDuplicate_CatchAllTopology(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)

	catchAll := newAPIRoute("catch-all", "default",
		&avapigwv1alpha1.URIMatch{Prefix: "/"})
	exactRoute := newAPIRoute("exact-users", "default",
		&avapigwv1alpha1.URIMatch{Exact: "/api/users"}, "GET")

	tests := []struct {
		name      string
		existing  []*avapigwv1alpha1.APIRoute
		candidate *avapigwv1alpha1.APIRoute
		wantErr   bool
	}{
		{
			name:     "exact route coexists with catch-all prefix /",
			existing: []*avapigwv1alpha1.APIRoute{catchAll},
			candidate: newAPIRoute("new-exact", "default",
				&avapigwv1alpha1.URIMatch{Exact: "/api/orders"}, "GET"),
			wantErr: false,
		},
		{
			name:     "specific prefix route coexists with catch-all prefix /",
			existing: []*avapigwv1alpha1.APIRoute{catchAll},
			candidate: newAPIRoute("new-prefix", "default",
				&avapigwv1alpha1.URIMatch{Prefix: "/api"}, "GET"),
			wantErr: false,
		},
		{
			name:     "catch-all self-update allowed (no self-conflict)",
			existing: []*avapigwv1alpha1.APIRoute{catchAll},
			// Same name/namespace as the existing catch-all → self is excluded.
			candidate: newAPIRoute("catch-all", "default",
				&avapigwv1alpha1.URIMatch{Prefix: "/"}),
			wantErr: false,
		},
		{
			name:     "catch-all re-admission allowed with other routes present",
			existing: []*avapigwv1alpha1.APIRoute{catchAll, exactRoute},
			candidate: newAPIRoute("catch-all", "default",
				&avapigwv1alpha1.URIMatch{Prefix: "/"}),
			wantErr: false,
		},
		{
			name:     "true duplicate catch-all still rejected",
			existing: []*avapigwv1alpha1.APIRoute{catchAll},
			candidate: newAPIRoute("second-catch-all", "default",
				&avapigwv1alpha1.URIMatch{Prefix: "/"}),
			wantErr: true,
		},
		{
			name:     "true duplicate exact still rejected",
			existing: []*avapigwv1alpha1.APIRoute{exactRoute},
			candidate: newAPIRoute("duplicate-exact", "default",
				&avapigwv1alpha1.URIMatch{Exact: "/api/users"}, "GET"),
			wantErr: true,
		},
		{
			name:     "same exact path with disjoint methods allowed",
			existing: []*avapigwv1alpha1.APIRoute{exactRoute},
			candidate: newAPIRoute("exact-users-post", "default",
				&avapigwv1alpha1.URIMatch{Exact: "/api/users"}, "POST"),
			wantErr: false,
		},
		{
			name:     "same exact path with unrestricted methods rejected",
			existing: []*avapigwv1alpha1.APIRoute{exactRoute},
			candidate: newAPIRoute("exact-users-all", "default",
				&avapigwv1alpha1.URIMatch{Exact: "/api/users"}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			for _, r := range tt.existing {
				builder = builder.WithObjects(r.DeepCopy())
			}
			checker := NewDuplicateChecker(builder.Build())

			err := checker.CheckAPIRouteDuplicate(context.Background(), tt.candidate)
			if tt.wantErr && err == nil {
				t.Errorf("CheckAPIRouteDuplicate() expected conflict error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("CheckAPIRouteDuplicate() expected admission, got %v", err)
			}
		})
	}
}
