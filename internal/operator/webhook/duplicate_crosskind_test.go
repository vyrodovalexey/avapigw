// Package webhook contains regression tests for the cross-kind
// APIRoute<->GraphQLRoute overlap semantics: the checks must mirror the
// same-kind identical-specificity rules so a catch-all APIRoute coexists with
// GraphQLRoutes (the data plane splits them deterministically by the GraphQL
// endpoint path), while identical-path cross-kind duplicates stay rejected.
package webhook

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// newCrossKindGraphQLRoute builds a GraphQLRoute with an optional path match.
func newCrossKindGraphQLRoute(name, namespace string, path *avapigwv1alpha1.StringMatch) *avapigwv1alpha1.GraphQLRoute {
	route := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	if path != nil {
		route.Spec.Match = []avapigwv1alpha1.GraphQLRouteMatch{{Path: path}}
	}
	return route
}

// newCrossKindChecker builds a namespace-scoped checker over the given objects.
func newCrossKindChecker(t *testing.T, objs ...client.Object) *DuplicateChecker {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
	return NewDuplicateChecker(fakeClient)
}

// TestCrossKind_APIRouteVsGraphQLRoute_Topology is the regression table test
// for the cross-kind overlap fix: only identical-specificity duplicates are
// admission conflicts, in BOTH check directions.
func TestCrossKind_APIRouteVsGraphQLRoute_Topology(t *testing.T) {
	tests := []struct {
		name         string
		apiURI       *avapigwv1alpha1.URIMatch // nil → match-less catch-all APIRoute
		graphqlPath  *avapigwv1alpha1.StringMatch
		wantConflict bool
	}{
		{
			name:         "catch-all APIRoute (no match) coexists with exact GraphQLRoute",
			apiURI:       nil,
			graphqlPath:  &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
			wantConflict: false,
		},
		{
			name:         "catch-all APIRoute (prefix /) coexists with exact GraphQLRoute",
			apiURI:       &avapigwv1alpha1.URIMatch{Prefix: "/"},
			graphqlPath:  &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
			wantConflict: false,
		},
		{
			name:         "catch-all APIRoute (prefix /) coexists with match-less GraphQLRoute",
			apiURI:       &avapigwv1alpha1.URIMatch{Prefix: "/"},
			graphqlPath:  nil,
			wantConflict: false,
		},
		{
			name:         "identical exact path cross-kind duplicate rejected",
			apiURI:       &avapigwv1alpha1.URIMatch{Exact: "/graphql"},
			graphqlPath:  &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
			wantConflict: true,
		},
		{
			name:         "identical prefix cross-kind duplicate rejected",
			apiURI:       &avapigwv1alpha1.URIMatch{Prefix: "/graphql"},
			graphqlPath:  &avapigwv1alpha1.StringMatch{Prefix: "/graphql"},
			wantConflict: true,
		},
		{
			name:         "APIRoute exact vs GraphQLRoute nested prefix admitted",
			apiURI:       &avapigwv1alpha1.URIMatch{Exact: "/api/graphql"},
			graphqlPath:  &avapigwv1alpha1.StringMatch{Prefix: "/api"},
			wantConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Direction 1: admitting an APIRoute against an existing GraphQLRoute.
			existingGQL := newCrossKindGraphQLRoute("existing-gql", "default", tt.graphqlPath)
			apiChecker := newCrossKindChecker(t, existingGQL)
			apiRoute := newAPIRoute("new-api", "default", tt.apiURI)

			err := apiChecker.CheckAPIRouteCrossConflictsWithGraphQL(context.Background(), apiRoute)
			if tt.wantConflict && err == nil {
				t.Error("CheckAPIRouteCrossConflictsWithGraphQL() should reject cross-kind duplicate")
			}
			if !tt.wantConflict && err != nil {
				t.Errorf("CheckAPIRouteCrossConflictsWithGraphQL() should admit, got %v", err)
			}

			// Direction 2: admitting a GraphQLRoute against an existing APIRoute.
			existingAPI := newAPIRoute("existing-api", "default", tt.apiURI)
			gqlChecker := newCrossKindChecker(t, existingAPI)
			graphqlRoute := newCrossKindGraphQLRoute("new-gql", "default", tt.graphqlPath)

			err = gqlChecker.CheckGraphQLRouteCrossConflictsWithAPIRoute(context.Background(), graphqlRoute)
			if tt.wantConflict && err == nil {
				t.Error("CheckGraphQLRouteCrossConflictsWithAPIRoute() should reject cross-kind duplicate")
			}
			if !tt.wantConflict && err != nil {
				t.Errorf("CheckGraphQLRouteCrossConflictsWithAPIRoute() should admit, got %v", err)
			}
		})
	}
}

// TestCrossKind_MultiMatch_OneIdenticalPairRejected verifies that a conflict
// in ANY match-condition pair rejects the resource even when other pairs are
// of different specificity.
func TestCrossKind_MultiMatch_OneIdenticalPairRejected(t *testing.T) {
	existingGQL := &avapigwv1alpha1.GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "existing-gql", Namespace: "default"},
		Spec: avapigwv1alpha1.GraphQLRouteSpec{
			Match: []avapigwv1alpha1.GraphQLRouteMatch{
				{Path: &avapigwv1alpha1.StringMatch{Prefix: "/api"}},
				{Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"}},
			},
		},
	}
	checker := newCrossKindChecker(t, existingGQL)

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "new-api", Namespace: "default"},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				// Different specificity vs both GraphQL matches.
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/"}},
				// Identical exact path vs the second GraphQL match.
				{URI: &avapigwv1alpha1.URIMatch{Exact: "/graphql"}},
			},
		},
	}

	if err := checker.CheckAPIRouteCrossConflictsWithGraphQL(context.Background(), apiRoute); err == nil {
		t.Error("identical exact pair within multi-match routes must be rejected")
	}
}
