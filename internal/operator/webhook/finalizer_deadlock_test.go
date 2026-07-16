// Package webhook contains regression tests for the webhook/finalizer
// deadlock: updates to terminating objects must be admitted unconditionally,
// metadata-only updates (finalizers, labels) must never be blocked by
// duplicate or cross-kind conflict rules while still running local spec
// validation, and terminating conflict candidates must not block surviving
// resources.
package webhook

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// testFinalizer simulates an operator-managed finalizer stuck on a resource.
const testFinalizer = "avapigw.io/test-finalizer"

// invalidDuration is a spec value that fails local duration validation.
const invalidDuration = "not-a-duration"

// newLifecycleScheme returns a scheme with the avapigw types registered.
func newLifecycleScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := avapigwv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}
	return scheme
}

// newLifecycleClient returns a fake client seeded with the given objects.
func newLifecycleClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	builder := fake.NewClientBuilder().WithScheme(newLifecycleScheme(t))
	for _, o := range objs {
		builder = builder.WithObjects(o.DeepCopyObject().(client.Object))
	}
	return builder.Build()
}

// markTerminating sets a deletion timestamp and a finalizer on the object,
// simulating a resource stuck in the terminating state.
func markTerminating(obj client.Object) {
	now := metav1.NewTime(time.Now())
	obj.SetDeletionTimestamp(&now)
	obj.SetFinalizers([]string{testFinalizer})
}

// deepCopy returns a typed deep copy of a client.Object.
func deepCopy(obj client.Object) client.Object {
	return obj.DeepCopyObject().(client.Object)
}

// lifecycleFixture describes one CRD kind for the finalizer-deadlock tests.
type lifecycleFixture struct {
	kind string

	// conflictingPair returns two objects (distinct names, same namespace)
	// whose specs mutually conflict under the duplicate rules — a "legacy
	// pair" admitted before conflict detection existed.
	conflictingPair func() (client.Object, client.Object)

	// nonConflicting returns an object named like the second pair member
	// whose spec does NOT conflict with the first pair member.
	nonConflicting func() client.Object

	// invalidObject returns an object whose spec fails local validation.
	invalidObject func() client.Object

	// validateUpdate invokes the kind's typed ValidateUpdate with a
	// validator wired to the given client and a duplicate checker.
	validateUpdate func(
		t *testing.T, c client.Client, oldObj, newObj client.Object,
	) (admission.Warnings, error)
}

// newBackendHostSpec returns a one-host backend host list.
func newBackendHostSpec(address string, port int) []avapigwv1alpha1.BackendHost {
	return []avapigwv1alpha1.BackendHost{{Address: address, Port: port}}
}

//nolint:gocognit,cyclop,maintidx // Table construction enumerates all six CRD kinds; no branching logic.
func lifecycleFixtures() []lifecycleFixture {
	objectMeta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: "default"}
	}

	apiRoute := func(name, prefix string) *avapigwv1alpha1.APIRoute {
		return &avapigwv1alpha1.APIRoute{
			ObjectMeta: objectMeta(name),
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: prefix}},
				},
			},
		}
	}
	graphqlRoute := func(name, prefix string) *avapigwv1alpha1.GraphQLRoute {
		return &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: objectMeta(name),
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{Path: &avapigwv1alpha1.StringMatch{Prefix: prefix}},
				},
			},
		}
	}
	grpcRouteExact := func(name, service string) *avapigwv1alpha1.GRPCRoute {
		return &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: objectMeta(name),
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Match: []avapigwv1alpha1.GRPCRouteMatch{
					{Service: &avapigwv1alpha1.StringMatch{Exact: service}},
				},
			},
		}
	}
	backend := func(name, address string) *avapigwv1alpha1.Backend {
		return &avapigwv1alpha1.Backend{
			ObjectMeta: objectMeta(name),
			Spec:       avapigwv1alpha1.BackendSpec{Hosts: newBackendHostSpec(address, 8080)},
		}
	}
	grpcBackend := func(name, address string) *avapigwv1alpha1.GRPCBackend {
		return &avapigwv1alpha1.GRPCBackend{
			ObjectMeta: objectMeta(name),
			Spec:       avapigwv1alpha1.GRPCBackendSpec{Hosts: newBackendHostSpec(address, 50051)},
		}
	}
	graphqlBackend := func(name, address string) *avapigwv1alpha1.GraphQLBackend {
		return &avapigwv1alpha1.GraphQLBackend{
			ObjectMeta: objectMeta(name),
			Spec:       avapigwv1alpha1.GraphQLBackendSpec{Hosts: newBackendHostSpec(address, 4000)},
		}
	}

	return []lifecycleFixture{
		{
			kind: "APIRoute",
			conflictingPair: func() (client.Object, client.Object) {
				return apiRoute("legacy-a", "/legacy"), apiRoute("legacy-b", "/legacy")
			},
			nonConflicting: func() client.Object { return apiRoute("legacy-b", "/other") },
			invalidObject: func() client.Object {
				route := apiRoute("invalid", "/invalid")
				route.Spec.Timeout = avapigwv1alpha1.Duration(invalidDuration)
				return route
			},
			validateUpdate: func(
				t *testing.T, c client.Client, oldObj, newObj client.Object,
			) (admission.Warnings, error) {
				t.Helper()
				v := &APIRouteValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}
				return v.ValidateUpdate(context.Background(),
					oldObj.(*avapigwv1alpha1.APIRoute), newObj.(*avapigwv1alpha1.APIRoute))
			},
		},
		{
			kind: "GraphQLRoute",
			conflictingPair: func() (client.Object, client.Object) {
				return graphqlRoute("legacy-a", "/graphql"), graphqlRoute("legacy-b", "/graphql")
			},
			nonConflicting: func() client.Object { return graphqlRoute("legacy-b", "/other") },
			invalidObject: func() client.Object {
				route := graphqlRoute("invalid", "/invalid")
				route.Spec.Timeout = avapigwv1alpha1.Duration(invalidDuration)
				return route
			},
			validateUpdate: func(
				t *testing.T, c client.Client, oldObj, newObj client.Object,
			) (admission.Warnings, error) {
				t.Helper()
				v := &GraphQLRouteValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}
				return v.ValidateUpdate(context.Background(),
					oldObj.(*avapigwv1alpha1.GraphQLRoute), newObj.(*avapigwv1alpha1.GraphQLRoute))
			},
		},
		{
			kind: "GRPCRoute",
			conflictingPair: func() (client.Object, client.Object) {
				return grpcRouteExact("legacy-a", "svc.v1.Legacy"),
					grpcRouteExact("legacy-b", "svc.v1.Legacy")
			},
			nonConflicting: func() client.Object { return grpcRouteExact("legacy-b", "svc.v1.Other") },
			invalidObject: func() client.Object {
				route := grpcRouteExact("invalid", "svc.v1.Invalid")
				route.Spec.Timeout = avapigwv1alpha1.Duration(invalidDuration)
				return route
			},
			validateUpdate: func(
				t *testing.T, c client.Client, oldObj, newObj client.Object,
			) (admission.Warnings, error) {
				t.Helper()
				v := &GRPCRouteValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}
				return v.ValidateUpdate(context.Background(),
					oldObj.(*avapigwv1alpha1.GRPCRoute), newObj.(*avapigwv1alpha1.GRPCRoute))
			},
		},
		{
			kind: "Backend",
			conflictingPair: func() (client.Object, client.Object) {
				return backend("legacy-a", "legacy.example.com"),
					backend("legacy-b", "legacy.example.com")
			},
			nonConflicting: func() client.Object { return backend("legacy-b", "other.example.com") },
			invalidObject: func() client.Object {
				b := backend("invalid", "invalid.example.com")
				b.Spec.Hosts = nil // at least one host is required
				return b
			},
			validateUpdate: func(
				t *testing.T, c client.Client, oldObj, newObj client.Object,
			) (admission.Warnings, error) {
				t.Helper()
				v := &BackendValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}
				return v.ValidateUpdate(context.Background(),
					oldObj.(*avapigwv1alpha1.Backend), newObj.(*avapigwv1alpha1.Backend))
			},
		},
		{
			kind: "GRPCBackend",
			conflictingPair: func() (client.Object, client.Object) {
				return grpcBackend("legacy-a", "legacy-grpc.example.com"),
					grpcBackend("legacy-b", "legacy-grpc.example.com")
			},
			nonConflicting: func() client.Object {
				return grpcBackend("legacy-b", "other-grpc.example.com")
			},
			invalidObject: func() client.Object {
				b := grpcBackend("invalid", "invalid-grpc.example.com")
				b.Spec.Hosts = nil // at least one host is required
				return b
			},
			validateUpdate: func(
				t *testing.T, c client.Client, oldObj, newObj client.Object,
			) (admission.Warnings, error) {
				t.Helper()
				v := &GRPCBackendValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}
				return v.ValidateUpdate(context.Background(),
					oldObj.(*avapigwv1alpha1.GRPCBackend), newObj.(*avapigwv1alpha1.GRPCBackend))
			},
		},
		{
			kind: "GraphQLBackend",
			conflictingPair: func() (client.Object, client.Object) {
				return graphqlBackend("legacy-a", "legacy-gql.example.com"),
					graphqlBackend("legacy-b", "legacy-gql.example.com")
			},
			nonConflicting: func() client.Object {
				return graphqlBackend("legacy-b", "other-gql.example.com")
			},
			invalidObject: func() client.Object {
				b := graphqlBackend("invalid", "invalid-gql.example.com")
				b.Spec.Hosts = nil // at least one host is required
				return b
			},
			validateUpdate: func(
				t *testing.T, c client.Client, oldObj, newObj client.Object,
			) (admission.Warnings, error) {
				t.Helper()
				v := &GraphQLBackendValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}
				return v.ValidateUpdate(context.Background(),
					oldObj.(*avapigwv1alpha1.GraphQLBackend), newObj.(*avapigwv1alpha1.GraphQLBackend))
			},
		},
	}
}

// TestValidateUpdate_TerminatingObjectAdmitted verifies that an update to an
// object with a deletion timestamp is admitted unconditionally — even with a
// spec that is both locally invalid and in conflict with an existing peer —
// so finalizer removal on terminating objects can never deadlock.
func TestValidateUpdate_TerminatingObjectAdmitted(t *testing.T) {
	for _, fx := range lifecycleFixtures() {
		t.Run(fx.kind, func(t *testing.T) {
			objA, objB := fx.conflictingPair()
			c := newLifecycleClient(t, objA)

			// Terminating update with a conflicting spec is admitted.
			oldObj := deepCopy(objB)
			newObj := deepCopy(objB)
			markTerminating(newObj)
			warnings, err := fx.validateUpdate(t, c, oldObj, newObj)
			if err != nil {
				t.Fatalf("ValidateUpdate() must admit terminating %s with conflicting spec, got: %v",
					fx.kind, err)
			}
			if warnings != nil {
				t.Errorf("ValidateUpdate() terminating short-circuit warnings = %v, want nil", warnings)
			}

			// Even a locally invalid spec is admitted while terminating.
			invalid := fx.invalidObject()
			terminatingInvalid := deepCopy(invalid)
			markTerminating(terminatingInvalid)
			if _, err := fx.validateUpdate(t, c, deepCopy(invalid), terminatingInvalid); err != nil {
				t.Errorf("ValidateUpdate() must admit terminating %s with invalid spec, got: %v",
					fx.kind, err)
			}
		})
	}
}

// TestValidateUpdate_FinalizerAddOnLegacyOverlappingPair is the core
// finalizer-deadlock regression: adding a finalizer (a metadata-only update)
// to either member of a pre-existing conflicting pair must be admitted in
// both directions because the spec is unchanged.
func TestValidateUpdate_FinalizerAddOnLegacyOverlappingPair(t *testing.T) {
	for _, fx := range lifecycleFixtures() {
		t.Run(fx.kind, func(t *testing.T) {
			objA, objB := fx.conflictingPair()
			c := newLifecycleClient(t, objA, objB)

			for _, member := range []struct {
				name string
				obj  client.Object
			}{
				{"first member", objA},
				{"second member", objB},
			} {
				oldObj := deepCopy(member.obj)
				newObj := deepCopy(member.obj)
				newObj.SetFinalizers(append(newObj.GetFinalizers(), testFinalizer))

				if _, err := fx.validateUpdate(t, c, oldObj, newObj); err != nil {
					t.Errorf("finalizer-only update on %s of a legacy %s pair must be admitted, got: %v",
						member.name, fx.kind, err)
				}
			}
		})
	}
}

// TestValidateUpdate_SpecChangeToConflict_StillRejected verifies the
// metadata-only short-circuit does not weaken genuine conflict detection: a
// real spec change that introduces a conflict is still rejected.
func TestValidateUpdate_SpecChangeToConflict_StillRejected(t *testing.T) {
	for _, fx := range lifecycleFixtures() {
		t.Run(fx.kind, func(t *testing.T) {
			objA, objB := fx.conflictingPair()
			oldObj := fx.nonConflicting()
			c := newLifecycleClient(t, objA, oldObj)

			if _, err := fx.validateUpdate(t, c, oldObj, deepCopy(objB)); err == nil {
				t.Errorf("ValidateUpdate() must reject a %s spec change that conflicts with a live peer",
					fx.kind)
			}
		})
	}
}

// TestValidateUpdate_TerminatingPeerUnblocksSurvivor verifies the candidate
// loop deletion-skip: once one member of a conflicting pair is terminating,
// spec updates to the survivor are no longer blocked by it.
func TestValidateUpdate_TerminatingPeerUnblocksSurvivor(t *testing.T) {
	for _, fx := range lifecycleFixtures() {
		t.Run(fx.kind, func(t *testing.T) {
			objA, objB := fx.conflictingPair()
			oldObj := fx.nonConflicting()

			// Control: with the peer alive, the conflicting spec change is
			// rejected (proves the conflict is genuine).
			liveClient := newLifecycleClient(t, objA, oldObj)
			if _, err := fx.validateUpdate(t, liveClient, oldObj, deepCopy(objB)); err == nil {
				t.Fatalf("control: conflicting %s spec change with a live peer must be rejected", fx.kind)
			}

			// With the peer terminating, the same spec change is admitted.
			terminatingPeer := deepCopy(objA)
			markTerminating(terminatingPeer)
			termClient := newLifecycleClient(t, terminatingPeer, oldObj)
			if _, err := fx.validateUpdate(t, termClient, oldObj, deepCopy(objB)); err != nil {
				t.Errorf("%s spec change must be admitted once the conflicting peer is terminating, got: %v",
					fx.kind, err)
			}
		})
	}
}

// TestValidateUpdate_MetadataOnlyInvalidSpec_StillValidated guards against
// the metadata-only short-circuit silently re-admitting a pre-existing
// invalid spec: local validation must still fire.
func TestValidateUpdate_MetadataOnlyInvalidSpec_StillValidated(t *testing.T) {
	for _, fx := range lifecycleFixtures() {
		t.Run(fx.kind, func(t *testing.T) {
			invalid := fx.invalidObject()
			c := newLifecycleClient(t)

			oldObj := deepCopy(invalid)
			newObj := deepCopy(invalid)
			newObj.SetLabels(map[string]string{"touched": "true"})

			if _, err := fx.validateUpdate(t, c, oldObj, newObj); err == nil {
				t.Errorf("metadata-only %s update must still run local spec validation", fx.kind)
			}
		})
	}
}

// TestValidateUpdate_CrossKindMetadataOnlyAndTerminatingPeer covers the
// cross-kind (APIRoute <-> GraphQLRoute) conflict path: metadata-only
// updates on a cross-kind conflicting pair are admitted, genuine spec
// changes are still rejected, and a terminating cross-kind peer no longer
// blocks the survivor.
func TestValidateUpdate_CrossKindMetadataOnlyAndTerminatingPeer(t *testing.T) {
	newAPIRouteExact := func(name, path string) *avapigwv1alpha1.APIRoute {
		return &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Exact: path}},
				},
			},
		}
	}
	newGraphQLRouteExact := func(name, path string) *avapigwv1alpha1.GraphQLRoute {
		return &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{Path: &avapigwv1alpha1.StringMatch{Exact: path}},
				},
			},
		}
	}

	graphqlPeer := newGraphQLRouteExact("gql-peer", "/shared")
	apiSurvivor := newAPIRouteExact("api-survivor", "/api-only")
	conflictingUpdate := newAPIRouteExact("api-survivor", "/shared")

	t.Run("metadata-only update admitted despite cross-kind conflict", func(t *testing.T) {
		legacyAPIRoute := newAPIRouteExact("api-legacy", "/shared")
		c := newLifecycleClient(t, graphqlPeer, legacyAPIRoute)
		v := &APIRouteValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}

		newObj := legacyAPIRoute.DeepCopy()
		newObj.SetFinalizers([]string{testFinalizer})
		if _, err := v.ValidateUpdate(context.Background(), legacyAPIRoute, newObj); err != nil {
			t.Errorf("finalizer-only update on cross-kind conflicting APIRoute must be admitted, got: %v", err)
		}
	})

	t.Run("spec change into cross-kind conflict still rejected", func(t *testing.T) {
		c := newLifecycleClient(t, graphqlPeer, apiSurvivor)
		v := &APIRouteValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}

		if _, err := v.ValidateUpdate(context.Background(), apiSurvivor, conflictingUpdate); err == nil {
			t.Error("APIRoute spec change conflicting with a live GraphQLRoute must be rejected")
		}
	})

	t.Run("terminating cross-kind peer unblocks survivor", func(t *testing.T) {
		terminatingPeer := graphqlPeer.DeepCopy()
		markTerminating(terminatingPeer)
		c := newLifecycleClient(t, terminatingPeer, apiSurvivor)
		v := &APIRouteValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}

		if _, err := v.ValidateUpdate(context.Background(), apiSurvivor, conflictingUpdate); err != nil {
			t.Errorf("APIRoute spec change must be admitted once the GraphQLRoute peer is terminating, got: %v", err)
		}
	})

	t.Run("reverse direction: terminating APIRoute peer unblocks GraphQLRoute", func(t *testing.T) {
		terminatingAPIRoute := newAPIRouteExact("api-legacy", "/shared")
		markTerminating(terminatingAPIRoute)
		gqlSurvivor := newGraphQLRouteExact("gql-survivor", "/gql-only")
		c := newLifecycleClient(t, terminatingAPIRoute, gqlSurvivor)
		v := &GraphQLRouteValidator{Client: c, DuplicateChecker: NewDuplicateChecker(c)}

		conflicting := newGraphQLRouteExact("gql-survivor", "/shared")
		if _, err := v.ValidateUpdate(context.Background(), gqlSurvivor, conflicting); err != nil {
			t.Errorf("GraphQLRoute spec change must be admitted once the APIRoute peer is terminating, got: %v", err)
		}
	})
}

// TestCrossKindBackendChecks_TerminatingCandidatesSkipped exercises the
// deletion-skip in every backend cross-kind candidate loop directly at the
// DuplicateChecker level: a terminating cross-kind peer must not conflict,
// while a live one must.
func TestCrossKindBackendChecks_TerminatingCandidatesSkipped(t *testing.T) {
	const (
		sharedAddress = "shared.example.com"
		sharedPort    = 9090
	)
	hosts := newBackendHostSpec(sharedAddress, sharedPort)

	newBackend := func(name string) *avapigwv1alpha1.Backend {
		return &avapigwv1alpha1.Backend{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec:       avapigwv1alpha1.BackendSpec{Hosts: hosts},
		}
	}
	newGRPCBackend := func(name string) *avapigwv1alpha1.GRPCBackend {
		return &avapigwv1alpha1.GRPCBackend{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec:       avapigwv1alpha1.GRPCBackendSpec{Hosts: hosts},
		}
	}
	newGraphQLBackend := func(name string) *avapigwv1alpha1.GraphQLBackend {
		return &avapigwv1alpha1.GraphQLBackend{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec:       avapigwv1alpha1.GraphQLBackendSpec{Hosts: hosts},
		}
	}

	tests := []struct {
		name  string
		peer  client.Object
		check func(c *DuplicateChecker) error
	}{
		{
			name: "Backend vs GRPCBackend",
			peer: newGRPCBackend("peer"),
			check: func(c *DuplicateChecker) error {
				return c.CheckBackendCrossConflicts(context.Background(), newBackend("subject"))
			},
		},
		{
			name: "GRPCBackend vs Backend",
			peer: newBackend("peer"),
			check: func(c *DuplicateChecker) error {
				return c.CheckGRPCBackendCrossConflicts(context.Background(), newGRPCBackend("subject"))
			},
		},
		{
			name: "Backend vs GraphQLBackend",
			peer: newGraphQLBackend("peer"),
			check: func(c *DuplicateChecker) error {
				return c.CheckBackendCrossConflictsWithGraphQL(context.Background(), newBackend("subject"))
			},
		},
		{
			name: "GRPCBackend vs GraphQLBackend",
			peer: newGraphQLBackend("peer"),
			check: func(c *DuplicateChecker) error {
				return c.CheckGRPCBackendCrossConflictsWithGraphQL(context.Background(), newGRPCBackend("subject"))
			},
		},
		{
			name: "GraphQLBackend vs Backend",
			peer: newBackend("peer"),
			check: func(c *DuplicateChecker) error {
				return c.CheckGraphQLBackendCrossConflicts(context.Background(), newGraphQLBackend("subject"))
			},
		},
		{
			name: "GraphQLBackend vs GRPCBackend",
			peer: newGRPCBackend("peer"),
			check: func(c *DuplicateChecker) error {
				return c.CheckGraphQLBackendCrossConflicts(context.Background(), newGraphQLBackend("subject"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Control: a live cross-kind peer on the same host:port conflicts.
			liveChecker := NewDuplicateChecker(newLifecycleClient(t, tt.peer))
			if err := tt.check(liveChecker); err == nil {
				t.Fatal("control: live cross-kind peer on the same host:port must conflict")
			}

			// A terminating peer is skipped and no longer conflicts.
			terminating := deepCopy(tt.peer)
			markTerminating(terminating)
			termChecker := NewDuplicateChecker(newLifecycleClient(t, terminating))
			if err := tt.check(termChecker); err != nil {
				t.Errorf("terminating cross-kind peer must be skipped, got: %v", err)
			}
		})
	}
}
