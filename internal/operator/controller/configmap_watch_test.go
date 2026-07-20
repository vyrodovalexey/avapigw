// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// newConfigMapWatchScheme returns a scheme with both the avapigw CRD types
// and the core types (ConfigMap) registered.
func newConfigMapWatchScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	return scheme
}

// ============================================================================
// Reference helpers
// ============================================================================

func TestConfigMapRefName(t *testing.T) {
	ref := &avapigwv1alpha1.ConfigMapKeyRef{Name: "spec-cm"}

	assert.Empty(t, configMapRefName(false, ref), "disabled validation has no reference")
	assert.Empty(t, configMapRefName(true, nil), "missing ref has no reference")
	assert.Equal(t, "spec-cm", configMapRefName(true, ref))
}

func TestRouteConfigMapNameHelpers(t *testing.T) {
	apiRoute := &avapigwv1alpha1.APIRoute{Spec: avapigwv1alpha1.APIRouteSpec{
		OpenAPIValidation: &avapigwv1alpha1.OpenAPIValidationConfig{
			Enabled:          true,
			SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{Name: "openapi-cm"},
		},
	}}
	assert.Equal(t, "openapi-cm", apiRouteConfigMapName(apiRoute))
	assert.Empty(t, apiRouteConfigMapName(&avapigwv1alpha1.APIRoute{}))

	grpcRoute := &avapigwv1alpha1.GRPCRoute{Spec: avapigwv1alpha1.GRPCRouteSpec{
		ProtoValidation: &avapigwv1alpha1.ProtoValidationConfig{
			Enabled:                true,
			DescriptorConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{Name: "proto-cm"},
		},
	}}
	assert.Equal(t, "proto-cm", grpcRouteConfigMapName(grpcRoute))
	assert.Empty(t, grpcRouteConfigMapName(&avapigwv1alpha1.GRPCRoute{}))

	graphqlRoute := &avapigwv1alpha1.GraphQLRoute{Spec: avapigwv1alpha1.GraphQLRouteSpec{
		SchemaValidation: &avapigwv1alpha1.GraphQLSchemaValidationConfig{
			Enabled:            true,
			SchemaConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{Name: "schema-cm"},
		},
	}}
	assert.Equal(t, "schema-cm", graphqlRouteConfigMapName(graphqlRoute))
	assert.Empty(t, graphqlRouteConfigMapName(&avapigwv1alpha1.GraphQLRoute{}))
}

func TestConfigMapIndexValues(t *testing.T) {
	assert.Nil(t, configMapIndexValues(""))
	assert.Equal(t, []string{"cm"}, configMapIndexValues("cm"))
}

// ============================================================================
// configMapMapFunc
// ============================================================================

// newAPIRouteWithConfigMap builds an APIRoute referencing the given ConfigMap.
func newAPIRouteWithConfigMap(name, namespace, cmName string) *avapigwv1alpha1.APIRoute {
	return &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: avapigwv1alpha1.APIRouteSpec{
			OpenAPIValidation: &avapigwv1alpha1.OpenAPIValidationConfig{
				Enabled:          true,
				SpecConfigMapRef: &avapigwv1alpha1.ConfigMapKeyRef{Name: cmName},
			},
		},
	}
}

func TestConfigMapMapFunc_EnqueuesReferencingRoutes(t *testing.T) {
	scheme := newConfigMapWatchScheme(t)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.APIRoute{}, apiRouteConfigMapIndexField,
			func(obj client.Object) []string {
				return configMapIndexValues(apiRouteConfigMapName(obj.(*avapigwv1alpha1.APIRoute)))
			}).
		WithObjects(
			newAPIRouteWithConfigMap("route-a", "default", "openapi-cm"),
			newAPIRouteWithConfigMap("route-b", "default", "openapi-cm"),
			newAPIRouteWithConfigMap("route-other-cm", "default", "another-cm"),
			newAPIRouteWithConfigMap("route-other-ns", "other", "openapi-cm"),
		).
		Build()

	mapFunc := configMapMapFunc(fakeClient, KindAPIRoute, apiRouteConfigMapIndexField,
		func() client.ObjectList { return &avapigwv1alpha1.APIRouteList{} })

	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "openapi-cm", Namespace: "default"}}
	requests := mapFunc(context.Background(), cm)

	require.Len(t, requests, 2, "exactly the referencing routes in the ConfigMap namespace")
	names := []string{requests[0].Name, requests[1].Name}
	assert.ElementsMatch(t, []string{"route-a", "route-b"}, names)
	for _, req := range requests {
		assert.Equal(t, "default", req.Namespace)
	}
}

func TestConfigMapMapFunc_NoReferences(t *testing.T) {
	scheme := newConfigMapWatchScheme(t)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&avapigwv1alpha1.APIRoute{}, apiRouteConfigMapIndexField,
			func(obj client.Object) []string {
				return configMapIndexValues(apiRouteConfigMapName(obj.(*avapigwv1alpha1.APIRoute)))
			}).
		Build()

	mapFunc := configMapMapFunc(fakeClient, KindAPIRoute, apiRouteConfigMapIndexField,
		func() client.ObjectList { return &avapigwv1alpha1.APIRouteList{} })

	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "unreferenced", Namespace: "default"}}
	assert.Empty(t, mapFunc(context.Background(), cm))
}

func TestConfigMapMapFunc_ListErrorReturnsNil(t *testing.T) {
	scheme := newConfigMapWatchScheme(t)

	// A client WITHOUT the field index makes MatchingFields fail on List.
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	mapFunc := configMapMapFunc(fakeClient, KindAPIRoute, apiRouteConfigMapIndexField,
		func() client.ObjectList { return &avapigwv1alpha1.APIRouteList{} })

	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "default"}}
	assert.Nil(t, mapFunc(context.Background(), cm), "list errors degrade to no enqueue")
}

// ============================================================================
// ReferencesExternalConfig — generation-skip bypass wiring
// ============================================================================

func TestReferencesExternalConfig_Callbacks(t *testing.T) {
	apiReconciler := &APIRouteReconciler{}
	grpcReconciler := &GRPCRouteReconciler{}
	graphqlReconciler := &GraphQLRouteReconciler{}

	apiCB := apiReconciler.callbacks()
	require.NotNil(t, apiCB.ReferencesExternalConfig)
	assert.True(t, apiCB.ReferencesExternalConfig(newAPIRouteWithConfigMap("r", "ns", "cm")))
	assert.False(t, apiCB.ReferencesExternalConfig(&avapigwv1alpha1.APIRoute{}))

	grpcCB := grpcReconciler.callbacks()
	require.NotNil(t, grpcCB.ReferencesExternalConfig)
	assert.False(t, grpcCB.ReferencesExternalConfig(&avapigwv1alpha1.GRPCRoute{}))

	graphqlCB := graphqlReconciler.callbacks()
	require.NotNil(t, graphqlCB.ReferencesExternalConfig)
	assert.False(t, graphqlCB.ReferencesExternalConfig(&avapigwv1alpha1.GraphQLRoute{}))
}

func TestReferencesExternalConfigHelper(t *testing.T) {
	cb := &ReconcileCallbacks{}
	assert.False(t, referencesExternalConfig(cb, &avapigwv1alpha1.APIRoute{}),
		"nil callback means no external config")

	cb.ReferencesExternalConfig = func(Reconcilable) bool { return true }
	assert.True(t, referencesExternalConfig(cb, &avapigwv1alpha1.APIRoute{}))
}

// newReadyAPIRouteWithConfigMap builds a Ready APIRoute (generation matches
// the Ready condition's observed generation) that references a ConfigMap.
func newReadyAPIRouteWithConfigMap(name string) *avapigwv1alpha1.APIRoute {
	route := newAPIRouteWithConfigMap(name, "default", "openapi-cm")
	route.Generation = 3
	route.Finalizers = []string{APIRouteFinalizerName}
	route.Status.Conditions = []avapigwv1alpha1.Condition{{
		Type:               avapigwv1alpha1.ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             avapigwv1alpha1.ReasonReconciled,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: 3,
	}}
	return route
}

// bypassCallbacks builds minimal callbacks counting Reconcile invocations,
// with the given external-config declaration.
func bypassCallbacks(reconciled *int, referencesExternal bool) *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   KindAPIRoute,
		ControllerName: "apiroute",
		FinalizerName:  APIRouteFinalizerName,
		NewResource:    func() Reconcilable { return &avapigwv1alpha1.APIRoute{} },
		Reconcile: func(context.Context, Reconcilable) error {
			*reconciled++
			return nil
		},
		Cleanup: func(context.Context, Reconcilable) error { return nil },
		UpdateStatus: func(context.Context, *StatusUpdater, Reconcilable) error {
			// no-op: status writes are not part of the skip semantics under test.
			return nil
		},
		RecordSuccessEvent: func(record.EventRecorder, Reconcilable) {
			// no-op: events are not asserted by the skip-bypass tests.
		},
		RecordFailureEvent: func(recorder record.EventRecorder, resource Reconcilable, err error) {
			recorder.Event(resource, "Warning", EventReasonReconcileFailed, err.Error())
		},
		// IsApplied true: the resource IS in the gRPC store, so only the
		// external-config declaration can force reconciliation.
		IsApplied:                func(context.Context, Reconcilable) bool { return true },
		ReferencesExternalConfig: func(Reconcilable) bool { return referencesExternal },
	}
}

// TestBaseReconcile_ExternalConfigBypassesGenerationSkip verifies that a
// Ready resource referencing a ConfigMap is still fully reconciled (the
// generation-based skip is bypassed) so ConfigMap edits propagate without a
// route change or operator restart.
func TestBaseReconcile_ExternalConfigBypassesGenerationSkip(t *testing.T) {
	scheme := newConfigMapWatchScheme(t)
	route := newReadyAPIRouteWithConfigMap("bypass-route")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route).
		WithStatusSubresource(route).
		Build()

	reconciled := 0
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: route.Name, Namespace: "default"}}

	result, err := BaseReconcile(
		context.Background(), fakeClient, NewStatusUpdater(fakeClient), newFakeRecorder(),
		req, bypassCallbacks(&reconciled, true),
	)

	assert.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)
	assert.Equal(t, 1, reconciled,
		"reconcile must run for Ready resources that inline external ConfigMap content")
}

// TestBaseReconcile_NoExternalConfig_GenerationSkipApplies verifies the
// generation-based skip is preserved for resources without external
// configuration references.
func TestBaseReconcile_NoExternalConfig_GenerationSkipApplies(t *testing.T) {
	scheme := newConfigMapWatchScheme(t)
	route := newReadyAPIRouteWithConfigMap("skip-route")

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route).
		WithStatusSubresource(route).
		Build()

	reconciled := 0
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: route.Name, Namespace: "default"}}

	result, err := BaseReconcile(
		context.Background(), fakeClient, NewStatusUpdater(fakeClient), newFakeRecorder(),
		req, bypassCallbacks(&reconciled, false),
	)

	assert.NoError(t, err)
	assert.Zero(t, result.RequeueAfter)
	assert.Zero(t, reconciled, "generation skip must prevent reconciliation")
}
