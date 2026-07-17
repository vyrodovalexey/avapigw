// Package controller provides Kubernetes controllers for the operator.
//
// This file verifies the Result-vs-error return semantics of the reconcilers:
// controller-runtime ignores a non-empty Result when the returned error is
// non-nil, so a reconciler must return EITHER a fixed-delay requeue with a nil
// error OR an empty Result with an error (exponential backoff), never both.
package controller

import (
	"context"
	"errors"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// Sentinel errors injected into the reconcile/cleanup callbacks to simulate
// transient external failures (e.g., gRPC push to the gateway).
var (
	errResultSemanticsReconcile = errors.New("reconcile failed: gateway push unavailable")
	errResultSemanticsCleanup   = errors.New("cleanup failed: gateway unavailable")
	errResultSemanticsGet       = errors.New("get failed: apiserver unavailable")
	errResultSemanticsPatch     = errors.New("patch failed: apiserver conflict")
)

// resultSemanticsCallbacks returns minimal ReconcileCallbacks for exercising
// BaseReconcile Result-vs-error semantics directly. The injected reconcileErr
// and cleanupErr control the failure paths under test; failureStatusUpdated,
// when non-nil, records whether UpdateFailureStatus was invoked.
func resultSemanticsCallbacks(reconcileErr, cleanupErr error, failureStatusUpdated *bool) *ReconcileCallbacks {
	return &ReconcileCallbacks{
		ResourceKind:   KindAPIRoute,
		ControllerName: "apiroute",
		FinalizerName:  APIRouteFinalizerName,
		NewResource: func() Reconcilable {
			return &avapigwv1alpha1.APIRoute{}
		},
		Reconcile: func(context.Context, Reconcilable) error {
			return reconcileErr
		},
		Cleanup: func(context.Context, Reconcilable) error {
			return cleanupErr
		},
		UpdateStatus: func(context.Context, *StatusUpdater, Reconcilable) error {
			// no-op: status writes are not part of the Result-vs-error
			// semantics exercised by these tests.
			return nil
		},
		UpdateFailureStatus: func(context.Context, *StatusUpdater, Reconcilable, error) error {
			if failureStatusUpdated != nil {
				*failureStatusUpdated = true
			}
			return nil
		},
		RecordSuccessEvent: func(record.EventRecorder, Reconcilable) {
			// no-op: success events are not asserted by these tests.
		},
		RecordFailureEvent: func(recorder record.EventRecorder, resource Reconcilable, err error) {
			recorder.Event(resource, "Warning", EventReasonReconcileFailed, err.Error())
		},
	}
}

// newResultSemanticsAPIRoute builds an APIRoute fixture carrying the finalizer,
// optionally marked as being deleted.
func newResultSemanticsAPIRoute(name string, deleted bool) *avapigwv1alpha1.APIRoute {
	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  "default",
			Finalizers: []string{APIRouteFinalizerName},
		},
	}
	if deleted {
		now := metav1.Now()
		apiRoute.DeletionTimestamp = &now
	}
	return apiRoute
}

// resultSemanticsRequest builds the reconcile request for a fixture name.
func resultSemanticsRequest(name string) ctrl.Request {
	return ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: "default"},
	}
}

// TestBaseReconcile_ReconcileFailure_FixedDelayRequeueNoError asserts that a
// reconcile-callback failure schedules a fixed-delay requeue and returns a nil
// error, so controller-runtime honors RequeueAfterReconcileFailure instead of
// discarding it in favor of exponential backoff.
func TestBaseReconcile_ReconcileFailure_FixedDelayRequeueNoError(t *testing.T) {
	scheme := newTestScheme()
	apiRoute := newResultSemanticsAPIRoute("result-reconcile-failure", false)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()
	recorder := newFakeRecorder()
	failureStatusUpdated := false
	cb := resultSemanticsCallbacks(errResultSemanticsReconcile, nil, &failureStatusUpdated)

	result, err := BaseReconcile(
		context.Background(), fakeClient, NewStatusUpdater(fakeClient), recorder,
		resultSemanticsRequest(apiRoute.Name), cb,
	)

	if err != nil {
		t.Errorf("BaseReconcile() error = %v, want nil (reconcile failure must requeue with fixed delay)", err)
	}
	if result.RequeueAfter != RequeueAfterReconcileFailure {
		t.Errorf("BaseReconcile() RequeueAfter = %v, want %v", result.RequeueAfter, RequeueAfterReconcileFailure)
	}
	if !failureStatusUpdated {
		t.Error("BaseReconcile() should update failure status on reconcile failure")
	}
	if events := recorder.getEvents(); len(events) == 0 {
		t.Error("BaseReconcile() should record a failure event on reconcile failure")
	}
}

// TestBaseReconcile_CleanupFailure_FixedDelayRequeueNoError asserts that a
// cleanup failure during deletion schedules a fixed-delay requeue with a nil
// error and keeps the finalizer so the deletion is retried.
func TestBaseReconcile_CleanupFailure_FixedDelayRequeueNoError(t *testing.T) {
	scheme := newTestScheme()
	apiRoute := newResultSemanticsAPIRoute("result-cleanup-failure", true)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()
	recorder := newFakeRecorder()
	cb := resultSemanticsCallbacks(nil, errResultSemanticsCleanup, nil)

	req := resultSemanticsRequest(apiRoute.Name)
	result, err := BaseReconcile(
		context.Background(), fakeClient, NewStatusUpdater(fakeClient), recorder, req, cb,
	)

	if err != nil {
		t.Errorf("BaseReconcile() error = %v, want nil (cleanup failure must requeue with fixed delay)", err)
	}
	if result.RequeueAfter != RequeueAfterCleanupFailure {
		t.Errorf("BaseReconcile() RequeueAfter = %v, want %v", result.RequeueAfter, RequeueAfterCleanupFailure)
	}

	// The finalizer must remain in place so the retried reconciliation can
	// complete the deletion once cleanup succeeds.
	var updated avapigwv1alpha1.APIRoute
	if getErr := fakeClient.Get(context.Background(), req.NamespacedName, &updated); getErr != nil {
		t.Fatalf("Get() after failed cleanup error = %v, want resource still present", getErr)
	}
	if len(updated.Finalizers) == 0 {
		t.Error("BaseReconcile() must not remove the finalizer when cleanup fails")
	}
}

// TestBaseReconcile_GetError_EmptyResultWithError asserts that a transient
// apiserver Get failure returns an empty Result together with the error, so
// the workqueue applies exponential backoff.
func TestBaseReconcile_GetError_EmptyResultWithError(t *testing.T) {
	scheme := newTestScheme()
	apiRoute := newResultSemanticsAPIRoute("result-get-error", false)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		Build()
	errClient := &testErrorClient{Client: fakeClient, getErr: errResultSemanticsGet}
	cb := resultSemanticsCallbacks(nil, nil, nil)

	result, err := BaseReconcile(
		context.Background(), errClient, NewStatusUpdater(errClient), newFakeRecorder(),
		resultSemanticsRequest(apiRoute.Name), cb,
	)

	if !errors.Is(err, errResultSemanticsGet) {
		t.Errorf("BaseReconcile() error = %v, want %v", err, errResultSemanticsGet)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Errorf("BaseReconcile() result = %+v, want empty Result on error return", result)
	}
}

// TestBaseReconcile_FinalizerRemovePatchError_EmptyResultWithError asserts
// that a finalizer-removal patch failure during deletion returns an empty
// Result with the error (backoff-driven retry), never a Result+error pair.
func TestBaseReconcile_FinalizerRemovePatchError_EmptyResultWithError(t *testing.T) {
	scheme := newTestScheme()
	apiRoute := newResultSemanticsAPIRoute("result-patch-error", true)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()
	errClient := &testErrorClient{Client: fakeClient, patchErr: errResultSemanticsPatch}
	cb := resultSemanticsCallbacks(nil, nil, nil)

	result, err := BaseReconcile(
		context.Background(), errClient, NewStatusUpdater(errClient), newFakeRecorder(),
		resultSemanticsRequest(apiRoute.Name), cb,
	)

	if !errors.Is(err, errResultSemanticsPatch) {
		t.Errorf("BaseReconcile() error = %v, want %v", err, errResultSemanticsPatch)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Errorf("BaseReconcile() result = %+v, want empty Result on error return", result)
	}
}

// TestIngressReconciler_HandleDeletion_CleanupFailure_FixedDelayRequeueNoError
// asserts that the Ingress deletion path follows the same semantics as the
// base reconciler: cleanup failures schedule a fixed-delay requeue with a nil
// error instead of returning a Result+error pair.
func TestIngressReconciler_HandleDeletion_CleanupFailure_FixedDelayRequeueNoError(t *testing.T) {
	scheme := newIngressTestScheme()
	now := metav1.Now()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "result-ingress-cleanup-failure",
			Namespace:         "default",
			Finalizers:        []string{IngressFinalizerName},
			DeletionTimestamp: &now,
			Annotations: map[string]string{
				AnnotationAppliedRoutes: "routes:result-ingress-route;backends:",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString("avapigw"),
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ingress).
		Build()
	recorder := newFakeRecorder()
	reconciler := &IngressReconciler{
		Client:           fakeClient,
		Scheme:           scheme,
		Recorder:         recorder,
		GRPCServer:       getTestGRPCServer(t),
		Converter:        NewIngressConverter(),
		IngressClassName: "avapigw",
	}

	// A canceled context makes the gRPC server delete call fail, which is the
	// transient-cleanup-failure condition under test.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := reconciler.handleDeletion(ctx, ingress)

	if err != nil {
		t.Errorf("handleDeletion() error = %v, want nil (cleanup failure must requeue with fixed delay)", err)
	}
	if result.RequeueAfter != RequeueAfterCleanupFailure {
		t.Errorf("handleDeletion() RequeueAfter = %v, want %v", result.RequeueAfter, RequeueAfterCleanupFailure)
	}
	if events := recorder.getEvents(); len(events) == 0 {
		t.Error("handleDeletion() should record a Warning event on cleanup failure")
	}
}
