// Package base provides a generic base controller framework for Kubernetes operators.
package base

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ReconcilableObject is the interface that reconcilable objects must implement.
// It combines client.Object with the ability to check deletion timestamp.
type ReconcilableObject interface {
	client.Object
}

// ReconcilerConfig holds configuration for a reconciler.
type ReconcilerConfig struct {
	// Name is the controller name (used for logging and metrics).
	Name string

	// FinalizerName is the finalizer to use for this controller.
	FinalizerName string

	// ReconcileTimeout is the maximum duration for a single reconciliation.
	ReconcileTimeout time.Duration
}

// DefaultReconcileTimeout is the default timeout for reconciliation operations.
const DefaultReconcileTimeout = 30 * time.Second

// ReconcileFunc is the function signature for the main reconciliation logic.
// It receives the context and the object to reconcile.
// Returns an error if reconciliation fails.
type ReconcileFunc[T ReconcilableObject] func(ctx context.Context, obj T) error

// DeleteFunc is the function signature for deletion handling.
// It receives the context and the object being deleted.
// Returns an error if cleanup fails.
type DeleteFunc[T ReconcilableObject] func(ctx context.Context, obj T) error

// ObjectFactory is a function that creates a new instance of the reconciled object type.
type ObjectFactory[T ReconcilableObject] func() T

// RequeueStrategyProvider is an interface for providing requeue strategies.
// This allows the base package to work with any requeue strategy implementation.
type RequeueStrategyProvider interface {
	// ForSuccess returns the Result for a successful reconciliation.
	ForSuccess() ctrl.Result
	// ForImmediateRequeue returns a Result for immediate requeue.
	ForImmediateRequeue() ctrl.Result
	// ForTransientErrorWithBackoff returns the Result for a transient error with backoff.
	ForTransientErrorWithBackoff(key string) ctrl.Result
	// ForValidationError returns the Result for a validation error.
	ForValidationError() ctrl.Result
	// ForPermanentError returns the Result for a permanent error.
	ForPermanentError() ctrl.Result
	// ForDependencyErrorWithBackoff returns the Result for a dependency error with backoff.
	ForDependencyErrorWithBackoff(key string) ctrl.Result
	// GetFailureCount returns the current failure count for a resource.
	GetFailureCount(key string) int
	// ResetFailureCount resets the failure count for a resource.
	ResetFailureCount(key string)
}

// ErrorClassifier is an interface for classifying errors.
type ErrorClassifier interface {
	// ClassifyError classifies an error and returns error type information.
	ClassifyError(op, resource string, err error) ClassifiedError
}

// ClassifiedError represents a classified error with type information.
type ClassifiedError interface {
	error
	// ErrorType returns the type of the error.
	ErrorType() string
	// IsRetryable returns whether the error should trigger a retry.
	IsRetryable() bool
	// IsUserActionRequired returns whether user intervention is needed.
	IsUserActionRequired() bool
}

// SimpleReconciler provides a simplified reconciliation flow for controllers.
// It handles the common boilerplate of fetching resources, handling deletion,
// managing finalizers, and tracking metrics.
type SimpleReconciler[T ReconcilableObject] struct {
	Client           client.Client
	Scheme           *runtime.Scheme
	Recorder         record.EventRecorder
	Config           ReconcilerConfig
	Metrics          *ControllerMetrics
	FinalizerHandler *FinalizerHandler
}

// NewSimpleReconciler creates a new SimpleReconciler with the given configuration.
func NewSimpleReconciler[T ReconcilableObject](
	c client.Client,
	scheme *runtime.Scheme,
	recorder record.EventRecorder,
	config ReconcilerConfig,
) *SimpleReconciler[T] {
	if config.ReconcileTimeout == 0 {
		config.ReconcileTimeout = DefaultReconcileTimeout
	}

	return &SimpleReconciler[T]{
		Client:           c,
		Scheme:           scheme,
		Recorder:         recorder,
		Config:           config,
		Metrics:          DefaultMetricsRegistry.RegisterController(config.Name),
		FinalizerHandler: NewFinalizerHandler(c, config.FinalizerName),
	}
}

// ReconcileParams holds parameters for a reconciliation operation.
type ReconcileParams[T ReconcilableObject] struct {
	// Ctx is the context for the reconciliation.
	Ctx context.Context
	// Req is the reconcile request.
	Req ctrl.Request
	// NewObject creates a new instance of the object type.
	NewObject ObjectFactory[T]
	// ReconcileFunc is the main reconciliation logic.
	ReconcileFunc ReconcileFunc[T]
	// DeleteFunc is the deletion handling logic (optional).
	DeleteFunc DeleteFunc[T]
	// Strategy is the requeue strategy provider.
	Strategy RequeueStrategyProvider
	// ErrorClassifier classifies errors (optional, uses default if nil).
	ErrorClassifier ErrorClassifier
}

// Reconcile performs the common reconciliation flow.
// It handles:
//   - Timeout handling with context
//   - Metrics tracking
//   - Logging reconciliation start
//   - Fetching the resource with not-found handling
//   - Handling deletion with finalizer removal
//   - Adding finalizer if not present
//   - Calling the reconcile function
//   - Success handling with RequeueStrategy
func (r *SimpleReconciler[T]) Reconcile(params ReconcileParams[T]) (ctrl.Result, error) {
	// Add timeout to prevent hanging
	ctx, cancel := context.WithTimeout(params.Ctx, r.Config.ReconcileTimeout)
	defer cancel()

	logger := log.FromContext(ctx)
	strategy := params.Strategy
	resourceKey := params.Req.String()

	// Track reconciliation metrics
	start := time.Now()
	var hasError bool
	defer func() {
		duration := time.Since(start).Seconds()
		r.Metrics.ObserveReconcile(duration, !hasError)
	}()

	logger.Info("Reconciling "+r.Config.Name,
		"name", params.Req.Name,
		"namespace", params.Req.Namespace,
		"failureCount", strategy.GetFailureCount(resourceKey),
	)

	// Fetch the resource instance
	obj, result, found, err := r.fetchResource(ctx, params, logger, strategy, resourceKey)
	if err != nil || !found {
		if err != nil {
			hasError = true
		}
		return result, err
	}

	// Handle deletion
	if !obj.GetDeletionTimestamp().IsZero() {
		result, err := r.handleDeletion(ctx, obj, params.DeleteFunc, logger, strategy, resourceKey)
		if err != nil {
			hasError = true
		} else {
			strategy.ResetFailureCount(resourceKey)
		}
		return result, err
	}

	// Ensure finalizer and reconcile
	return r.ensureFinalizerAndReconcile(ctx, obj, params, logger, strategy, resourceKey, &hasError)
}

// fetchResource fetches the resource instance and handles not-found errors.
// Returns the object, result, a boolean indicating if the object was found, and any error.
func (r *SimpleReconciler[T]) fetchResource(
	ctx context.Context,
	params ReconcileParams[T],
	logger logr.Logger,
	strategy RequeueStrategyProvider,
	resourceKey string,
) (obj T, result ctrl.Result, found bool, err error) {
	obj = params.NewObject()
	if err = r.Client.Get(ctx, params.Req.NamespacedName, obj); err != nil {
		if errors.IsNotFound(err) {
			logger.Info(r.Config.Name + " not found, ignoring")
			strategy.ResetFailureCount(resourceKey)
			return obj, ctrl.Result{}, false, nil
		}
		logger.Error(err, "Failed to get "+r.Config.Name)
		return obj, strategy.ForTransientErrorWithBackoff(resourceKey), false, err
	}
	return obj, ctrl.Result{}, true, nil
}

// ensureFinalizerAndReconcile ensures the finalizer is present and performs reconciliation.
func (r *SimpleReconciler[T]) ensureFinalizerAndReconcile(
	ctx context.Context,
	obj T,
	params ReconcileParams[T],
	logger logr.Logger,
	strategy RequeueStrategyProvider,
	resourceKey string,
	hasError *bool,
) (ctrl.Result, error) {
	// Add finalizer if not present
	if !r.FinalizerHandler.HasFinalizer(obj) {
		added, err := r.FinalizerHandler.EnsureFinalizer(ctx, obj)
		if err != nil {
			*hasError = true
			logger.Error(err, "Failed to add finalizer")
			r.Recorder.Event(obj, corev1.EventTypeWarning, "FinalizerError", err.Error())
			return strategy.ForTransientErrorWithBackoff(resourceKey), err
		}
		if added {
			return strategy.ForImmediateRequeue(), nil
		}
	}

	// Reconcile the resource
	if err := params.ReconcileFunc(ctx, obj); err != nil {
		*hasError = true
		logger.Error(err, "Failed to reconcile "+r.Config.Name)
		r.Recorder.Event(obj, corev1.EventTypeWarning, "ReconcileError", err.Error())
		return strategy.ForTransientErrorWithBackoff(resourceKey), err
	}

	// Success - reset failure count and requeue for periodic reconciliation
	strategy.ResetFailureCount(resourceKey)
	logger.Info(r.Config.Name+" reconciled successfully", "name", params.Req.Name, "namespace", params.Req.Namespace)
	return strategy.ForSuccess(), nil
}

// handleDeletion handles resource deletion with finalizer removal.
func (r *SimpleReconciler[T]) handleDeletion(
	ctx context.Context,
	obj T,
	deleteFunc DeleteFunc[T],
	logger logr.Logger,
	strategy RequeueStrategyProvider,
	resourceKey string,
) (ctrl.Result, error) {
	if !r.FinalizerHandler.HasFinalizer(obj) {
		return ctrl.Result{}, nil
	}

	// Perform cleanup
	logger.Info("Performing cleanup for "+r.Config.Name+" deletion",
		"name", obj.GetName(),
		"namespace", obj.GetNamespace(),
	)

	// Call the delete function if provided
	if deleteFunc != nil {
		if err := deleteFunc(ctx, obj); err != nil {
			logger.Error(err, "Failed to perform cleanup")
			return strategy.ForTransientErrorWithBackoff(resourceKey), err
		}
	}

	// Record event
	r.Recorder.Event(obj, corev1.EventTypeNormal, "Deleting", r.Config.Name+" is being deleted")

	// Remove finalizer
	if _, err := r.FinalizerHandler.RemoveFinalizer(ctx, obj); err != nil {
		logger.Error(err, "Failed to remove finalizer")
		return strategy.ForTransientErrorWithBackoff(resourceKey), err
	}

	return ctrl.Result{}, nil
}
