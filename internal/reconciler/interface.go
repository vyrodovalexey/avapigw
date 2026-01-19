package reconciler

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Reconciler defines the interface for resource reconciliation
type Reconciler interface {
	// Reconcile performs the reconciliation logic
	Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error)
}

// Finalizer defines the interface for resource finalization
type Finalizer interface {
	// Finalize performs cleanup logic before resource deletion
	Finalize(ctx context.Context, obj interface{}) error
}

// Validator defines the interface for resource validation
type Validator interface {
	// Validate validates the resource specification
	Validate(obj interface{}) error
}
