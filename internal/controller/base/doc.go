// Package base provides a generic base controller framework for Kubernetes operators.
//
// This package eliminates code duplication across controllers by providing:
//   - Generic base reconciler with common reconciliation patterns
//   - Centralized metrics registration and tracking
//   - Finalizer handling utilities
//   - Status update helpers with retry on conflict
//
// # Usage
//
// Controllers can embed the BaseReconciler to inherit common functionality:
//
//	type MyReconciler struct {
//	    base.BaseReconciler[*v1alpha1.MyResource]
//	    // controller-specific fields
//	}
//
//	func (r *MyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
//	    return r.BaseReconciler.Reconcile(ctx, req,
//	        func() *v1alpha1.MyResource { return &v1alpha1.MyResource{} },
//	        r.reconcileResource,
//	        r.handleDeletion,
//	    )
//	}
//
// # Metrics
//
// The package provides centralized metrics registration:
//
//	metrics := base.DefaultMetricsRegistry.RegisterController("mycontroller")
//	// metrics.ReconcileDuration and metrics.ReconcileTotal are now available
//
// # Finalizers
//
// Finalizer handling is simplified:
//
//	handler := base.NewFinalizerHandler(client, "mycontroller-finalizer")
//	if err := handler.EnsureFinalizer(ctx, obj); err != nil {
//	    return err
//	}
package base
