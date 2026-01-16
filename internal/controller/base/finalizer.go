// Package base provides a generic base controller framework for Kubernetes operators.
package base

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// FinalizerHandler provides utilities for managing finalizers on Kubernetes objects.
type FinalizerHandler struct {
	client        client.Client
	finalizerName string
}

// NewFinalizerHandler creates a new FinalizerHandler.
func NewFinalizerHandler(c client.Client, finalizerName string) *FinalizerHandler {
	return &FinalizerHandler{
		client:        c,
		finalizerName: finalizerName,
	}
}

// HasFinalizer checks if the object has the finalizer.
func (h *FinalizerHandler) HasFinalizer(obj client.Object) bool {
	return controllerutil.ContainsFinalizer(obj, h.finalizerName)
}

// EnsureFinalizer adds the finalizer to the object if not present.
// Returns true if the finalizer was added (object was updated), false if already present.
func (h *FinalizerHandler) EnsureFinalizer(ctx context.Context, obj client.Object) (bool, error) {
	if controllerutil.ContainsFinalizer(obj, h.finalizerName) {
		return false, nil
	}

	controllerutil.AddFinalizer(obj, h.finalizerName)
	if err := h.client.Update(ctx, obj); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveFinalizer removes the finalizer from the object.
// Returns true if the finalizer was removed (object was updated), false if not present.
func (h *FinalizerHandler) RemoveFinalizer(ctx context.Context, obj client.Object) (bool, error) {
	if !controllerutil.ContainsFinalizer(obj, h.finalizerName) {
		return false, nil
	}

	controllerutil.RemoveFinalizer(obj, h.finalizerName)
	if err := h.client.Update(ctx, obj); err != nil {
		return false, err
	}
	return true, nil
}

// FinalizerName returns the finalizer name.
func (h *FinalizerHandler) FinalizerName() string {
	return h.finalizerName
}

// ContainsFinalizer is a convenience function that checks if an object has a specific finalizer.
func ContainsFinalizer(obj client.Object, finalizerName string) bool {
	return controllerutil.ContainsFinalizer(obj, finalizerName)
}

// AddFinalizer is a convenience function that adds a finalizer to an object.
func AddFinalizer(obj client.Object, finalizerName string) {
	controllerutil.AddFinalizer(obj, finalizerName)
}

// RemoveFinalizerFromObject is a convenience function that removes a finalizer from an object.
func RemoveFinalizerFromObject(obj client.Object, finalizerName string) {
	controllerutil.RemoveFinalizer(obj, finalizerName)
}
