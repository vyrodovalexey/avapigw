// Package base provides a generic base controller framework for Kubernetes operators.
package base

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// StatusUpdater provides utilities for updating resource status with retry on conflict.
type StatusUpdater struct {
	client     client.Client
	maxRetries int
}

// NewStatusUpdater creates a new StatusUpdater.
func NewStatusUpdater(c client.Client) *StatusUpdater {
	return &StatusUpdater{
		client:     c,
		maxRetries: 3,
	}
}

// WithMaxRetries sets the maximum number of retries for status updates.
func (u *StatusUpdater) WithMaxRetries(maxRetries int) *StatusUpdater {
	u.maxRetries = maxRetries
	return u
}

// UpdateStatus updates the status of an object with retry on conflict.
func (u *StatusUpdater) UpdateStatus(ctx context.Context, obj client.Object) error {
	var lastErr error
	for i := 0; i < u.maxRetries; i++ {
		if err := u.client.Status().Update(ctx, obj); err != nil {
			if errors.IsConflict(err) {
				// Refresh the object and retry
				if refreshErr := u.client.Get(ctx, client.ObjectKeyFromObject(obj), obj); refreshErr != nil {
					return refreshErr
				}
				lastErr = err
				continue
			}
			return err
		}
		return nil
	}
	return lastErr
}

// UpdateStatusFunc is a function type for updating status with custom logic.
// The function receives the object and should modify its status.
// It will be called in a retry loop on conflict.
type UpdateStatusFunc[T client.Object] func(obj T) error

// UpdateStatusWithRetry updates the status of an object with retry on conflict,
// using a custom update function that can modify the status.
func UpdateStatusWithRetry[T client.Object](
	ctx context.Context,
	c client.Client,
	obj T,
	updateFn UpdateStatusFunc[T],
	maxRetries int,
) error {
	if maxRetries <= 0 {
		maxRetries = 3
	}

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		// Apply the update function
		if err := updateFn(obj); err != nil {
			return err
		}

		// Try to update the status
		if err := c.Status().Update(ctx, obj); err != nil {
			if errors.IsConflict(err) {
				// Refresh the object and retry
				if refreshErr := c.Get(ctx, client.ObjectKeyFromObject(obj), obj); refreshErr != nil {
					return refreshErr
				}
				lastErr = err
				continue
			}
			return err
		}
		return nil
	}
	return lastErr
}
