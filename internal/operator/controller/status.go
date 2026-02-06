// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ValidConditionFromBool creates a ConditionUpdate for the Valid condition
// based on a boolean valid state.
func ValidConditionFromBool(valid bool, reason, message string, generation int64) ConditionUpdate {
	status := metav1.ConditionFalse
	if valid {
		status = metav1.ConditionTrue
	}
	return ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionValid,
		Status:     status,
		Reason:     avapigwv1alpha1.ConditionReason(reason),
		Message:    message,
		Generation: generation,
	}
}

// FindCondition finds a condition by type in the conditions slice.
// Returns nil if not found.
func FindCondition(
	conditions []avapigwv1alpha1.Condition,
	condType avapigwv1alpha1.ConditionType,
) *avapigwv1alpha1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

// IsConditionTrue returns true if the condition with the given type is True.
func IsConditionTrue(conditions []avapigwv1alpha1.Condition, condType avapigwv1alpha1.ConditionType) bool {
	cond := FindCondition(conditions, condType)
	return cond != nil && cond.Status == metav1.ConditionTrue
}

// IsConditionFalse returns true if the condition with the given type is False.
func IsConditionFalse(conditions []avapigwv1alpha1.Condition, condType avapigwv1alpha1.ConditionType) bool {
	cond := FindCondition(conditions, condType)
	return cond != nil && cond.Status == metav1.ConditionFalse
}

// IsConditionUnknown returns true if the condition with the given type is Unknown or not found.
func IsConditionUnknown(conditions []avapigwv1alpha1.Condition, condType avapigwv1alpha1.ConditionType) bool {
	cond := FindCondition(conditions, condType)
	return cond == nil || cond.Status == metav1.ConditionUnknown
}

// GetConditionReason returns the reason for a condition, or empty string if not found.
func GetConditionReason(conditions []avapigwv1alpha1.Condition, condType avapigwv1alpha1.ConditionType) string {
	cond := FindCondition(conditions, condType)
	if cond == nil {
		return ""
	}
	return string(cond.Reason)
}

// GetConditionMessage returns the message for a condition, or empty string if not found.
func GetConditionMessage(conditions []avapigwv1alpha1.Condition, condType avapigwv1alpha1.ConditionType) string {
	cond := FindCondition(conditions, condType)
	if cond == nil {
		return ""
	}
	return cond.Message
}

// Status message constants for health conditions.
const (
	messageAllHostsHealthy    = "All hosts are healthy"
	messageSomeHostsUnhealthy = "Some hosts are unhealthy"
)

// StatusUpdater provides helper methods for updating resource status conditions.
// It encapsulates common status update logic used across all controllers.
type StatusUpdater struct {
	client client.Client
}

// NewStatusUpdater creates a new StatusUpdater with the given client.
func NewStatusUpdater(c client.Client) *StatusUpdater {
	return &StatusUpdater{client: c}
}

// ConditionUpdate represents the parameters for updating a condition.
type ConditionUpdate struct {
	Type       avapigwv1alpha1.ConditionType
	Status     metav1.ConditionStatus
	Reason     avapigwv1alpha1.ConditionReason
	Message    string
	Generation int64
}

// UpdateCondition updates or adds a condition in the given conditions slice.
// It returns the updated conditions slice.
func UpdateCondition(
	conditions []avapigwv1alpha1.Condition,
	update ConditionUpdate,
) []avapigwv1alpha1.Condition {
	now := metav1.Now()

	newCondition := avapigwv1alpha1.Condition{
		Type:               update.Type,
		Status:             update.Status,
		Reason:             update.Reason,
		Message:            update.Message,
		LastTransitionTime: now,
		ObservedGeneration: update.Generation,
	}

	// Find existing condition
	for i, c := range conditions {
		if c.Type == update.Type {
			// Only update LastTransitionTime if status changed
			if c.Status != update.Status {
				conditions[i] = newCondition
			} else {
				// Update other fields but keep LastTransitionTime
				conditions[i].Reason = update.Reason
				conditions[i].Message = update.Message
				conditions[i].ObservedGeneration = update.Generation
			}
			return conditions
		}
	}

	// Condition not found, append new one
	return append(conditions, newCondition)
}

// ReadyConditionFromBool creates a ConditionUpdate for the Ready condition
// based on a boolean ready state.
func ReadyConditionFromBool(ready bool, reason, message string, generation int64) ConditionUpdate {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	return ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionReady,
		Status:     status,
		Reason:     avapigwv1alpha1.ConditionReason(reason),
		Message:    message,
		Generation: generation,
	}
}

// HealthyConditionFromBool creates a ConditionUpdate for the Healthy condition
// based on a boolean healthy state.
func HealthyConditionFromBool(healthy bool, generation int64) ConditionUpdate {
	status := metav1.ConditionFalse
	reason := avapigwv1alpha1.ReasonHealthCheckFail
	message := messageSomeHostsUnhealthy
	if healthy {
		status = metav1.ConditionTrue
		reason = avapigwv1alpha1.ReasonHealthCheckOK
		message = messageAllHostsHealthy
	}
	return ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionHealthy,
		Status:     status,
		Reason:     reason,
		Message:    message,
		Generation: generation,
	}
}

// RouteStatusUpdatable is an interface for route resources that have status conditions.
type RouteStatusUpdatable interface {
	client.Object
	GetConditions() []avapigwv1alpha1.Condition
	SetConditions([]avapigwv1alpha1.Condition)
	GetGeneration() int64
	SetObservedGeneration(int64)
}

// BackendStatusUpdatable is an interface for backend resources that have status conditions
// and health information.
type BackendStatusUpdatable interface {
	client.Object
	GetConditions() []avapigwv1alpha1.Condition
	SetConditions([]avapigwv1alpha1.Condition)
	GetGeneration() int64
	SetObservedGeneration(int64)
	SetHealthInfo(totalHosts, healthyHosts int, lastHealthCheck *metav1.Time)
}

// UpdateRouteStatus updates the status of a route resource (APIRoute or GRPCRoute).
// It updates the Ready condition and observed generation using a merge patch
// to reduce conflicts from concurrent updates.
func (u *StatusUpdater) UpdateRouteStatus(
	ctx context.Context,
	route RouteStatusUpdatable,
	ready bool,
	reason, message string,
) error {
	logger := log.FromContext(ctx)
	startTime := time.Now()
	kind := route.GetObjectKind().GroupVersionKind().Kind
	if kind == "" {
		// Fallback for when GVK is not set
		kind = "Route"
	}

	// Capture the base state before modifications for the merge patch
	patch := client.MergeFrom(route.DeepCopyObject().(client.Object))

	// Update Ready condition
	conditions := UpdateCondition(
		route.GetConditions(),
		ReadyConditionFromBool(ready, reason, message, route.GetGeneration()),
	)
	route.SetConditions(conditions)
	route.SetObservedGeneration(route.GetGeneration())

	// Patch status using merge patch to reduce conflicts
	if err := u.client.Status().Patch(ctx, route, patch); err != nil {
		GetStatusUpdateMetrics().RecordStatusUpdate(kind, time.Since(startTime), false)
		logger.Error(err, "failed to patch route status",
			"kind", kind,
			"name", route.GetName(),
			"namespace", route.GetNamespace(),
		)
		return fmt.Errorf("failed to patch route status: %w", err)
	}

	GetStatusUpdateMetrics().RecordStatusUpdate(kind, time.Since(startTime), true)
	return nil
}

// UpdateBackendStatus updates the status of a backend resource (Backend or GRPCBackend).
// It updates the Ready and Healthy conditions, observed generation, and health information
// using a merge patch to reduce conflicts from concurrent updates.
func (u *StatusUpdater) UpdateBackendStatus(
	ctx context.Context,
	backend BackendStatusUpdatable,
	ready, healthy bool,
	reason, message string,
	totalHosts int,
) error {
	logger := log.FromContext(ctx)
	startTime := time.Now()
	kind := backend.GetObjectKind().GroupVersionKind().Kind
	if kind == "" {
		// Fallback for when GVK is not set
		kind = "Backend"
	}

	// Capture the base state before modifications for the merge patch
	patch := client.MergeFrom(backend.DeepCopyObject().(client.Object))

	// Update Ready condition
	conditions := UpdateCondition(
		backend.GetConditions(),
		ReadyConditionFromBool(ready, reason, message, backend.GetGeneration()),
	)

	// Update Healthy condition
	conditions = UpdateCondition(
		conditions,
		HealthyConditionFromBool(healthy, backend.GetGeneration()),
	)

	backend.SetConditions(conditions)
	backend.SetObservedGeneration(backend.GetGeneration())

	// Update health info
	now := metav1.Now()
	healthyHosts := 0
	if healthy {
		healthyHosts = totalHosts
	}
	backend.SetHealthInfo(totalHosts, healthyHosts, &now)

	// Patch status using merge patch to reduce conflicts
	if err := u.client.Status().Patch(ctx, backend, patch); err != nil {
		GetStatusUpdateMetrics().RecordStatusUpdate(kind, time.Since(startTime), false)
		logger.Error(err, "failed to patch backend status",
			"kind", kind,
			"name", backend.GetName(),
			"namespace", backend.GetNamespace(),
		)
		return fmt.Errorf("failed to patch backend status: %w", err)
	}

	GetStatusUpdateMetrics().RecordStatusUpdate(kind, time.Since(startTime), true)
	return nil
}
