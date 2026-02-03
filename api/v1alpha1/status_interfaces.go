// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RouteStatusUpdatable interface methods for APIRoute.

// GetConditions returns the conditions for APIRoute.
func (r *APIRoute) GetConditions() []Condition {
	return r.Status.Conditions
}

// SetConditions sets the conditions for APIRoute.
func (r *APIRoute) SetConditions(conditions []Condition) {
	r.Status.Conditions = conditions
}

// SetObservedGeneration sets the observed generation for APIRoute.
func (r *APIRoute) SetObservedGeneration(generation int64) {
	r.Status.ObservedGeneration = generation
}

// RouteStatusUpdatable interface methods for GRPCRoute.

// GetConditions returns the conditions for GRPCRoute.
func (r *GRPCRoute) GetConditions() []Condition {
	return r.Status.Conditions
}

// SetConditions sets the conditions for GRPCRoute.
func (r *GRPCRoute) SetConditions(conditions []Condition) {
	r.Status.Conditions = conditions
}

// SetObservedGeneration sets the observed generation for GRPCRoute.
func (r *GRPCRoute) SetObservedGeneration(generation int64) {
	r.Status.ObservedGeneration = generation
}

// BackendStatusUpdatable interface methods for Backend.

// GetConditions returns the conditions for Backend.
func (b *Backend) GetConditions() []Condition {
	return b.Status.Conditions
}

// SetConditions sets the conditions for Backend.
func (b *Backend) SetConditions(conditions []Condition) {
	b.Status.Conditions = conditions
}

// SetObservedGeneration sets the observed generation for Backend.
func (b *Backend) SetObservedGeneration(generation int64) {
	b.Status.ObservedGeneration = generation
}

// SetHealthInfo sets the health information for Backend.
func (b *Backend) SetHealthInfo(totalHosts, healthyHosts int, lastHealthCheck *metav1.Time) {
	b.Status.TotalHosts = totalHosts
	b.Status.HealthyHosts = healthyHosts
	b.Status.LastHealthCheck = lastHealthCheck
}

// BackendStatusUpdatable interface methods for GRPCBackend.

// GetConditions returns the conditions for GRPCBackend.
func (b *GRPCBackend) GetConditions() []Condition {
	return b.Status.Conditions
}

// SetConditions sets the conditions for GRPCBackend.
func (b *GRPCBackend) SetConditions(conditions []Condition) {
	b.Status.Conditions = conditions
}

// SetObservedGeneration sets the observed generation for GRPCBackend.
func (b *GRPCBackend) SetObservedGeneration(generation int64) {
	b.Status.ObservedGeneration = generation
}

// SetHealthInfo sets the health information for GRPCBackend.
func (b *GRPCBackend) SetHealthInfo(totalHosts, healthyHosts int, lastHealthCheck *metav1.Time) {
	b.Status.TotalHosts = totalHosts
	b.Status.HealthyHosts = healthyHosts
	b.Status.LastHealthCheck = lastHealthCheck
}
