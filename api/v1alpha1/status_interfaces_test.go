// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// APIRoute Status Interface Tests
// ============================================================================

func TestAPIRoute_GetConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions []Condition
		want       []Condition
	}{
		{
			name:       "nil conditions",
			conditions: nil,
			want:       nil,
		},
		{
			name:       "empty conditions",
			conditions: []Condition{},
			want:       []Condition{},
		},
		{
			name: "single condition",
			conditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
			},
			want: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
			},
		},
		{
			name: "multiple conditions",
			conditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
				{
					Type:    "Accepted",
					Status:  "True",
					Reason:  "Accepted",
					Message: "Route is accepted",
				},
			},
			want: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
				{
					Type:    "Accepted",
					Status:  "True",
					Reason:  "Accepted",
					Message: "Route is accepted",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &APIRoute{
				Status: APIRouteStatus{
					Conditions: tt.conditions,
				},
			}

			got := route.GetConditions()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAPIRoute_SetConditions(t *testing.T) {
	tests := []struct {
		name           string
		initial        []Condition
		newConditions  []Condition
		wantConditions []Condition
	}{
		{
			name:    "set conditions on empty",
			initial: nil,
			newConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
			},
			wantConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
			},
		},
		{
			name: "replace existing conditions",
			initial: []Condition{
				{
					Type:    "Ready",
					Status:  "False",
					Reason:  "NotConfigured",
					Message: "Route is not configured",
				},
			},
			newConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
			},
			wantConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
			},
		},
		{
			name: "clear conditions",
			initial: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
			},
			newConditions:  nil,
			wantConditions: nil,
		},
		{
			name: "set empty slice",
			initial: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "Route is configured",
				},
			},
			newConditions:  []Condition{},
			wantConditions: []Condition{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &APIRoute{
				Status: APIRouteStatus{
					Conditions: tt.initial,
				},
			}

			route.SetConditions(tt.newConditions)
			assert.Equal(t, tt.wantConditions, route.Status.Conditions)
		})
	}
}

func TestAPIRoute_SetObservedGeneration(t *testing.T) {
	tests := []struct {
		name       string
		initial    int64
		generation int64
		want       int64
	}{
		{
			name:       "set from zero",
			initial:    0,
			generation: 1,
			want:       1,
		},
		{
			name:       "increment generation",
			initial:    1,
			generation: 2,
			want:       2,
		},
		{
			name:       "set to zero",
			initial:    5,
			generation: 0,
			want:       0,
		},
		{
			name:       "large generation",
			initial:    0,
			generation: 9999999,
			want:       9999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &APIRoute{
				Status: APIRouteStatus{
					ObservedGeneration: tt.initial,
				},
			}

			route.SetObservedGeneration(tt.generation)
			assert.Equal(t, tt.want, route.Status.ObservedGeneration)
		})
	}
}

// ============================================================================
// GRPCRoute Status Interface Tests
// ============================================================================

func TestGRPCRoute_GetConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions []Condition
		want       []Condition
	}{
		{
			name:       "nil conditions",
			conditions: nil,
			want:       nil,
		},
		{
			name:       "empty conditions",
			conditions: []Condition{},
			want:       []Condition{},
		},
		{
			name: "single condition",
			conditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "gRPC route is configured",
				},
			},
			want: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "gRPC route is configured",
				},
			},
		},
		{
			name: "multiple conditions",
			conditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "gRPC route is configured",
				},
				{
					Type:    "Accepted",
					Status:  "True",
					Reason:  "Accepted",
					Message: "gRPC route is accepted",
				},
			},
			want: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "gRPC route is configured",
				},
				{
					Type:    "Accepted",
					Status:  "True",
					Reason:  "Accepted",
					Message: "gRPC route is accepted",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &GRPCRoute{
				Status: GRPCRouteStatus{
					Conditions: tt.conditions,
				},
			}

			got := route.GetConditions()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGRPCRoute_SetConditions(t *testing.T) {
	tests := []struct {
		name           string
		initial        []Condition
		newConditions  []Condition
		wantConditions []Condition
	}{
		{
			name:    "set conditions on empty",
			initial: nil,
			newConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "gRPC route is configured",
				},
			},
			wantConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "gRPC route is configured",
				},
			},
		},
		{
			name: "replace existing conditions",
			initial: []Condition{
				{
					Type:    "Ready",
					Status:  "False",
					Reason:  "NotConfigured",
					Message: "gRPC route is not configured",
				},
			},
			newConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "gRPC route is configured",
				},
			},
			wantConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "gRPC route is configured",
				},
			},
		},
		{
			name: "clear conditions",
			initial: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Configured",
					Message: "gRPC route is configured",
				},
			},
			newConditions:  nil,
			wantConditions: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &GRPCRoute{
				Status: GRPCRouteStatus{
					Conditions: tt.initial,
				},
			}

			route.SetConditions(tt.newConditions)
			assert.Equal(t, tt.wantConditions, route.Status.Conditions)
		})
	}
}

func TestGRPCRoute_SetObservedGeneration(t *testing.T) {
	tests := []struct {
		name       string
		initial    int64
		generation int64
		want       int64
	}{
		{
			name:       "set from zero",
			initial:    0,
			generation: 1,
			want:       1,
		},
		{
			name:       "increment generation",
			initial:    1,
			generation: 2,
			want:       2,
		},
		{
			name:       "set to zero",
			initial:    5,
			generation: 0,
			want:       0,
		},
		{
			name:       "large generation",
			initial:    0,
			generation: 9999999,
			want:       9999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &GRPCRoute{
				Status: GRPCRouteStatus{
					ObservedGeneration: tt.initial,
				},
			}

			route.SetObservedGeneration(tt.generation)
			assert.Equal(t, tt.want, route.Status.ObservedGeneration)
		})
	}
}

// ============================================================================
// Backend Status Interface Tests
// ============================================================================

func TestBackend_GetConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions []Condition
		want       []Condition
	}{
		{
			name:       "nil conditions",
			conditions: nil,
			want:       nil,
		},
		{
			name:       "empty conditions",
			conditions: []Condition{},
			want:       []Condition{},
		},
		{
			name: "single condition",
			conditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "Backend is healthy",
				},
			},
			want: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "Backend is healthy",
				},
			},
		},
		{
			name: "multiple conditions",
			conditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "Backend is healthy",
				},
				{
					Type:    "Healthy",
					Status:  "True",
					Reason:  "AllHostsHealthy",
					Message: "All hosts are healthy",
				},
			},
			want: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "Backend is healthy",
				},
				{
					Type:    "Healthy",
					Status:  "True",
					Reason:  "AllHostsHealthy",
					Message: "All hosts are healthy",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &Backend{
				Status: BackendStatus{
					Conditions: tt.conditions,
				},
			}

			got := backend.GetConditions()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBackend_SetConditions(t *testing.T) {
	tests := []struct {
		name           string
		initial        []Condition
		newConditions  []Condition
		wantConditions []Condition
	}{
		{
			name:    "set conditions on empty",
			initial: nil,
			newConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "Backend is healthy",
				},
			},
			wantConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "Backend is healthy",
				},
			},
		},
		{
			name: "replace existing conditions",
			initial: []Condition{
				{
					Type:    "Ready",
					Status:  "False",
					Reason:  "Unhealthy",
					Message: "Backend is unhealthy",
				},
			},
			newConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "Backend is healthy",
				},
			},
			wantConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "Backend is healthy",
				},
			},
		},
		{
			name: "clear conditions",
			initial: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "Backend is healthy",
				},
			},
			newConditions:  nil,
			wantConditions: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &Backend{
				Status: BackendStatus{
					Conditions: tt.initial,
				},
			}

			backend.SetConditions(tt.newConditions)
			assert.Equal(t, tt.wantConditions, backend.Status.Conditions)
		})
	}
}

func TestBackend_SetObservedGeneration(t *testing.T) {
	tests := []struct {
		name       string
		initial    int64
		generation int64
		want       int64
	}{
		{
			name:       "set from zero",
			initial:    0,
			generation: 1,
			want:       1,
		},
		{
			name:       "increment generation",
			initial:    1,
			generation: 2,
			want:       2,
		},
		{
			name:       "set to zero",
			initial:    5,
			generation: 0,
			want:       0,
		},
		{
			name:       "large generation",
			initial:    0,
			generation: 9999999,
			want:       9999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &Backend{
				Status: BackendStatus{
					ObservedGeneration: tt.initial,
				},
			}

			backend.SetObservedGeneration(tt.generation)
			assert.Equal(t, tt.want, backend.Status.ObservedGeneration)
		})
	}
}

func TestBackend_SetHealthInfo(t *testing.T) {
	now := metav1.Now()
	pastTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))

	tests := []struct {
		name             string
		totalHosts       int
		healthyHosts     int
		lastHealthCheck  *metav1.Time
		wantTotalHosts   int
		wantHealthyHosts int
		wantHealthCheck  *metav1.Time
	}{
		{
			name:             "set all healthy",
			totalHosts:       3,
			healthyHosts:     3,
			lastHealthCheck:  &now,
			wantTotalHosts:   3,
			wantHealthyHosts: 3,
			wantHealthCheck:  &now,
		},
		{
			name:             "set partial healthy",
			totalHosts:       5,
			healthyHosts:     2,
			lastHealthCheck:  &pastTime,
			wantTotalHosts:   5,
			wantHealthyHosts: 2,
			wantHealthCheck:  &pastTime,
		},
		{
			name:             "set none healthy",
			totalHosts:       3,
			healthyHosts:     0,
			lastHealthCheck:  &now,
			wantTotalHosts:   3,
			wantHealthyHosts: 0,
			wantHealthCheck:  &now,
		},
		{
			name:             "nil health check time",
			totalHosts:       2,
			healthyHosts:     1,
			lastHealthCheck:  nil,
			wantTotalHosts:   2,
			wantHealthyHosts: 1,
			wantHealthCheck:  nil,
		},
		{
			name:             "zero hosts",
			totalHosts:       0,
			healthyHosts:     0,
			lastHealthCheck:  nil,
			wantTotalHosts:   0,
			wantHealthyHosts: 0,
			wantHealthCheck:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &Backend{}

			backend.SetHealthInfo(tt.totalHosts, tt.healthyHosts, tt.lastHealthCheck)

			assert.Equal(t, tt.wantTotalHosts, backend.Status.TotalHosts)
			assert.Equal(t, tt.wantHealthyHosts, backend.Status.HealthyHosts)
			assert.Equal(t, tt.wantHealthCheck, backend.Status.LastHealthCheck)
		})
	}
}

// ============================================================================
// GRPCBackend Status Interface Tests
// ============================================================================

func TestGRPCBackend_GetConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions []Condition
		want       []Condition
	}{
		{
			name:       "nil conditions",
			conditions: nil,
			want:       nil,
		},
		{
			name:       "empty conditions",
			conditions: []Condition{},
			want:       []Condition{},
		},
		{
			name: "single condition",
			conditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "gRPC backend is healthy",
				},
			},
			want: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "gRPC backend is healthy",
				},
			},
		},
		{
			name: "multiple conditions",
			conditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "gRPC backend is healthy",
				},
				{
					Type:    "Healthy",
					Status:  "True",
					Reason:  "AllHostsHealthy",
					Message: "All gRPC hosts are healthy",
				},
			},
			want: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "gRPC backend is healthy",
				},
				{
					Type:    "Healthy",
					Status:  "True",
					Reason:  "AllHostsHealthy",
					Message: "All gRPC hosts are healthy",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &GRPCBackend{
				Status: GRPCBackendStatus{
					Conditions: tt.conditions,
				},
			}

			got := backend.GetConditions()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGRPCBackend_SetConditions(t *testing.T) {
	tests := []struct {
		name           string
		initial        []Condition
		newConditions  []Condition
		wantConditions []Condition
	}{
		{
			name:    "set conditions on empty",
			initial: nil,
			newConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "gRPC backend is healthy",
				},
			},
			wantConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "gRPC backend is healthy",
				},
			},
		},
		{
			name: "replace existing conditions",
			initial: []Condition{
				{
					Type:    "Ready",
					Status:  "False",
					Reason:  "Unhealthy",
					Message: "gRPC backend is unhealthy",
				},
			},
			newConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "gRPC backend is healthy",
				},
			},
			wantConditions: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "gRPC backend is healthy",
				},
			},
		},
		{
			name: "clear conditions",
			initial: []Condition{
				{
					Type:    "Ready",
					Status:  "True",
					Reason:  "Healthy",
					Message: "gRPC backend is healthy",
				},
			},
			newConditions:  nil,
			wantConditions: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &GRPCBackend{
				Status: GRPCBackendStatus{
					Conditions: tt.initial,
				},
			}

			backend.SetConditions(tt.newConditions)
			assert.Equal(t, tt.wantConditions, backend.Status.Conditions)
		})
	}
}

func TestGRPCBackend_SetObservedGeneration(t *testing.T) {
	tests := []struct {
		name       string
		initial    int64
		generation int64
		want       int64
	}{
		{
			name:       "set from zero",
			initial:    0,
			generation: 1,
			want:       1,
		},
		{
			name:       "increment generation",
			initial:    1,
			generation: 2,
			want:       2,
		},
		{
			name:       "set to zero",
			initial:    5,
			generation: 0,
			want:       0,
		},
		{
			name:       "large generation",
			initial:    0,
			generation: 9999999,
			want:       9999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &GRPCBackend{
				Status: GRPCBackendStatus{
					ObservedGeneration: tt.initial,
				},
			}

			backend.SetObservedGeneration(tt.generation)
			assert.Equal(t, tt.want, backend.Status.ObservedGeneration)
		})
	}
}

func TestGRPCBackend_SetHealthInfo(t *testing.T) {
	now := metav1.Now()
	pastTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))

	tests := []struct {
		name             string
		totalHosts       int
		healthyHosts     int
		lastHealthCheck  *metav1.Time
		wantTotalHosts   int
		wantHealthyHosts int
		wantHealthCheck  *metav1.Time
	}{
		{
			name:             "set all healthy",
			totalHosts:       3,
			healthyHosts:     3,
			lastHealthCheck:  &now,
			wantTotalHosts:   3,
			wantHealthyHosts: 3,
			wantHealthCheck:  &now,
		},
		{
			name:             "set partial healthy",
			totalHosts:       5,
			healthyHosts:     2,
			lastHealthCheck:  &pastTime,
			wantTotalHosts:   5,
			wantHealthyHosts: 2,
			wantHealthCheck:  &pastTime,
		},
		{
			name:             "set none healthy",
			totalHosts:       3,
			healthyHosts:     0,
			lastHealthCheck:  &now,
			wantTotalHosts:   3,
			wantHealthyHosts: 0,
			wantHealthCheck:  &now,
		},
		{
			name:             "nil health check time",
			totalHosts:       2,
			healthyHosts:     1,
			lastHealthCheck:  nil,
			wantTotalHosts:   2,
			wantHealthyHosts: 1,
			wantHealthCheck:  nil,
		},
		{
			name:             "zero hosts",
			totalHosts:       0,
			healthyHosts:     0,
			lastHealthCheck:  nil,
			wantTotalHosts:   0,
			wantHealthyHosts: 0,
			wantHealthCheck:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &GRPCBackend{}

			backend.SetHealthInfo(tt.totalHosts, tt.healthyHosts, tt.lastHealthCheck)

			assert.Equal(t, tt.wantTotalHosts, backend.Status.TotalHosts)
			assert.Equal(t, tt.wantHealthyHosts, backend.Status.HealthyHosts)
			assert.Equal(t, tt.wantHealthCheck, backend.Status.LastHealthCheck)
		})
	}
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

func TestAPIRoute_ConditionsRoundTrip(t *testing.T) {
	// Test that setting and getting conditions preserves data
	route := &APIRoute{}

	conditions := []Condition{
		{
			Type:               "Ready",
			Status:             "True",
			Reason:             "Configured",
			Message:            "Route is configured",
			LastTransitionTime: metav1.Now(),
		},
	}

	route.SetConditions(conditions)
	got := route.GetConditions()

	assert.Equal(t, conditions, got)
}

func TestGRPCRoute_ConditionsRoundTrip(t *testing.T) {
	// Test that setting and getting conditions preserves data
	route := &GRPCRoute{}

	conditions := []Condition{
		{
			Type:               "Ready",
			Status:             "True",
			Reason:             "Configured",
			Message:            "gRPC route is configured",
			LastTransitionTime: metav1.Now(),
		},
	}

	route.SetConditions(conditions)
	got := route.GetConditions()

	assert.Equal(t, conditions, got)
}

func TestBackend_ConditionsRoundTrip(t *testing.T) {
	// Test that setting and getting conditions preserves data
	backend := &Backend{}

	conditions := []Condition{
		{
			Type:               "Ready",
			Status:             "True",
			Reason:             "Healthy",
			Message:            "Backend is healthy",
			LastTransitionTime: metav1.Now(),
		},
	}

	backend.SetConditions(conditions)
	got := backend.GetConditions()

	assert.Equal(t, conditions, got)
}

func TestGRPCBackend_ConditionsRoundTrip(t *testing.T) {
	// Test that setting and getting conditions preserves data
	backend := &GRPCBackend{}

	conditions := []Condition{
		{
			Type:               "Ready",
			Status:             "True",
			Reason:             "Healthy",
			Message:            "gRPC backend is healthy",
			LastTransitionTime: metav1.Now(),
		},
	}

	backend.SetConditions(conditions)
	got := backend.GetConditions()

	assert.Equal(t, conditions, got)
}

func TestBackend_SetHealthInfo_UpdateExisting(t *testing.T) {
	// Test updating health info multiple times
	backend := &Backend{}
	now := metav1.Now()

	// First update
	backend.SetHealthInfo(3, 3, &now)
	assert.Equal(t, 3, backend.Status.TotalHosts)
	assert.Equal(t, 3, backend.Status.HealthyHosts)

	// Second update - some hosts become unhealthy
	later := metav1.NewTime(time.Now().Add(1 * time.Minute))
	backend.SetHealthInfo(3, 1, &later)
	assert.Equal(t, 3, backend.Status.TotalHosts)
	assert.Equal(t, 1, backend.Status.HealthyHosts)
	assert.Equal(t, &later, backend.Status.LastHealthCheck)
}

func TestGRPCBackend_SetHealthInfo_UpdateExisting(t *testing.T) {
	// Test updating health info multiple times
	backend := &GRPCBackend{}
	now := metav1.Now()

	// First update
	backend.SetHealthInfo(3, 3, &now)
	assert.Equal(t, 3, backend.Status.TotalHosts)
	assert.Equal(t, 3, backend.Status.HealthyHosts)

	// Second update - some hosts become unhealthy
	later := metav1.NewTime(time.Now().Add(1 * time.Minute))
	backend.SetHealthInfo(3, 1, &later)
	assert.Equal(t, 3, backend.Status.TotalHosts)
	assert.Equal(t, 1, backend.Status.HealthyHosts)
	assert.Equal(t, &later, backend.Status.LastHealthCheck)
}
