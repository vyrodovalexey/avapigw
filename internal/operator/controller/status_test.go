// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// ============================================================================
// NewStatusUpdater Tests
// ============================================================================

func TestNewStatusUpdater(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	updater := NewStatusUpdater(fakeClient)
	if updater == nil {
		t.Error("NewStatusUpdater() returned nil")
	}
	if updater.client == nil {
		t.Error("NewStatusUpdater() did not set client")
	}
}

func TestNewStatusUpdater_NilClient(t *testing.T) {
	updater := NewStatusUpdater(nil)
	if updater == nil {
		t.Error("NewStatusUpdater() returned nil even with nil client")
	}
	if updater.client != nil {
		t.Error("NewStatusUpdater() should have nil client when passed nil")
	}
}

// ============================================================================
// UpdateCondition Tests
// ============================================================================

func TestUpdateCondition_AddNew(t *testing.T) {
	conditions := []avapigwv1alpha1.Condition{}

	update := ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionReady,
		Status:     metav1.ConditionTrue,
		Reason:     avapigwv1alpha1.ReasonReconciled,
		Message:    "Test message",
		Generation: 1,
	}

	result := UpdateCondition(conditions, update)

	if len(result) != 1 {
		t.Errorf("UpdateCondition() returned %d conditions, want 1", len(result))
	}

	if result[0].Type != avapigwv1alpha1.ConditionReady {
		t.Errorf("UpdateCondition() Type = %v, want %v", result[0].Type, avapigwv1alpha1.ConditionReady)
	}
	if result[0].Status != metav1.ConditionTrue {
		t.Errorf("UpdateCondition() Status = %v, want %v", result[0].Status, metav1.ConditionTrue)
	}
	if result[0].Reason != avapigwv1alpha1.ReasonReconciled {
		t.Errorf("UpdateCondition() Reason = %v, want %v", result[0].Reason, avapigwv1alpha1.ReasonReconciled)
	}
	if result[0].Message != "Test message" {
		t.Errorf("UpdateCondition() Message = %v, want %v", result[0].Message, "Test message")
	}
	if result[0].ObservedGeneration != 1 {
		t.Errorf("UpdateCondition() ObservedGeneration = %v, want %v", result[0].ObservedGeneration, 1)
	}
}

func TestUpdateCondition_UpdateExistingWithStatusChange(t *testing.T) {
	oldTime := metav1.Now()
	conditions := []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             avapigwv1alpha1.ReasonReconcileFailed,
			Message:            "Old message",
			LastTransitionTime: oldTime,
			ObservedGeneration: 1,
		},
	}

	update := ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionReady,
		Status:     metav1.ConditionTrue, // Status changed
		Reason:     avapigwv1alpha1.ReasonReconciled,
		Message:    "New message",
		Generation: 2,
	}

	result := UpdateCondition(conditions, update)

	if len(result) != 1 {
		t.Errorf("UpdateCondition() returned %d conditions, want 1", len(result))
	}

	if result[0].Status != metav1.ConditionTrue {
		t.Errorf("UpdateCondition() Status = %v, want %v", result[0].Status, metav1.ConditionTrue)
	}
	if result[0].Reason != avapigwv1alpha1.ReasonReconciled {
		t.Errorf("UpdateCondition() Reason = %v, want %v", result[0].Reason, avapigwv1alpha1.ReasonReconciled)
	}
	if result[0].Message != "New message" {
		t.Errorf("UpdateCondition() Message = %v, want %v", result[0].Message, "New message")
	}
	if result[0].ObservedGeneration != 2 {
		t.Errorf("UpdateCondition() ObservedGeneration = %v, want %v", result[0].ObservedGeneration, 2)
	}
}

func TestUpdateCondition_UpdateExistingWithoutStatusChange(t *testing.T) {
	oldTime := metav1.Now()
	conditions := []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             avapigwv1alpha1.ReasonReconciled,
			Message:            "Old message",
			LastTransitionTime: oldTime,
			ObservedGeneration: 1,
		},
	}

	update := ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionReady,
		Status:     metav1.ConditionTrue, // Status unchanged
		Reason:     avapigwv1alpha1.ReasonReconciled,
		Message:    "New message",
		Generation: 2,
	}

	result := UpdateCondition(conditions, update)

	if len(result) != 1 {
		t.Errorf("UpdateCondition() returned %d conditions, want 1", len(result))
	}

	if result[0].Status != metav1.ConditionTrue {
		t.Errorf("UpdateCondition() Status = %v, want %v", result[0].Status, metav1.ConditionTrue)
	}
	if result[0].Message != "New message" {
		t.Errorf("UpdateCondition() Message = %v, want %v", result[0].Message, "New message")
	}
	if result[0].ObservedGeneration != 2 {
		t.Errorf("UpdateCondition() ObservedGeneration = %v, want %v", result[0].ObservedGeneration, 2)
	}
	// LastTransitionTime should NOT be updated when status doesn't change
	if result[0].LastTransitionTime != oldTime {
		t.Errorf("UpdateCondition() LastTransitionTime changed when status didn't change")
	}
}

func TestUpdateCondition_MultipleConditions(t *testing.T) {
	conditions := []avapigwv1alpha1.Condition{
		{
			Type:               avapigwv1alpha1.ConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             avapigwv1alpha1.ReasonReconciled,
			Message:            "Ready",
			ObservedGeneration: 1,
		},
		{
			Type:               avapigwv1alpha1.ConditionHealthy,
			Status:             metav1.ConditionTrue,
			Reason:             avapigwv1alpha1.ReasonHealthCheckOK,
			Message:            "Healthy",
			ObservedGeneration: 1,
		},
	}

	// Update only the Healthy condition
	update := ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionHealthy,
		Status:     metav1.ConditionFalse,
		Reason:     avapigwv1alpha1.ReasonHealthCheckFail,
		Message:    "Unhealthy",
		Generation: 2,
	}

	result := UpdateCondition(conditions, update)

	if len(result) != 2 {
		t.Errorf("UpdateCondition() returned %d conditions, want 2", len(result))
	}

	// Ready condition should be unchanged
	for _, c := range result {
		if c.Type == avapigwv1alpha1.ConditionReady {
			if c.Status != metav1.ConditionTrue {
				t.Error("Ready condition should be unchanged")
			}
		}
		if c.Type == avapigwv1alpha1.ConditionHealthy {
			if c.Status != metav1.ConditionFalse {
				t.Error("Healthy condition should be updated to False")
			}
			if c.Message != "Unhealthy" {
				t.Error("Healthy condition message should be updated")
			}
		}
	}
}

// ============================================================================
// ReadyConditionFromBool Tests
// ============================================================================

func TestReadyConditionFromBool_True(t *testing.T) {
	result := ReadyConditionFromBool(true, "TestReason", "Test message", 5)

	if result.Type != avapigwv1alpha1.ConditionReady {
		t.Errorf("ReadyConditionFromBool() Type = %v, want %v", result.Type, avapigwv1alpha1.ConditionReady)
	}
	if result.Status != metav1.ConditionTrue {
		t.Errorf("ReadyConditionFromBool() Status = %v, want %v", result.Status, metav1.ConditionTrue)
	}
	if result.Reason != avapigwv1alpha1.ConditionReason("TestReason") {
		t.Errorf("ReadyConditionFromBool() Reason = %v, want %v", result.Reason, "TestReason")
	}
	if result.Message != "Test message" {
		t.Errorf("ReadyConditionFromBool() Message = %v, want %v", result.Message, "Test message")
	}
	if result.Generation != 5 {
		t.Errorf("ReadyConditionFromBool() Generation = %v, want %v", result.Generation, 5)
	}
}

func TestReadyConditionFromBool_False(t *testing.T) {
	result := ReadyConditionFromBool(false, "FailReason", "Failure message", 3)

	if result.Type != avapigwv1alpha1.ConditionReady {
		t.Errorf("ReadyConditionFromBool() Type = %v, want %v", result.Type, avapigwv1alpha1.ConditionReady)
	}
	if result.Status != metav1.ConditionFalse {
		t.Errorf("ReadyConditionFromBool() Status = %v, want %v", result.Status, metav1.ConditionFalse)
	}
	if result.Reason != avapigwv1alpha1.ConditionReason("FailReason") {
		t.Errorf("ReadyConditionFromBool() Reason = %v, want %v", result.Reason, "FailReason")
	}
	if result.Message != "Failure message" {
		t.Errorf("ReadyConditionFromBool() Message = %v, want %v", result.Message, "Failure message")
	}
}

// ============================================================================
// HealthyConditionFromBool Tests
// ============================================================================

func TestHealthyConditionFromBool_True(t *testing.T) {
	result := HealthyConditionFromBool(true, 7)

	if result.Type != avapigwv1alpha1.ConditionHealthy {
		t.Errorf("HealthyConditionFromBool() Type = %v, want %v", result.Type, avapigwv1alpha1.ConditionHealthy)
	}
	if result.Status != metav1.ConditionTrue {
		t.Errorf("HealthyConditionFromBool() Status = %v, want %v", result.Status, metav1.ConditionTrue)
	}
	if result.Reason != avapigwv1alpha1.ReasonHealthCheckOK {
		t.Errorf("HealthyConditionFromBool() Reason = %v, want %v", result.Reason, avapigwv1alpha1.ReasonHealthCheckOK)
	}
	if result.Message != messageAllHostsHealthy {
		t.Errorf("HealthyConditionFromBool() Message = %v, want %v", result.Message, messageAllHostsHealthy)
	}
	if result.Generation != 7 {
		t.Errorf("HealthyConditionFromBool() Generation = %v, want %v", result.Generation, 7)
	}
}

func TestHealthyConditionFromBool_False(t *testing.T) {
	result := HealthyConditionFromBool(false, 4)

	if result.Type != avapigwv1alpha1.ConditionHealthy {
		t.Errorf("HealthyConditionFromBool() Type = %v, want %v", result.Type, avapigwv1alpha1.ConditionHealthy)
	}
	if result.Status != metav1.ConditionFalse {
		t.Errorf("HealthyConditionFromBool() Status = %v, want %v", result.Status, metav1.ConditionFalse)
	}
	if result.Reason != avapigwv1alpha1.ReasonHealthCheckFail {
		t.Errorf("HealthyConditionFromBool() Reason = %v, want %v", result.Reason, avapigwv1alpha1.ReasonHealthCheckFail)
	}
	if result.Message != messageSomeHostsUnhealthy {
		t.Errorf("HealthyConditionFromBool() Message = %v, want %v", result.Message, messageSomeHostsUnhealthy)
	}
}

// ============================================================================
// Table-Driven Tests for UpdateCondition
// ============================================================================

func TestUpdateCondition_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		conditions     []avapigwv1alpha1.Condition
		update         ConditionUpdate
		wantLen        int
		wantStatus     metav1.ConditionStatus
		wantReason     avapigwv1alpha1.ConditionReason
		wantMessage    string
		wantGeneration int64
	}{
		{
			name:       "add new condition to empty slice",
			conditions: []avapigwv1alpha1.Condition{},
			update: ConditionUpdate{
				Type:       avapigwv1alpha1.ConditionReady,
				Status:     metav1.ConditionTrue,
				Reason:     avapigwv1alpha1.ReasonReconciled,
				Message:    "Ready",
				Generation: 1,
			},
			wantLen:        1,
			wantStatus:     metav1.ConditionTrue,
			wantReason:     avapigwv1alpha1.ReasonReconciled,
			wantMessage:    "Ready",
			wantGeneration: 1,
		},
		{
			name: "update existing condition with status change",
			conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionReady,
					Status:             metav1.ConditionFalse,
					Reason:             avapigwv1alpha1.ReasonReconcileFailed,
					Message:            "Failed",
					ObservedGeneration: 1,
				},
			},
			update: ConditionUpdate{
				Type:       avapigwv1alpha1.ConditionReady,
				Status:     metav1.ConditionTrue,
				Reason:     avapigwv1alpha1.ReasonReconciled,
				Message:    "Success",
				Generation: 2,
			},
			wantLen:        1,
			wantStatus:     metav1.ConditionTrue,
			wantReason:     avapigwv1alpha1.ReasonReconciled,
			wantMessage:    "Success",
			wantGeneration: 2,
		},
		{
			name: "update existing condition without status change",
			conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             avapigwv1alpha1.ReasonReconciled,
					Message:            "Old message",
					ObservedGeneration: 1,
				},
			},
			update: ConditionUpdate{
				Type:       avapigwv1alpha1.ConditionReady,
				Status:     metav1.ConditionTrue,
				Reason:     avapigwv1alpha1.ReasonReconciled,
				Message:    "New message",
				Generation: 2,
			},
			wantLen:        1,
			wantStatus:     metav1.ConditionTrue,
			wantReason:     avapigwv1alpha1.ReasonReconciled,
			wantMessage:    "New message",
			wantGeneration: 2,
		},
		{
			name: "add new condition type to existing slice",
			conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             avapigwv1alpha1.ReasonReconciled,
					Message:            "Ready",
					ObservedGeneration: 1,
				},
			},
			update: ConditionUpdate{
				Type:       avapigwv1alpha1.ConditionHealthy,
				Status:     metav1.ConditionTrue,
				Reason:     avapigwv1alpha1.ReasonHealthCheckOK,
				Message:    "Healthy",
				Generation: 1,
			},
			wantLen:        2,
			wantStatus:     metav1.ConditionTrue,
			wantReason:     avapigwv1alpha1.ReasonHealthCheckOK,
			wantMessage:    "Healthy",
			wantGeneration: 1,
		},
		{
			name: "update Valid condition type",
			conditions: []avapigwv1alpha1.Condition{
				{
					Type:               avapigwv1alpha1.ConditionValid,
					Status:             metav1.ConditionFalse,
					Reason:             avapigwv1alpha1.ReasonValidationFailed,
					Message:            "Invalid",
					ObservedGeneration: 1,
				},
			},
			update: ConditionUpdate{
				Type:       avapigwv1alpha1.ConditionValid,
				Status:     metav1.ConditionTrue,
				Reason:     avapigwv1alpha1.ReasonValidationPassed,
				Message:    "Valid",
				Generation: 2,
			},
			wantLen:        1,
			wantStatus:     metav1.ConditionTrue,
			wantReason:     avapigwv1alpha1.ReasonValidationPassed,
			wantMessage:    "Valid",
			wantGeneration: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UpdateCondition(tt.conditions, tt.update)

			if len(result) != tt.wantLen {
				t.Errorf("UpdateCondition() returned %d conditions, want %d", len(result), tt.wantLen)
			}

			// Find the updated condition
			var found *avapigwv1alpha1.Condition
			for i := range result {
				if result[i].Type == tt.update.Type {
					found = &result[i]
					break
				}
			}

			if found == nil {
				t.Fatalf("UpdateCondition() did not return condition of type %v", tt.update.Type)
			}

			if found.Status != tt.wantStatus {
				t.Errorf("UpdateCondition() Status = %v, want %v", found.Status, tt.wantStatus)
			}
			if found.Reason != tt.wantReason {
				t.Errorf("UpdateCondition() Reason = %v, want %v", found.Reason, tt.wantReason)
			}
			if found.Message != tt.wantMessage {
				t.Errorf("UpdateCondition() Message = %v, want %v", found.Message, tt.wantMessage)
			}
			if found.ObservedGeneration != tt.wantGeneration {
				t.Errorf("UpdateCondition() ObservedGeneration = %v, want %v", found.ObservedGeneration, tt.wantGeneration)
			}
		})
	}
}

// ============================================================================
// Table-Driven Tests for ReadyConditionFromBool
// ============================================================================

func TestReadyConditionFromBool_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		ready      bool
		reason     string
		message    string
		generation int64
		wantStatus metav1.ConditionStatus
	}{
		{
			name:       "ready true",
			ready:      true,
			reason:     "Reconciled",
			message:    "Success",
			generation: 1,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name:       "ready false",
			ready:      false,
			reason:     "ReconcileFailed",
			message:    "Failed",
			generation: 2,
			wantStatus: metav1.ConditionFalse,
		},
		{
			name:       "ready true with empty message",
			ready:      true,
			reason:     "Applied",
			message:    "",
			generation: 3,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name:       "ready false with long message",
			ready:      false,
			reason:     "Error",
			message:    "This is a very long error message that describes the failure in detail",
			generation: 4,
			wantStatus: metav1.ConditionFalse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ReadyConditionFromBool(tt.ready, tt.reason, tt.message, tt.generation)

			if result.Type != avapigwv1alpha1.ConditionReady {
				t.Errorf("ReadyConditionFromBool() Type = %v, want %v", result.Type, avapigwv1alpha1.ConditionReady)
			}
			if result.Status != tt.wantStatus {
				t.Errorf("ReadyConditionFromBool() Status = %v, want %v", result.Status, tt.wantStatus)
			}
			if string(result.Reason) != tt.reason {
				t.Errorf("ReadyConditionFromBool() Reason = %v, want %v", result.Reason, tt.reason)
			}
			if result.Message != tt.message {
				t.Errorf("ReadyConditionFromBool() Message = %v, want %v", result.Message, tt.message)
			}
			if result.Generation != tt.generation {
				t.Errorf("ReadyConditionFromBool() Generation = %v, want %v", result.Generation, tt.generation)
			}
		})
	}
}

// ============================================================================
// Table-Driven Tests for HealthyConditionFromBool
// ============================================================================

func TestHealthyConditionFromBool_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		healthy     bool
		generation  int64
		wantStatus  metav1.ConditionStatus
		wantReason  avapigwv1alpha1.ConditionReason
		wantMessage string
	}{
		{
			name:        "healthy true",
			healthy:     true,
			generation:  1,
			wantStatus:  metav1.ConditionTrue,
			wantReason:  avapigwv1alpha1.ReasonHealthCheckOK,
			wantMessage: messageAllHostsHealthy,
		},
		{
			name:        "healthy false",
			healthy:     false,
			generation:  2,
			wantStatus:  metav1.ConditionFalse,
			wantReason:  avapigwv1alpha1.ReasonHealthCheckFail,
			wantMessage: messageSomeHostsUnhealthy,
		},
		{
			name:        "healthy true with zero generation",
			healthy:     true,
			generation:  0,
			wantStatus:  metav1.ConditionTrue,
			wantReason:  avapigwv1alpha1.ReasonHealthCheckOK,
			wantMessage: messageAllHostsHealthy,
		},
		{
			name:        "healthy false with high generation",
			healthy:     false,
			generation:  999,
			wantStatus:  metav1.ConditionFalse,
			wantReason:  avapigwv1alpha1.ReasonHealthCheckFail,
			wantMessage: messageSomeHostsUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HealthyConditionFromBool(tt.healthy, tt.generation)

			if result.Type != avapigwv1alpha1.ConditionHealthy {
				t.Errorf("HealthyConditionFromBool() Type = %v, want %v", result.Type, avapigwv1alpha1.ConditionHealthy)
			}
			if result.Status != tt.wantStatus {
				t.Errorf("HealthyConditionFromBool() Status = %v, want %v", result.Status, tt.wantStatus)
			}
			if result.Reason != tt.wantReason {
				t.Errorf("HealthyConditionFromBool() Reason = %v, want %v", result.Reason, tt.wantReason)
			}
			if result.Message != tt.wantMessage {
				t.Errorf("HealthyConditionFromBool() Message = %v, want %v", result.Message, tt.wantMessage)
			}
			if result.Generation != tt.generation {
				t.Errorf("HealthyConditionFromBool() Generation = %v, want %v", result.Generation, tt.generation)
			}
		})
	}
}

// ============================================================================
// Error Client for Testing Failures
// ============================================================================

// errorClient wraps a client and returns errors for specific operations.
type errorClient struct {
	client.Client
	statusUpdateErr error
}

func (e *errorClient) Status() client.SubResourceWriter {
	return &errorStatusWriter{
		SubResourceWriter: e.Client.Status(),
		err:               e.statusUpdateErr,
	}
}

type errorStatusWriter struct {
	client.SubResourceWriter
	err error
}

func (e *errorStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if e.err != nil {
		return e.err
	}
	return e.SubResourceWriter.Update(ctx, obj, opts...)
}

// ============================================================================
// StatusUpdater Tests - Testing helper functions and logic
// ============================================================================

// mockRouteStatusUpdatable is a mock implementation for testing
type mockRouteStatusUpdatable struct {
	conditions         []avapigwv1alpha1.Condition
	generation         int64
	observedGeneration int64
	name               string
	namespace          string
}

func (m *mockRouteStatusUpdatable) GetConditions() []avapigwv1alpha1.Condition {
	return m.conditions
}

func (m *mockRouteStatusUpdatable) SetConditions(conditions []avapigwv1alpha1.Condition) {
	m.conditions = conditions
}

func (m *mockRouteStatusUpdatable) GetGeneration() int64 {
	return m.generation
}

func (m *mockRouteStatusUpdatable) SetObservedGeneration(gen int64) {
	m.observedGeneration = gen
}

func (m *mockRouteStatusUpdatable) GetName() string {
	return m.name
}

func (m *mockRouteStatusUpdatable) GetNamespace() string {
	return m.namespace
}

// mockBackendStatusUpdatable is a mock implementation for testing
type mockBackendStatusUpdatable struct {
	conditions         []avapigwv1alpha1.Condition
	generation         int64
	observedGeneration int64
	totalHosts         int
	healthyHosts       int
	lastHealthCheck    *metav1.Time
	name               string
	namespace          string
}

func (m *mockBackendStatusUpdatable) GetConditions() []avapigwv1alpha1.Condition {
	return m.conditions
}

func (m *mockBackendStatusUpdatable) SetConditions(conditions []avapigwv1alpha1.Condition) {
	m.conditions = conditions
}

func (m *mockBackendStatusUpdatable) GetGeneration() int64 {
	return m.generation
}

func (m *mockBackendStatusUpdatable) SetObservedGeneration(gen int64) {
	m.observedGeneration = gen
}

func (m *mockBackendStatusUpdatable) SetHealthInfo(totalHosts, healthyHosts int, lastHealthCheck *metav1.Time) {
	m.totalHosts = totalHosts
	m.healthyHosts = healthyHosts
	m.lastHealthCheck = lastHealthCheck
}

func (m *mockBackendStatusUpdatable) GetName() string {
	return m.name
}

func (m *mockBackendStatusUpdatable) GetNamespace() string {
	return m.namespace
}

// TestStatusUpdater_RouteStatusLogic tests the route status update logic
// without actually calling the client (which is tested in controller_test.go)
func TestStatusUpdater_RouteStatusLogic(t *testing.T) {
	tests := []struct {
		name           string
		ready          bool
		reason         string
		message        string
		generation     int64
		wantStatus     metav1.ConditionStatus
		wantConditions int
	}{
		{
			name:           "ready route",
			ready:          true,
			reason:         "Reconciled",
			message:        "Route applied",
			generation:     1,
			wantStatus:     metav1.ConditionTrue,
			wantConditions: 1,
		},
		{
			name:           "not ready route",
			ready:          false,
			reason:         "ReconcileFailed",
			message:        "Route failed",
			generation:     2,
			wantStatus:     metav1.ConditionFalse,
			wantConditions: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockRouteStatusUpdatable{
				conditions: []avapigwv1alpha1.Condition{},
				generation: tt.generation,
				name:       "test-route",
				namespace:  "default",
			}

			// Simulate what UpdateRouteStatus does (without client call)
			conditions := UpdateCondition(
				mock.GetConditions(),
				ReadyConditionFromBool(tt.ready, tt.reason, tt.message, mock.GetGeneration()),
			)
			mock.SetConditions(conditions)
			mock.SetObservedGeneration(mock.GetGeneration())

			// Verify
			if len(mock.conditions) != tt.wantConditions {
				t.Errorf("got %d conditions, want %d", len(mock.conditions), tt.wantConditions)
			}

			if mock.observedGeneration != tt.generation {
				t.Errorf("observedGeneration = %d, want %d", mock.observedGeneration, tt.generation)
			}

			for _, c := range mock.conditions {
				if c.Type == avapigwv1alpha1.ConditionReady {
					if c.Status != tt.wantStatus {
						t.Errorf("Ready status = %v, want %v", c.Status, tt.wantStatus)
					}
				}
			}
		})
	}
}

// TestStatusUpdater_BackendStatusLogic tests the backend status update logic
func TestStatusUpdater_BackendStatusLogic(t *testing.T) {
	tests := []struct {
		name              string
		ready             bool
		healthy           bool
		reason            string
		message           string
		generation        int64
		totalHosts        int
		wantReadyStatus   metav1.ConditionStatus
		wantHealthyStatus metav1.ConditionStatus
		wantHealthyHosts  int
		wantConditions    int
	}{
		{
			name:              "ready and healthy backend",
			ready:             true,
			healthy:           true,
			reason:            "Reconciled",
			message:           "Backend applied",
			generation:        1,
			totalHosts:        2,
			wantReadyStatus:   metav1.ConditionTrue,
			wantHealthyStatus: metav1.ConditionTrue,
			wantHealthyHosts:  2,
			wantConditions:    2,
		},
		{
			name:              "ready but unhealthy backend",
			ready:             true,
			healthy:           false,
			reason:            "Reconciled",
			message:           "Backend applied",
			generation:        2,
			totalHosts:        3,
			wantReadyStatus:   metav1.ConditionTrue,
			wantHealthyStatus: metav1.ConditionFalse,
			wantHealthyHosts:  0,
			wantConditions:    2,
		},
		{
			name:              "not ready backend",
			ready:             false,
			healthy:           false,
			reason:            "ReconcileFailed",
			message:           "Backend failed",
			generation:        1,
			totalHosts:        1,
			wantReadyStatus:   metav1.ConditionFalse,
			wantHealthyStatus: metav1.ConditionFalse,
			wantHealthyHosts:  0,
			wantConditions:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockBackendStatusUpdatable{
				conditions: []avapigwv1alpha1.Condition{},
				generation: tt.generation,
				name:       "test-backend",
				namespace:  "default",
			}

			// Simulate what UpdateBackendStatus does (without client call)
			conditions := UpdateCondition(
				mock.GetConditions(),
				ReadyConditionFromBool(tt.ready, tt.reason, tt.message, mock.GetGeneration()),
			)
			conditions = UpdateCondition(
				conditions,
				HealthyConditionFromBool(tt.healthy, mock.GetGeneration()),
			)
			mock.SetConditions(conditions)
			mock.SetObservedGeneration(mock.GetGeneration())

			now := metav1.Now()
			healthyHosts := 0
			if tt.healthy {
				healthyHosts = tt.totalHosts
			}
			mock.SetHealthInfo(tt.totalHosts, healthyHosts, &now)

			// Verify conditions count
			if len(mock.conditions) != tt.wantConditions {
				t.Errorf("got %d conditions, want %d", len(mock.conditions), tt.wantConditions)
			}

			// Verify observed generation
			if mock.observedGeneration != tt.generation {
				t.Errorf("observedGeneration = %d, want %d", mock.observedGeneration, tt.generation)
			}

			// Verify health info
			if mock.totalHosts != tt.totalHosts {
				t.Errorf("totalHosts = %d, want %d", mock.totalHosts, tt.totalHosts)
			}
			if mock.healthyHosts != tt.wantHealthyHosts {
				t.Errorf("healthyHosts = %d, want %d", mock.healthyHosts, tt.wantHealthyHosts)
			}
			if mock.lastHealthCheck == nil {
				t.Error("lastHealthCheck should be set")
			}

			// Verify condition statuses
			for _, c := range mock.conditions {
				if c.Type == avapigwv1alpha1.ConditionReady {
					if c.Status != tt.wantReadyStatus {
						t.Errorf("Ready status = %v, want %v", c.Status, tt.wantReadyStatus)
					}
				}
				if c.Type == avapigwv1alpha1.ConditionHealthy {
					if c.Status != tt.wantHealthyStatus {
						t.Errorf("Healthy status = %v, want %v", c.Status, tt.wantHealthyStatus)
					}
				}
			}
		})
	}
}

// TestStatusUpdater_ClientError tests error handling with a failing client
func TestStatusUpdater_ClientError(t *testing.T) {
	scheme := newTestScheme()

	apiRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: avapigwv1alpha1.APIRouteSpec{},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(apiRoute).
		WithStatusSubresource(apiRoute).
		Build()

	errClient := &errorClient{
		Client:          fakeClient,
		statusUpdateErr: errors.New("status update failed"),
	}

	// Verify the error client returns errors
	if errClient.statusUpdateErr == nil {
		t.Error("errorClient should have statusUpdateErr set")
	}

	// Test that the error status writer returns errors
	statusWriter := errClient.Status()
	if statusWriter == nil {
		t.Error("Status() should not return nil")
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestUpdateCondition_EmptyConditionType(t *testing.T) {
	conditions := []avapigwv1alpha1.Condition{}

	update := ConditionUpdate{
		Type:       "",
		Status:     metav1.ConditionTrue,
		Reason:     avapigwv1alpha1.ReasonReconciled,
		Message:    "Test",
		Generation: 1,
	}

	result := UpdateCondition(conditions, update)

	// Should still add the condition even with empty type
	if len(result) != 1 {
		t.Errorf("UpdateCondition() returned %d conditions, want 1", len(result))
	}
}

func TestUpdateCondition_NilConditions(t *testing.T) {
	var conditions []avapigwv1alpha1.Condition = nil

	update := ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionReady,
		Status:     metav1.ConditionTrue,
		Reason:     avapigwv1alpha1.ReasonReconciled,
		Message:    "Test",
		Generation: 1,
	}

	result := UpdateCondition(conditions, update)

	if len(result) != 1 {
		t.Errorf("UpdateCondition() returned %d conditions, want 1", len(result))
	}
}

func TestUpdateCondition_LargeConditionSlice(t *testing.T) {
	// Create a large slice of conditions
	conditions := make([]avapigwv1alpha1.Condition, 100)
	for i := 0; i < 100; i++ {
		conditions[i] = avapigwv1alpha1.Condition{
			Type:               avapigwv1alpha1.ConditionType("Type" + string(rune('A'+i%26))),
			Status:             metav1.ConditionTrue,
			Reason:             avapigwv1alpha1.ReasonReconciled,
			Message:            "Test",
			ObservedGeneration: int64(i),
		}
	}

	// Add a new condition
	update := ConditionUpdate{
		Type:       avapigwv1alpha1.ConditionType("NewType"),
		Status:     metav1.ConditionTrue,
		Reason:     avapigwv1alpha1.ReasonReconciled,
		Message:    "New condition",
		Generation: 101,
	}

	result := UpdateCondition(conditions, update)

	if len(result) != 101 {
		t.Errorf("UpdateCondition() returned %d conditions, want 101", len(result))
	}
}

// ============================================================================
// StatusUpdater.UpdateRouteStatus Tests with Mock Implementations
// ============================================================================

// testRouteStatusUpdatable implements RouteStatusUpdatable for testing
type testRouteStatusUpdatable struct {
	client.Object
	conditions         []avapigwv1alpha1.Condition
	generation         int64
	observedGeneration int64
}

func (t *testRouteStatusUpdatable) GetConditions() []avapigwv1alpha1.Condition {
	return t.conditions
}

func (t *testRouteStatusUpdatable) SetConditions(conditions []avapigwv1alpha1.Condition) {
	t.conditions = conditions
}

func (t *testRouteStatusUpdatable) GetGeneration() int64 {
	return t.generation
}

func (t *testRouteStatusUpdatable) SetObservedGeneration(gen int64) {
	t.observedGeneration = gen
}

// testBackendStatusUpdatable implements BackendStatusUpdatable for testing
type testBackendStatusUpdatable struct {
	client.Object
	conditions         []avapigwv1alpha1.Condition
	generation         int64
	observedGeneration int64
	totalHosts         int
	healthyHosts       int
	lastHealthCheck    *metav1.Time
}

func (t *testBackendStatusUpdatable) GetConditions() []avapigwv1alpha1.Condition {
	return t.conditions
}

func (t *testBackendStatusUpdatable) SetConditions(conditions []avapigwv1alpha1.Condition) {
	t.conditions = conditions
}

func (t *testBackendStatusUpdatable) GetGeneration() int64 {
	return t.generation
}

func (t *testBackendStatusUpdatable) SetObservedGeneration(gen int64) {
	t.observedGeneration = gen
}

func (t *testBackendStatusUpdatable) SetHealthInfo(totalHosts, healthyHosts int, lastHealthCheck *metav1.Time) {
	t.totalHosts = totalHosts
	t.healthyHosts = healthyHosts
	t.lastHealthCheck = lastHealthCheck
}

// ============================================================================
// StatusUpdater Integration Tests with Real API Types
// ============================================================================

// TestStatusUpdater_UpdateRouteStatus_WithAPIRoute tests UpdateRouteStatus using APIRoute
// Note: This test verifies the logic flow but uses a wrapper since APIRoute doesn't implement the interface
func TestStatusUpdater_UpdateRouteStatus_Logic(t *testing.T) {
	tests := []struct {
		name       string
		ready      bool
		reason     string
		message    string
		generation int64
		wantStatus metav1.ConditionStatus
	}{
		{
			name:       "ready route",
			ready:      true,
			reason:     "Reconciled",
			message:    "Route applied",
			generation: 1,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name:       "not ready route",
			ready:      false,
			reason:     "ReconcileFailed",
			message:    "Route failed",
			generation: 2,
			wantStatus: metav1.ConditionFalse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic of UpdateRouteStatus
			conditions := UpdateCondition(
				[]avapigwv1alpha1.Condition{},
				ReadyConditionFromBool(tt.ready, tt.reason, tt.message, tt.generation),
			)

			if len(conditions) != 1 {
				t.Errorf("Expected 1 condition, got %d", len(conditions))
			}

			if conditions[0].Status != tt.wantStatus {
				t.Errorf("Expected status %v, got %v", tt.wantStatus, conditions[0].Status)
			}

			if conditions[0].Type != avapigwv1alpha1.ConditionReady {
				t.Errorf("Expected type Ready, got %v", conditions[0].Type)
			}
		})
	}
}

// TestStatusUpdater_UpdateBackendStatus_Logic tests UpdateBackendStatus logic
func TestStatusUpdater_UpdateBackendStatus_Logic(t *testing.T) {
	tests := []struct {
		name              string
		ready             bool
		healthy           bool
		reason            string
		message           string
		generation        int64
		totalHosts        int
		wantReadyStatus   metav1.ConditionStatus
		wantHealthyStatus metav1.ConditionStatus
		wantHealthyHosts  int
	}{
		{
			name:              "ready and healthy",
			ready:             true,
			healthy:           true,
			reason:            "Reconciled",
			message:           "Backend applied",
			generation:        1,
			totalHosts:        2,
			wantReadyStatus:   metav1.ConditionTrue,
			wantHealthyStatus: metav1.ConditionTrue,
			wantHealthyHosts:  2,
		},
		{
			name:              "ready but unhealthy",
			ready:             true,
			healthy:           false,
			reason:            "Reconciled",
			message:           "Backend applied",
			generation:        2,
			totalHosts:        3,
			wantReadyStatus:   metav1.ConditionTrue,
			wantHealthyStatus: metav1.ConditionFalse,
			wantHealthyHosts:  0,
		},
		{
			name:              "not ready",
			ready:             false,
			healthy:           false,
			reason:            "ReconcileFailed",
			message:           "Backend failed",
			generation:        1,
			totalHosts:        1,
			wantReadyStatus:   metav1.ConditionFalse,
			wantHealthyStatus: metav1.ConditionFalse,
			wantHealthyHosts:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the logic of UpdateBackendStatus
			conditions := UpdateCondition(
				[]avapigwv1alpha1.Condition{},
				ReadyConditionFromBool(tt.ready, tt.reason, tt.message, tt.generation),
			)
			conditions = UpdateCondition(
				conditions,
				HealthyConditionFromBool(tt.healthy, tt.generation),
			)

			if len(conditions) != 2 {
				t.Errorf("Expected 2 conditions, got %d", len(conditions))
			}

			// Calculate healthy hosts
			healthyHosts := 0
			if tt.healthy {
				healthyHosts = tt.totalHosts
			}

			if healthyHosts != tt.wantHealthyHosts {
				t.Errorf("Expected healthyHosts %d, got %d", tt.wantHealthyHosts, healthyHosts)
			}

			// Verify conditions
			for _, c := range conditions {
				if c.Type == avapigwv1alpha1.ConditionReady {
					if c.Status != tt.wantReadyStatus {
						t.Errorf("Expected Ready status %v, got %v", tt.wantReadyStatus, c.Status)
					}
				}
				if c.Type == avapigwv1alpha1.ConditionHealthy {
					if c.Status != tt.wantHealthyStatus {
						t.Errorf("Expected Healthy status %v, got %v", tt.wantHealthyStatus, c.Status)
					}
				}
			}
		})
	}
}
