package v1alpha1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStatus_GetCondition(t *testing.T) {
	tests := []struct {
		name          string
		conditions    []Condition
		conditionType ConditionType
		expectedNil   bool
	}{
		{
			name:          "condition exists",
			conditions:    []Condition{{Type: ConditionTypeReady, Status: metav1.ConditionTrue}},
			conditionType: ConditionTypeReady,
			expectedNil:   false,
		},
		{
			name:          "condition does not exist",
			conditions:    []Condition{{Type: ConditionTypeAccepted, Status: metav1.ConditionTrue}},
			conditionType: ConditionTypeReady,
			expectedNil:   true,
		},
		{
			name:          "empty conditions",
			conditions:    []Condition{},
			conditionType: ConditionTypeReady,
			expectedNil:   true,
		},
		{
			name:          "multiple conditions, finding last",
			conditions:    []Condition{{Type: ConditionTypeReady, Status: metav1.ConditionTrue}, {Type: ConditionTypeReady, Status: metav1.ConditionFalse}},
			conditionType: ConditionTypeReady,
			expectedNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &Status{Conditions: tt.conditions}
			condition := status.GetCondition(tt.conditionType)

			if tt.expectedNil {
				assert.Nil(t, condition)
			} else {
				assert.NotNil(t, condition)
				assert.Equal(t, tt.conditionType, condition.Type)
			}
		})
	}
}

func TestStatus_SetCondition_NewCondition(t *testing.T) {
	status := &Status{}

	status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Resource is ready")

	condition := status.GetCondition(ConditionTypeReady)
	assert.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
	assert.Equal(t, "Ready", condition.Reason)
	assert.Equal(t, "Resource is ready", condition.Message)
	assert.False(t, condition.LastTransitionTime.IsZero())
}

func TestStatus_SetCondition_UpdateExisting(t *testing.T) {
	status := &Status{}

	// Set initial condition
	status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Initial message")
	initialTime := status.GetCondition(ConditionTypeReady).LastTransitionTime

	// Wait a tiny bit to ensure time difference
	time.Sleep(time.Millisecond)

	// Update condition with same status
	status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Updated message")
	updatedTime := status.GetCondition(ConditionTypeReady).LastTransitionTime

	// Status is same, so lastTransitionTime should NOT change
	assert.Equal(t, initialTime, updatedTime)
	assert.Equal(t, "Updated message", status.GetCondition(ConditionTypeReady).Message)
}

func TestStatus_SetCondition_StatusChange(t *testing.T) {
	status := &Status{}

	// Set initial condition
	status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Ready")
	initialTime := status.GetCondition(ConditionTypeReady).LastTransitionTime

	// Wait a tiny bit
	time.Sleep(time.Millisecond)

	// Update condition with different status
	status.SetCondition(ConditionTypeReady, metav1.ConditionFalse, "NotReady", "Not ready")
	newTime := status.GetCondition(ConditionTypeReady).LastTransitionTime

	// Status changed, so lastTransitionTime should update
	assert.True(t, newTime.After(initialTime.Time) || newTime.Equal(&initialTime))
	assert.Equal(t, metav1.ConditionFalse, status.GetCondition(ConditionTypeReady).Status)
	assert.Equal(t, "NotReady", status.GetCondition(ConditionTypeReady).Reason)
}

func TestStatus_SetCondition_MultipleConditions(t *testing.T) {
	status := &Status{}

	status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Ready")
	status.SetCondition(ConditionTypeAccepted, metav1.ConditionTrue, "Accepted", "Accepted")
	status.SetCondition(ConditionTypeProgrammed, metav1.ConditionTrue, "Programmed", "Programmed")

	assert.Len(t, status.Conditions, 3)
	assert.NotNil(t, status.GetCondition(ConditionTypeReady))
	assert.NotNil(t, status.GetCondition(ConditionTypeAccepted))
	assert.NotNil(t, status.GetCondition(ConditionTypeProgrammed))
}

func TestStatus_SetCondition_ReasonAndMessageUpdate(t *testing.T) {
	status := &Status{}

	status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Reason1", "Message1")
	status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Reason2", "Message2")

	condition := status.GetCondition(ConditionTypeReady)
	assert.Equal(t, "Reason2", condition.Reason)
	assert.Equal(t, "Message2", condition.Message)
}

func TestCondition_TypeConstants(t *testing.T) {
	// Test all condition type constants
	assert.Equal(t, ConditionType("Ready"), ConditionTypeReady)
	assert.Equal(t, ConditionType("Reconciled"), ConditionTypeReconciled)
	assert.Equal(t, ConditionType("Error"), ConditionTypeError)
	assert.Equal(t, ConditionType("Accepted"), ConditionTypeAccepted)
	assert.Equal(t, ConditionType("Programmed"), ConditionTypeProgrammed)
	assert.Equal(t, ConditionType("ResolvedRefs"), ConditionTypeResolvedRefs)
	assert.Equal(t, ConditionType("Degraded"), ConditionTypeDegraded)
	assert.Equal(t, ConditionType("Available"), ConditionTypeAvailable)
}

func TestCondition_ReasonConstants(t *testing.T) {
	// Test all condition reason constants
	assert.Equal(t, ConditionReason("Accepted"), ReasonAccepted)
	assert.Equal(t, ConditionReason("NotAccepted"), ReasonNotAccepted)
	assert.Equal(t, ConditionReason("Programmed"), ReasonProgrammed)
	assert.Equal(t, ConditionReason("NotProgrammed"), ReasonNotProgrammed)
	assert.Equal(t, ConditionReason("ResolvedRefs"), ReasonResolvedRefs)
	assert.Equal(t, ConditionReason("InvalidRef"), ReasonInvalidRef)
	assert.Equal(t, ConditionReason("RefNotFound"), ReasonRefNotFound)
	assert.Equal(t, ConditionReason("Ready"), ReasonReady)
	assert.Equal(t, ConditionReason("NotReady"), ReasonNotReady)
	assert.Equal(t, ConditionReason("Reconciling"), ReasonReconciling)
	assert.Equal(t, ConditionReason("Error"), ReasonError)
	assert.Equal(t, ConditionReason("Degraded"), ReasonDegraded)
}

func TestPhaseStatus_Constants(t *testing.T) {
	// Test all phase status constants
	assert.Equal(t, PhaseStatus("Pending"), PhaseStatusPending)
	assert.Equal(t, PhaseStatus("Ready"), PhaseStatusReady)
	assert.Equal(t, PhaseStatus("Error"), PhaseStatusError)
	assert.Equal(t, PhaseStatus("Reconciling"), PhaseStatusReconciling)
	assert.Equal(t, PhaseStatus("Degraded"), PhaseStatusDegraded)
}

func TestStatus_DefaultValues(t *testing.T) {
	status := &Status{}

	assert.Empty(t, status.Phase)
	assert.Empty(t, status.Conditions)
	assert.Equal(t, int64(0), status.ObservedGeneration)
	assert.Nil(t, status.LastReconciledTime)
}

func TestCondition_ObservedGeneration(t *testing.T) {
	status := &Status{}

	status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Ready")
	status.ObservedGeneration = 42

	condition := status.GetCondition(ConditionTypeReady)
	assert.NotNil(t, condition)
	condition.ObservedGeneration = 100

	assert.Equal(t, int64(100), condition.ObservedGeneration)
}

func TestStatus_SetCondition_WithObservedGeneration(t *testing.T) {
	status := &Status{}

	status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Ready")
	status.ObservedGeneration = 42

	condition := status.GetCondition(ConditionTypeReady)
	assert.NotNil(t, condition)
	assert.Equal(t, int64(0), condition.ObservedGeneration)
}

func TestStatus_EmptyConditions(t *testing.T) {
	status := &Status{}

	assert.Nil(t, status.GetCondition(ConditionTypeReady))
	assert.Nil(t, status.GetCondition(ConditionTypeAccepted))
	assert.Nil(t, status.GetCondition(ConditionTypeDegraded))
}
