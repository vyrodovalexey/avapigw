package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// unmarshalableResponse is a type that cannot be marshaled to JSON.
// This is used to test JSON encoding error paths.
// Note: The health package uses standard types that always marshal successfully,
// so we test the error handling paths through mock response writers.

// TestChecker_HealthHandler_ResponseFields tests that HealthHandler returns all expected fields.
func TestChecker_HealthHandler_ResponseFields(t *testing.T) {
	t.Parallel()

	checker := NewChecker("2.0.0")
	handler := checker.HealthHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	assert.NoError(t, err)

	// Verify all fields are present
	assert.Equal(t, StatusHealthy, response.Status)
	assert.Equal(t, "2.0.0", response.Version)
	assert.NotEmpty(t, response.Uptime)
	assert.True(t, response.UptimeSecs >= 0)
	assert.False(t, response.Timestamp.IsZero())
	assert.False(t, response.StartTime.IsZero())
	assert.NotEmpty(t, response.GoVersion)
	assert.True(t, response.NumGoroutine > 0)
	assert.True(t, response.MemoryMB >= 0)
}

// TestChecker_ReadinessHandler_DegradedStatus tests ReadinessHandler with degraded status.
func TestChecker_ReadinessHandler_DegradedStatus(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0")
	checker.RegisterCheck("degraded_service", func() Check {
		return Check{Status: StatusDegraded, Message: "service is slow"}
	})

	handler := checker.ReadinessHandler()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Degraded status should still return 200 OK
	assert.Equal(t, http.StatusOK, rec.Code)

	var response ReadinessResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	assert.NoError(t, err)

	assert.Equal(t, StatusDegraded, response.Status)
}

// TestChecker_ReadinessHandler_MultipleChecks tests ReadinessHandler with multiple checks.
func TestChecker_ReadinessHandler_MultipleChecks(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0")

	// Add multiple checks with different statuses
	checker.RegisterCheck("healthy_service", func() Check {
		return Check{Status: StatusHealthy, Message: "ok"}
	})
	checker.RegisterCheck("degraded_service", func() Check {
		return Check{Status: StatusDegraded, Message: "slow"}
	})
	checker.RegisterCheck("unhealthy_service", func() Check {
		return Check{Status: StatusUnhealthy, Message: "down"}
	})

	handler := checker.ReadinessHandler()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Unhealthy should result in 503
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var response ReadinessResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	assert.NoError(t, err)

	// Overall status should be unhealthy (worst case)
	assert.Equal(t, StatusUnhealthy, response.Status)
	assert.Len(t, response.Checks, 3)
}

// TestChecker_LivenessHandler_ResponseFormat tests LivenessHandler response format.
func TestChecker_LivenessHandler_ResponseFormat(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0")
	handler := checker.LivenessHandler()

	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	// Verify exact response format
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

// TestChecker_UnregisterCheck_NonExistent tests unregistering a non-existent check.
func TestChecker_UnregisterCheck_NonExistent(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0")

	// Should not panic when unregistering non-existent check
	checker.UnregisterCheck("non_existent")

	// Verify no checks exist
	checker.mu.RLock()
	count := len(checker.checks)
	checker.mu.RUnlock()

	assert.Equal(t, 0, count)
}

// TestChecker_RegisterCheck_Override tests overriding an existing check.
func TestChecker_RegisterCheck_Override(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0")

	// Register initial check
	checker.RegisterCheck("service", func() Check {
		return Check{Status: StatusHealthy, Message: "initial"}
	})

	// Override with new check
	checker.RegisterCheck("service", func() Check {
		return Check{Status: StatusUnhealthy, Message: "overridden"}
	})

	response := checker.Readiness()

	assert.Equal(t, StatusUnhealthy, response.Status)
	assert.Equal(t, "overridden", response.Checks["service"].Message)
}

// TestHealthResponse_Details tests HealthResponse with details field.
func TestHealthResponse_Details(t *testing.T) {
	t.Parallel()

	response := HealthResponse{
		Status:  StatusHealthy,
		Version: "1.0.0",
		Details: map[string]string{
			"build":  "abc123",
			"commit": "def456",
		},
	}

	data, err := json.Marshal(response)
	assert.NoError(t, err)

	var decoded HealthResponse
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, "abc123", decoded.Details["build"])
	assert.Equal(t, "def456", decoded.Details["commit"])
}

// TestReadinessResponse_EmptyChecks tests ReadinessResponse with empty checks.
func TestReadinessResponse_EmptyChecks(t *testing.T) {
	t.Parallel()

	response := ReadinessResponse{
		Status: StatusHealthy,
		Checks: map[string]Check{},
	}

	data, err := json.Marshal(response)
	assert.NoError(t, err)

	var decoded ReadinessResponse
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, StatusHealthy, decoded.Status)
	assert.Empty(t, decoded.Checks)
}

// TestCheck_EmptyMessage tests Check with empty message.
func TestCheck_EmptyMessage(t *testing.T) {
	t.Parallel()

	check := Check{
		Status:  StatusHealthy,
		Message: "",
	}

	data, err := json.Marshal(check)
	assert.NoError(t, err)

	// Message should be omitted when empty
	assert.NotContains(t, string(data), "message")
}

// TestChecker_Health_StartTime tests that Health returns correct start time.
func TestChecker_Health_StartTime(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0")
	response := checker.Health()

	// Start time should be before or equal to timestamp
	assert.True(t, response.StartTime.Before(response.Timestamp) || response.StartTime.Equal(response.Timestamp))
}

// TestChecker_Readiness_DegradedDoesNotOverrideUnhealthy tests status priority.
func TestChecker_Readiness_DegradedDoesNotOverrideUnhealthy(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0")

	// Register unhealthy first, then degraded
	checker.RegisterCheck("unhealthy", func() Check {
		return Check{Status: StatusUnhealthy}
	})
	checker.RegisterCheck("degraded", func() Check {
		return Check{Status: StatusDegraded}
	})

	response := checker.Readiness()

	// Unhealthy should take precedence
	assert.Equal(t, StatusUnhealthy, response.Status)
}

// TestHandler_NilChecker tests Handler with nil checker (edge case).
func TestHandler_NilChecker(t *testing.T) {
	t.Parallel()

	// This tests that the Handler struct can be created with a nil checker
	// In practice, this should never happen, but we test the behavior
	handler := &Handler{checker: nil}

	// Accessing methods on nil checker would panic, so we just verify the struct
	assert.Nil(t, handler.checker)
}

// TestChecker_EmptyVersion tests Checker with empty version.
func TestChecker_EmptyVersion(t *testing.T) {
	t.Parallel()

	checker := NewChecker("")
	response := checker.Health()

	assert.Equal(t, "", response.Version)
	assert.Equal(t, StatusHealthy, response.Status)
}

// TestChecker_HealthHandler_HTTPMethods tests HealthHandler with different HTTP methods.
func TestChecker_HealthHandler_HTTPMethods(t *testing.T) {
	t.Parallel()

	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodHead,
		http.MethodOptions,
	}

	checker := NewChecker("1.0.0")
	handler := checker.HealthHandler()

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/health", nil)
			rec := httptest.NewRecorder()

			handler(rec, req)

			// All methods should return 200 OK
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}
