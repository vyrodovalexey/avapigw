package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// failingMarshalResponseWriter simulates a response writer where json.Marshal
// of the response would fail. Since HealthResponse always marshals successfully,
// we test the write-error path by using a writer that fails on Write after
// headers are already sent.

// TestChecker_HealthHandler_ContentTypeHeader verifies Content-Type is set correctly.
func TestChecker_HealthHandler_ContentTypeHeader(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0")
	handler := checker.HealthHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, ContentTypeJSON, rec.Header().Get(HeaderContentType))

	// Verify response is valid JSON
	var response HealthResponse
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, StatusHealthy, response.Status)
}

// TestChecker_ReadinessHandler_ContentTypeAndStatus verifies ReadinessHandler
// sets correct content type and status for various scenarios.
func TestChecker_ReadinessHandler_ContentTypeAndStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		checks         map[string]CheckFunc
		expectedStatus int
		expectedBody   Status
	}{
		{
			name:           "healthy with no checks",
			checks:         nil,
			expectedStatus: http.StatusOK,
			expectedBody:   StatusHealthy,
		},
		{
			name: "healthy with healthy check",
			checks: map[string]CheckFunc{
				"db": func() Check { return Check{Status: StatusHealthy} },
			},
			expectedStatus: http.StatusOK,
			expectedBody:   StatusHealthy,
		},
		{
			name: "degraded returns 200",
			checks: map[string]CheckFunc{
				"db": func() Check { return Check{Status: StatusDegraded, Message: "slow"} },
			},
			expectedStatus: http.StatusOK,
			expectedBody:   StatusDegraded,
		},
		{
			name: "unhealthy returns 503",
			checks: map[string]CheckFunc{
				"db": func() Check { return Check{Status: StatusUnhealthy, Message: "down"} },
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   StatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := NewChecker("1.0.0")
			for name, fn := range tt.checks {
				checker.RegisterCheck(name, fn)
			}

			handler := checker.ReadinessHandler()
			req := httptest.NewRequest(http.MethodGet, "/ready", nil)
			rec := httptest.NewRecorder()

			handler(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			assert.Equal(t, ContentTypeJSON, rec.Header().Get(HeaderContentType))

			var response ReadinessResponse
			err := json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedBody, response.Status)
		})
	}
}

// TestChecker_ReadinessHandler_WriteError tests ReadinessHandler when write fails
// for unhealthy status (503 path).
func TestChecker_ReadinessHandler_WriteError_Unhealthy(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0")
	checker.RegisterCheck("failing", func() Check {
		return Check{Status: StatusUnhealthy, Message: "down"}
	})

	handler := checker.ReadinessHandler()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := newErrorResponseWriter()

	// Should not panic even when Write fails with unhealthy status
	handler(rec, req)

	assert.True(t, rec.written)
	assert.Equal(t, http.StatusServiceUnavailable, rec.statusCode)
}

// TestHandler_AllEndpoints_Integration tests all Handler endpoints in sequence.
func TestHandler_AllEndpoints_Integration(t *testing.T) {
	t.Parallel()

	checker := NewChecker("3.0.0")
	checker.RegisterCheck("cache", func() Check {
		return Check{Status: StatusHealthy, Message: "connected"}
	})

	handler := NewHandler(checker)

	// Test Health
	{
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		handler.Health(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp HealthResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, "3.0.0", resp.Version)
	}

	// Test Readiness
	{
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		handler.Readiness(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp ReadinessResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, StatusHealthy, resp.Status)
		assert.Contains(t, resp.Checks, "cache")
	}

	// Test Liveness
	{
		req := httptest.NewRequest(http.MethodGet, "/live", nil)
		rec := httptest.NewRecorder()
		handler.Liveness(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
	}
}
