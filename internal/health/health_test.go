package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestStatus_Constants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, Status("healthy"), StatusHealthy)
	assert.Equal(t, Status("unhealthy"), StatusUnhealthy)
	assert.Equal(t, Status("degraded"), StatusDegraded)
}

func TestNewChecker(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	assert.NotNil(t, checker)
	assert.Equal(t, "1.0.0", checker.version)
	assert.NotNil(t, checker.checks)
	assert.False(t, checker.startTime.IsZero())
}

func TestChecker_RegisterCheck(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	checker.RegisterCheck("database", func() Check {
		return Check{Status: StatusHealthy}
	})

	checker.mu.RLock()
	_, exists := checker.checks["database"]
	checker.mu.RUnlock()

	assert.True(t, exists)
}

func TestChecker_UnregisterCheck(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	checker.RegisterCheck("database", func() Check {
		return Check{Status: StatusHealthy}
	})

	checker.UnregisterCheck("database")

	checker.mu.RLock()
	_, exists := checker.checks["database"]
	checker.mu.RUnlock()

	assert.False(t, exists)
}

func TestChecker_Health(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	response := checker.Health()

	assert.Equal(t, StatusHealthy, response.Status)
	assert.Equal(t, "1.0.0", response.Version)
	assert.NotEmpty(t, response.Uptime)
	assert.False(t, response.Timestamp.IsZero())
}

func TestChecker_Readiness_NoChecks(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	response := checker.Readiness()

	assert.Equal(t, StatusHealthy, response.Status)
	assert.Empty(t, response.Checks)
	assert.False(t, response.Timestamp.IsZero())
}

func TestChecker_Readiness_AllHealthy(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	checker.RegisterCheck("database", func() Check {
		return Check{Status: StatusHealthy, Message: "connected"}
	})
	checker.RegisterCheck("cache", func() Check {
		return Check{Status: StatusHealthy, Message: "available"}
	})

	response := checker.Readiness()

	assert.Equal(t, StatusHealthy, response.Status)
	assert.Len(t, response.Checks, 2)
	assert.Equal(t, StatusHealthy, response.Checks["database"].Status)
	assert.Equal(t, StatusHealthy, response.Checks["cache"].Status)
}

func TestChecker_Readiness_OneUnhealthy(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	checker.RegisterCheck("database", func() Check {
		return Check{Status: StatusHealthy}
	})
	checker.RegisterCheck("cache", func() Check {
		return Check{Status: StatusUnhealthy, Message: "connection failed"}
	})

	response := checker.Readiness()

	assert.Equal(t, StatusUnhealthy, response.Status)
	assert.Len(t, response.Checks, 2)
}

func TestChecker_Readiness_OneDegraded(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	checker.RegisterCheck("database", func() Check {
		return Check{Status: StatusHealthy}
	})
	checker.RegisterCheck("cache", func() Check {
		return Check{Status: StatusDegraded, Message: "slow response"}
	})

	response := checker.Readiness()

	assert.Equal(t, StatusDegraded, response.Status)
}

func TestChecker_Readiness_UnhealthyOverridesDegraded(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	checker.RegisterCheck("database", func() Check {
		return Check{Status: StatusDegraded}
	})
	checker.RegisterCheck("cache", func() Check {
		return Check{Status: StatusUnhealthy}
	})

	response := checker.Readiness()

	assert.Equal(t, StatusUnhealthy, response.Status)
}

func TestChecker_HealthHandler(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := checker.HealthHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, StatusHealthy, response.Status)
	assert.Equal(t, "1.0.0", response.Version)
}

func TestChecker_ReadinessHandler_Healthy(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.RegisterCheck("database", func() Check {
		return Check{Status: StatusHealthy}
	})

	handler := checker.ReadinessHandler()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response ReadinessResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, StatusHealthy, response.Status)
}

func TestChecker_ReadinessHandler_Unhealthy(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.RegisterCheck("database", func() Check {
		return Check{Status: StatusUnhealthy, Message: "connection failed"}
	})

	handler := checker.ReadinessHandler()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var response ReadinessResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, StatusUnhealthy, response.Status)
}

func TestChecker_LivenessHandler(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := checker.LivenessHandler()

	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Body.String(), `"status":"ok"`)
}

func TestNewHandler(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := NewHandler(checker)

	assert.NotNil(t, handler)
	assert.Equal(t, checker, handler.checker)
}

func TestHandler_Health(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := NewHandler(checker)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.Health(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_Readiness(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := NewHandler(checker)

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	handler.Readiness(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandler_Liveness(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := NewHandler(checker)

	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	rec := httptest.NewRecorder()

	handler.Liveness(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestChecker_Uptime(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	response := checker.Health()

	// Uptime should be non-empty and contain time units
	assert.NotEmpty(t, response.Uptime)
}

func TestHealthResponse_JSON(t *testing.T) {
	t.Parallel()

	response := HealthResponse{
		Status:    StatusHealthy,
		Version:   "1.0.0",
		Uptime:    "1h30m",
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	var decoded HealthResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, response.Status, decoded.Status)
	assert.Equal(t, response.Version, decoded.Version)
	assert.Equal(t, response.Uptime, decoded.Uptime)
}

func TestReadinessResponse_JSON(t *testing.T) {
	t.Parallel()

	response := ReadinessResponse{
		Status: StatusHealthy,
		Checks: map[string]Check{
			"database": {Status: StatusHealthy, Message: "connected"},
		},
		Timestamp: time.Now(),
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	var decoded ReadinessResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, response.Status, decoded.Status)
	assert.Equal(t, response.Checks["database"].Status, decoded.Checks["database"].Status)
}

func TestCheck_JSON(t *testing.T) {
	t.Parallel()

	check := Check{
		Status:  StatusHealthy,
		Message: "all good",
	}

	data, err := json.Marshal(check)
	require.NoError(t, err)

	var decoded Check
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, check.Status, decoded.Status)
	assert.Equal(t, check.Message, decoded.Message)
}
