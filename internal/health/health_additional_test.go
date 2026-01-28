package health

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// errorResponseWriter is a mock ResponseWriter that fails on Write.
type errorResponseWriter struct {
	header     http.Header
	statusCode int
	written    bool
}

func newErrorResponseWriter() *errorResponseWriter {
	return &errorResponseWriter{
		header: make(http.Header),
	}
}

func (w *errorResponseWriter) Header() http.Header {
	return w.header
}

func (w *errorResponseWriter) Write(data []byte) (int, error) {
	// Simulate write failure
	return 0, assert.AnError
}

func (w *errorResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.written = true
}

// TestChecker_HealthHandler_WriteFailure tests HealthHandler when Write fails.
func TestChecker_HealthHandler_WriteFailure(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := checker.HealthHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := newErrorResponseWriter()

	// Should not panic even when Write fails
	handler(rec, req)

	// Headers should still be written
	assert.True(t, rec.written)
	assert.Equal(t, http.StatusOK, rec.statusCode)
}

// TestChecker_ReadinessHandler_WriteFailure tests ReadinessHandler when Write fails.
func TestChecker_ReadinessHandler_WriteFailure(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := checker.ReadinessHandler()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := newErrorResponseWriter()

	// Should not panic even when Write fails
	handler(rec, req)

	// Headers should still be written
	assert.True(t, rec.written)
	assert.Equal(t, http.StatusOK, rec.statusCode)
}

// TestChecker_Concurrent tests concurrent access to Checker methods.
func TestChecker_Concurrent(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	// Register some checks
	checker.RegisterCheck("db", func() Check {
		return Check{Status: StatusHealthy, Message: "connected"}
	})

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 4)

	// Concurrent Health calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			response := checker.Health()
			assert.Equal(t, StatusHealthy, response.Status)
		}()
	}

	// Concurrent Readiness calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			response := checker.Readiness()
			assert.NotNil(t, response)
		}()
	}

	// Concurrent RegisterCheck calls
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			checker.RegisterCheck("check"+string(rune('a'+idx%26)), func() Check {
				return Check{Status: StatusHealthy}
			})
		}(i)
	}

	// Concurrent UnregisterCheck calls
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			checker.UnregisterCheck("check" + string(rune('a'+idx%26)))
		}(i)
	}

	wg.Wait()
}

// TestChecker_HealthHandler_Concurrent tests concurrent HealthHandler calls.
func TestChecker_HealthHandler_Concurrent(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := checker.HealthHandler()

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			rec := httptest.NewRecorder()
			handler(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}()
	}

	wg.Wait()
}

// TestChecker_ReadinessHandler_Concurrent tests concurrent ReadinessHandler calls.
func TestChecker_ReadinessHandler_Concurrent(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.RegisterCheck("db", func() Check {
		return Check{Status: StatusHealthy}
	})

	handler := checker.ReadinessHandler()

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/ready", nil)
			rec := httptest.NewRecorder()
			handler(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}()
	}

	wg.Wait()
}

// TestChecker_LivenessHandler_Concurrent tests concurrent LivenessHandler calls.
func TestChecker_LivenessHandler_Concurrent(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := checker.LivenessHandler()

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/live", nil)
			rec := httptest.NewRecorder()
			handler(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}()
	}

	wg.Wait()
}

// TestChecker_Health_MemoryStats tests that Health returns memory stats.
func TestChecker_Health_MemoryStats(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	response := checker.Health()

	assert.True(t, response.MemoryMB > 0, "memory should be greater than 0")
	assert.True(t, response.NumGoroutine > 0, "num goroutines should be greater than 0")
	assert.NotEmpty(t, response.GoVersion)
}

// TestChecker_Health_Hostname tests that Health returns hostname.
func TestChecker_Health_Hostname(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	response := checker.Health()

	// Hostname might be empty in some environments, but should not panic
	_ = response.Hostname
}

// TestChecker_Readiness_StatusPriority tests status priority in Readiness.
func TestChecker_Readiness_StatusPriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		checks         map[string]Check
		expectedStatus Status
	}{
		{
			name:           "no checks",
			checks:         map[string]Check{},
			expectedStatus: StatusHealthy,
		},
		{
			name: "all healthy",
			checks: map[string]Check{
				"db":    {Status: StatusHealthy},
				"cache": {Status: StatusHealthy},
			},
			expectedStatus: StatusHealthy,
		},
		{
			name: "one degraded",
			checks: map[string]Check{
				"db":    {Status: StatusHealthy},
				"cache": {Status: StatusDegraded},
			},
			expectedStatus: StatusDegraded,
		},
		{
			name: "one unhealthy",
			checks: map[string]Check{
				"db":    {Status: StatusHealthy},
				"cache": {Status: StatusUnhealthy},
			},
			expectedStatus: StatusUnhealthy,
		},
		{
			name: "unhealthy overrides degraded",
			checks: map[string]Check{
				"db":    {Status: StatusDegraded},
				"cache": {Status: StatusUnhealthy},
			},
			expectedStatus: StatusUnhealthy,
		},
		{
			name: "multiple unhealthy",
			checks: map[string]Check{
				"db":    {Status: StatusUnhealthy},
				"cache": {Status: StatusUnhealthy},
			},
			expectedStatus: StatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := NewChecker("1.0.0", observability.NopLogger())
			for name, check := range tt.checks {
				checkCopy := check // Capture for closure
				checker.RegisterCheck(name, func() Check {
					return checkCopy
				})
			}

			response := checker.Readiness()
			assert.Equal(t, tt.expectedStatus, response.Status)
		})
	}
}

// TestHandler_Methods tests Handler wrapper methods.
func TestHandler_Methods(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := NewHandler(checker)

	tests := []struct {
		name       string
		method     func(http.ResponseWriter, *http.Request)
		path       string
		expectCode int
	}{
		{
			name:       "Health",
			method:     handler.Health,
			path:       "/health",
			expectCode: http.StatusOK,
		},
		{
			name:       "Readiness",
			method:     handler.Readiness,
			path:       "/ready",
			expectCode: http.StatusOK,
		},
		{
			name:       "Liveness",
			method:     handler.Liveness,
			path:       "/live",
			expectCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			tt.method(rec, req)

			assert.Equal(t, tt.expectCode, rec.Code)
		})
	}
}

// TestHealthResponse_Fields tests all fields in HealthResponse.
func TestHealthResponse_Fields(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	response := checker.Health()

	// Verify all fields are populated
	assert.Equal(t, StatusHealthy, response.Status)
	assert.Equal(t, "1.0.0", response.Version)
	assert.NotEmpty(t, response.Uptime)
	assert.True(t, response.UptimeSecs >= 0)
	assert.False(t, response.Timestamp.IsZero())
	assert.False(t, response.StartTime.IsZero())
	assert.NotEmpty(t, response.GoVersion)
	assert.True(t, response.NumGoroutine > 0)
	assert.True(t, response.MemoryMB >= 0)
}

// TestReadinessResponse_Fields tests all fields in ReadinessResponse.
func TestReadinessResponse_Fields(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.RegisterCheck("test", func() Check {
		return Check{Status: StatusHealthy, Message: "ok"}
	})

	response := checker.Readiness()

	assert.Equal(t, StatusHealthy, response.Status)
	assert.NotNil(t, response.Checks)
	assert.Len(t, response.Checks, 1)
	assert.False(t, response.Timestamp.IsZero())
}

// TestCheck_Fields tests all fields in Check.
func TestCheck_Fields(t *testing.T) {
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

// TestConstants tests the package constants.
func TestConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "Content-Type", HeaderContentType)
	assert.Equal(t, "application/json", ContentTypeJSON)
}

// TestChecker_HealthHandler_MarshalError tests HealthHandler when json.Marshal fails.
// Not parallel — modifies package-level jsonMarshalFunc.
func TestChecker_HealthHandler_MarshalError(t *testing.T) {
	// Save and restore original marshal function
	origMarshal := jsonMarshalFunc
	defer func() { jsonMarshalFunc = origMarshal }()

	// Inject a failing marshal function
	jsonMarshalFunc = func(_ interface{}) ([]byte, error) {
		return nil, errors.New("simulated marshal error")
	}

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := checker.HealthHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Should return 500 Internal Server Error
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed to encode response")
}

// TestChecker_ReadinessHandler_MarshalError tests ReadinessHandler when json.Marshal fails.
// Not parallel — modifies package-level jsonMarshalFunc.
func TestChecker_ReadinessHandler_MarshalError(t *testing.T) {
	// Save and restore original marshal function
	origMarshal := jsonMarshalFunc
	defer func() { jsonMarshalFunc = origMarshal }()

	// Inject a failing marshal function
	jsonMarshalFunc = func(_ interface{}) ([]byte, error) {
		return nil, errors.New("simulated marshal error")
	}

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := checker.ReadinessHandler()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Should return 500 Internal Server Error
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed to encode response")
}
