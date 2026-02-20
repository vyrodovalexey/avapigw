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

// ============================================================================
// SetDraining / IsDraining Tests
// ============================================================================

func TestChecker_SetDraining_True(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	// Initially not draining
	assert.False(t, checker.IsDraining())

	// Set draining to true
	checker.SetDraining(true)
	assert.True(t, checker.IsDraining())
}

func TestChecker_SetDraining_False(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	// Set draining to true first
	checker.SetDraining(true)
	assert.True(t, checker.IsDraining())

	// Clear draining
	checker.SetDraining(false)
	assert.False(t, checker.IsDraining())
}

func TestChecker_IsDraining_DefaultFalse(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	assert.False(t, checker.IsDraining())
}

func TestChecker_SetDraining_TransitionRecovery(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	// healthy -> draining -> healthy (recovery scenario)
	assert.False(t, checker.IsDraining(), "should start healthy")

	checker.SetDraining(true)
	assert.True(t, checker.IsDraining(), "should be draining after SetDraining(true)")

	checker.SetDraining(false)
	assert.False(t, checker.IsDraining(), "should recover after SetDraining(false)")
}

func TestChecker_SetDraining_Idempotent(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	// Setting draining true multiple times should be idempotent
	checker.SetDraining(true)
	checker.SetDraining(true)
	assert.True(t, checker.IsDraining())

	// Setting draining false multiple times should be idempotent
	checker.SetDraining(false)
	checker.SetDraining(false)
	assert.False(t, checker.IsDraining())
}

// ============================================================================
// HealthHandler Draining Tests
// ============================================================================

func TestChecker_HealthHandler_Draining(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.SetDraining(true)

	handler := checker.HealthHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Should return 503 Service Unavailable when draining
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, ContentTypeJSON, rec.Header().Get(HeaderContentType))

	var response HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, StatusUnhealthy, response.Status)
	assert.Equal(t, "1.0.0", response.Version)
	assert.Equal(t, "draining", response.Details["reason"])
}

func TestChecker_HealthHandler_DrainingThenRecovered(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	handler := checker.HealthHandler()

	// First request: healthy
	{
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	// Set draining
	checker.SetDraining(true)

	// Second request: draining (503)
	{
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	}

	// Clear draining
	checker.SetDraining(false)

	// Third request: healthy again
	{
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestChecker_HealthHandler_DrainingWriteError(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.SetDraining(true)

	handler := checker.HealthHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := newErrorResponseWriter()

	// Should not panic even when Write fails during draining
	handler(rec, req)

	assert.True(t, rec.written)
	assert.Equal(t, http.StatusServiceUnavailable, rec.statusCode)
}

// TestChecker_HealthHandler_DrainingMarshalError tests the draining path when
// json.Marshal fails. Not parallel — modifies package-level jsonMarshalFunc.
func TestChecker_HealthHandler_DrainingMarshalError(t *testing.T) {
	origMarshal := jsonMarshalFunc
	defer func() { jsonMarshalFunc = origMarshal }()

	jsonMarshalFunc = func(_ interface{}) ([]byte, error) {
		return nil, errors.New("simulated marshal error")
	}

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.SetDraining(true)

	handler := checker.HealthHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed to encode response")
}

// ============================================================================
// ReadinessHandler Draining Tests
// ============================================================================

func TestChecker_ReadinessHandler_Draining(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.SetDraining(true)

	handler := checker.ReadinessHandler()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Should return 503 Service Unavailable when draining
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, ContentTypeJSON, rec.Header().Get(HeaderContentType))

	var response ReadinessResponse
	err := json.NewDecoder(rec.Body).Decode(&response)
	require.NoError(t, err)

	assert.Equal(t, StatusUnhealthy, response.Status)
	assert.Contains(t, response.Checks, "draining")
	assert.Equal(t, StatusUnhealthy, response.Checks["draining"].Status)
	assert.Equal(t, "gateway is draining", response.Checks["draining"].Message)
}

func TestChecker_ReadinessHandler_DrainingThenRecovered(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.RegisterCheck("db", func() Check {
		return Check{Status: StatusHealthy, Message: "connected"}
	})

	handler := checker.ReadinessHandler()

	// First request: healthy
	{
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}

	// Set draining
	checker.SetDraining(true)

	// Second request: draining (503)
	{
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	}

	// Clear draining
	checker.SetDraining(false)

	// Third request: healthy again
	{
		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestChecker_ReadinessHandler_DrainingWriteError(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.SetDraining(true)

	handler := checker.ReadinessHandler()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := newErrorResponseWriter()

	// Should not panic even when Write fails during draining
	handler(rec, req)

	assert.True(t, rec.written)
	assert.Equal(t, http.StatusServiceUnavailable, rec.statusCode)
}

// TestChecker_ReadinessHandler_DrainingMarshalError tests the draining path when
// json.Marshal fails. Not parallel — modifies package-level jsonMarshalFunc.
func TestChecker_ReadinessHandler_DrainingMarshalError(t *testing.T) {
	origMarshal := jsonMarshalFunc
	defer func() { jsonMarshalFunc = origMarshal }()

	jsonMarshalFunc = func(_ interface{}) ([]byte, error) {
		return nil, errors.New("simulated marshal error")
	}

	checker := NewChecker("1.0.0", observability.NopLogger())
	checker.SetDraining(true)

	handler := checker.ReadinessHandler()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed to encode response")
}

// ============================================================================
// Concurrent Draining Tests
// ============================================================================

func TestChecker_Draining_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3)

	// Concurrent SetDraining(true) calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			checker.SetDraining(true)
		}()
	}

	// Concurrent SetDraining(false) calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			checker.SetDraining(false)
		}()
	}

	// Concurrent IsDraining calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = checker.IsDraining()
		}()
	}

	wg.Wait()
	// Test passes if no race conditions occur (run with -race flag)
}

func TestChecker_Draining_ConcurrentHandlerAccess(t *testing.T) {
	t.Parallel()

	checker := NewChecker("1.0.0", observability.NopLogger())
	healthHandler := checker.HealthHandler()
	readinessHandler := checker.ReadinessHandler()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3)

	// Concurrent health handler calls while toggling draining
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			rec := httptest.NewRecorder()
			healthHandler(rec, req)
			// Status should be either 200 or 503
			code := rec.Code
			assert.True(t, code == http.StatusOK || code == http.StatusServiceUnavailable)
		}()
	}

	// Concurrent readiness handler calls
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/ready", nil)
			rec := httptest.NewRecorder()
			readinessHandler(rec, req)
			code := rec.Code
			assert.True(t, code == http.StatusOK || code == http.StatusServiceUnavailable)
		}()
	}

	// Concurrent draining toggles
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			checker.SetDraining(idx%2 == 0)
		}(i)
	}

	wg.Wait()
}

// ============================================================================
// Table-Driven Draining Tests
// ============================================================================

func TestChecker_HealthHandler_DrainingTableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		draining       bool
		expectedStatus int
		expectedHealth Status
	}{
		{
			name:           "not draining returns 200",
			draining:       false,
			expectedStatus: http.StatusOK,
			expectedHealth: StatusHealthy,
		},
		{
			name:           "draining returns 503",
			draining:       true,
			expectedStatus: http.StatusServiceUnavailable,
			expectedHealth: StatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := NewChecker("1.0.0", observability.NopLogger())
			checker.SetDraining(tt.draining)

			handler := checker.HealthHandler()
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			rec := httptest.NewRecorder()

			handler(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			assert.Equal(t, ContentTypeJSON, rec.Header().Get(HeaderContentType))

			var response HealthResponse
			err := json.Unmarshal(rec.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedHealth, response.Status)
		})
	}
}

func TestChecker_ReadinessHandler_DrainingTableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		draining       bool
		expectedStatus int
		expectedHealth Status
	}{
		{
			name:           "not draining returns 200",
			draining:       false,
			expectedStatus: http.StatusOK,
			expectedHealth: StatusHealthy,
		},
		{
			name:           "draining returns 503",
			draining:       true,
			expectedStatus: http.StatusServiceUnavailable,
			expectedHealth: StatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := NewChecker("1.0.0", observability.NopLogger())
			checker.SetDraining(tt.draining)

			handler := checker.ReadinessHandler()
			req := httptest.NewRequest(http.MethodGet, "/ready", nil)
			rec := httptest.NewRecorder()

			handler(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			assert.Equal(t, ContentTypeJSON, rec.Header().Get(HeaderContentType))

			var response ReadinessResponse
			err := json.Unmarshal(rec.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedHealth, response.Status)
		})
	}
}
