//go:build functional
// +build functional

package functional

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/health"
)

func TestFunctional_Health_Endpoints(t *testing.T) {
	t.Parallel()

	t.Run("health endpoint returns healthy status", func(t *testing.T) {
		t.Parallel()

		checker := health.NewChecker("1.0.0")
		handler := checker.HealthHandler()

		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

		var response health.HealthResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, health.StatusHealthy, response.Status)
		assert.Equal(t, "1.0.0", response.Version)
		assert.NotEmpty(t, response.Uptime)
		assert.False(t, response.Timestamp.IsZero())
	})

	t.Run("readiness endpoint returns ready status", func(t *testing.T) {
		t.Parallel()

		checker := health.NewChecker("1.0.0")
		handler := checker.ReadinessHandler()

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response health.ReadinessResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, health.StatusHealthy, response.Status)
	})

	t.Run("liveness endpoint returns ok", func(t *testing.T) {
		t.Parallel()

		checker := health.NewChecker("1.0.0")
		handler := checker.LivenessHandler()

		req := httptest.NewRequest(http.MethodGet, "/live", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "ok")
	})

	t.Run("readiness with registered checks - all healthy", func(t *testing.T) {
		t.Parallel()

		checker := health.NewChecker("1.0.0")

		// Register healthy checks
		checker.RegisterCheck("database", func() health.Check {
			return health.Check{Status: health.StatusHealthy, Message: "connected"}
		})
		checker.RegisterCheck("cache", func() health.Check {
			return health.Check{Status: health.StatusHealthy, Message: "connected"}
		})

		handler := checker.ReadinessHandler()

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response health.ReadinessResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, health.StatusHealthy, response.Status)
		assert.Len(t, response.Checks, 2)
		assert.Equal(t, health.StatusHealthy, response.Checks["database"].Status)
		assert.Equal(t, health.StatusHealthy, response.Checks["cache"].Status)
	})

	t.Run("readiness with unhealthy check", func(t *testing.T) {
		t.Parallel()

		checker := health.NewChecker("1.0.0")

		// Register one healthy and one unhealthy check
		checker.RegisterCheck("database", func() health.Check {
			return health.Check{Status: health.StatusHealthy, Message: "connected"}
		})
		checker.RegisterCheck("cache", func() health.Check {
			return health.Check{Status: health.StatusUnhealthy, Message: "connection failed"}
		})

		handler := checker.ReadinessHandler()

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		var response health.ReadinessResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, health.StatusUnhealthy, response.Status)
		assert.Equal(t, health.StatusUnhealthy, response.Checks["cache"].Status)
	})

	t.Run("readiness with degraded check", func(t *testing.T) {
		t.Parallel()

		checker := health.NewChecker("1.0.0")

		// Register one healthy and one degraded check
		checker.RegisterCheck("database", func() health.Check {
			return health.Check{Status: health.StatusHealthy, Message: "connected"}
		})
		checker.RegisterCheck("cache", func() health.Check {
			return health.Check{Status: health.StatusDegraded, Message: "slow response"}
		})

		handler := checker.ReadinessHandler()

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var response health.ReadinessResponse
		err := json.NewDecoder(rec.Body).Decode(&response)
		require.NoError(t, err)

		assert.Equal(t, health.StatusDegraded, response.Status)
	})

	t.Run("unregister check", func(t *testing.T) {
		t.Parallel()

		checker := health.NewChecker("1.0.0")

		checker.RegisterCheck("database", func() health.Check {
			return health.Check{Status: health.StatusHealthy}
		})

		// Verify check exists
		response := checker.Readiness()
		assert.Contains(t, response.Checks, "database")

		// Unregister check
		checker.UnregisterCheck("database")

		// Verify check is removed
		response = checker.Readiness()
		assert.NotContains(t, response.Checks, "database")
	})

	t.Run("health handler wrapper", func(t *testing.T) {
		t.Parallel()

		checker := health.NewChecker("1.0.0")
		handler := health.NewHandler(checker)

		// Test Health
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		handler.Health(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Test Readiness
		req = httptest.NewRequest(http.MethodGet, "/ready", nil)
		rec = httptest.NewRecorder()
		handler.Readiness(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Test Liveness
		req = httptest.NewRequest(http.MethodGet, "/live", nil)
		rec = httptest.NewRecorder()
		handler.Liveness(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestFunctional_Health_Status(t *testing.T) {
	t.Parallel()

	t.Run("status string representations", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "healthy", string(health.StatusHealthy))
		assert.Equal(t, "unhealthy", string(health.StatusUnhealthy))
		assert.Equal(t, "degraded", string(health.StatusDegraded))
	})
}
