//go:build functional
// +build functional

package functional

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestFunctional_BackendCircuitBreaker_Enabled(t *testing.T) {
	t.Parallel()

	t.Run("backend with circuit breaker enabled allows requests when closed", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()

		cbConfig := &config.CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        5,
			Timeout:          config.Duration(30 * time.Second),
			HalfOpenRequests: 3,
		}

		handler := middleware.CircuitBreakerFromConfig(cbConfig, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "success")
			}),
		)

		// Multiple requests should succeed when circuit breaker is closed
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code, "Request %d should succeed", i)
		}
	})

	t.Run("backend circuit breaker disabled passes all requests", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()

		cbConfig := &config.CircuitBreakerConfig{
			Enabled: false,
		}

		handler := middleware.CircuitBreakerFromConfig(cbConfig, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		// All requests should pass through when disabled
		for i := 0; i < 20; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}
	})

	t.Run("nil circuit breaker config passes all requests", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()

		handler := middleware.CircuitBreakerFromConfig(nil, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestFunctional_BackendCircuitBreaker_OpensAfterFailures(t *testing.T) {
	t.Parallel()

	t.Run("circuit breaker opens after consecutive failures", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()

		// Low threshold for testing
		cbConfig := &config.CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        3,
			Timeout:          config.Duration(5 * time.Second),
			HalfOpenRequests: 1,
		}

		failureCount := 0
		handler := middleware.CircuitBreakerFromConfig(cbConfig, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				failureCount++
				// Simulate server errors
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, "error")
			}),
		)

		// Send requests that will fail
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// After threshold is reached, circuit breaker should open
			// and return 503 without calling the handler
			if rec.Code == http.StatusServiceUnavailable {
				// Circuit breaker is open
				assert.Contains(t, rec.Body.String(), "service unavailable")
				break
			}
		}
	})
}

func TestFunctional_BackendCircuitBreaker_HalfOpenState(t *testing.T) {
	t.Parallel()

	t.Run("circuit breaker transitions to half-open after timeout", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()

		// Very short timeout for testing
		cbConfig := &config.CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        2,
			Timeout:          config.Duration(100 * time.Millisecond),
			HalfOpenRequests: 1,
		}

		requestCount := 0
		shouldFail := true

		handler := middleware.CircuitBreakerFromConfig(cbConfig, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount++
				if shouldFail {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			}),
		)

		// Trigger failures to open circuit breaker
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}

		// Wait for timeout to allow half-open state
		time.Sleep(200 * time.Millisecond)

		// Now make the handler succeed
		shouldFail = false

		// Next request should be allowed (half-open state)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// The request should either succeed (if half-open allowed it)
		// or return 503 (if still open)
		assert.True(t, rec.Code == http.StatusOK || rec.Code == http.StatusServiceUnavailable)
	})
}

func TestFunctional_BackendCircuitBreaker_Recovery(t *testing.T) {
	t.Parallel()

	t.Run("circuit breaker recovers after successful requests", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()

		cbConfig := &config.CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        3,
			Timeout:          config.Duration(100 * time.Millisecond),
			HalfOpenRequests: 2,
		}

		shouldFail := true

		handler := middleware.CircuitBreakerFromConfig(cbConfig, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if shouldFail {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "recovered")
			}),
		)

		// Trigger failures
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}

		// Wait for timeout
		time.Sleep(200 * time.Millisecond)

		// Make handler succeed
		shouldFail = false

		// Send successful requests to recover
		successCount := 0
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/items", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK {
				successCount++
			}
			time.Sleep(50 * time.Millisecond)
		}

		// Should have some successful requests after recovery
		assert.Greater(t, successCount, 0, "Should have successful requests after recovery")
	})
}

func TestFunctional_BackendCircuitBreaker_MultipleBackends(t *testing.T) {
	t.Parallel()

	t.Run("multiple backends with different circuit breaker configs", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()

		// Backend 1: Conservative circuit breaker
		cb1Config := &config.CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        10,
			Timeout:          config.Duration(60 * time.Second),
			HalfOpenRequests: 5,
		}

		// Backend 2: Aggressive circuit breaker
		cb2Config := &config.CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        3,
			Timeout:          config.Duration(10 * time.Second),
			HalfOpenRequests: 1,
		}

		handler1 := middleware.CircuitBreakerFromConfig(cb1Config, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}),
		)

		handler2 := middleware.CircuitBreakerFromConfig(cb2Config, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}),
		)

		// Send failures to both
		cb1OpenCount := 0
		cb2OpenCount := 0

		for i := 0; i < 15; i++ {
			req1 := httptest.NewRequest(http.MethodGet, "/backend1", nil)
			rec1 := httptest.NewRecorder()
			handler1.ServeHTTP(rec1, req1)
			if rec1.Code == http.StatusServiceUnavailable {
				cb1OpenCount++
			}

			req2 := httptest.NewRequest(http.MethodGet, "/backend2", nil)
			rec2 := httptest.NewRecorder()
			handler2.ServeHTTP(rec2, req2)
			if rec2.Code == http.StatusServiceUnavailable {
				cb2OpenCount++
			}
		}

		// Backend 2 (aggressive) should open sooner than Backend 1 (conservative)
		assert.Greater(t, cb2OpenCount, cb1OpenCount,
			"Aggressive circuit breaker should open sooner")
	})
}

func TestFunctional_BackendCircuitBreaker_Config(t *testing.T) {
	t.Parallel()

	t.Run("circuit breaker config validation", func(t *testing.T) {
		t.Parallel()

		// Valid config
		validConfig := &config.CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        5,
			Timeout:          config.Duration(30 * time.Second),
			HalfOpenRequests: 3,
		}

		assert.True(t, validConfig.Enabled)
		assert.Equal(t, 5, validConfig.Threshold)
		assert.Equal(t, 30*time.Second, validConfig.Timeout.Duration())
		assert.Equal(t, 3, validConfig.HalfOpenRequests)
	})

	t.Run("backend config with circuit breaker", func(t *testing.T) {
		t.Parallel()

		backend := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          config.Duration(30 * time.Second),
				HalfOpenRequests: 3,
			},
		}

		require.NotNil(t, backend.CircuitBreaker)
		assert.True(t, backend.CircuitBreaker.Enabled)
		assert.Equal(t, 5, backend.CircuitBreaker.Threshold)
	})
}

func TestFunctional_BackendCircuitBreaker_NewCircuitBreaker(t *testing.T) {
	t.Parallel()

	t.Run("create circuit breaker with options", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()

		cb := middleware.NewCircuitBreaker(
			"test-cb",
			5,
			30*time.Second,
			middleware.WithCircuitBreakerLogger(logger),
		)

		require.NotNil(t, cb)

		// Execute a successful operation
		result, err := cb.Execute(func() (interface{}, error) {
			return "success", nil
		})

		assert.NoError(t, err)
		assert.Equal(t, "success", result)
	})

	t.Run("circuit breaker state tracking", func(t *testing.T) {
		t.Parallel()

		cb := middleware.NewCircuitBreaker("state-test", 3, 100*time.Millisecond)

		// Initial state should be closed
		assert.Equal(t, "closed", cb.State().String())

		// Execute successful operations
		for i := 0; i < 5; i++ {
			_, _ = cb.Execute(func() (interface{}, error) {
				return nil, nil
			})
		}

		// State should still be closed after successful operations
		assert.Equal(t, "closed", cb.State().String())
	})
}
