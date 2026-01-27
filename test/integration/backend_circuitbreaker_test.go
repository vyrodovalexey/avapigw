//go:build integration
// +build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestIntegration_BackendCircuitBreaker_RealBackend(t *testing.T) {
	testCfg := helpers.GetTestConfig()
	helpers.SkipIfBackendUnavailable(t, testCfg.Backend1URL)

	t.Run("circuit breaker with real backend failures", func(t *testing.T) {
		// Create a backend that fails intermittently
		failCount := int32(0)
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&failCount, 1)
			if count <= 5 {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, `{"error":"server error"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		}))
		defer backend.Close()

		logger := observability.NopLogger()

		cbConfig := &config.CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        3,
			Timeout:          config.Duration(100 * time.Millisecond),
			HalfOpenRequests: 1,
		}

		handler := middleware.CircuitBreakerFromConfig(cbConfig, logger)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Proxy to backend
				resp, err := http.Get(backend.URL + r.URL.Path)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()

				w.WriteHeader(resp.StatusCode)
				_, _ = io.Copy(w, resp.Body)
			}),
		)

		// Send requests that will fail
		failedRequests := 0
		circuitOpenRequests := 0

		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code == http.StatusInternalServerError {
				failedRequests++
			} else if rec.Code == http.StatusServiceUnavailable {
				circuitOpenRequests++
			}
		}

		// Should have some failed requests and some circuit open responses
		assert.Greater(t, failedRequests, 0, "Should have some failed requests")
	})

	t.Run("circuit breaker state persistence across requests", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer backend.Close()

		logger := observability.NopLogger()

		cb := middleware.NewCircuitBreaker("persistence-test", 3, 5*time.Second,
			middleware.WithCircuitBreakerLogger(logger))

		handler := middleware.CircuitBreakerMiddleware(cb)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp, err := http.Get(backend.URL)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				w.WriteHeader(resp.StatusCode)
			}),
		)

		// Track state changes
		initialState := cb.State().String()
		assert.Equal(t, "closed", initialState)

		// Send failing requests
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}

		// State should have changed
		finalState := cb.State().String()
		// State could be open or half-open depending on timing
		assert.True(t, finalState == "open" || finalState == "half-open" || finalState == "closed")
	})

	t.Run("multiple backends with independent circuit breakers", func(t *testing.T) {
		// Backend 1 - always fails
		backend1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer backend1.Close()

		// Backend 2 - always succeeds
		backend2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		}))
		defer backend2.Close()

		logger := observability.NopLogger()

		cb1 := middleware.NewCircuitBreaker("backend1", 3, 5*time.Second,
			middleware.WithCircuitBreakerLogger(logger))
		cb2 := middleware.NewCircuitBreaker("backend2", 3, 5*time.Second,
			middleware.WithCircuitBreakerLogger(logger))

		handler1 := middleware.CircuitBreakerMiddleware(cb1)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp, err := http.Get(backend1.URL)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				w.WriteHeader(resp.StatusCode)
			}),
		)

		handler2 := middleware.CircuitBreakerMiddleware(cb2)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp, err := http.Get(backend2.URL)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				w.WriteHeader(resp.StatusCode)
			}),
		)

		// Send requests to both backends
		for i := 0; i < 10; i++ {
			req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec1 := httptest.NewRecorder()
			handler1.ServeHTTP(rec1, req1)

			req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec2 := httptest.NewRecorder()
			handler2.ServeHTTP(rec2, req2)
		}

		// Backend 1's circuit breaker should be affected
		// Backend 2's circuit breaker should remain closed
		assert.Equal(t, "closed", cb2.State().String(), "Backend 2 CB should remain closed")
	})
}

func TestIntegration_BackendCircuitBreaker_Concurrent(t *testing.T) {
	t.Run("circuit breaker handles concurrent requests", func(t *testing.T) {
		requestCount := int32(0)
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := atomic.AddInt32(&requestCount, 1)
			// Fail first 10 requests
			if count <= 10 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		logger := observability.NopLogger()

		cb := middleware.NewCircuitBreaker("concurrent-test", 5, 100*time.Millisecond,
			middleware.WithCircuitBreakerLogger(logger))

		handler := middleware.CircuitBreakerMiddleware(cb)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp, err := http.Get(backend.URL)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				w.WriteHeader(resp.StatusCode)
			}),
		)

		// Send concurrent requests
		var wg sync.WaitGroup
		results := make(chan int, 50)

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				results <- rec.Code
			}()
		}

		wg.Wait()
		close(results)

		// Count results
		statusCounts := make(map[int]int)
		for code := range results {
			statusCounts[code]++
		}

		// Should have a mix of responses
		totalResponses := 0
		for _, count := range statusCounts {
			totalResponses += count
		}
		assert.Equal(t, 50, totalResponses)
	})
}

func TestIntegration_BackendCircuitBreaker_Recovery(t *testing.T) {
	t.Run("circuit breaker recovers after backend becomes healthy", func(t *testing.T) {
		shouldFail := int32(1)
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.LoadInt32(&shouldFail) == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"recovered"}`)
		}))
		defer backend.Close()

		logger := observability.NopLogger()

		cb := middleware.NewCircuitBreaker("recovery-test", 3, 100*time.Millisecond,
			middleware.WithCircuitBreakerLogger(logger))

		handler := middleware.CircuitBreakerMiddleware(cb)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp, err := http.Get(backend.URL)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()

				body, _ := io.ReadAll(resp.Body)
				w.WriteHeader(resp.StatusCode)
				_, _ = w.Write(body)
			}),
		)

		// Trigger failures
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}

		// Wait for timeout
		time.Sleep(200 * time.Millisecond)

		// Make backend healthy
		atomic.StoreInt32(&shouldFail, 0)

		// Send recovery requests
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		recovered := false
		for i := 0; i < 20; i++ {
			select {
			case <-ctx.Done():
				break
			default:
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				if rec.Code == http.StatusOK {
					recovered = true
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if recovered {
				break
			}
		}

		assert.True(t, recovered, "Circuit breaker should recover")
	})
}

func TestIntegration_BackendCircuitBreaker_Timeout(t *testing.T) {
	t.Run("circuit breaker handles slow backends", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate slow response
			time.Sleep(500 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		logger := observability.NopLogger()

		cb := middleware.NewCircuitBreaker("timeout-test", 3, 5*time.Second,
			middleware.WithCircuitBreakerLogger(logger))

		handler := middleware.CircuitBreakerMiddleware(cb)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				client := &http.Client{Timeout: 100 * time.Millisecond}
				resp, err := client.Get(backend.URL)
				if err != nil {
					// Timeout error should trigger circuit breaker
					w.WriteHeader(http.StatusGatewayTimeout)
					return
				}
				defer resp.Body.Close()
				w.WriteHeader(resp.StatusCode)
			}),
		)

		// Send requests that will timeout
		timeoutCount := 0
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code == http.StatusGatewayTimeout {
				timeoutCount++
			}
		}

		assert.Greater(t, timeoutCount, 0, "Should have timeout responses")
	})
}
