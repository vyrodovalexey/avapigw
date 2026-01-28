//go:build functional
// +build functional

package functional

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestFunctional_Middleware_Chain(t *testing.T) {
	t.Parallel()

	t.Run("middleware chain execution order", func(t *testing.T) {
		t.Parallel()

		var executionOrder []string

		// Create middlewares that record execution order
		middleware1 := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				executionOrder = append(executionOrder, "middleware1-before")
				next.ServeHTTP(w, r)
				executionOrder = append(executionOrder, "middleware1-after")
			})
		}

		middleware2 := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				executionOrder = append(executionOrder, "middleware2-before")
				next.ServeHTTP(w, r)
				executionOrder = append(executionOrder, "middleware2-after")
			})
		}

		middleware3 := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				executionOrder = append(executionOrder, "middleware3-before")
				next.ServeHTTP(w, r)
				executionOrder = append(executionOrder, "middleware3-after")
			})
		}

		// Final handler
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			executionOrder = append(executionOrder, "handler")
			w.WriteHeader(http.StatusOK)
		})

		// Chain middlewares
		chain := middleware1(middleware2(middleware3(handler)))

		// Execute
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)

		// Verify execution order
		expected := []string{
			"middleware1-before",
			"middleware2-before",
			"middleware3-before",
			"handler",
			"middleware3-after",
			"middleware2-after",
			"middleware1-after",
		}
		assert.Equal(t, expected, executionOrder)
	})
}

func TestFunctional_Middleware_RateLimit(t *testing.T) {
	t.Parallel()

	t.Run("rate limit allows requests within limit", func(t *testing.T) {
		t.Parallel()

		rl := middleware.NewRateLimiter(10, 10, false)
		handler := middleware.RateLimit(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Send requests within limit
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code, "Request %d should succeed", i)
		}
	})

	t.Run("rate limit blocks requests exceeding limit", func(t *testing.T) {
		t.Parallel()

		// Very low rate limit
		rl := middleware.NewRateLimiter(1, 1, false)
		handler := middleware.RateLimit(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// First request should succeed
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Second request should be rate limited
		req = httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	})

	t.Run("per-client rate limiting", func(t *testing.T) {
		t.Parallel()

		rl := middleware.NewRateLimiter(1, 1, true)
		handler := middleware.RateLimit(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// First client - first request should succeed
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		// First client - second request should be rate limited
		req = httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)

		// Second client - first request should succeed (different rate limit)
		req = httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.2:12345"
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("rate limit from config - disabled", func(t *testing.T) {
		t.Parallel()

		cfg := &config.RateLimitConfig{
			Enabled: false,
		}

		rateLimitMiddleware, rateLimiter := middleware.RateLimitFromConfig(cfg, observability.NopLogger())
		if rateLimiter != nil {
			defer rateLimiter.Stop()
		}
		handler := rateLimitMiddleware(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		// All requests should succeed when disabled
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}
	})
}

func TestFunctional_Middleware_CircuitBreaker(t *testing.T) {
	t.Parallel()

	t.Run("circuit breaker allows requests when closed", func(t *testing.T) {
		t.Parallel()

		cb := middleware.NewCircuitBreaker("test", 5, 30*time.Second)
		handler := middleware.CircuitBreakerMiddleware(cb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("circuit breaker from config - disabled", func(t *testing.T) {
		t.Parallel()

		cfg := &config.CircuitBreakerConfig{
			Enabled: false,
		}

		handler := middleware.CircuitBreakerFromConfig(cfg, observability.NopLogger())(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestFunctional_Middleware_Headers(t *testing.T) {
	t.Parallel()

	t.Run("set request headers", func(t *testing.T) {
		t.Parallel()

		cfg := middleware.HeadersConfig{
			RequestSet: map[string]string{
				"X-Custom-Header": "custom-value",
			},
		}

		var receivedHeader string
		handler := middleware.Headers(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeader = r.Header.Get("X-Custom-Header")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, "custom-value", receivedHeader)
	})

	t.Run("add request headers", func(t *testing.T) {
		t.Parallel()

		cfg := middleware.HeadersConfig{
			RequestAdd: map[string]string{
				"X-Added-Header": "added-value",
			},
		}

		var receivedHeaders []string
		handler := middleware.Headers(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Values("X-Added-Header")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Add("X-Added-Header", "original-value")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Contains(t, receivedHeaders, "original-value")
		assert.Contains(t, receivedHeaders, "added-value")
	})

	t.Run("remove request headers", func(t *testing.T) {
		t.Parallel()

		cfg := middleware.HeadersConfig{
			RequestRemove: []string{"X-Remove-Me"},
		}

		var headerExists bool
		handler := middleware.Headers(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headerExists = r.Header.Get("X-Remove-Me") != ""
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Remove-Me", "should-be-removed")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.False(t, headerExists)
	})

	t.Run("set response headers", func(t *testing.T) {
		t.Parallel()

		cfg := middleware.HeadersConfig{
			ResponseSet: map[string]string{
				"X-Response-Header": "response-value",
			},
		}

		handler := middleware.Headers(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, "response-value", rec.Header().Get("X-Response-Header"))
	})

	t.Run("headers from config", func(t *testing.T) {
		t.Parallel()

		cfg := &config.HeaderManipulation{
			Request: &config.HeaderOperation{
				Set: map[string]string{
					"X-Gateway": "avapigw",
				},
			},
			Response: &config.HeaderOperation{
				Set: map[string]string{
					"X-Powered-By": "avapigw",
				},
			},
		}

		var receivedHeader string
		handler := middleware.HeadersFromConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeader = r.Header.Get("X-Gateway")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, "avapigw", receivedHeader)
		assert.Equal(t, "avapigw", rec.Header().Get("X-Powered-By"))
	})
}

func TestFunctional_Middleware_CORS(t *testing.T) {
	t.Parallel()

	t.Run("CORS preflight request", func(t *testing.T) {
		t.Parallel()

		cfg := middleware.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
			AllowHeaders: []string{"Content-Type", "Authorization"},
			MaxAge:       86400,
		}

		handler := middleware.CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodOptions, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// When AllowOrigins contains "*", the actual origin is returned
		assert.Equal(t, "http://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "POST")
	})

	t.Run("CORS actual request", func(t *testing.T) {
		t.Parallel()

		cfg := middleware.CORSConfig{
			AllowOrigins: []string{"http://example.com"},
			AllowMethods: []string{"GET", "POST"},
		}

		handler := middleware.CORS(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "OK")
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "http://example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "http://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestFunctional_Middleware_RequestID(t *testing.T) {
	t.Parallel()

	t.Run("generates request ID", func(t *testing.T) {
		t.Parallel()

		var receivedRequestID string
		handler := middleware.RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Request ID is added to context, not request header
			receivedRequestID = w.Header().Get("X-Request-ID")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.NotEmpty(t, rec.Header().Get("X-Request-ID"))
		assert.NotEmpty(t, receivedRequestID)
	})

	t.Run("preserves existing request ID", func(t *testing.T) {
		t.Parallel()

		handler := middleware.RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The original request header is preserved
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", "existing-id")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, "existing-id", rec.Header().Get("X-Request-ID"))
	})
}

func TestFunctional_Middleware_Recovery(t *testing.T) {
	t.Parallel()

	t.Run("recovers from panic", func(t *testing.T) {
		t.Parallel()

		handler := middleware.Recovery(observability.NopLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("test panic")
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		// Should not panic
		require.NotPanics(t, func() {
			handler.ServeHTTP(rec, req)
		})

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestFunctional_Middleware_Timeout(t *testing.T) {
	t.Parallel()

	t.Run("request completes within timeout", func(t *testing.T) {
		t.Parallel()

		handler := middleware.Timeout(5*time.Second, observability.NopLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "OK")
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestFunctional_Middleware_MaxSessions(t *testing.T) {
	t.Parallel()

	t.Run("max sessions middleware allows requests within limit", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 10,
			QueueSize:     0,
		}

		mw, limiter := middleware.MaxSessionsFromConfig(cfg, observability.NopLogger())
		require.NotNil(t, limiter)
		defer limiter.Stop()

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Send requests within limit
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code, "Request %d should succeed", i)
		}
	})

	t.Run("max sessions middleware rejects requests exceeding limit", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1,
			QueueSize:     0,
		}

		mw, limiter := middleware.MaxSessionsFromConfig(cfg, observability.NopLogger())
		require.NotNil(t, limiter)
		defer limiter.Stop()

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))

		// Start first request that will hold the slot
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}()

		// Give first request time to acquire slot
		time.Sleep(10 * time.Millisecond)

		// Second request should be rejected
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		wg.Wait()
	})

	t.Run("max sessions from config - disabled", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled: false,
		}

		mw, limiter := middleware.MaxSessionsFromConfig(cfg, observability.NopLogger())
		assert.Nil(t, limiter)

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// All requests should succeed when disabled
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}
	})

	t.Run("max sessions with queue", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1,
			QueueSize:     5,
			QueueTimeout:  config.Duration(500 * time.Millisecond),
		}

		mw, limiter := middleware.MaxSessionsFromConfig(cfg, observability.NopLogger())
		require.NotNil(t, limiter)
		defer limiter.Stop()

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(20 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))

		var wg sync.WaitGroup
		var successCount int32

		// Start 3 requests with max 1 concurrent but queue of 5
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code == http.StatusOK {
					atomic.AddInt32(&successCount, 1)
				}
			}()
		}

		wg.Wait()

		// All 3 should eventually succeed due to queuing
		assert.Equal(t, int32(3), successCount)
	})
}
