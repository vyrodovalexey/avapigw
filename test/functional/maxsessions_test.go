//go:build functional
// +build functional

package functional

import (
	"context"
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

func TestFunctional_MaxSessions_GlobalLevel(t *testing.T) {
	t.Parallel()

	t.Run("max sessions limits concurrent requests", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 2,
			QueueSize:     0,
		}

		mw, limiter := middleware.MaxSessionsFromConfig(cfg, observability.NopLogger())
		require.NotNil(t, limiter)
		defer limiter.Stop()

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))

		var wg sync.WaitGroup
		var successCount, rejectCount atomic.Int64

		// Start 5 concurrent requests with max 2 allowed
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code == http.StatusOK {
					successCount.Add(1)
				} else if rec.Code == http.StatusServiceUnavailable {
					rejectCount.Add(1)
				}
			}()
		}

		wg.Wait()

		// At least 2 should succeed, at least 1 should be rejected
		assert.GreaterOrEqual(t, successCount.Load(), int64(2))
		assert.GreaterOrEqual(t, rejectCount.Load(), int64(1))
	})

	t.Run("disabled max sessions allows all requests", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled:       false,
			MaxConcurrent: 1,
		}

		mw, limiter := middleware.MaxSessionsFromConfig(cfg, observability.NopLogger())
		assert.Nil(t, limiter)

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// All requests should succeed when disabled
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}
	})

	t.Run("nil config allows all requests", func(t *testing.T) {
		t.Parallel()

		mw, limiter := middleware.MaxSessionsFromConfig(nil, observability.NopLogger())
		assert.Nil(t, limiter)

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestFunctional_MaxSessions_RouteLevel(t *testing.T) {
	t.Parallel()

	t.Run("route level max sessions config", func(t *testing.T) {
		t.Parallel()

		// Simulate route-level configuration
		routeCfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 3,
			QueueSize:     2,
			QueueTimeout:  config.Duration(100 * time.Millisecond),
		}

		routeMw, limiter := middleware.MaxSessionsFromConfig(routeCfg, observability.NopLogger())
		require.NotNil(t, limiter)
		require.NotNil(t, routeMw)
		defer limiter.Stop()

		assert.Equal(t, int64(3), limiter.MaxConcurrent())
	})

	t.Run("route config overrides global", func(t *testing.T) {
		t.Parallel()

		// Global config with higher limit
		globalCfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 100,
		}

		// Route config with lower limit
		routeCfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 2,
		}

		globalMw, globalLimiter := middleware.MaxSessionsFromConfig(globalCfg, observability.NopLogger())
		require.NotNil(t, globalLimiter)
		require.NotNil(t, globalMw)
		defer globalLimiter.Stop()

		routeMw, routeLimiter := middleware.MaxSessionsFromConfig(routeCfg, observability.NopLogger())
		require.NotNil(t, routeLimiter)
		require.NotNil(t, routeMw)
		defer routeLimiter.Stop()

		// Route limiter should have lower limit
		assert.Equal(t, int64(2), routeLimiter.MaxConcurrent())
		assert.Equal(t, int64(100), globalLimiter.MaxConcurrent())
	})
}

func TestFunctional_MaxSessions_BackendLevel(t *testing.T) {
	t.Parallel()

	t.Run("backend max sessions config structure", func(t *testing.T) {
		t.Parallel()

		backendCfg := config.Backend{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "127.0.0.1", Port: 8080},
			},
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 10,
			},
		}

		assert.NotNil(t, backendCfg.MaxSessions)
		assert.True(t, backendCfg.MaxSessions.Enabled)
		assert.Equal(t, 10, backendCfg.MaxSessions.MaxConcurrent)
	})
}

func TestFunctional_MaxSessions_Inheritance(t *testing.T) {
	t.Parallel()

	t.Run("route inherits global when not specified", func(t *testing.T) {
		t.Parallel()

		// Global config
		globalCfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 50,
			QueueSize:     10,
			QueueTimeout:  config.Duration(5 * time.Second),
		}

		// Route without max sessions config should use global
		route := config.Route{
			Name: "test-route",
			// MaxSessions is nil - should inherit from global
		}

		// Determine effective config
		effectiveCfg := route.MaxSessions
		if effectiveCfg == nil {
			effectiveCfg = globalCfg
		}

		assert.Equal(t, 50, effectiveCfg.MaxConcurrent)
		assert.Equal(t, 10, effectiveCfg.QueueSize)
	})

	t.Run("route overrides global when specified", func(t *testing.T) {
		t.Parallel()

		// Global config
		globalCfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 50,
		}

		// Route with its own max sessions config
		route := config.Route{
			Name: "test-route",
			MaxSessions: &config.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 10,
			},
		}

		// Determine effective config
		effectiveCfg := route.MaxSessions
		if effectiveCfg == nil {
			effectiveCfg = globalCfg
		}

		assert.Equal(t, 10, effectiveCfg.MaxConcurrent)
	})

	t.Run("disabled route overrides enabled global", func(t *testing.T) {
		t.Parallel()

		// Global config enabled
		globalCfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 50,
		}

		// Route explicitly disables max sessions
		route := config.Route{
			Name: "test-route",
			MaxSessions: &config.MaxSessionsConfig{
				Enabled: false,
			},
		}

		// Determine effective config
		effectiveCfg := route.MaxSessions
		if effectiveCfg == nil {
			effectiveCfg = globalCfg
		}

		assert.False(t, effectiveCfg.Enabled)
	})
}

func TestFunctional_MaxSessions_Validation(t *testing.T) {
	t.Parallel()

	t.Run("valid config with all fields", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 100,
			QueueSize:     50,
			QueueTimeout:  config.Duration(10 * time.Second),
		}

		assert.True(t, cfg.Enabled)
		assert.Equal(t, 100, cfg.MaxConcurrent)
		assert.Equal(t, 50, cfg.QueueSize)
		assert.Equal(t, 10*time.Second, cfg.GetEffectiveQueueTimeout())
	})

	t.Run("default queue timeout when not specified", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 10,
			// QueueTimeout not specified
		}

		// Should use default timeout
		assert.Equal(t, config.DefaultMaxSessionsQueueTimeout, cfg.GetEffectiveQueueTimeout())
	})

	t.Run("zero queue size means reject immediately", func(t *testing.T) {
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
			time.Sleep(100 * time.Millisecond)
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

		// Second request should be rejected immediately (no queue)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		wg.Wait()
	})
}

func TestFunctional_MaxSessions_QueueBehavior(t *testing.T) {
	t.Parallel()

	t.Run("requests queue when at capacity", func(t *testing.T) {
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
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))

		var wg sync.WaitGroup
		var successCount atomic.Int64

		// Start 3 requests with max 1 concurrent but queue of 5
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code == http.StatusOK {
					successCount.Add(1)
				}
			}()
		}

		wg.Wait()

		// All 3 should eventually succeed due to queuing
		assert.Equal(t, int64(3), successCount.Load())
	})

	t.Run("queue timeout returns 503", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1,
			QueueSize:     5,
			QueueTimeout:  config.Duration(50 * time.Millisecond),
		}

		mw, limiter := middleware.MaxSessionsFromConfig(cfg, observability.NopLogger())
		require.NotNil(t, limiter)
		defer limiter.Stop()

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond) // Longer than queue timeout
			w.WriteHeader(http.StatusOK)
		}))

		var wg sync.WaitGroup
		var rejectCount atomic.Int64

		// Start first request that will hold the slot
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}()

		// Give first request time to acquire slot
		time.Sleep(10 * time.Millisecond)

		// Second request should timeout in queue
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code == http.StatusServiceUnavailable {
				rejectCount.Add(1)
			}
		}()

		wg.Wait()

		assert.Equal(t, int64(1), rejectCount.Load())
	})
}

func TestFunctional_MaxSessions_ContextCancellation(t *testing.T) {
	t.Parallel()

	t.Run("context cancellation releases waiting requests", func(t *testing.T) {
		t.Parallel()

		cfg := &config.MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1,
			QueueSize:     5,
			QueueTimeout:  config.Duration(5 * time.Second),
		}

		limiter := middleware.NewMaxSessionsLimiter(
			cfg.MaxConcurrent,
			cfg.QueueSize,
			cfg.GetEffectiveQueueTimeout(),
		)
		defer limiter.Stop()

		// Acquire the only slot
		ctx := context.Background()
		acquired := limiter.Acquire(ctx)
		require.True(t, acquired)

		// Create a cancellable context
		cancelCtx, cancel := context.WithCancel(context.Background())

		// Start a goroutine that will wait in queue
		done := make(chan bool)
		go func() {
			result := limiter.Acquire(cancelCtx)
			done <- result
		}()

		// Give goroutine time to enter queue
		time.Sleep(20 * time.Millisecond)

		// Cancel the context
		cancel()

		// Waiting goroutine should return false
		select {
		case result := <-done:
			assert.False(t, result)
		case <-time.After(200 * time.Millisecond):
			t.Error("waiting goroutine should have returned")
		}

		limiter.Release()
	})
}

func TestFunctional_MaxSessions_ResponseHeaders(t *testing.T) {
	t.Parallel()

	t.Run("rejected requests have proper headers", func(t *testing.T) {
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
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))

		// Start first request
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

		// Second request should be rejected with proper headers
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, "1", rec.Header().Get("Retry-After"))
		assert.Contains(t, rec.Body.String(), "max sessions exceeded")

		wg.Wait()
	})
}

func TestFunctional_MaxSessions_ConcurrentSafety(t *testing.T) {
	t.Parallel()

	t.Run("concurrent acquire and release is safe", func(t *testing.T) {
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
			time.Sleep(time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))

		var wg sync.WaitGroup
		var maxObserved atomic.Int64

		// Run many concurrent requests
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)

				current := limiter.Current()
				for {
					old := maxObserved.Load()
					if current <= old || maxObserved.CompareAndSwap(old, current) {
						break
					}
				}
			}()
		}

		wg.Wait()

		// Max observed should never exceed limit
		assert.LessOrEqual(t, maxObserved.Load(), int64(10))
		// Current should be 0 after all requests complete
		assert.Equal(t, int64(0), limiter.Current())
	})
}
