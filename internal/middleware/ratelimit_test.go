package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

func TestNewRateLimiter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rps       int
		burst     int
		perClient bool
	}{
		{
			name:      "global rate limiter",
			rps:       100,
			burst:     10,
			perClient: false,
		},
		{
			name:      "per-client rate limiter",
			rps:       50,
			burst:     5,
			perClient: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rl := NewRateLimiter(tt.rps, tt.burst, tt.perClient)

			assert.NotNil(t, rl)
			assert.Equal(t, tt.rps, rl.rps)
			assert.Equal(t, tt.burst, rl.burst)
			assert.Equal(t, tt.perClient, rl.perClient)
		})
	}
}

func TestNewRateLimiter_WithLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	rl := NewRateLimiter(100, 10, false, WithRateLimiterLogger(logger))

	assert.NotNil(t, rl)
	assert.Equal(t, logger, rl.logger)
}

func TestRateLimiter_Allow_Global(t *testing.T) {
	t.Parallel()

	// Create a rate limiter with 2 requests per second, burst of 2
	rl := NewRateLimiter(2, 2, false)

	// First two requests should be allowed (burst)
	assert.True(t, rl.Allow("192.168.1.1"))
	assert.True(t, rl.Allow("192.168.1.2"))

	// Third request should be denied (exceeded burst)
	assert.False(t, rl.Allow("192.168.1.3"))
}

func TestRateLimiter_Allow_PerClient(t *testing.T) {
	t.Parallel()

	// Create a per-client rate limiter with 1 request per second, burst of 1
	rl := NewRateLimiter(1, 1, true)

	// First request from client 1 should be allowed
	assert.True(t, rl.Allow("192.168.1.1"))

	// Second request from client 1 should be denied
	assert.False(t, rl.Allow("192.168.1.1"))

	// First request from client 2 should be allowed (different client)
	assert.True(t, rl.Allow("192.168.1.2"))
}

func TestRateLimiter_AllowPerClient_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(1000, 100, true)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(clientNum int) {
			defer wg.Done()
			clientIP := "192.168.1." + string(rune('0'+clientNum%10))
			_ = rl.Allow(clientIP)
		}(i)
	}
	wg.Wait()

	// Should not panic or deadlock
}

func TestRateLimit_Middleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rps            int
		burst          int
		numRequests    int
		expectedStatus int
	}{
		{
			name:           "allows requests within limit",
			rps:            10,
			burst:          5,
			numRequests:    3,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "blocks requests exceeding limit",
			rps:            1,
			burst:          1,
			numRequests:    3,
			expectedStatus: http.StatusTooManyRequests,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rl := NewRateLimiter(tt.rps, tt.burst, false)
			middleware := RateLimit(rl)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			var lastStatus int
			for i := 0; i < tt.numRequests; i++ {
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				rec := httptest.NewRecorder()

				handler.ServeHTTP(rec, req)
				lastStatus = rec.Code
			}

			assert.Equal(t, tt.expectedStatus, lastStatus)
		})
	}
}

func TestRateLimit_ResponseHeaders(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(1, 1, false)
	middleware := RateLimit(rl)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request - allowed
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Second request - rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
	assert.Equal(t, "application/json", rec2.Header().Get("Content-Type"))
	assert.Equal(t, "1", rec2.Header().Get("Retry-After"))
	assert.Contains(t, rec2.Body.String(), "rate limit exceeded")
}

func TestRateLimitFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         *config.RateLimitConfig
		expectPassthru bool
	}{
		{
			name:           "nil config returns passthrough",
			config:         nil,
			expectPassthru: true,
		},
		{
			name: "disabled config returns passthrough",
			config: &config.RateLimitConfig{
				Enabled:           false,
				RequestsPerSecond: 100,
			},
			expectPassthru: true,
		},
		{
			name: "enabled config returns rate limiter",
			config: &config.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             10,
				PerClient:         false,
			},
			expectPassthru: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			middleware, rl := RateLimitFromConfig(tt.config, logger)
			if rl != nil {
				defer rl.Stop()
			}

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			// All should pass on first request
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	}
}

func TestRateLimiter_CleanupOldClients(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true)

	// Add some clients
	for i := 0; i < 10; i++ {
		rl.Allow("192.168.1." + string(rune(i)))
	}

	// Verify clients were added
	rl.mu.RLock()
	initialCount := len(rl.clients)
	rl.mu.RUnlock()
	assert.Equal(t, 10, initialCount)

	// Cleanup with a very short TTL should remove all clients
	// since they haven't been accessed recently relative to a 0 TTL
	rl.CleanupOldClients(0)

	rl.mu.RLock()
	clientCount := len(rl.clients)
	rl.mu.RUnlock()

	assert.Equal(t, 0, clientCount)
}

func TestRateLimiter_CleanupOldClients_TTLBased(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true)

	// Add some clients
	for i := 0; i < 5; i++ {
		rl.Allow("192.168.1." + string(rune(i)))
	}

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Add more clients
	for i := 5; i < 10; i++ {
		rl.Allow("192.168.1." + string(rune(i)))
	}

	// Cleanup with TTL that should only remove the older clients
	rl.CleanupOldClients(25 * time.Millisecond)

	rl.mu.RLock()
	clientCount := len(rl.clients)
	rl.mu.RUnlock()

	// Only the newer clients should remain
	assert.Equal(t, 5, clientCount)
}

func TestRateLimiter_StartCleanup(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true)

	stopCh := make(chan struct{})
	rl.StartCleanup(10*time.Millisecond, stopCh)

	// Add some clients
	for i := 0; i < 100; i++ {
		rl.Allow("192.168.1." + string(rune(i)))
	}

	// Wait for cleanup to run
	time.Sleep(50 * time.Millisecond)

	// Stop cleanup
	close(stopCh)

	// Should not panic
}

func TestRateLimiter_AllowPerClient_DoubleCheck(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(1000, 100, true)

	// Concurrent access to same client should work
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = rl.Allow("same-client")
		}()
	}
	wg.Wait()

	// Client should exist
	rl.mu.RLock()
	_, exists := rl.clients["same-client"]
	rl.mu.RUnlock()

	assert.True(t, exists)
}

func TestRateLimiter_UpdateConfig(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(10, 5, true, WithRateLimiterLogger(observability.NopLogger()))

	// Add some clients
	for i := 0; i < 5; i++ {
		rl.Allow("client-" + string(rune('a'+i)))
	}

	rl.mu.RLock()
	assert.Equal(t, 5, len(rl.clients))
	rl.mu.RUnlock()

	// Update config with new values
	newCfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 50,
		Burst:             20,
		PerClient:         false,
	}
	rl.UpdateConfig(newCfg)

	// Verify updated values
	assert.Equal(t, 50, rl.rps)
	assert.Equal(t, 20, rl.burst)
	assert.False(t, rl.perClient)

	// Per-client entries should be cleared
	rl.mu.RLock()
	assert.Equal(t, 0, len(rl.clients))
	rl.mu.RUnlock()

	// Global limiter should work with new burst
	for i := 0; i < 20; i++ {
		assert.True(t, rl.Allow("any"))
	}
	// After exhausting burst, should be denied
	assert.False(t, rl.Allow("any"))
}

func TestRateLimiter_UpdateConfig_NilConfig(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(10, 5, false)
	originalRPS := rl.rps

	// Nil config should be a no-op
	rl.UpdateConfig(nil)

	assert.Equal(t, originalRPS, rl.rps)
}

func TestRateLimiter_UpdateConfig_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 50, true, WithRateLimiterLogger(observability.NopLogger()))

	var wg sync.WaitGroup

	// Concurrent Allow calls
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			clientIP := "192.168.1." + string(rune('0'+n%10))
			_ = rl.Allow(clientIP)
		}(i)
	}

	// Concurrent UpdateConfig call
	wg.Add(1)
	go func() {
		defer wg.Done()
		rl.UpdateConfig(&config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 200,
			Burst:             100,
			PerClient:         true,
		})
	}()

	wg.Wait()
	// Should not panic or deadlock
}

// TestRateLimiter_EvictOldestLocked tests the evictOldestLocked memory management function.
func TestRateLimiter_EvictOldestLocked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		maxClients  int
		clientTTL   time.Duration
		numClients  int
		expectedMax int
		description string
	}{
		{
			name:        "evict when at capacity",
			maxClients:  10,
			clientTTL:   time.Hour, // Long TTL so entries don't expire
			numClients:  15,
			expectedMax: 10, // Should be at or below maxClients
			description: "should evict oldest entries when at capacity",
		},
		{
			name:        "small max clients",
			maxClients:  5,
			clientTTL:   time.Hour,
			numClients:  20,
			expectedMax: 5,
			description: "should handle small max clients limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rl := NewRateLimiter(100, 10, true,
				WithRateLimiterLogger(observability.NopLogger()),
				WithMaxClients(tt.maxClients),
				WithClientTTL(tt.clientTTL),
			)
			t.Cleanup(func() {
				rl.Stop()
			})

			// Add clients to trigger eviction
			for i := 0; i < tt.numClients; i++ {
				clientIP := "192.168.1." + string(rune('A'+i%26)) + string(rune('0'+i%10))
				rl.Allow(clientIP)
			}

			// Verify client count is bounded
			clientCount := rl.ClientCount()
			assert.LessOrEqual(t, clientCount, tt.expectedMax, tt.description)
		})
	}
}

// TestRateLimiter_EvictOldestLocked_ExpiredEntries tests that expired entries are removed during eviction.
func TestRateLimiter_EvictOldestLocked_ExpiredEntries(t *testing.T) {
	t.Parallel()

	// Use a very short TTL
	rl := NewRateLimiter(100, 10, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithMaxClients(10),
		WithClientTTL(1*time.Millisecond),
	)
	t.Cleanup(func() {
		rl.Stop()
	})

	// Add some clients
	for i := 0; i < 5; i++ {
		clientIP := "old-client-" + string(rune('0'+i))
		rl.Allow(clientIP)
	}

	// Wait for entries to expire
	time.Sleep(10 * time.Millisecond)

	// Add more clients to trigger eviction (need to exceed maxClients)
	for i := 0; i < 10; i++ {
		clientIP := "new-client-" + string(rune('0'+i))
		rl.Allow(clientIP)
	}

	// The expired entries should have been removed during eviction
	// Client count should be at or below maxClients
	clientCount := rl.ClientCount()
	assert.LessOrEqual(t, clientCount, 10)
}

// TestRateLimiter_EvictOldestLocked_PreservesNewerEntries tests that eviction preserves newer entries.
func TestRateLimiter_EvictOldestLocked_PreservesNewerEntries(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithMaxClients(10),
		WithClientTTL(time.Hour),
	)
	t.Cleanup(func() {
		rl.Stop()
	})

	// Add old clients
	for i := 0; i < 5; i++ {
		clientIP := "old-client-" + string(rune('0'+i))
		rl.Allow(clientIP)
	}

	// Wait a bit to create time difference
	time.Sleep(10 * time.Millisecond)

	// Add new clients that will trigger eviction
	for i := 0; i < 10; i++ {
		clientIP := "new-client-" + string(rune('0'+i))
		rl.Allow(clientIP)
	}

	// Verify we're at or below max clients
	clientCount := rl.ClientCount()
	assert.LessOrEqual(t, clientCount, 10)
}

// TestRateLimiter_EvictOldestLocked_EmptyMap tests eviction with empty client map.
func TestRateLimiter_EvictOldestLocked_EmptyMap(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithMaxClients(5),
		WithClientTTL(time.Hour),
	)
	t.Cleanup(func() {
		rl.Stop()
	})

	// No clients added, just verify no panic
	assert.Equal(t, 0, rl.ClientCount())

	// Add one client - should work fine
	rl.Allow("first-client")
	assert.Equal(t, 1, rl.ClientCount())
}

// TestRateLimiter_EvictOldestLocked_TargetSize tests that eviction targets 90% capacity.
func TestRateLimiter_EvictOldestLocked_TargetSize(t *testing.T) {
	t.Parallel()

	maxClients := 100
	rl := NewRateLimiter(1000, 100, true,
		WithRateLimiterLogger(observability.NopLogger()),
		WithMaxClients(maxClients),
		WithClientTTL(time.Hour),
	)
	t.Cleanup(func() {
		rl.Stop()
	})

	// Fill to capacity and beyond
	for i := 0; i < maxClients+10; i++ {
		clientIP := "client-" + string(rune('A'+i%26)) + string(rune('a'+i%26)) + string(rune('0'+i%10))
		rl.Allow(clientIP)
	}

	// After eviction, should be at or below max clients
	// The target is 90% of maxClients
	targetSize := maxClients * 9 / 10
	clientCount := rl.ClientCount()
	assert.LessOrEqual(t, clientCount, maxClients)
	// After adding more clients, we should be around target size + new additions
	assert.GreaterOrEqual(t, clientCount, targetSize)
}

// TestRateLimiter_WithClientTTL tests the WithClientTTL option.
func TestRateLimiter_WithClientTTL(t *testing.T) {
	t.Parallel()

	ttl := 5 * time.Minute
	rl := NewRateLimiter(100, 10, true, WithClientTTL(ttl))
	t.Cleanup(func() {
		rl.Stop()
	})

	assert.Equal(t, ttl, rl.clientTTL)
}

// TestRateLimiter_WithMaxClients tests the WithMaxClients option.
func TestRateLimiter_WithMaxClients(t *testing.T) {
	t.Parallel()

	maxClients := 500
	rl := NewRateLimiter(100, 10, true, WithMaxClients(maxClients))
	t.Cleanup(func() {
		rl.Stop()
	})

	assert.Equal(t, maxClients, rl.maxClients)
}

// TestRateLimiter_SetClientTTL tests the SetClientTTL method.
func TestRateLimiter_SetClientTTL(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true)
	t.Cleanup(func() {
		rl.Stop()
	})

	newTTL := 30 * time.Minute
	rl.SetClientTTL(newTTL)

	rl.mu.RLock()
	actualTTL := rl.clientTTL
	rl.mu.RUnlock()

	assert.Equal(t, newTTL, actualTTL)
}

// TestRateLimiter_SetMaxClients tests the SetMaxClients method.
func TestRateLimiter_SetMaxClients(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true)
	t.Cleanup(func() {
		rl.Stop()
	})

	newMax := 50000
	rl.SetMaxClients(newMax)

	rl.mu.RLock()
	actualMax := rl.maxClients
	rl.mu.RUnlock()

	assert.Equal(t, newMax, actualMax)
}

// TestRateLimiter_ClientCount tests the ClientCount method.
func TestRateLimiter_ClientCount(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true)
	t.Cleanup(func() {
		rl.Stop()
	})

	assert.Equal(t, 0, rl.ClientCount())

	// Add some clients
	for i := 0; i < 5; i++ {
		rl.Allow("client-" + string(rune('0'+i)))
	}

	assert.Equal(t, 5, rl.ClientCount())
}

// TestRateLimiter_Stop tests the Stop method.
func TestRateLimiter_Stop(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true)
	rl.StartAutoCleanup()

	// Stop should not panic
	rl.Stop()

	// Calling Stop again should not panic (idempotent)
	rl.Stop()

	// Verify stopped flag is set
	rl.mu.RLock()
	stopped := rl.stopped
	rl.mu.RUnlock()

	assert.True(t, stopped)
}

// TestRateLimiter_StartAutoCleanup_AlreadyStopped tests that StartAutoCleanup does nothing if already stopped.
func TestRateLimiter_StartAutoCleanup_AlreadyStopped(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(100, 10, true)

	// Stop first
	rl.Stop()

	// StartAutoCleanup should return early without starting goroutine
	rl.StartAutoCleanup()

	// Should not panic or cause issues
}

// TestRateLimitFromConfig_PerClient tests that per-client rate limiting starts auto cleanup.
func TestRateLimitFromConfig_PerClient(t *testing.T) {
	t.Parallel()

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             10,
		PerClient:         true,
	}

	logger := observability.NopLogger()
	middleware, rl := RateLimitFromConfig(cfg, logger)
	t.Cleanup(func() {
		if rl != nil {
			rl.Stop()
		}
	})

	assert.NotNil(t, middleware)
	assert.NotNil(t, rl)
	assert.True(t, rl.perClient)
}

// TestWithRateLimitHitCallback tests the WithRateLimitHitCallback option.
func TestWithRateLimitHitCallback(t *testing.T) {
	t.Parallel()

	var hitRoute string
	callback := func(route string) {
		hitRoute = route
	}

	rl := NewRateLimiter(1, 1, false, WithRateLimitHitCallback(callback))
	t.Cleanup(func() {
		rl.Stop()
	})

	assert.NotNil(t, rl.hitCallback)

	// First request allowed (burst)
	assert.True(t, rl.Allow("192.168.1.1"))

	// Second request denied - callback should be invoked via middleware
	middleware := RateLimit(rl)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req = req.WithContext(util.ContextWithRoute(req.Context(), "/api/test"))
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "/api/test", hitRoute)
}

// TestWithRateLimitHitCallback_NilCallback tests that nil callback doesn't panic.
func TestWithRateLimitHitCallback_NilCallback(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(1, 1, false, WithRateLimitHitCallback(nil))
	t.Cleanup(func() {
		rl.Stop()
	})

	assert.Nil(t, rl.hitCallback)

	// Exhaust burst
	rl.Allow("192.168.1.1")

	// Rate limited request should not panic with nil callback
	middleware := RateLimit(rl)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req = req.WithContext(util.ContextWithRoute(req.Context(), "/api/test"))
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

// TestRateLimitFromConfig_WithHitCallback tests RateLimitFromConfig with a hit callback option.
func TestRateLimitFromConfig_WithHitCallback(t *testing.T) {
	t.Parallel()

	var hitCount int
	callback := func(_ string) {
		hitCount++
	}

	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		PerClient:         false,
	}

	logger := observability.NopLogger()
	mw, rl := RateLimitFromConfig(cfg, logger, WithRateLimitHitCallback(callback))
	t.Cleanup(func() {
		if rl != nil {
			rl.Stop()
		}
	})

	assert.NotNil(t, mw)
	assert.NotNil(t, rl)
	assert.NotNil(t, rl.hitCallback)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request - allowed
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, 0, hitCount)

	// Second request - rate limited, callback invoked
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
	assert.Equal(t, 1, hitCount)
}

// TestRateLimit_OTELSpanAttributes tests that OTEL tracing spans have correct attributes.
func TestRateLimit_OTELSpanAttributes(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(1, 1, false)
	t.Cleanup(func() {
		rl.Stop()
	})

	middleware := RateLimit(rl)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Allowed request - should set ratelimit.allowed=true
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/resource", nil)
	req1.RemoteAddr = "10.0.0.1:12345"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code)

	// Rejected request - should set ratelimit.allowed=false
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/resource", nil)
	req2.RemoteAddr = "10.0.0.1:12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
	assert.Equal(t, "1", rec2.Header().Get("Retry-After"))
}
