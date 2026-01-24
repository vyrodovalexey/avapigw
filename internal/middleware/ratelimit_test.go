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
