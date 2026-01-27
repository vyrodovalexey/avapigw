package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TestMatchWildcardOrigin_Comprehensive tests the matchWildcardOrigin function with various patterns.
func TestMatchWildcardOrigin_Comprehensive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		origin  string
		pattern string
		want    bool
	}{
		{
			name:    "matching subdomain with https",
			origin:  "https://sub.example.com",
			pattern: "*.example.com",
			want:    true,
		},
		{
			name:    "matching subdomain with port",
			origin:  "https://sub.example.com:8080",
			pattern: "*.example.com",
			want:    true,
		},
		{
			name:    "matching deep subdomain",
			origin:  "http://api.v2.example.com",
			pattern: "*.example.com",
			want:    true,
		},
		{
			name:    "non-matching domain",
			origin:  "https://other.com",
			pattern: "*.example.com",
			want:    false,
		},
		{
			name:    "exact domain without subdomain does not match",
			origin:  "https://example.com",
			pattern: "*.example.com",
			want:    false,
		},
		{
			name:    "non-wildcard pattern returns false",
			origin:  "https://sub.example.com",
			pattern: "example.com",
			want:    false,
		},
		{
			name:    "origin without protocol",
			origin:  "sub.example.com",
			pattern: "*.example.com",
			want:    true,
		},
		{
			name:    "origin with http protocol",
			origin:  "http://api.example.com",
			pattern: "*.example.com",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := matchWildcardOrigin(tt.origin, tt.pattern)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCORS_WildcardOriginPatternMatching tests CORS with wildcard origin patterns.
func TestCORS_WildcardOriginPatternMatching(t *testing.T) {
	t.Parallel()

	corsMiddleware := CORS(CORSConfig{
		AllowOrigins: []string{"*.example.com"},
		AllowMethods: []string{"GET"},
		AllowHeaders: []string{"Content-Type"},
	})

	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name         string
		origin       string
		expectOrigin string
	}{
		{
			name:         "matching wildcard subdomain",
			origin:       "https://api.example.com",
			expectOrigin: "https://api.example.com",
		},
		{
			name:         "non-matching origin gets no header",
			origin:       "https://other.com",
			expectOrigin: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectOrigin, rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

// TestBodyLimitFromRequestLimits_NilConfigUsesDefaults tests BodyLimitFromRequestLimits with nil config.
func TestBodyLimitFromRequestLimits_NilConfigUsesDefaults(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	mw := BodyLimitFromRequestLimits(nil, logger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("test body")))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestRateLimitFromConfig_PerClientEnabled tests RateLimitFromConfig with per-client rate limiting.
func TestRateLimitFromConfig_PerClientEnabled(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             200,
		PerClient:         true,
	}

	mw, rl := RateLimitFromConfig(cfg, logger)
	require.NotNil(t, mw)
	require.NotNil(t, rl)

	// Clean up
	defer rl.Stop()

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestStartAutoCleanup_RunsAndCleansUp tests the StartAutoCleanup method.
func TestStartAutoCleanup_RunsAndCleansUp(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(10, 20, true)
	rl.SetClientTTL(50 * time.Millisecond)

	// Add some clients
	rl.Allow("client1")
	rl.Allow("client2")

	// StartAutoCleanup starts a goroutine; verify it doesn't panic
	rl.StartAutoCleanup()

	// The MinCleanupInterval is 10s, so the ticker won't fire in a short test.
	// Instead, manually call CleanupOldClients to verify cleanup logic works.
	time.Sleep(100 * time.Millisecond) // Wait for TTL to expire

	rl.CleanupOldClients(rl.clientTTL)

	// Stop the rate limiter
	rl.Stop()

	// Clients should have been cleaned up by the manual call
	rl.mu.RLock()
	count := len(rl.clients)
	rl.mu.RUnlock()

	assert.Equal(t, 0, count)
}

// TestStartAutoCleanup_OnStoppedLimiter tests StartAutoCleanup on a stopped limiter.
func TestStartAutoCleanup_OnStoppedLimiter(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(10, 20, true)
	rl.Stop()

	// Should not panic
	rl.StartAutoCleanup()
}

// TestSetClientTTL_UpdatesTTL tests the SetClientTTL method.
func TestSetClientTTL_UpdatesTTL(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(10, 20, true)
	defer rl.Stop()

	rl.SetClientTTL(30 * time.Second)

	rl.mu.RLock()
	ttl := rl.clientTTL
	rl.mu.RUnlock()

	assert.Equal(t, 30*time.Second, ttl)
}

// TestSafeIntToUint32_AllEdgeCases tests safeIntToUint32 with edge cases.
func TestSafeIntToUint32_AllEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    int
		expected uint32
	}{
		{
			name:     "negative value returns 0",
			input:    -1,
			expected: 0,
		},
		{
			name:     "zero returns 0",
			input:    0,
			expected: 0,
		},
		{
			name:     "normal value",
			input:    100,
			expected: 100,
		},
		{
			name:     "max uint32 value",
			input:    int(^uint32(0)),
			expected: ^uint32(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := safeIntToUint32(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRetry_BodyTooLargeForRetryBuffering tests that requests with bodies too large
// for retry buffering are executed without retry.
func TestRetry_BodyTooLargeForRetryBuffering(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := RetryConfig{
		Attempts:    3,
		RetryOn:     []string{"5xx"},
		BackoffBase: time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
		MaxBodySize: 5, // Very small limit
	}

	callCount := 0
	retryMiddleware := Retry(cfg, logger)
	handler := retryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Read body to verify it's available
		body, _ := io.ReadAll(r.Body)
		_ = body
		w.WriteHeader(http.StatusInternalServerError)
	}))

	// Body larger than MaxBodySize via Content-Length header
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("this is a longer body")))
	req.ContentLength = 21
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should only be called once (no retry)
	assert.Equal(t, 1, callCount)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestRetry_BodyExceedsLimitDuringRead tests retry when body exceeds limit during read.
func TestRetry_BodyExceedsLimitDuringRead(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := RetryConfig{
		Attempts:    3,
		RetryOn:     []string{"5xx"},
		BackoffBase: time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
		MaxBodySize: 5,
	}

	callCount := 0
	retryMiddleware := Retry(cfg, logger)
	handler := retryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))

	// Body larger than MaxBodySize but Content-Length is unknown
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("this is a longer body")))
	req.ContentLength = -1 // Unknown content length
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should only be called once (no retry because body too large)
	assert.Equal(t, 1, callCount)
}

// TestIsOriginAllowed_EmptyOriginReturnsFalse tests isOriginAllowed with empty origin.
func TestIsOriginAllowed_EmptyOriginReturnsFalse(t *testing.T) {
	t.Parallel()

	headers := newCORSHeaders(CORSConfig{
		AllowOrigins: []string{"https://example.com"},
	})

	assert.False(t, headers.isOriginAllowed(""))
}

// TestNewCORSHeaders_AllOptions tests newCORSHeaders with all options set.
func TestNewCORSHeaders_AllOptions(t *testing.T) {
	t.Parallel()

	headers := newCORSHeaders(CORSConfig{
		AllowOrigins:     []string{"*.example.com", "https://specific.com"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Content-Type"},
		ExposeHeaders:    []string{"X-Custom"},
		AllowCredentials: true,
		MaxAge:           3600,
	})

	assert.True(t, headers.isOriginAllowed("https://sub.example.com"))
	assert.True(t, headers.isOriginAllowed("https://specific.com"))
	assert.False(t, headers.isOriginAllowed("https://other.com"))
	assert.True(t, headers.allowCredentials)
	assert.True(t, headers.hasMaxAge)
	assert.True(t, headers.hasExposeHeaders)
	assert.True(t, headers.hasAllowMethods)
	assert.True(t, headers.hasAllowHeaders)
}

// TestRetry_ZeroMaxBodySize tests retry with zero MaxBodySize uses default.
func TestRetry_ZeroMaxBodySize(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := RetryConfig{
		Attempts:    2,
		RetryOn:     []string{"5xx"},
		BackoffBase: time.Millisecond,
		BackoffMax:  10 * time.Millisecond,
		MaxBodySize: 0, // Should use default
	}

	callCount := 0
	retryMiddleware := Retry(cfg, logger)
	handler := retryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("small body")))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, 1, callCount) // Success on first try
	assert.Equal(t, http.StatusOK, rec.Code)
}
