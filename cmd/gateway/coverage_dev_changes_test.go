// Package main provides tests for DEV-001 (reload metrics with custom registry),
// DEV-004 (metrics server security headers), and DEV-009 (audit metrics registry).
package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// DEV-001: newReloadMetrics / ensureReloadMetrics
// ============================================================================

func TestNewReloadMetrics(t *testing.T) {
	t.Parallel()

	m := observability.NewMetrics("test_reload_metrics")
	rm := newReloadMetrics(m)

	require.NotNil(t, rm)
	require.NotNil(t, rm.configReloadTotal)
	require.NotNil(t, rm.configReloadDuration)
	require.NotNil(t, rm.configReloadLastSuccess)
	require.NotNil(t, rm.configWatcherStatus)
	require.NotNil(t, rm.configReloadComponentTotal)

	// Verify metrics are registered with the custom registry
	handler := m.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	// The metrics should be registered but may not have values yet
	// Just verify the handler works
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, body)
}

func TestNewReloadMetrics_RecordMetrics(t *testing.T) {
	t.Parallel()

	m := observability.NewMetrics("test_reload_record")
	rm := newReloadMetrics(m)

	// Exercise all metric recording paths
	rm.configReloadTotal.WithLabelValues("success").Inc()
	rm.configReloadTotal.WithLabelValues("error").Inc()
	rm.configReloadDuration.Observe(0.5)
	rm.configReloadLastSuccess.SetToCurrentTime()
	rm.configWatcherStatus.Set(1)
	rm.configReloadComponentTotal.WithLabelValues("routes", "success").Inc()
	rm.configReloadComponentTotal.WithLabelValues("backends", "error").Inc()
	rm.configReloadComponentTotal.WithLabelValues("rate_limiter", "success").Inc()
	rm.configReloadComponentTotal.WithLabelValues("max_sessions", "success").Inc()
	rm.configReloadComponentTotal.WithLabelValues("audit", "success").Inc()

	// Verify metrics appear in the handler output
	handler := m.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "gateway_config_reload_total")
	assert.Contains(t, body, "gateway_config_reload_duration_seconds")
	assert.Contains(t, body, "gateway_config_reload_last_success_timestamp")
	assert.Contains(t, body, "gateway_config_watcher_running")
	assert.Contains(t, body, "gateway_config_reload_component_total")
}

func TestEnsureReloadMetrics_AlreadyInitialized(t *testing.T) {
	t.Parallel()

	m := observability.NewMetrics("test_ensure_existing")
	rm := newReloadMetrics(m)

	app := &application{
		reloadMetrics: rm,
	}

	result := ensureReloadMetrics(app)
	assert.Equal(t, rm, result, "should return existing reload metrics")
}

func TestEnsureReloadMetrics_LazyInitialization(t *testing.T) {
	t.Parallel()

	app := &application{
		reloadMetrics: nil,
	}

	result := ensureReloadMetrics(app)
	require.NotNil(t, result, "should lazily initialize reload metrics")
	require.NotNil(t, result.configReloadTotal)
	require.NotNil(t, result.configReloadDuration)
	require.NotNil(t, result.configReloadLastSuccess)
	require.NotNil(t, result.configWatcherStatus)
	require.NotNil(t, result.configReloadComponentTotal)

	// Calling again should return the same instance
	result2 := ensureReloadMetrics(app)
	assert.Equal(t, result, result2, "should return same instance on second call")
}

// ============================================================================
// DEV-004: securityHeadersMiddleware
// ============================================================================

func TestSecurityHeadersMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		innerHandler   http.Handler
		expectedStatus int
		expectedBody   string
	}{
		{
			name: "adds security headers to 200 response",
			innerHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			}),
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name: "adds security headers to 404 response",
			innerHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("Not Found"))
			}),
			expectedStatus: http.StatusNotFound,
			expectedBody:   "Not Found",
		},
		{
			name: "adds security headers to metrics handler",
			innerHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("# HELP test_metric A test metric"))
			}),
			expectedStatus: http.StatusOK,
			expectedBody:   "# HELP test_metric A test metric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := securityHeadersMiddleware(tt.innerHandler)

			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			// Verify status code
			assert.Equal(t, tt.expectedStatus, rec.Code)

			// Verify body
			assert.Equal(t, tt.expectedBody, rec.Body.String())

			// Verify security headers
			assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"),
				"X-Content-Type-Options should be nosniff")
			assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"),
				"X-Frame-Options should be DENY")
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
				"Cache-Control should be no-store")
		})
	}
}

func TestSecurityHeadersMiddleware_PreservesInnerHeaders(t *testing.T) {
	t.Parallel()

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})

	handler := securityHeadersMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Security headers should be present
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	// Inner handler's headers should also be present
	assert.Equal(t, "custom-value", rec.Header().Get("X-Custom-Header"))
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestSecurityHeadersMiddleware_PassesRequestThrough(t *testing.T) {
	t.Parallel()

	var capturedPath string
	var capturedMethod string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	})

	handler := securityHeadersMiddleware(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "/api/data", capturedPath)
	assert.Equal(t, http.MethodPost, capturedMethod)
}
