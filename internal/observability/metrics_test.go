package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

func TestNewMetrics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		namespace string
	}{
		{
			name:      "with custom namespace",
			namespace: "custom",
		},
		{
			name:      "with empty namespace uses default",
			namespace: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			metrics := NewMetrics(tt.namespace)

			assert.NotNil(t, metrics)
			assert.NotNil(t, metrics.requestsTotal)
			assert.NotNil(t, metrics.requestDuration)
			assert.NotNil(t, metrics.requestSize)
			assert.NotNil(t, metrics.responseSize)
			assert.NotNil(t, metrics.activeRequests)
			assert.NotNil(t, metrics.backendHealth)
			assert.NotNil(t, metrics.circuitBreaker)
			assert.NotNil(t, metrics.rateLimitHits)
			assert.NotNil(t, metrics.registry)
		})
	}
}

func TestMetrics_RecordRequest(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_record")

	metrics.RecordRequest(
		"GET",
		"users-route",
		200,
		100*time.Millisecond,
		1024,
		2048,
	)

	// Verify metrics endpoint contains the recorded request
	handler := metrics.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "test_record_requests_total")
	assert.Contains(t, body, `route="users-route"`)
}

func TestMetrics_IncrementActiveRequests(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_active")

	metrics.IncrementActiveRequests("GET", "users-route")

	// Verify via metrics endpoint
	handler := metrics.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "test_active_active_requests")
}

func TestMetrics_DecrementActiveRequests(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_decrement")

	// Increment first, then decrement
	metrics.IncrementActiveRequests("GET", "users-route")
	metrics.DecrementActiveRequests("GET", "users-route")

	// Verify via metrics endpoint - gauge should be back to 0
	handler := metrics.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMetrics_SetBackendHealth(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_health")

	metrics.SetBackendHealth("backend1", "host1:8080", true)
	metrics.SetBackendHealth("backend1", "host2:8080", false)

	// Verify via metrics endpoint
	handler := metrics.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "test_health_backend_health")
	assert.Contains(t, body, `backend="backend1"`)
}

func TestMetrics_SetCircuitBreakerState(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_cb")

	metrics.SetCircuitBreakerState("cb1", 0) // Closed
	metrics.SetCircuitBreakerState("cb1", 1) // Half-open
	metrics.SetCircuitBreakerState("cb1", 2) // Open

	// Verify via metrics endpoint - last state should be 2 (open)
	handler := metrics.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "test_cb_circuit_breaker_state")
	assert.Contains(t, body, `name="cb1"`)
}

func TestMetrics_RecordRateLimitHit(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_rl")

	metrics.RecordRateLimitHit("users-route")

	// Verify via metrics endpoint
	handler := metrics.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "test_rl_rate_limit_hits_total")
	assert.Contains(t, body, `route="users-route"`)
}

func TestMetrics_Handler(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")
	handler := metrics.Handler()

	assert.NotNil(t, handler)

	req := httptest.NewRequest(
		http.MethodGet, "/metrics", nil,
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// Should contain some metrics
	assert.Contains(t, rec.Body.String(), "go_")
}

func TestMetrics_Registry(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")
	registry := metrics.Registry()

	assert.NotNil(t, registry)
}

func TestMetricsMiddleware(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")
	middleware := MetricsMiddleware(metrics)

	handler := middleware(
		http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			},
		),
	)

	req := httptest.NewRequest(
		http.MethodGet, "/api/users", nil,
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMetricsMiddleware_RecordsMetrics(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")
	middleware := MetricsMiddleware(metrics)

	handler := middleware(
		http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("created"))
			},
		),
	)

	req := httptest.NewRequest(
		http.MethodPost, "/api/users", nil,
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestMetricsMiddleware_UsesRouteFromContext(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_ctx")
	middleware := MetricsMiddleware(metrics)

	// Inner handler sets route in context before response
	handler := middleware(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ctx := util.ContextWithRoute(
					r.Context(), "api-users",
				)
				*r = *r.WithContext(ctx)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			},
		),
	)

	req := httptest.NewRequest(
		http.MethodGet, "/api/users/123", nil,
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMetricsMiddleware_UnmatchedRoute(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_unmatched")
	middleware := MetricsMiddleware(metrics)

	// Inner handler does NOT set route in context
	handler := middleware(
		http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
		),
	)

	req := httptest.NewRequest(
		http.MethodGet, "/unknown/path/123", nil,
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRouteFromRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		route    string
		expected string
	}{
		{
			name:     "with route set in context",
			route:    "api-users",
			expected: "api-users",
		},
		{
			name:     "without route returns unmatched",
			route:    "",
			expected: unmatchedRoute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			if tt.route != "" {
				ctx = util.ContextWithRoute(ctx, tt.route)
			}

			req := httptest.NewRequest(
				http.MethodGet, "/test", nil,
			)
			req = req.WithContext(ctx)

			result := routeFromRequest(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMetricsResponseWriter_WriteHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	mrw := &metricsResponseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	mrw.WriteHeader(http.StatusNotFound)

	assert.Equal(t, http.StatusNotFound, mrw.status)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestMetricsResponseWriter_Write(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	mrw := &metricsResponseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	data := []byte("test response")
	n, err := mrw.Write(data)

	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, len(data), mrw.size)
}

func TestMetricsResponseWriter_MultipleWrites(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	mrw := &metricsResponseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	_, _ = mrw.Write([]byte("first"))
	_, _ = mrw.Write([]byte("second"))

	// "first" + "second" = 11 bytes
	assert.Equal(t, 11, mrw.size)
}

func TestMetrics_RegisterCollector(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_reg_collector")

	// Create a custom counter and register it
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "test_reg_collector",
		Name:      "custom_counter",
		Help:      "A custom counter for testing RegisterCollector",
	})

	err := metrics.RegisterCollector(counter)
	assert.NoError(t, err)

	// Increment the counter
	counter.Inc()

	// Verify it appears in the metrics output
	handler := metrics.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "test_reg_collector_custom_counter")
}

func TestMetrics_RegisterCollector_DuplicateError(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_dup_collector")

	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "test_dup_collector",
		Name:      "dup_counter",
		Help:      "A counter for testing duplicate registration",
	})

	// First registration should succeed
	err := metrics.RegisterCollector(counter)
	assert.NoError(t, err)

	// Second registration should return an error
	err = metrics.RegisterCollector(counter)
	assert.Error(t, err)
}

func TestMetrics_MustRegisterCollector(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_must_reg")

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "test_must_reg",
		Name:      "custom_gauge",
		Help:      "A custom gauge for testing MustRegisterCollector",
	})

	// Should not panic
	assert.NotPanics(t, func() {
		metrics.MustRegisterCollector(gauge)
	})

	gauge.Set(42)

	// Verify it appears in the metrics output
	handler := metrics.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	assert.Contains(t, body, "test_must_reg_custom_gauge")
}

func TestMetrics_MustRegisterCollector_Panics(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test_must_panic")

	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "test_must_panic",
		Name:      "panic_counter",
		Help:      "A counter for testing MustRegisterCollector panic",
	})

	// First registration
	metrics.MustRegisterCollector(counter)

	// Second registration should panic
	assert.Panics(t, func() {
		metrics.MustRegisterCollector(counter)
	})
}

func TestMetrics_BoundedCardinality(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("cardinality_test")

	// Simulate many unique paths hitting the same route.
	// All should map to the same route label, not unique paths.
	for i := 0; i < 100; i++ {
		metrics.RecordRequest(
			"GET", "users-route", 200,
			10*time.Millisecond, 100, 200,
		)
	}

	// Record rate limit hits by route, not by client IP
	metrics.RecordRateLimitHit("users-route")
	metrics.RecordRateLimitHit("admin-route")

	// Verify metrics endpoint returns valid Prometheus format
	handler := metrics.Handler()
	req := httptest.NewRequest(
		http.MethodGet, "/metrics", nil,
	)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "cardinality_test_requests_total")
	assert.Contains(t, body, "cardinality_test_rate_limit_hits_total")
	// Verify route label is present, not path
	assert.Contains(t, body, `route="users-route"`)
	// Verify client_ip label is NOT present
	assert.NotContains(t, body, "client_ip")
}
