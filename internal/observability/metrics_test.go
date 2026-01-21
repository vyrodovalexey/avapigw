package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

	metrics := NewMetrics("test")

	// Should not panic
	metrics.RecordRequest(
		"GET",
		"/api/users",
		"users-route",
		200,
		100*time.Millisecond,
		1024,
		2048,
	)
}

func TestMetrics_IncrementActiveRequests(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")

	// Should not panic
	metrics.IncrementActiveRequests("GET", "/api/users")
}

func TestMetrics_DecrementActiveRequests(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")

	// Increment first
	metrics.IncrementActiveRequests("GET", "/api/users")

	// Should not panic
	metrics.DecrementActiveRequests("GET", "/api/users")
}

func TestMetrics_SetBackendHealth(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")

	// Should not panic
	metrics.SetBackendHealth("backend1", "host1:8080", true)
	metrics.SetBackendHealth("backend1", "host2:8080", false)
}

func TestMetrics_SetCircuitBreakerState(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")

	// Should not panic
	metrics.SetCircuitBreakerState("cb1", 0) // Closed
	metrics.SetCircuitBreakerState("cb1", 1) // Half-open
	metrics.SetCircuitBreakerState("cb1", 2) // Open
}

func TestMetrics_RecordRateLimitHit(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")

	// Should not panic
	metrics.RecordRateLimitHit("192.168.1.1", "/api/users")
}

func TestMetrics_Handler(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")
	handler := metrics.Handler()

	assert.NotNil(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
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

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMetricsMiddleware_RecordsMetrics(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics("test")
	middleware := MetricsMiddleware(metrics)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
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

	assert.Equal(t, 11, mrw.size) // "first" + "second" = 11 bytes
}
