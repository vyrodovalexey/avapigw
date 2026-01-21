package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/util"
)

func TestLogging(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		path           string
		query          string
		handler        http.HandlerFunc
		expectedStatus int
	}{
		{
			name:   "logs successful GET request",
			method: http.MethodGet,
			path:   "/api/users",
			query:  "page=1",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"users":[]}`))
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "logs POST request",
			method: http.MethodPost,
			path:   "/api/users",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":1}`))
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:   "logs error response",
			method: http.MethodGet,
			path:   "/api/error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal error"}`))
			},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:   "logs not found",
			method: http.MethodGet,
			path:   "/api/notfound",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			middleware := Logging(logger)

			handler := middleware(tt.handler)

			url := tt.path
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest(tt.method, url, nil)
			req.RemoteAddr = "192.168.1.1:12345"
			req.Header.Set("User-Agent", "test-agent")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

func TestLogging_AddsStartTimeToContext(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	middleware := Logging(logger)

	var hasStartTime bool
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := util.StartTimeFromContext(r.Context())
		hasStartTime = !startTime.IsZero()
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, hasStartTime)
}

func TestAccessLog(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		path           string
		route          string
		expectedStatus int
	}{
		{
			name:           "logs access for GET",
			method:         http.MethodGet,
			path:           "/api/users",
			route:          "users-route",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "logs access for POST",
			method:         http.MethodPost,
			path:           "/api/users",
			route:          "create-user",
			expectedStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			middleware := AccessLog(logger)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.expectedStatus)
			}))

			req := httptest.NewRequest(tt.method, tt.path, nil)
			// Add route to context
			ctx := util.ContextWithRoute(req.Context(), tt.route)
			req = req.WithContext(ctx)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

func TestGetClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "uses X-Forwarded-For",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "10.0.0.1",
		},
		{
			name:       "uses X-Real-IP when no X-Forwarded-For",
			headers:    map[string]string{"X-Real-IP": "10.0.0.2"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "10.0.0.2",
		},
		{
			name:       "falls back to RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "192.168.1.1:12345",
		},
		{
			name:       "X-Forwarded-For takes precedence over X-Real-IP",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1", "X-Real-IP": "10.0.0.2"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := getClientIP(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	rw.WriteHeader(http.StatusNotFound)

	assert.Equal(t, http.StatusNotFound, rw.status)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestResponseWriter_Write(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	data := []byte("test response body")
	n, err := rw.Write(data)

	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, len(data), rw.size)
	assert.Equal(t, "test response body", rec.Body.String())
}

func TestResponseWriter_MultipleWrites(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	_, _ = rw.Write([]byte("first"))
	_, _ = rw.Write([]byte("second"))

	assert.Equal(t, 11, rw.size) // "first" + "second" = 11 bytes
}
