package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// mockAuditLogger captures audit events for testing.
type mockAuditLogger struct {
	mu     sync.Mutex
	events []*audit.Event
}

func newMockAuditLogger() *mockAuditLogger {
	return &mockAuditLogger{}
}

func (m *mockAuditLogger) LogEvent(_ context.Context, event *audit.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

func (m *mockAuditLogger) LogAuthentication(_ context.Context, _ audit.Action, _ audit.Outcome, _ *audit.Subject) {
}

func (m *mockAuditLogger) LogAuthorization(_ context.Context, _ audit.Outcome, _ *audit.Subject, _ *audit.Resource) {
}

func (m *mockAuditLogger) LogSecurity(
	_ context.Context,
	_ audit.Action,
	_ audit.Outcome,
	_ *audit.Subject,
	_ map[string]interface{},
) {
}

func (m *mockAuditLogger) Close() error { return nil }

func (m *mockAuditLogger) getEvents() []*audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*audit.Event, len(m.events))
	copy(result, m.events)
	return result
}

// ============================================================
// TestAudit_BasicRequest
// ============================================================

func TestAudit_BasicRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		path           string
		handlerStatus  int
		handlerBody    string
		expectedStatus int
	}{
		{
			name:           "GET request passes through",
			method:         http.MethodGet,
			path:           "/api/users",
			handlerStatus:  http.StatusOK,
			handlerBody:    `{"users":[]}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST request passes through",
			method:         http.MethodPost,
			path:           "/api/users",
			handlerStatus:  http.StatusCreated,
			handlerBody:    `{"id":1}`,
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "DELETE request passes through",
			method:         http.MethodDelete,
			path:           "/api/users/1",
			handlerStatus:  http.StatusNoContent,
			handlerBody:    "",
			expectedStatus: http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLogger := newMockAuditLogger()
			mw := Audit(mockLogger)

			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.handlerStatus)
				if tt.handlerBody != "" {
					_, _ = w.Write([]byte(tt.handlerBody))
				}
			}))

			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = "192.168.1.1:12345"
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.handlerBody != "" {
				assert.Equal(t, tt.handlerBody, rec.Body.String())
			}

			// Should have logged 2 events: request + response
			events := mockLogger.getEvents()
			assert.Len(t, events, 2)
		})
	}
}

// ============================================================
// TestAudit_CapturesStatusCode
// ============================================================

func TestAudit_CapturesStatusCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		handlerStatus      int
		expectedOutcome    audit.Outcome
		expectedStatusCode int
	}{
		{
			name:               "captures 200 OK",
			handlerStatus:      http.StatusOK,
			expectedOutcome:    audit.OutcomeSuccess,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "captures 404 Not Found",
			handlerStatus:      http.StatusNotFound,
			expectedOutcome:    audit.OutcomeFailure,
			expectedStatusCode: http.StatusNotFound,
		},
		{
			name:               "captures 500 Internal Server Error",
			handlerStatus:      http.StatusInternalServerError,
			expectedOutcome:    audit.OutcomeFailure,
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name:               "captures 201 Created",
			handlerStatus:      http.StatusCreated,
			expectedOutcome:    audit.OutcomeSuccess,
			expectedStatusCode: http.StatusCreated,
		},
		{
			name:               "captures 400 Bad Request",
			handlerStatus:      http.StatusBadRequest,
			expectedOutcome:    audit.OutcomeFailure,
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLogger := newMockAuditLogger()
			mw := Audit(mockLogger)

			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.handlerStatus)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "10.0.0.1:5000"
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			events := mockLogger.getEvents()
			require.Len(t, events, 2)

			// Second event is the response event
			respEvent := events[1]
			assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
			assert.Equal(t, tt.expectedOutcome, respEvent.Outcome)
			require.NotNil(t, respEvent.Response)
			assert.Equal(t, tt.expectedStatusCode, respEvent.Response.StatusCode)
		})
	}
}

// ============================================================
// TestAudit_CapturesResponseSize
// ============================================================

func TestAudit_CapturesResponseSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		body         string
		expectedSize int64
	}{
		{
			name:         "empty body",
			body:         "",
			expectedSize: 0,
		},
		{
			name:         "small body",
			body:         "hello",
			expectedSize: 5,
		},
		{
			name:         "json body",
			body:         `{"key":"value","number":42}`,
			expectedSize: 27,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLogger := newMockAuditLogger()
			mw := Audit(mockLogger)

			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				if tt.body != "" {
					_, _ = w.Write([]byte(tt.body))
				}
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "10.0.0.1:5000"
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			events := mockLogger.getEvents()
			require.Len(t, events, 2)

			respEvent := events[1]
			require.NotNil(t, respEvent.Response)
			assert.Equal(t, tt.expectedSize, respEvent.Response.ContentLength)
		})
	}
}

// ============================================================
// TestAudit_WithNoopLogger
// ============================================================

func TestAudit_WithNoopLogger(t *testing.T) {
	t.Parallel()

	noopLogger := audit.NewNoopLogger()
	mw := Audit(noopLogger)

	handlerCalled := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	// Should not panic
	handler.ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "OK", rec.Body.String())
}

// ============================================================
// TestAudit_RequestDetails
// ============================================================

func TestAudit_RequestDetails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		method         string
		path           string
		query          string
		headers        map[string]string
		remoteAddr     string
		expectedMethod string
		expectedPath   string
		expectedQuery  string
		expectedProto  string
		expectedIP     string
		expectedUA     string
	}{
		{
			name:           "GET with query params",
			method:         http.MethodGet,
			path:           "/api/users",
			query:          "page=1&limit=10",
			headers:        map[string]string{"User-Agent": "test-agent"},
			remoteAddr:     "192.168.1.1:12345",
			expectedMethod: http.MethodGet,
			expectedPath:   "/api/users",
			expectedQuery:  "page=1&limit=10",
			expectedProto:  "HTTP/1.1",
			expectedIP:     "192.168.1.1",
			expectedUA:     "test-agent",
		},
		{
			name:           "POST with content type",
			method:         http.MethodPost,
			path:           "/api/data",
			query:          "",
			headers:        map[string]string{"Content-Type": "application/json", "User-Agent": "curl/7.68"},
			remoteAddr:     "10.0.0.5:9999",
			expectedMethod: http.MethodPost,
			expectedPath:   "/api/data",
			expectedQuery:  "",
			expectedProto:  "HTTP/1.1",
			expectedIP:     "10.0.0.5",
			expectedUA:     "curl/7.68",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLogger := newMockAuditLogger()
			mw := Audit(mockLogger)

			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			url := tt.path
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest(tt.method, url, nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			events := mockLogger.getEvents()
			require.Len(t, events, 2)

			// First event is the request event
			reqEvent := events[0]
			assert.Equal(t, audit.EventTypeRequest, reqEvent.Type)
			require.NotNil(t, reqEvent.Request)
			assert.Equal(t, tt.expectedMethod, reqEvent.Request.Method)
			assert.Equal(t, tt.expectedPath, reqEvent.Request.Path)
			assert.Equal(t, tt.expectedQuery, reqEvent.Request.Query)
			assert.Equal(t, tt.expectedProto, reqEvent.Request.Protocol)
			assert.Equal(t, tt.expectedIP, reqEvent.Request.RemoteAddr)

			// Check subject
			require.NotNil(t, reqEvent.Subject)
			assert.Equal(t, tt.expectedIP, reqEvent.Subject.IPAddress)
			assert.Equal(t, tt.expectedUA, reqEvent.Subject.UserAgent)

			// Check resource
			require.NotNil(t, reqEvent.Resource)
			assert.Equal(t, "http", reqEvent.Resource.Type)
			assert.Equal(t, tt.expectedPath, reqEvent.Resource.Path)
			assert.Equal(t, tt.expectedMethod, reqEvent.Resource.Method)
		})
	}
}

// ============================================================
// TestAudit_ResponseDuration
// ============================================================

func TestAudit_ResponseDuration(t *testing.T) {
	t.Parallel()

	mockLogger := newMockAuditLogger()
	mw := Audit(mockLogger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	events := mockLogger.getEvents()
	require.Len(t, events, 2)

	respEvent := events[1]
	assert.Equal(t, audit.EventTypeResponse, respEvent.Type)
	// Duration should be at least 10ms
	assert.GreaterOrEqual(t, respEvent.Duration, 10*time.Millisecond)
	// But not unreasonably long (less than 5 seconds)
	assert.Less(t, respEvent.Duration, 5*time.Second)
}

// ============================================================
// TestAudit_ClientIP
// ============================================================

func TestAudit_ClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "uses RemoteAddr when no forwarding headers",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "ignores X-Forwarded-For without trusted proxies",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "192.168.1.1",
		},
		{
			name:       "ignores X-Real-IP without trusted proxies",
			headers:    map[string]string{"X-Real-IP": "10.0.0.2"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLogger := newMockAuditLogger()
			mw := Audit(mockLogger)

			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			events := mockLogger.getEvents()
			require.Len(t, events, 2)

			reqEvent := events[0]
			require.NotNil(t, reqEvent.Request)
			assert.Equal(t, tt.expectedIP, reqEvent.Request.RemoteAddr)
			require.NotNil(t, reqEvent.Subject)
			assert.Equal(t, tt.expectedIP, reqEvent.Subject.IPAddress)
		})
	}
}

// ============================================================
// TestAudit_RequestID
// ============================================================

func TestAudit_RequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		requestID         string
		expectMetadataKey bool
	}{
		{
			name:              "with request ID in context",
			requestID:         "test-request-id-123",
			expectMetadataKey: true,
		},
		{
			name:              "without request ID in context",
			requestID:         "",
			expectMetadataKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLogger := newMockAuditLogger()
			mw := Audit(mockLogger)

			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "10.0.0.1:5000"

			if tt.requestID != "" {
				ctx := observability.ContextWithRequestID(req.Context(), tt.requestID)
				req = req.WithContext(ctx)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			events := mockLogger.getEvents()
			require.Len(t, events, 2)

			// Check request event metadata
			reqEvent := events[0]
			if tt.expectMetadataKey {
				require.NotNil(t, reqEvent.Metadata)
				assert.Equal(t, tt.requestID, reqEvent.Metadata["request_id"])
			} else {
				// Metadata may be nil or not contain request_id
				if reqEvent.Metadata != nil {
					_, exists := reqEvent.Metadata["request_id"]
					assert.False(t, exists)
				}
			}

			// Check response event metadata
			respEvent := events[1]
			if tt.expectMetadataKey {
				require.NotNil(t, respEvent.Metadata)
				assert.Equal(t, tt.requestID, respEvent.Metadata["request_id"])
			} else {
				if respEvent.Metadata != nil {
					_, exists := respEvent.Metadata["request_id"]
					assert.False(t, exists)
				}
			}
		})
	}
}

// ============================================================
// TestAuditResponseWriter_WriteHeader
// ============================================================

func TestAuditResponseWriter_WriteHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		statusCode     int
		expectedStatus int
	}{
		{
			name:           "sets 200 OK",
			statusCode:     http.StatusOK,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "sets 404 Not Found",
			statusCode:     http.StatusNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "sets 500 Internal Server Error",
			statusCode:     http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "sets 301 Moved Permanently",
			statusCode:     http.StatusMovedPermanently,
			expectedStatus: http.StatusMovedPermanently,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			aw := &auditResponseWriter{
				ResponseWriter: rec,
				status:         http.StatusOK,
			}

			aw.WriteHeader(tt.statusCode)

			assert.Equal(t, tt.expectedStatus, aw.status)
			assert.True(t, aw.wroteHeader)
			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

// ============================================================
// TestAuditResponseWriter_WriteHeader_OnlyOnce
// ============================================================

func TestAuditResponseWriter_WriteHeader_OnlyOnce(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	aw := &auditResponseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	// First call should set the status
	aw.WriteHeader(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, aw.status)
	assert.True(t, aw.wroteHeader)

	// Second call should NOT change the captured status
	// (though the underlying writer may still receive it)
	aw.WriteHeader(http.StatusInternalServerError)
	assert.Equal(t, http.StatusNotFound, aw.status)
}

// ============================================================
// TestAuditResponseWriter_Write
// ============================================================

func TestAuditResponseWriter_Write(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		data         string
		expectedSize int
	}{
		{
			name:         "writes small body",
			data:         "hello",
			expectedSize: 5,
		},
		{
			name:         "writes json body",
			data:         `{"key":"value"}`,
			expectedSize: 15,
		},
		{
			name:         "writes empty body",
			data:         "",
			expectedSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			aw := &auditResponseWriter{
				ResponseWriter: rec,
				status:         http.StatusOK,
			}

			n, err := aw.Write([]byte(tt.data))

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedSize, n)
			assert.Equal(t, tt.expectedSize, aw.size)
			assert.Equal(t, tt.data, rec.Body.String())
			// Write should trigger WriteHeader with 200 if not already called
			assert.True(t, aw.wroteHeader)
		})
	}
}

// ============================================================
// TestAuditResponseWriter_Write_MultipleWrites
// ============================================================

func TestAuditResponseWriter_Write_MultipleWrites(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	aw := &auditResponseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	n1, err1 := aw.Write([]byte("first"))
	assert.NoError(t, err1)
	assert.Equal(t, 5, n1)

	n2, err2 := aw.Write([]byte("second"))
	assert.NoError(t, err2)
	assert.Equal(t, 6, n2)

	assert.Equal(t, 11, aw.size)
	assert.Equal(t, "firstsecond", rec.Body.String())
}

// ============================================================
// TestAuditResponseWriter_DefaultStatus
// ============================================================

func TestAuditResponseWriter_DefaultStatus(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	aw := &auditResponseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	// Write without calling WriteHeader first
	_, err := aw.Write([]byte("body"))
	assert.NoError(t, err)

	// Should default to 200 OK
	assert.Equal(t, http.StatusOK, aw.status)
	assert.True(t, aw.wroteHeader)
}

// ============================================================
// TestAudit_ResponseResource
// ============================================================

func TestAudit_ResponseResource(t *testing.T) {
	t.Parallel()

	mockLogger := newMockAuditLogger()
	mw := Audit(mockLogger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPut, "/api/items/42", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	events := mockLogger.getEvents()
	require.Len(t, events, 2)

	// Check response event resource
	respEvent := events[1]
	require.NotNil(t, respEvent.Resource)
	assert.Equal(t, "http", respEvent.Resource.Type)
	assert.Equal(t, "/api/items/42", respEvent.Resource.Path)
	assert.Equal(t, http.MethodPut, respEvent.Resource.Method)
}

// ============================================================
// TestAudit_ContentTypeCapture
// ============================================================

func TestAudit_ContentTypeCapture(t *testing.T) {
	t.Parallel()

	mockLogger := newMockAuditLogger()
	mw := Audit(mockLogger)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.1:5000"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	events := mockLogger.getEvents()
	require.Len(t, events, 2)

	// Check request content type
	reqEvent := events[0]
	require.NotNil(t, reqEvent.Request)
	assert.Equal(t, "application/json", reqEvent.Request.ContentType)

	// Check response content type
	respEvent := events[1]
	require.NotNil(t, respEvent.Response)
	assert.Equal(t, "application/json", respEvent.Response.ContentType)
}

// ============================================================
// TestAudit_TraceContext
// ============================================================

func TestAudit_TraceContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		traceID       string
		spanID        string
		expectTraceID bool
		expectSpanID  bool
	}{
		{
			name:          "with trace and span IDs in context",
			traceID:       "abc123trace",
			spanID:        "def456span",
			expectTraceID: true,
			expectSpanID:  true,
		},
		{
			name:          "with only trace ID",
			traceID:       "abc123trace",
			spanID:        "",
			expectTraceID: true,
			expectSpanID:  false,
		},
		{
			name:          "with only span ID",
			traceID:       "",
			spanID:        "def456span",
			expectTraceID: false,
			expectSpanID:  true,
		},
		{
			name:          "without trace context",
			traceID:       "",
			spanID:        "",
			expectTraceID: false,
			expectSpanID:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockLogger := newMockAuditLogger()
			mw := Audit(mockLogger)

			handler := mw(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "10.0.0.1:5000"

			ctx := req.Context()
			if tt.traceID != "" {
				ctx = observability.ContextWithTraceID(ctx, tt.traceID)
			}
			if tt.spanID != "" {
				ctx = observability.ContextWithSpanID(ctx, tt.spanID)
			}
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			events := mockLogger.getEvents()
			require.Len(t, events, 2)

			// Verify request event trace context
			reqEvent := events[0]
			if tt.expectTraceID {
				assert.Equal(t, tt.traceID, reqEvent.TraceID)
			} else {
				assert.Empty(t, reqEvent.TraceID)
			}
			if tt.expectSpanID {
				assert.Equal(t, tt.spanID, reqEvent.SpanID)
			} else {
				assert.Empty(t, reqEvent.SpanID)
			}

			// Verify response event trace context
			respEvent := events[1]
			if tt.expectTraceID {
				assert.Equal(t, tt.traceID, respEvent.TraceID)
			} else {
				assert.Empty(t, respEvent.TraceID)
			}
			if tt.expectSpanID {
				assert.Equal(t, tt.spanID, respEvent.SpanID)
			} else {
				assert.Empty(t, respEvent.SpanID)
			}
		})
	}
}

// ============================================================
// TestEnrichWithTraceContext
// ============================================================

func TestEnrichWithTraceContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		traceID         string
		spanID          string
		expectedTraceID string
		expectedSpanID  string
	}{
		{
			name:            "sets both trace and span IDs",
			traceID:         "trace-123",
			spanID:          "span-456",
			expectedTraceID: "trace-123",
			expectedSpanID:  "span-456",
		},
		{
			name:            "empty values leave fields unchanged",
			traceID:         "",
			spanID:          "",
			expectedTraceID: "",
			expectedSpanID:  "",
		},
		{
			name:            "sets only trace ID",
			traceID:         "trace-only",
			spanID:          "",
			expectedTraceID: "trace-only",
			expectedSpanID:  "",
		},
		{
			name:            "sets only span ID",
			traceID:         "",
			spanID:          "span-only",
			expectedTraceID: "",
			expectedSpanID:  "span-only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			event := audit.NewEvent(
				audit.EventTypeRequest,
				audit.ActionHTTPRequest,
				audit.OutcomeSuccess,
			)

			enrichWithTraceContext(event, tt.traceID, tt.spanID)

			assert.Equal(t, tt.expectedTraceID, event.TraceID)
			assert.Equal(t, tt.expectedSpanID, event.SpanID)
		})
	}
}
