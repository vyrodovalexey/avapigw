package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		existingRequestID string
		expectNewID       bool
	}{
		{
			name:              "generates new request ID",
			existingRequestID: "",
			expectNewID:       true,
		},
		{
			name:              "uses existing request ID",
			existingRequestID: "existing-request-id-123",
			expectNewID:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			middleware := RequestID()

			var capturedRequestID string
			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedRequestID = observability.RequestIDFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.existingRequestID != "" {
				req.Header.Set(RequestIDHeader, tt.existingRequestID)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			// Check response header
			responseRequestID := rec.Header().Get(RequestIDHeader)
			assert.NotEmpty(t, responseRequestID)

			// Check context
			assert.NotEmpty(t, capturedRequestID)
			assert.Equal(t, responseRequestID, capturedRequestID)

			if tt.expectNewID {
				// Should be a UUID format
				assert.Len(t, responseRequestID, 36) // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
			} else {
				assert.Equal(t, tt.existingRequestID, responseRequestID)
			}
		})
	}
}

func TestRequestIDWithGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		generator         func() string
		existingRequestID string
		expectedID        string
	}{
		{
			name: "uses custom generator",
			generator: func() string {
				return "custom-generated-id"
			},
			existingRequestID: "",
			expectedID:        "custom-generated-id",
		},
		{
			name: "preserves existing ID with custom generator",
			generator: func() string {
				return "should-not-be-used"
			},
			existingRequestID: "existing-id",
			expectedID:        "existing-id",
		},
		{
			name: "sequential generator",
			generator: func() string {
				return "seq-001"
			},
			existingRequestID: "",
			expectedID:        "seq-001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			middleware := RequestIDWithGenerator(tt.generator)

			var capturedRequestID string
			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedRequestID = observability.RequestIDFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.existingRequestID != "" {
				req.Header.Set(RequestIDHeader, tt.existingRequestID)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedID, rec.Header().Get(RequestIDHeader))
			assert.Equal(t, tt.expectedID, capturedRequestID)
		})
	}
}

func TestRequestIDHeader_Constant(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "X-Request-ID", RequestIDHeader)
}
