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

func TestIsValidRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		id       string
		expected bool
	}{
		{
			name:     "valid UUID",
			id:       "550e8400-e29b-41d4-a716-446655440000",
			expected: true,
		},
		{
			name:     "valid alphanumeric",
			id:       "abc123",
			expected: true,
		},
		{
			name:     "valid with hyphens",
			id:       "request-id-123",
			expected: true,
		},
		{
			name:     "valid with underscores",
			id:       "request_id_123",
			expected: true,
		},
		{
			name:     "valid mixed",
			id:       "req-123_abc-DEF",
			expected: true,
		},
		{
			name:     "empty string",
			id:       "",
			expected: false,
		},
		{
			name:     "too long string",
			id:       string(make([]byte, 129)),
			expected: false,
		},
		{
			name:     "exactly max length",
			id:       string(make([]byte, 128)),
			expected: false, // all null bytes are not alphanumeric
		},
		{
			name:     "128 alphanumeric chars",
			id:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expected: false, // 130 chars
		},
		{
			name:     "special characters - spaces",
			id:       "request id",
			expected: false,
		},
		{
			name:     "special characters - dots",
			id:       "request.id",
			expected: false,
		},
		{
			name:     "special characters - slashes",
			id:       "request/id",
			expected: false,
		},
		{
			name:     "special characters - angle brackets",
			id:       "<script>alert(1)</script>",
			expected: false,
		},
		{
			name:     "special characters - newline",
			id:       "request\nid",
			expected: false,
		},
		{
			name:     "special characters - null byte",
			id:       "request\x00id",
			expected: false,
		},
		{
			name:     "single character",
			id:       "a",
			expected: true,
		},
		{
			name:     "single hyphen",
			id:       "-",
			expected: true,
		},
		{
			name:     "single underscore",
			id:       "_",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isValidRequestID(tt.id)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRequestID_InvalidExistingID_GeneratesNew(t *testing.T) {
	t.Parallel()

	middleware := RequestID()

	var capturedRequestID string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRequestID = observability.RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Set an invalid request ID with special characters
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(RequestIDHeader, "<script>alert(1)</script>")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should have generated a new UUID
	responseID := rec.Header().Get(RequestIDHeader)
	assert.NotEqual(t, "<script>alert(1)</script>", responseID)
	assert.Len(t, responseID, 36) // UUID format
	assert.Equal(t, responseID, capturedRequestID)
}

func TestRequestIDHeader_Constant(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "X-Request-ID", RequestIDHeader)
}
