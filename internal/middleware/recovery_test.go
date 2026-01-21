package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestRecovery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedStatus int
		expectedBody   string
		shouldPanic    bool
	}{
		{
			name: "no panic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
			shouldPanic:    false,
		},
		{
			name: "panic with string",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("test panic")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"internal server error"}`,
			shouldPanic:    true,
		},
		{
			name: "panic with error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"internal server error"}`,
			shouldPanic:    true,
		},
		{
			name: "panic with nil",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic(nil)
			},
			expectedStatus: http.StatusInternalServerError, // nil panic still triggers recovery in Go 1.21+
			expectedBody:   `{"error":"internal server error"}`,
			shouldPanic:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			middleware := Recovery(logger)

			handler := middleware(tt.handler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectedBody != "" {
				assert.Equal(t, tt.expectedBody, rec.Body.String())
			}
		})
	}
}

func TestRecoveryWithWriter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedStatus int
		expectOutput   bool
	}{
		{
			name: "no panic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			expectedStatus: http.StatusOK,
			expectOutput:   false,
		},
		{
			name: "panic writes to custom writer",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("custom writer panic")
			},
			expectedStatus: http.StatusInternalServerError,
			expectOutput:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := observability.NopLogger()
			var buf bytes.Buffer
			middleware := RecoveryWithWriter(logger, &buf)

			handler := middleware(tt.handler)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
			if tt.expectOutput {
				assert.Contains(t, buf.String(), "panic:")
				assert.Contains(t, buf.String(), "custom writer panic")
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestRecovery_ContentType(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	middleware := Recovery(logger)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}
