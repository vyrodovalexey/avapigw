package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteResponse_CopiesHeaders(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           bytes.NewBufferString("response body"),
		header:         make(http.Header),
		status:         http.StatusOK,
	}

	// Set headers on the retry response writer
	rw.header.Set("Content-Type", "application/json")
	rw.header.Set("X-Custom-Header", "custom-value")
	rw.header.Set("X-Request-Id", "req-123")

	writeResponse(rec, rw)

	// Verify headers were copied to the actual ResponseWriter
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "custom-value", rec.Header().Get("X-Custom-Header"))
	assert.Equal(t, "req-123", rec.Header().Get("X-Request-Id"))
}

func TestWriteResponse_CopiesMultiValueHeaders(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           bytes.NewBufferString("response body"),
		header:         make(http.Header),
		status:         http.StatusOK,
	}

	// Set multi-value headers
	rw.header.Add("Set-Cookie", "session=abc123; Path=/")
	rw.header.Add("Set-Cookie", "theme=dark; Path=/")

	writeResponse(rec, rw)

	// Verify multi-value headers were copied
	cookies := rec.Header().Values("Set-Cookie")
	assert.Len(t, cookies, 2)
	assert.Contains(t, cookies, "session=abc123; Path=/")
	assert.Contains(t, cookies, "theme=dark; Path=/")
}

func TestWriteResponse_CopiesStatusCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
	}{
		{name: "200 OK", status: http.StatusOK},
		{name: "201 Created", status: http.StatusCreated},
		{name: "204 No Content", status: http.StatusNoContent},
		{name: "301 Moved", status: http.StatusMovedPermanently},
		{name: "400 Bad Request", status: http.StatusBadRequest},
		{name: "404 Not Found", status: http.StatusNotFound},
		{name: "500 Internal Server Error", status: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			rw := &retryResponseWriter{
				ResponseWriter: rec,
				body:           &bytes.Buffer{},
				header:         make(http.Header),
				status:         tt.status,
			}

			writeResponse(rec, rw)

			assert.Equal(t, tt.status, rec.Code)
		})
	}
}

func TestWriteResponse_CopiesBody(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	bodyContent := `{"message": "hello world"}`
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           bytes.NewBufferString(bodyContent),
		header:         make(http.Header),
		status:         http.StatusOK,
	}

	writeResponse(rec, rw)

	assert.Equal(t, bodyContent, rec.Body.String())
}

func TestWriteResponse_EmptyBody(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
		status:         http.StatusNoContent,
	}

	writeResponse(rec, rw)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String())
}

func TestWriteResponse_EmptyHeaders(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           bytes.NewBufferString("body"),
		header:         make(http.Header),
		status:         http.StatusOK,
	}

	writeResponse(rec, rw)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "body", rec.Body.String())
}

func TestRetryResponseWriter_Header_ReturnsCapture(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
		status:         http.StatusOK,
	}

	// Header() should return the captured header, not the underlying writer's header
	rw.Header().Set("X-Test", "value")

	// The captured header should have the value
	assert.Equal(t, "value", rw.header.Get("X-Test"))

	// The underlying writer should NOT have the value yet
	assert.Empty(t, rec.Header().Get("X-Test"))
}

func TestRetryResponseWriter_WriteHeader_OnlyOnce(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
		status:         http.StatusOK,
	}

	rw.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, rw.status)
	assert.True(t, rw.headerWritten)

	// Second call should be ignored
	rw.WriteHeader(http.StatusBadRequest)
	assert.Equal(t, http.StatusCreated, rw.status)
}

func TestRetryResponseWriter_Write_ImplicitWriteHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           &bytes.Buffer{},
		header:         make(http.Header),
		status:         http.StatusOK,
	}

	// Write without calling WriteHeader first
	n, err := rw.Write([]byte("hello"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)

	// Should have implicitly called WriteHeader with 200
	assert.True(t, rw.headerWritten)
	assert.Equal(t, http.StatusOK, rw.status)
}

func TestIsWebSocketUpgrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name: "websocket upgrade",
			headers: map[string]string{
				"Upgrade":    "websocket",
				"Connection": "upgrade",
			},
			expected: true,
		},
		{
			name: "websocket upgrade case insensitive",
			headers: map[string]string{
				"Upgrade":    "WebSocket",
				"Connection": "Upgrade",
			},
			expected: true,
		},
		{
			name: "no upgrade header",
			headers: map[string]string{
				"Connection": "upgrade",
			},
			expected: false,
		},
		{
			name: "no connection header",
			headers: map[string]string{
				"Upgrade": "websocket",
			},
			expected: false,
		},
		{
			name:     "no headers",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name: "non-websocket upgrade",
			headers: map[string]string{
				"Upgrade":    "h2c",
				"Connection": "upgrade",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			assert.Equal(t, tt.expected, isWebSocketUpgrade(req))
		})
	}
}

func TestApplyPerTryTimeout(t *testing.T) {
	t.Parallel()

	t.Run("with timeout", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		result := applyPerTryTimeout(ctx, 5*1e9) // 5 seconds

		assert.NotNil(t, result.ctx)
		assert.NotNil(t, result.cancel)

		// Context should have a deadline
		_, ok := result.ctx.Deadline()
		assert.True(t, ok)

		result.cancel()
	})

	t.Run("without timeout", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		result := applyPerTryTimeout(ctx, 0)

		assert.NotNil(t, result.ctx)
		assert.NotNil(t, result.cancel)

		// Context should NOT have a deadline
		_, ok := result.ctx.Deadline()
		assert.False(t, ok)

		// Cancel should be a no-op
		assert.NotPanics(t, func() {
			result.cancel()
		})
	})
}
