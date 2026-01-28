package util

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// flusherRecorder wraps httptest.ResponseRecorder and implements http.Flusher.
type flusherRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flusherRecorder) Flush() {
	f.flushed = true
}

// nonFlusherWriter is a ResponseWriter that does NOT implement http.Flusher.
type nonFlusherWriter struct {
	header     http.Header
	statusCode int
	body       []byte
}

func newNonFlusherWriter() *nonFlusherWriter {
	return &nonFlusherWriter{header: make(http.Header)}
}

func (w *nonFlusherWriter) Header() http.Header  { return w.header }
func (w *nonFlusherWriter) WriteHeader(code int) { w.statusCode = code }
func (w *nonFlusherWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}

func TestServerError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		expected   string
	}{
		{
			name:       "500 Internal Server Error",
			statusCode: http.StatusInternalServerError,
			expected:   "server error: status 500",
		},
		{
			name:       "502 Bad Gateway",
			statusCode: http.StatusBadGateway,
			expected:   "server error: status 502",
		},
		{
			name:       "503 Service Unavailable",
			statusCode: http.StatusServiceUnavailable,
			expected:   "server error: status 503",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := NewServerError(tt.statusCode)
			assert.Equal(t, tt.expected, err.Error())
			assert.Equal(t, tt.statusCode, err.StatusCode)
		})
	}
}

func TestNewStatusCapturingResponseWriter(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	w := NewStatusCapturingResponseWriter(rec)

	assert.NotNil(t, w)
	assert.Equal(t, http.StatusOK, w.StatusCode)
	assert.False(t, w.HeaderWritten)
}

func TestStatusCapturingResponseWriter_WriteHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
	}{
		{"200 OK", http.StatusOK},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			w := NewStatusCapturingResponseWriter(rec)

			w.WriteHeader(tt.statusCode)

			assert.Equal(t, tt.statusCode, w.StatusCode)
			assert.True(t, w.HeaderWritten)
			assert.Equal(t, tt.statusCode, rec.Code)
		})
	}
}

func TestStatusCapturingResponseWriter_WriteHeader_OnlyOnce(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	w := NewStatusCapturingResponseWriter(rec)

	w.WriteHeader(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, w.StatusCode)
	assert.True(t, w.HeaderWritten)

	// Second call should be ignored
	w.WriteHeader(http.StatusInternalServerError)
	assert.Equal(t, http.StatusNotFound, w.StatusCode)
}

func TestStatusCapturingResponseWriter_Write(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	w := NewStatusCapturingResponseWriter(rec)

	data := []byte("hello world")
	n, err := w.Write(data)

	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.True(t, w.HeaderWritten)
	assert.Equal(t, "hello world", rec.Body.String())
}

func TestStatusCapturingResponseWriter_Write_SetsHeaderWritten(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	w := NewStatusCapturingResponseWriter(rec)

	assert.False(t, w.HeaderWritten)

	_, err := w.Write([]byte("data"))
	assert.NoError(t, err)
	assert.True(t, w.HeaderWritten)
}

func TestStatusCapturingResponseWriter_Flush_WithFlusher(t *testing.T) {
	t.Parallel()

	rec := &flusherRecorder{
		ResponseRecorder: httptest.NewRecorder(),
	}
	w := NewStatusCapturingResponseWriter(rec)

	w.Flush()

	assert.True(t, rec.flushed)
}

func TestStatusCapturingResponseWriter_Flush_WithoutFlusher(t *testing.T) {
	t.Parallel()

	nfw := newNonFlusherWriter()
	w := NewStatusCapturingResponseWriter(nfw)

	// Should not panic when underlying writer doesn't implement Flusher
	w.Flush()
}

func TestStatusCapturingResponseWriter_ImplementsFlusher(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	w := NewStatusCapturingResponseWriter(rec)

	// Verify compile-time interface assertion
	var _ http.Flusher = w
}
