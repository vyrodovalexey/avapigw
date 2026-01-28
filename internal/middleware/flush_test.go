package middleware

import (
	"bytes"
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

func (w *nonFlusherWriter) Header() http.Header {
	return w.header
}

func (w *nonFlusherWriter) WriteHeader(code int) {
	w.statusCode = code
}

func (w *nonFlusherWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}

// ============================================================
// auditResponseWriter.Flush tests
// ============================================================

func TestAuditResponseWriter_Flush_WithFlusher(t *testing.T) {
	t.Parallel()

	rec := &flusherRecorder{
		ResponseRecorder: httptest.NewRecorder(),
	}
	aw := &auditResponseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	aw.Flush()

	assert.True(t, rec.flushed)
}

func TestAuditResponseWriter_Flush_WithoutFlusher(t *testing.T) {
	t.Parallel()

	nfw := newNonFlusherWriter()
	aw := &auditResponseWriter{
		ResponseWriter: nfw,
		status:         http.StatusOK,
	}

	// Should not panic when underlying writer doesn't implement Flusher
	aw.Flush()
}

// ============================================================
// responseWriter.Flush tests (logging.go)
// ============================================================

func TestLoggingResponseWriter_Flush_WithFlusher(t *testing.T) {
	t.Parallel()

	rec := &flusherRecorder{
		ResponseRecorder: httptest.NewRecorder(),
	}
	rw := &responseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	rw.Flush()

	assert.True(t, rec.flushed)
}

func TestLoggingResponseWriter_Flush_WithoutFlusher(t *testing.T) {
	t.Parallel()

	nfw := newNonFlusherWriter()
	rw := &responseWriter{
		ResponseWriter: nfw,
		status:         http.StatusOK,
	}

	// Should not panic when underlying writer doesn't implement Flusher
	rw.Flush()
}

// ============================================================
// retryResponseWriter.Flush tests
// ============================================================

func TestRetryResponseWriter_Flush_IsNoOp(t *testing.T) {
	t.Parallel()

	rec := &flusherRecorder{
		ResponseRecorder: httptest.NewRecorder(),
	}
	rw := &retryResponseWriter{
		ResponseWriter: rec,
		body:           &bytes.Buffer{},
		status:         http.StatusOK,
	}

	// Flush is intentionally a no-op for retry writer
	rw.Flush()

	// Underlying flusher should NOT be called since retry buffers the response
	assert.False(t, rec.flushed)
}

func TestRetryResponseWriter_Flush_WithoutFlusher(t *testing.T) {
	t.Parallel()

	nfw := newNonFlusherWriter()
	rw := &retryResponseWriter{
		ResponseWriter: nfw,
		body:           &bytes.Buffer{},
		status:         http.StatusOK,
	}

	// Should not panic
	rw.Flush()
}
