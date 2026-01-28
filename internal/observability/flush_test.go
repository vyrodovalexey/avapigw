package observability

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
// metricsResponseWriter.Flush tests
// ============================================================

func TestMetricsResponseWriter_Flush_WithFlusher(t *testing.T) {
	t.Parallel()

	rec := &flusherRecorder{
		ResponseRecorder: httptest.NewRecorder(),
	}
	mrw := &metricsResponseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	mrw.Flush()

	assert.True(t, rec.flushed)
}

func TestMetricsResponseWriter_Flush_WithoutFlusher(t *testing.T) {
	t.Parallel()

	nfw := newNonFlusherWriter()
	mrw := &metricsResponseWriter{
		ResponseWriter: nfw,
		status:         http.StatusOK,
	}

	// Should not panic when underlying writer doesn't implement Flusher
	mrw.Flush()
}

// ============================================================
// tracingResponseWriter.Flush tests
// ============================================================

func TestTracingResponseWriter_Flush_WithFlusher(t *testing.T) {
	t.Parallel()

	rec := &flusherRecorder{
		ResponseRecorder: httptest.NewRecorder(),
	}
	trw := &tracingResponseWriter{
		ResponseWriter: rec,
		status:         http.StatusOK,
	}

	trw.Flush()

	assert.True(t, rec.flushed)
}

func TestTracingResponseWriter_Flush_WithoutFlusher(t *testing.T) {
	t.Parallel()

	nfw := newNonFlusherWriter()
	trw := &tracingResponseWriter{
		ResponseWriter: nfw,
		status:         http.StatusOK,
	}

	// Should not panic when underlying writer doesn't implement Flusher
	trw.Flush()
}
