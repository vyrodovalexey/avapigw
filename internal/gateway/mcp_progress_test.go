package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonFlushWriter wraps an http.ResponseWriter without exposing Flush, so
// http.NewResponseController(w).Flush() reports http.ErrNotSupported and the
// SSE writer construction fails (the ErrSSEUnsupported path, HUB-102).
type nonFlushWriter struct {
	header http.Header
	code   int
}

func newNonFlushWriter() *nonFlushWriter {
	return &nonFlushWriter{header: make(http.Header)}
}

func (w *nonFlushWriter) Header() http.Header         { return w.header }
func (w *nonFlushWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *nonFlushWriter) WriteHeader(code int)        { w.code = code }

// ============================================================================
// 5.1 withProgressRelayContext
// ============================================================================

func TestWithProgressRelayContext(t *testing.T) {
	t.Parallel()

	t.Run("no SSE accept → unchanged, nil relay", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
		rec := httptest.NewRecorder()

		got := withProgressRelayContext(r, rec)
		assert.Same(t, r, got, "request must be returned unchanged")
		assert.Nil(t, progressRelayFromContext(got))
	})

	t.Run("SSE accept → relay attached", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodPost, "/mcp", http.NoBody)
		r.Header.Set("Accept", "text/event-stream")
		rec := httptest.NewRecorder()

		got := withProgressRelayContext(r, rec)
		assert.NotSame(t, r, got)
		require.NotNil(t, progressRelayFromContext(got))
	})
}

// ============================================================================
// 5.2 writeProgress opens the stream once (ensureOpenLocked re-entry)
// ============================================================================

func TestProgressRelay_WriteProgress_OpensOnce(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	relay := newProgressRelay(rec)

	// First progress event opens the SSE stream and writes a message event.
	require.NoError(t, relay.writeProgress([]byte(`{"progress":0.1}`)))
	assert.True(t, relay.active())
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

	// Second event reuses the already-open stream (opened==true arm).
	require.NoError(t, relay.writeProgress([]byte(`{"progress":0.9}`)))

	body := rec.Body.String()
	assert.Equal(t, 2, countOccurrences(body, "event: message"))
}

// ============================================================================
// 5.3 non-flushable writer → failed=true, subsequent ErrSSEUnsupported
// ============================================================================

func TestProgressRelay_WriteProgress_NonFlushable(t *testing.T) {
	t.Parallel()

	relay := newProgressRelay(newNonFlushWriter())

	// First call fails to open the SSE stream (ErrSSEUnsupported) and marks
	// the relay failed.
	err := relay.writeProgress([]byte(`{"progress":0.1}`))
	require.ErrorIs(t, err, ErrSSEUnsupported)
	assert.False(t, relay.active())

	// A subsequent call short-circuits on the failed arm (opened && failed).
	err = relay.writeProgress([]byte(`{"progress":0.2}`))
	require.ErrorIs(t, err, ErrSSEUnsupported)
}

// ============================================================================
// 5.4 active() / writeTerminal()
// ============================================================================

func TestProgressRelay_Active_And_WriteTerminal(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	relay := newProgressRelay(rec)

	// Before opening, the relay is inactive.
	assert.False(t, relay.active())

	// Open via a progress event, then write the terminal body.
	require.NoError(t, relay.writeProgress([]byte(`{"progress":0.5}`)))
	assert.True(t, relay.active())

	require.NoError(t, relay.writeTerminal([]byte(`{"result":"done"}`)))
	body := rec.Body.String()
	assert.Contains(t, body, `data: {"result":"done"}`)
}

// countOccurrences counts non-overlapping occurrences of sub in s.
func countOccurrences(s, sub string) int {
	count := 0
	for i := 0; i+len(sub) <= len(s); {
		if s[i:i+len(sub)] == sub {
			count++
			i += len(sub)
			continue
		}
		i++
	}
	return count
}
