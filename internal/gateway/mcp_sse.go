package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// SSE downstream response header values (HUB-107). X-Accel-Buffering: no
// disables proxy buffering so events reach the client promptly.
const (
	sseContentType     = "text/event-stream"
	sseCacheControl    = "no-cache"
	sseConnection      = "keep-alive"
	sseAccelBuffering  = "no"
	acceptHeaderName   = "Accept"
	acceptSSEMediaType = "text/event-stream"
)

// ErrSSEUnsupported indicates the downstream ResponseWriter does not support
// flushing and therefore cannot originate an SSE stream.
var ErrSSEUnsupported = errors.New("mcp: response writer does not support SSE flushing")

// sseResponseWriter originates a downstream SSE response over an
// http.ResponseWriter, satisfying mcpproxy.SSEWriter. It writes the SSE
// response headers on construction (HUB-107) and serializes every write behind
// a mutex so the keep-alive goroutine and the relay goroutine never interleave
// partial frames on the wire.
type sseResponseWriter struct {
	mu   sync.Mutex
	w    http.ResponseWriter
	rc   *http.ResponseController
	head bool // whether the SSE response head has been written
}

// newSSEResponseWriter constructs an SSE writer over w, writing the SSE
// response headers and status 200 immediately so the client learns the
// response is a stream (HUB-102/107). It returns ErrSSEUnsupported when the
// writer cannot be flushed.
func newSSEResponseWriter(w http.ResponseWriter) (*sseResponseWriter, error) {
	rc := http.NewResponseController(w)
	// Probe flush support up front: an SSE stream that cannot be flushed
	// would buffer indefinitely, so fail fast to the JSON path instead.
	if err := rc.Flush(); err != nil && errors.Is(err, http.ErrNotSupported) {
		return nil, ErrSSEUnsupported
	}
	s := &sseResponseWriter{w: w, rc: rc}
	s.writeHead()
	return s, nil
}

// writeHead sets the SSE response headers and status once (HUB-107).
func (s *sseResponseWriter) writeHead() {
	if s.head {
		return
	}
	h := s.w.Header()
	h.Set("Content-Type", sseContentType)
	h.Set("Cache-Control", sseCacheControl)
	h.Set("Connection", sseConnection)
	h.Set("X-Accel-Buffering", sseAccelBuffering)
	s.w.WriteHeader(http.StatusOK)
	s.head = true
	_ = s.rc.Flush()
}

// WriteEvent writes a named SSE event with the given data payload. The data is
// emitted as a single "data:" line; multi-line payloads are split so each
// physical line is prefixed per the SSE grammar.
func (s *sseResponseWriter) WriteEvent(event string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder
	if event != "" {
		b.WriteString("event: ")
		b.WriteString(event)
		b.WriteByte('\n')
	}
	// Split on newlines so embedded newlines never break the SSE framing.
	for _, line := range strings.Split(string(data), "\n") {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteByte('\n') // blank line terminates the event

	if _, err := s.w.Write([]byte(b.String())); err != nil {
		return fmt.Errorf("mcp: write SSE event: %w", err)
	}
	return s.flushLocked()
}

// WriteComment writes an SSE comment line, used for keep-alive (HUB-225).
func (s *sseResponseWriter) WriteComment(c string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.w.Write([]byte(": " + c + "\n\n")); err != nil {
		return fmt.Errorf("mcp: write SSE comment: %w", err)
	}
	return s.flushLocked()
}

// Flush flushes buffered bytes to the transport.
func (s *sseResponseWriter) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

// flushLocked flushes assuming the caller holds the mutex.
func (s *sseResponseWriter) flushLocked() error {
	if err := s.rc.Flush(); err != nil {
		return fmt.Errorf("mcp: flush SSE: %w", err)
	}
	return nil
}

// compile-time assertion that sseResponseWriter satisfies the proxy SSEWriter.
var _ mcpproxy.SSEWriter = (*sseResponseWriter)(nil)

// wantsSSE reports whether the request's Accept header includes
// text/event-stream, i.e. the client is willing to receive a stream (HUB-102).
func wantsSSE(r *http.Request) bool {
	accept := strings.ToLower(r.Header.Get(acceptHeaderName))
	return strings.Contains(accept, acceptSSEMediaType)
}
