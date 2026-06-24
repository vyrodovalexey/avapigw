package aggregate

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Frame is a single labeled streaming message produced by one target. Its JSON
// shape mirrors the unary Envelope: {"target","status","payload"}.
type Frame struct {
	// Target is the producing target name.
	Target string `json:"target"`

	// Status is an optional protocol status for this frame.
	Status int `json:"status"`

	// Payload is the raw or JSON message payload.
	Payload json.RawMessage `json:"payload"`
}

// FrameSink receives interleaved, labeled frames from all targets. Sink
// implementations are responsible for writing frames to the client transport
// (WebSocket, gRPC stream). Implementations must be safe for concurrent use.
type FrameSink interface {
	// WriteFrame writes a single framed message to the client. A returned error
	// terminates the contributing target's pump.
	WriteFrame(ctx context.Context, frame *Frame) error
}

// StreamMux multiplexes per-target streaming messages into a single labeled
// frame stream. It enforces backpressure (each WriteFrame call blocks the
// producing goroutine) and honors context cancellation for clean teardown with
// no goroutine leaks.
type StreamMux struct {
	sink            FrameSink
	perMessageMerge bool
	mergeStrategy   string
	merger          *Merger
	logger          observability.Logger

	mu     sync.Mutex
	closed bool
}

// NewStreamMux creates a StreamMux writing to sink.
func NewStreamMux(
	sink FrameSink,
	cfg *Config,
	merger *Merger,
	logger observability.Logger,
) *StreamMux {
	if logger == nil {
		logger = observability.NopLogger()
	}
	mux := &StreamMux{
		sink:   sink,
		merger: merger,
		logger: logger,
	}
	if cfg != nil {
		mux.perMessageMerge = cfg.PerMessageMerge
		if cfg.Merge != nil {
			mux.mergeStrategy = cfg.Merge.Strategy
		}
	}
	return mux
}

// Push forwards a single message from a target as a labeled frame. When
// per-message merge is enabled and the payload is JSON, the payload is kept as a
// JSON document (already valid). Otherwise it is wrapped raw. Push blocks until
// the sink accepts the frame (backpressure) or ctx is canceled.
func (s *StreamMux) Push(ctx context.Context, target string, status int, payload []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	frame := &Frame{
		Target:  target,
		Status:  status,
		Payload: rawPayload(payload),
	}
	return s.sink.WriteFrame(ctx, frame)
}

// Close marks the mux closed. It is idempotent and safe for concurrent use.
func (s *StreamMux) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}

// Closed reports whether the mux has been closed.
func (s *StreamMux) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// EncodeFrame encodes a frame to its JSON wire representation. Exposed for
// transports that frame messages themselves (e.g. WebSocket text frames).
func EncodeFrame(frame *Frame) ([]byte, error) {
	return json.Marshal(frame)
}
