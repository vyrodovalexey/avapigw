package era

import (
	"context"
	"errors"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ErrPoolClosed indicates the session pool has been closed and cannot hand out
// or create sessions.
var ErrPoolClosed = errors.New("era: session pool closed")

// SessionFactory supplies the per-upstream initialize parameters and the
// server-initiated-request handler for a newly created legacy session. It lets
// the pool build sessions without knowing about upstream configuration or the
// MRTR bridge.
type SessionFactory interface {
	// InitParams returns the legacy initialize parameters for upstreamID
	// (HUB-701).
	InitParams(upstreamID string) InitializeParams
	// ServerRequestHandler returns the handler that converts a legacy
	// server-initiated request from the upstream SSE pump for upstreamID into
	// an InputRequiredResult (HUB-704), or nil when no bridge is wired. When
	// non-nil the pool installs an EventDispatcher on the session so the pump
	// runs; when nil the session holds no background pump.
	ServerRequestHandler(upstreamID string) ServerRequestFunc
}

// ServerRequestFunc converts a legacy server-initiated request arriving on an
// upstream SSE stream into an InputRequiredResult toward the downstream client
// (HUB-704).
type ServerRequestFunc func(ctx context.Context, upstreamID string, req *jsonrpc.Request) error

// SessionPool owns legacy upstream sessions keyed by upstream id (HUB-702). A
// single session per upstream is shared across all downstream clients: the pool
// is NOT keyed by downstream client, so session identity never couples to or
// leaks toward a client. It re-initializes a session after session loss via the
// session's own retry path and closes all sessions on Close (stopping their SSE
// pumps, so no goroutine leaks).
type SessionPool struct {
	transport LegacyTransport
	factory   SessionFactory
	metrics   *mcpmetrics.Metrics
	logger    observability.Logger

	mu       sync.Mutex
	sessions map[string]*LegacySession
	closed   bool
}

// PoolOption configures a SessionPool.
type PoolOption func(*SessionPool)

// WithPoolLogger sets the pool logger.
func WithPoolLogger(l observability.Logger) PoolOption {
	return func(p *SessionPool) {
		if l != nil {
			p.logger = l
		}
	}
}

// WithPoolMetrics sets the pool metrics recorder.
func WithPoolMetrics(m *mcpmetrics.Metrics) PoolOption {
	return func(p *SessionPool) {
		if m != nil {
			p.metrics = m
		}
	}
}

// NewSessionPool constructs a SessionPool over the given transport and factory.
func NewSessionPool(transport LegacyTransport, factory SessionFactory, opts ...PoolOption) (*SessionPool, error) {
	if transport == nil {
		return nil, errors.New("era: nil legacy transport")
	}
	if factory == nil {
		return nil, errors.New("era: nil session factory")
	}
	p := &SessionPool{
		transport: transport,
		factory:   factory,
		metrics:   mcpmetrics.GetMetrics(),
		logger:    observability.NopLogger(),
		sessions:  make(map[string]*LegacySession),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Acquire returns the pooled legacy session for upstreamID, initializing it on
// first use (HUB-701/702). Concurrent Acquire calls for the same upstream share
// one session. The returned session is owned by the pool; callers MUST NOT
// close it (use the pool's Close).
func (p *SessionPool) Acquire(ctx context.Context, upstreamID string) (*LegacySession, error) {
	sess, needsInit, err := p.getOrCreate(upstreamID)
	if err != nil {
		return nil, err
	}
	if needsInit {
		if err := sess.initialize(ctx); err != nil {
			// Initialization failed: drop the half-built session so a later
			// Acquire retries cleanly rather than reusing a dead session.
			p.drop(upstreamID, sess)
			return nil, err
		}
		p.metrics.IncLegacySessions(upstreamID)
	}
	return sess, nil
}

// getOrCreate returns the existing session for upstreamID or a freshly built
// (uninitialized) one, reporting whether initialization is required. Building
// happens under the pool lock so exactly one session is created per upstream.
func (p *SessionPool) getOrCreate(upstreamID string) (sess *LegacySession, needsInit bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, false, ErrPoolClosed
	}
	if existing, ok := p.sessions[upstreamID]; ok {
		return existing, false, nil
	}
	sess = &LegacySession{
		upstreamID: upstreamID,
		transport:  p.transport,
		initParams: p.factory.InitParams(upstreamID),
		metrics:    p.metrics,
		logger:     p.logger,
	}
	// Install an event dispatcher whenever a server-request handler is wired
	// OR the upstream may relay subscription notifications; the dispatcher is
	// always safe (relays register lazily) so build it unconditionally and let
	// the session skip the pump only when there is genuinely no consumer.
	sess.dispatcher = newEventDispatcher(
		upstreamID, p.logger, p.factory.ServerRequestHandler(upstreamID),
	)
	p.sessions[upstreamID] = sess
	return sess, true, nil
}

// drop removes sess from the pool (only if it is still the registered session
// for upstreamID) and closes it, decrementing the open-session gauge only when
// the session had been counted. It is used to discard a failed-init session.
func (p *SessionPool) drop(upstreamID string, sess *LegacySession) {
	p.mu.Lock()
	if p.sessions[upstreamID] == sess {
		delete(p.sessions, upstreamID)
	}
	p.mu.Unlock()
	sess.close()
}

// Refresh forces re-initialization of an upstream's session (HUB-702). It is
// used when a session-loss condition is detected outside a request round-trip
// (e.g. the SSE pump reported ErrSessionLost). A missing session is a no-op.
func (p *SessionPool) Refresh(ctx context.Context, upstreamID string) error {
	p.mu.Lock()
	sess, ok := p.sessions[upstreamID]
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return ErrPoolClosed
	}
	if !ok {
		return nil
	}
	p.metrics.RecordLegacySessionReinit(upstreamID)
	return sess.reinitialize(ctx)
}

// Close closes every pooled session, stopping their SSE pumps so no background
// goroutine outlives the pool (goroutine-leak guard). It is idempotent.
func (p *SessionPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	sessions := make(map[string]*LegacySession, len(p.sessions))
	for id, s := range p.sessions {
		sessions[id] = s
	}
	p.sessions = make(map[string]*LegacySession)
	p.mu.Unlock()

	for id, s := range sessions {
		s.close()
		p.metrics.DecLegacySessions(id)
	}
}
