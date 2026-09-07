package era

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpmetrics "github.com/vyrodovalexey/avapigw/internal/mcp/metrics"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// initializeRequestID is the fixed JSON-RPC id used for the legacy initialize
// request; the session pumps exactly one initialize per handshake so a constant
// id is unambiguous.
var initializeRequestID = json.RawMessage(`1`)

// Legacy MCP session header and handshake constants (HUB-701).
const (
	// HeaderMcpSessionID carries the legacy session identity between the hub
	// and a legacy upstream. It is hub-internal and never exposed downstream
	// (HUB-702).
	HeaderMcpSessionID = "Mcp-Session-Id"
	// HeaderLastEventID requests SSE resumption from the last delivered event
	// where the upstream supports it (HUB-701).
	HeaderLastEventID = "Last-Event-ID"

	// MethodInitialize is the legacy initialization request.
	MethodInitialize = "initialize"
	// MethodInitialized is the legacy post-initialize notification.
	MethodInitialized = "notifications/initialized"
)

// ErrSessionLost indicates the upstream rejected a request because the legacy
// session was lost (e.g. 404 / session-not-found). It drives re-initialization
// (HUB-702).
var ErrSessionLost = errors.New("era: legacy upstream session lost")

// LegacyTransport is the minimal HTTP mechanism the session pool needs to speak
// the legacy era to an upstream. It is satisfied by the concrete backend-backed
// transport in this package and stubbed in tests, decoupling the session
// lifecycle from the backend registry.
type LegacyTransport interface {
	// PostRequest performs a legacy JSON-RPC POST to the upstream, applying
	// the session id header when non-empty. It returns the parsed response and
	// any session id the upstream assigned/rotated (from the response header).
	// A session-loss status (404/session-not-found) is reported as
	// ErrSessionLost.
	PostRequest(
		ctx context.Context, upstreamID string, req *jsonrpc.Request, sessionID string,
	) (resp *jsonrpc.Response, newSessionID string, err error)

	// PostNotification sends a legacy JSON-RPC notification (no response) with
	// the session id header when non-empty.
	PostNotification(
		ctx context.Context, upstreamID string, note *jsonrpc.Request, sessionID string,
	) error

	// OpenServerStream opens the upstream GET SSE stream for the session and
	// relays each event to handler until ctx is canceled or the stream ends.
	// lastEventID requests best-effort resumption (HUB-701). It returns when
	// the stream terminates; a session-loss condition yields ErrSessionLost.
	OpenServerStream(
		ctx context.Context, upstreamID, sessionID, lastEventID string, handler mcpproxy.SSEEventHandler,
	) error
}

// InitializeParams builds the legacy initialize request params for an upstream.
// The hub advertises its own clientInfo and the negotiated protocol version so
// the upstream never observes the downstream client identity (HUB-702).
type InitializeParams struct {
	// ProtocolVersion is the legacy protocol version to negotiate.
	ProtocolVersion string
	// ClientInfoJSON is the hub's clientInfo object (already JSON-encoded).
	ClientInfoJSON []byte
	// CapabilitiesJSON is the hub's advertised capabilities (JSON-encoded).
	CapabilitiesJSON []byte
}

// LegacySession is a single pooled legacy upstream session (HUB-701/702). It is
// owned by the hub PER UPSTREAM, not per downstream client: many downstream
// requests share one session. The session holds the Mcp-Session-Id, runs the
// GET SSE pump on a background goroutine that exits on context cancellation or
// pool close, and re-initializes after session loss.
type LegacySession struct {
	upstreamID string
	transport  LegacyTransport
	initParams InitializeParams
	metrics    *mcpmetrics.Metrics
	logger     observability.Logger

	// dispatcher classifies and routes every event from the GET SSE pump: a
	// server-initiated request to the MRTR bridge (HUB-704) and a notification
	// to registered subscription relays (HUB-703). Nil disables the pump.
	dispatcher *EventDispatcher

	// pumpCancel stops the background SSE pump; pumpDone closes when it exits.
	pumpCancel context.CancelFunc
	pumpDone   chan struct{}

	mu        sync.Mutex
	sessionID string
	closed    bool
}

// PostRequest forwards a legacy JSON-RPC request through the session, applying
// the current session id. On session loss it re-initializes once and retries so
// the caller observes a transparent recovery (HUB-702).
func (s *LegacySession) PostRequest(
	ctx context.Context, req *jsonrpc.Request,
) (*jsonrpc.Response, error) {
	resp, err := s.postOnce(ctx, req)
	if err == nil {
		return resp, nil
	}
	if !errors.Is(err, ErrSessionLost) {
		return nil, err
	}
	// Session loss: re-initialize once and retry (HUB-702).
	s.metrics.RecordLegacySessionReinit(s.upstreamID)
	if reinitErr := s.reinitialize(ctx); reinitErr != nil {
		return nil, fmt.Errorf("era: reinitialize after session loss: %w", reinitErr)
	}
	resp, err = s.postOnce(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// postOnce performs a single POST with the current session id, updating the
// session id when the upstream rotates it.
func (s *LegacySession) postOnce(
	ctx context.Context, req *jsonrpc.Request,
) (*jsonrpc.Response, error) {
	sid := s.currentSessionID()
	resp, newSID, err := s.transport.PostRequest(ctx, s.upstreamID, req, sid)
	if err != nil {
		return nil, err
	}
	if newSID != "" && newSID != sid {
		s.setSessionID(newSID)
	}
	return resp, nil
}

// PostNotification sends a legacy notification (e.g. logging/setLevel, ping)
// upstream through the session (HUB-707: used upstream only).
func (s *LegacySession) PostNotification(ctx context.Context, note *jsonrpc.Request) error {
	return s.transport.PostNotification(ctx, s.upstreamID, note, s.currentSessionID())
}

// SessionID returns the current hub-internal legacy session id. It is used only
// by the server-initiated-request bridge to key held state and is NEVER exposed
// downstream (HUB-702).
func (s *LegacySession) SessionID() string {
	return s.currentSessionID()
}

// currentSessionID returns the session id under the lock.
func (s *LegacySession) currentSessionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionID
}

// setSessionID stores a rotated session id under the lock.
func (s *LegacySession) setSessionID(id string) {
	s.mu.Lock()
	s.sessionID = id
	s.mu.Unlock()
}

// initialize performs the legacy handshake: initialize then
// notifications/initialized, recording the assigned session id (HUB-701). It
// starts the GET SSE pump on success.
func (s *LegacySession) initialize(ctx context.Context) error {
	initReq, err := buildInitializeRequest(s.initParams)
	if err != nil {
		return err
	}
	resp, newSID, err := s.transport.PostRequest(ctx, s.upstreamID, initReq, "")
	if err != nil {
		return fmt.Errorf("era: legacy initialize: %w", err)
	}
	if resp != nil && resp.Error != nil {
		return fmt.Errorf("era: legacy initialize rejected: %w", resp.Error)
	}
	s.setSessionID(newSID)

	if err := s.transport.PostNotification(ctx, s.upstreamID, buildInitializedNotification(), newSID); err != nil {
		return fmt.Errorf("era: legacy initialized notification: %w", err)
	}
	// The pump runs for the session's lifetime, not this request; it derives a
	// fresh background context in startPump and is stopped on close/reinit.
	s.startPump() //nolint:contextcheck // pump lifetime is the session, not ctx
	return nil
}

// reinitialize tears down the current pump and re-runs the handshake after a
// session loss (HUB-702).
func (s *LegacySession) reinitialize(ctx context.Context) error {
	s.stopPump()
	return s.initialize(ctx)
}

// Dispatcher returns the session's event dispatcher so subscription relays can
// register/unregister on the shared SSE pump (HUB-703). It is nil when the
// session has no server-event consumer configured.
func (s *LegacySession) Dispatcher() *EventDispatcher {
	return s.dispatcher
}

// startPump launches the background GET SSE pump. The pump exits when its
// context is canceled (stopPump / session close) so it never leaks (goroutine
// leak guard). Each event is routed through the dispatcher when set.
func (s *LegacySession) startPump() {
	if s.dispatcher == nil {
		// No consumer for server-initiated events: skip the pump entirely so
		// a session with no MRTR bridge holds no background goroutine.
		return
	}
	pumpCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	s.mu.Lock()
	s.pumpCancel = cancel
	s.pumpDone = done
	sid := s.sessionID
	s.mu.Unlock()

	go s.runPump(pumpCtx, sid, done)
}

// runPump drives the upstream GET SSE stream until the context is canceled,
// signaling completion by closing done. It is the sole background goroutine per
// session and always exits on ctx cancel (HUB-701 pump lifecycle).
func (s *LegacySession) runPump(ctx context.Context, sid string, done chan struct{}) {
	defer close(done)
	err := s.transport.OpenServerStream(ctx, s.upstreamID, sid, "", s.dispatcher.handle)
	if err != nil && ctx.Err() == nil {
		s.logger.Debug("era: legacy SSE pump ended",
			observability.String("upstream", s.upstreamID),
			observability.Error(err))
	}
}

// stopPump cancels the background pump and waits for it to exit so there is no
// goroutine leak across re-initialization or close.
func (s *LegacySession) stopPump() {
	s.mu.Lock()
	cancel := s.pumpCancel
	done := s.pumpDone
	s.pumpCancel = nil
	s.pumpDone = nil
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// close stops the pump and marks the session closed. It is idempotent.
func (s *LegacySession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.stopPump()
}

// buildInitializeRequest assembles the legacy initialize request (HUB-701).
func buildInitializeRequest(p InitializeParams) (*jsonrpc.Request, error) {
	params := map[string]json.RawMessage{
		"protocolVersion": mustJSONString(p.ProtocolVersion),
	}
	if len(p.ClientInfoJSON) > 0 {
		params["clientInfo"] = json.RawMessage(p.ClientInfoJSON)
	}
	if len(p.CapabilitiesJSON) > 0 {
		params["capabilities"] = json.RawMessage(p.CapabilitiesJSON)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("era: encode initialize params: %w", err)
	}
	return &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		ID:      initializeRequestID,
		Method:  MethodInitialize,
		Params:  raw,
	}, nil
}

// mustJSONString encodes s as a JSON string, returning a JSON null on the
// (unreachable for strings) marshal failure so callers keep small signatures.
func mustJSONString(s string) json.RawMessage {
	raw, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage("null")
	}
	return raw
}

// buildInitializedNotification assembles the legacy notifications/initialized
// message (HUB-701).
func buildInitializedNotification() *jsonrpc.Request {
	return &jsonrpc.Request{
		JSONRPC: jsonrpc.Version,
		Method:  MethodInitialized,
	}
}

// applySessionHeader sets the session id header on an outgoing legacy request
// when the id is non-empty (HUB-701). It is used by the concrete transport.
func applySessionHeader(h http.Header, sessionID string) {
	if sessionID != "" {
		h.Set(HeaderMcpSessionID, sessionID)
	}
}
