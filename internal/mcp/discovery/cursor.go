package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
)

// cursorTTL bounds the validity window of an issued pagination cursor. A cursor
// older than this is rejected and the client is instructed to restart from the
// beginning (HUB-166).
const cursorTTL = 10 * time.Minute

// ErrCursorRestart indicates a pagination cursor was invalid, expired, or does
// not belong to the requested list method; the client must restart the list
// from the beginning (HUB-166).
var ErrCursorRestart = errors.New(
	"discovery: invalid or expired pagination cursor; restart the list from the beginning",
)

// CursorState is the self-contained, per-upstream pagination state carried in a
// hub cursor. It records, for each contributing upstream, the opaque upstream
// cursor for its next page, so any replica can resume the walk without shared
// state (HUB-166). Upstream cursors are never exposed verbatim: the whole
// structure is sealed inside an AEAD envelope before it reaches the client.
type CursorState struct {
	// Method is the list method this cursor belongs to.
	Method string `json:"m"`
	// Upstreams maps an upstream id to its next-page upstream cursor.
	Upstreams map[string]string `json:"u"`
}

// cursorFor returns the recorded upstream cursor for an upstream, or "" (first
// page) when none was recorded.
func (s *CursorState) cursorFor(upstreamID string) string {
	if s == nil || s.Upstreams == nil {
		return ""
	}
	return s.Upstreams[upstreamID]
}

// set records an upstream's next-page cursor.
func (s *CursorState) set(upstreamID, cursor string) {
	if s.Upstreams == nil {
		s.Upstreams = make(map[string]string)
	}
	s.Upstreams[upstreamID] = cursor
}

// CursorCodec seals and opens opaque, integrity-protected pagination cursors.
// It reuses the envelope AEAD Sealer so a cursor is confidential, tamper-proof
// and self-contained; any replica sharing the key can serve the next page
// (HUB-166).
type CursorCodec struct {
	sealer envelope.Sealer
}

// NewCursorCodec constructs a CursorCodec over the given Sealer.
func NewCursorCodec(sealer envelope.Sealer) (*CursorCodec, error) {
	if sealer == nil {
		return nil, errors.New("discovery: nil cursor sealer")
	}
	return &CursorCodec{sealer: sealer}, nil
}

// Encode seals the pagination state into an opaque cursor token. The state is
// JSON-encoded and stored in the envelope's UpstreamState field; the envelope's
// TTL bounds cursor validity.
func (c *CursorCodec) Encode(ctx context.Context, state *CursorState) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("discovery: encode cursor state: %w", err)
	}
	env := &envelope.Envelope{
		OperationID:   "pagination",
		RetriedMethod: state.Method,
		IssuedAt:      time.Now(),
		TTL:           cursorTTL,
		UpstreamState: payload,
	}
	token, err := c.sealer.Seal(ctx, env)
	if err != nil {
		return "", fmt.Errorf("discovery: seal cursor: %w", err)
	}
	return token, nil
}

// Decode opens and verifies a cursor token, returning the pagination state. An
// invalid, tampered or expired cursor yields ErrCursorRestart so the caller can
// instruct the client to restart from the beginning (HUB-166).
func (c *CursorCodec) Decode(ctx context.Context, token string) (*CursorState, error) {
	env, err := c.sealer.Open(ctx, token)
	if err != nil {
		return nil, ErrCursorRestart
	}
	var state CursorState
	if err := json.Unmarshal(env.UpstreamState, &state); err != nil {
		return nil, ErrCursorRestart
	}
	return &state, nil
}
