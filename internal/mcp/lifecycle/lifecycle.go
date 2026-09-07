// Package lifecycle implements the hub's cancellation, timeout and progress
// handling for MCP requests (HUB-241..244). Closure of the downstream SSE
// response stream cancels the request and tears down the upstream stream
// (HUB-241/242); per-method and per-tool timeouts convert an upstream stall
// into a JSON-RPC error rather than a silent hang (HUB-243); and upstream
// notifications/progress are relayed on the correct response stream preserving
// progressToken semantics (HUB-244). subscriptions/listen streams are exempt
// from the request timeout.
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// DefaultTimeout bounds a non-subscription upstream call when no per-method,
// per-tool or default timeout is configured (HUB-243).
const DefaultTimeout = 30 * time.Second

// MethodProgress is the upstream progress notification method (HUB-244).
const MethodProgress = "notifications/progress"

// ErrUpstreamTimeout indicates the upstream call exceeded its configured
// timeout (HUB-243). Callers convert it into a JSON-RPC error, never a silent
// hang.
var ErrUpstreamTimeout = errors.New("lifecycle: upstream call timed out")

// TimeoutFor resolves the effective timeout for a (method, de-namespaced tool)
// pair from the upstream's configured timeouts, falling back to the default
// (HUB-243). A non-positive resolved value yields DefaultTimeout so a call is
// never left unbounded.
func TimeoutFor(timeouts *config.MCPTimeouts, method, tool string) time.Duration {
	if timeouts == nil {
		return DefaultTimeout
	}
	if tool != "" {
		if d, ok := timeouts.PerTool[tool]; ok && time.Duration(d) > 0 {
			return time.Duration(d)
		}
	}
	if d, ok := timeouts.PerMethod[method]; ok && time.Duration(d) > 0 {
		return time.Duration(d)
	}
	if d := time.Duration(timeouts.Default); d > 0 {
		return d
	}
	return DefaultTimeout
}

// WithTimeout derives a child context bounded by the resolved timeout for the
// (method, tool) pair (HUB-243). The parent context is reused so a downstream
// client disconnect still cancels the child (HUB-241). The caller MUST defer
// the returned cancel to release resources. subscriptions/listen callers MUST
// NOT use this helper — they are exempt from the request timeout.
func WithTimeout(
	parent context.Context, timeouts *config.MCPTimeouts, method, tool string,
) (context.Context, context.CancelFunc) {
	d := TimeoutFor(timeouts, method, tool)
	return context.WithTimeout(parent, d)
}

// IsTimeout reports whether an error resulted from the upstream call exceeding
// its deadline (HUB-243), so the caller can map it to a JSON-RPC error.
func IsTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrUpstreamTimeout)
}

// IsCancellation reports whether an error resulted from a client disconnect /
// context cancellation (HUB-241), so the caller can stop silently without
// writing further messages.
func IsCancellation(err error) bool {
	return errors.Is(err, context.Canceled)
}

// ProgressNotification is a decoded upstream progress notification (HUB-244).
type ProgressNotification struct {
	// ProgressToken carries the client's progress token verbatim.
	ProgressToken json.RawMessage
	// Params is the full notification params, forwarded to the client.
	Params json.RawMessage
}

// IsProgress reports whether a notification method is notifications/progress.
func IsProgress(method string) bool {
	return method == MethodProgress
}

// ParseProgress extracts the progressToken from a progress notification's
// params so its semantics are preserved when relayed downstream (HUB-244).
func ParseProgress(params json.RawMessage) (ProgressNotification, bool) {
	var obj struct {
		ProgressToken json.RawMessage `json:"progressToken"`
	}
	if err := json.Unmarshal(params, &obj); err != nil {
		return ProgressNotification{}, false
	}
	return ProgressNotification{ProgressToken: obj.ProgressToken, Params: params}, true
}

// MethodExemptFromTimeout reports whether a method is a long-lived stream exempt
// from the request timeout (HUB-243): subscriptions/listen.
func MethodExemptFromTimeout(method string) bool {
	return method == protocol.MethodSubscriptionsListen
}
