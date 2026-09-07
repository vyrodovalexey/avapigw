package gateway

import (
	"encoding/json"
	"sync"
)

// mcpLimiter bounds concurrent streams per principal and concurrent upstream
// connections (HUB-405). A zero bound disables the corresponding limit.
type mcpLimiter struct {
	maxStreamsPerPrincipal int

	upstreamConns chan struct{} // buffered semaphore; nil disables

	mu      sync.Mutex
	streams map[string]int // principal -> active stream count
}

// newMCPLimiter constructs a limiter. Non-positive bounds disable the limit.
func newMCPLimiter(maxStreamsPerPrincipal, maxUpstreamConns int) *mcpLimiter {
	l := &mcpLimiter{
		maxStreamsPerPrincipal: maxStreamsPerPrincipal,
		streams:                make(map[string]int),
	}
	if maxUpstreamConns > 0 {
		l.upstreamConns = make(chan struct{}, maxUpstreamConns)
	}
	return l
}

// acquireStream reserves a stream slot for a principal. It returns false when
// the principal is already at its limit. The check-and-increment is performed
// under a single lock so there is no time-of-check/time-of-use window.
func (l *mcpLimiter) acquireStream(principal string) bool {
	if l == nil || l.maxStreamsPerPrincipal <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.streams[principal] >= l.maxStreamsPerPrincipal {
		return false
	}
	l.streams[principal]++
	return true
}

// releaseStream releases a previously acquired stream slot for a principal.
func (l *mcpLimiter) releaseStream(principal string) {
	if l == nil || l.maxStreamsPerPrincipal <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.streams[principal] > 0 {
		l.streams[principal]--
	}
	if l.streams[principal] == 0 {
		delete(l.streams, principal)
	}
}

// tryAcquireUpstream reserves an upstream-connection slot without blocking. It
// returns false when the pool is exhausted (HUB-405).
func (l *mcpLimiter) tryAcquireUpstream() bool {
	if l == nil || l.upstreamConns == nil {
		return true
	}
	select {
	case l.upstreamConns <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseUpstream releases a previously acquired upstream-connection slot.
func (l *mcpLimiter) releaseUpstream() {
	if l == nil || l.upstreamConns == nil {
		return
	}
	select {
	case <-l.upstreamConns:
	default:
	}
}

// enforceResultLimits enforces the content-block count and total response size
// bounds on a brokered result (HUB-405). It returns an error describing the
// first breach, or nil when the result is within limits. Zero bounds disable
// the corresponding check.
func enforceResultLimits(result json.RawMessage, maxBlocks int, maxSize int64) error {
	if maxSize > 0 && int64(len(result)) > maxSize {
		return errResponseTooLarge
	}
	if maxBlocks <= 0 || len(result) == 0 {
		return nil
	}
	var obj struct {
		Content []json.RawMessage `json:"content"`
	}
	// A result that does not decode as a content-bearing object carries no
	// content blocks to bound; treat it as within limits.
	if json.Unmarshal(result, &obj) == nil && len(obj.Content) > maxBlocks {
		return errTooManyContentBlocks
	}
	return nil
}

// resultLimitError classifies a result-limit breach for logging.
type resultLimitError struct {
	msg string
}

// Error implements the error interface.
func (e *resultLimitError) Error() string { return e.msg }

var (
	// errResponseTooLarge indicates a result exceeded the max response size.
	errResponseTooLarge = &resultLimitError{msg: "mcp: response exceeds max size"}
	// errTooManyContentBlocks indicates a result exceeded the content-block
	// count.
	errTooManyContentBlocks = &resultLimitError{msg: "mcp: too many content blocks"}
)
