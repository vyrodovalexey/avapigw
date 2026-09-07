package cache

import (
	"encoding/json"
	"math"
	"math/rand/v2"
	"time"
)

// pollBaseDelay / pollMaxDelay bound the exponential backoff schedule used by
// any future notification-driven poller (HUB-185). No active poller runs now;
// these support one when it is added, and enforce that ttlMs is never used as a
// polling interval.
const (
	pollBaseDelay = 1 * time.Second
	pollMaxDelay  = 5 * time.Minute
)

// RequestCacheable reports whether a request's params may be cached. Results of
// requests carrying inputResponses or requestState MUST NOT be cached (HUB-184)
// because they are MRTR-round-specific and per-caller.
func RequestCacheable(params map[string]any) bool {
	if _, ok := params["inputResponses"]; ok {
		return false
	}
	if _, ok := params["requestState"]; ok {
		return false
	}
	return true
}

// ResultCacheable reports whether a result payload may be cached. A result
// carrying inputResponses or requestState (an input_required round) MUST NOT be
// cached (HUB-184).
func ResultCacheable(result json.RawMessage) bool {
	if len(result) == 0 {
		return false
	}
	obj := make(map[string]json.RawMessage)
	if err := json.Unmarshal(result, &obj); err != nil {
		return false
	}
	if _, ok := obj["inputResponses"]; ok {
		return false
	}
	if _, ok := obj["requestState"]; ok {
		return false
	}
	if _, ok := obj["inputRequests"]; ok {
		return false
	}
	return true
}

// PollBackoff returns the jittered exponential backoff delay for the nth poll
// attempt (0-based), capped at pollMaxDelay. It applies full jitter so
// concurrent replicas do not synchronize (HUB-185: jitter + backoff, never
// ttl-as-interval).
func PollBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	backoff := float64(pollBaseDelay) * math.Pow(2, float64(attempt))
	if backoff > float64(pollMaxDelay) {
		backoff = float64(pollMaxDelay)
	}
	// Full jitter in [0, backoff].
	jittered := rand.Float64() * backoff //nolint:gosec // non-cryptographic poll jitter
	return time.Duration(jittered)
}
