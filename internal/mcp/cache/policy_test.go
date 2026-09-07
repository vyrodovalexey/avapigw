package cache

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRequestCacheable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		params map[string]any
		want   bool
	}{
		{"plain params cacheable", map[string]any{"cursor": "c"}, true},
		{"nil params cacheable", nil, true},
		{"inputResponses not cacheable", map[string]any{"inputResponses": []any{}}, false},
		{"requestState not cacheable", map[string]any{"requestState": "tok"}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, RequestCacheable(tc.params))
		})
	}
}

func TestResultCacheable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		result json.RawMessage
		want   bool
	}{
		{"plain result cacheable", json.RawMessage(`{"tools":[]}`), true},
		{"empty not cacheable", json.RawMessage(``), false},
		{"invalid json not cacheable", json.RawMessage(`nope`), false},
		{"inputResponses not cacheable", json.RawMessage(`{"inputResponses":[]}`), false},
		{"requestState not cacheable", json.RawMessage(`{"requestState":"x"}`), false},
		{"inputRequests not cacheable", json.RawMessage(`{"inputRequests":{}}`), false},
		{"array (not object) not cacheable", json.RawMessage(`[1,2]`), false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, ResultCacheable(tc.result))
		})
	}
}

func TestPollBackoff(t *testing.T) {
	t.Parallel()
	// Full jitter in [0, backoff]; assert bounds hold across attempts.
	for attempt := 0; attempt < 12; attempt++ {
		cap := float64(pollBaseDelay) * pow2(attempt)
		if cap > float64(pollMaxDelay) {
			cap = float64(pollMaxDelay)
		}
		for i := 0; i < 20; i++ {
			d := PollBackoff(attempt)
			assert.GreaterOrEqual(t, d, time.Duration(0))
			assert.LessOrEqual(t, d, time.Duration(cap))
		}
	}
}

func TestPollBackoffNegativeAttempt(t *testing.T) {
	t.Parallel()
	// Negative attempt is treated as 0; bounded by base delay.
	for i := 0; i < 20; i++ {
		d := PollBackoff(-5)
		assert.GreaterOrEqual(t, d, time.Duration(0))
		assert.LessOrEqual(t, d, pollBaseDelay)
	}
}

func TestPollBackoffCapped(t *testing.T) {
	t.Parallel()
	// Very large attempt saturates at pollMaxDelay.
	for i := 0; i < 20; i++ {
		d := PollBackoff(100)
		assert.LessOrEqual(t, d, pollMaxDelay)
	}
}

func pow2(n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= 2
	}
	return r
}
