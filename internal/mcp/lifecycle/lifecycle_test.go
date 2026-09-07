package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

func TestTimeoutFor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		timeouts *config.MCPTimeouts
		method   string
		tool     string
		want     time.Duration
	}{
		{"nil timeouts -> default", nil, "tools/call", "echo", DefaultTimeout},
		{
			"per-tool wins",
			&config.MCPTimeouts{PerTool: map[string]config.Duration{"echo": config.Duration(2 * time.Second)}},
			"tools/call", "echo", 2 * time.Second,
		},
		{
			"per-method used when no tool",
			&config.MCPTimeouts{PerMethod: map[string]config.Duration{"tools/call": config.Duration(3 * time.Second)}},
			"tools/call", "", 3 * time.Second,
		},
		{
			"per-tool zero falls through to per-method",
			&config.MCPTimeouts{
				PerTool:   map[string]config.Duration{"echo": config.Duration(0)},
				PerMethod: map[string]config.Duration{"tools/call": config.Duration(4 * time.Second)},
			},
			"tools/call", "echo", 4 * time.Second,
		},
		{
			"default field used when no per-method/tool",
			&config.MCPTimeouts{Default: config.Duration(7 * time.Second)},
			"tools/call", "echo", 7 * time.Second,
		},
		{
			"empty timeouts -> default const",
			&config.MCPTimeouts{}, "tools/call", "echo", DefaultTimeout,
		},
		{
			"per-method zero falls through to default const",
			&config.MCPTimeouts{PerMethod: map[string]config.Duration{"tools/call": config.Duration(0)}},
			"tools/call", "", DefaultTimeout,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, TimeoutFor(tc.timeouts, tc.method, tc.tool))
		})
	}
}

func TestWithTimeoutFiresError(t *testing.T) {
	t.Parallel()
	timeouts := &config.MCPTimeouts{Default: config.Duration(10 * time.Millisecond)}
	ctx, cancel := WithTimeout(context.Background(), timeouts, "tools/call", "")
	defer cancel()

	select {
	case <-ctx.Done():
		require.True(t, IsTimeout(ctx.Err()), "deadline exceeded must be classified as timeout")
	case <-time.After(2 * time.Second):
		t.Fatal("WithTimeout did not fire within tolerance")
	}
}

func TestWithTimeoutParentCancelPropagates(t *testing.T) {
	t.Parallel()
	parent, cancelParent := context.WithCancel(context.Background())
	// Long timeout so only parent cancel ends the child.
	ctx, cancel := WithTimeout(parent, &config.MCPTimeouts{Default: config.Duration(time.Hour)}, "tools/call", "")
	defer cancel()
	cancelParent()

	select {
	case <-ctx.Done():
		require.True(t, IsCancellation(ctx.Err()), "parent cancel must classify as cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("child context did not cancel with parent")
	}
}

func TestIsTimeout(t *testing.T) {
	t.Parallel()
	assert.True(t, IsTimeout(context.DeadlineExceeded))
	assert.True(t, IsTimeout(ErrUpstreamTimeout))
	assert.True(t, IsTimeout(fmt.Errorf("wrap: %w", ErrUpstreamTimeout)))
	assert.False(t, IsTimeout(context.Canceled))
	assert.False(t, IsTimeout(errors.New("other")))
	assert.False(t, IsTimeout(nil))
}

func TestIsCancellation(t *testing.T) {
	t.Parallel()
	assert.True(t, IsCancellation(context.Canceled))
	assert.True(t, IsCancellation(fmt.Errorf("wrap: %w", context.Canceled)))
	assert.False(t, IsCancellation(context.DeadlineExceeded))
	assert.False(t, IsCancellation(nil))
}

func TestIsProgress(t *testing.T) {
	t.Parallel()
	assert.True(t, IsProgress(MethodProgress))
	assert.True(t, IsProgress("notifications/progress"))
	assert.False(t, IsProgress("notifications/message"))
	assert.False(t, IsProgress(""))
}

func TestParseProgress(t *testing.T) {
	t.Parallel()

	t.Run("valid with token", func(t *testing.T) {
		t.Parallel()
		params := json.RawMessage(`{"progressToken":"tok-1","progress":0.5}`)
		pn, ok := ParseProgress(params)
		require.True(t, ok)
		assert.JSONEq(t, `"tok-1"`, string(pn.ProgressToken))
		assert.Equal(t, params, pn.Params)
	})

	t.Run("valid numeric token", func(t *testing.T) {
		t.Parallel()
		pn, ok := ParseProgress(json.RawMessage(`{"progressToken":42}`))
		require.True(t, ok)
		assert.JSONEq(t, `42`, string(pn.ProgressToken))
	})

	t.Run("missing token still ok", func(t *testing.T) {
		t.Parallel()
		pn, ok := ParseProgress(json.RawMessage(`{"progress":1}`))
		require.True(t, ok)
		assert.Nil(t, pn.ProgressToken)
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()
		pn, ok := ParseProgress(json.RawMessage(`not-json`))
		assert.False(t, ok)
		assert.Equal(t, ProgressNotification{}, pn)
	})
}

func TestMethodExemptFromTimeout(t *testing.T) {
	t.Parallel()
	assert.True(t, MethodExemptFromTimeout(protocol.MethodSubscriptionsListen))
	assert.False(t, MethodExemptFromTimeout("tools/call"))
	assert.False(t, MethodExemptFromTimeout(""))
}
