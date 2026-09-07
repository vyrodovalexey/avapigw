package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
	mcpsub "github.com/vyrodovalexey/avapigw/internal/mcp/subscription"
)

// newSubscriptionHandler builds a handler with a real subscription manager and a
// per-principal stream limit.
func newSubscriptionHandler(t *testing.T, maxStreamsPerPrincipal int) *MCPHandler {
	t.Helper()

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	routes := []config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}}
	upstreams := map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix},
	}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(&fakeHub{}),
		WithMCPHandlerConfig(routes, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerLimits(maxStreamsPerPrincipal, 0),
	)
	require.NoError(t, err)

	mgr, err := mcpsub.NewManager(h.NewUpstreamStreamer(), h.mapper, mcpsub.Config{})
	require.NoError(t, err)
	h.AttachSubscriptionManager(mgr)
	return h
}

func TestMCPHandler_Subscription_StreamLimitExceeded(t *testing.T) {
	t.Parallel()

	h := newSubscriptionHandler(t, 1)
	// Pre-acquire the single per-principal slot (keyed by remote addr).
	require.True(t, h.limiter.acquireStream("192.0.2.1:1111"))

	body := mcpBody{method: protocol.MethodSubscriptionsListen}.build(t)
	r := newMCPRequest(t, body, protocol.MethodSubscriptionsListen, "")
	r.RemoteAddr = "192.0.2.1:1111"

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

func TestMCPHandler_Subscription_ClientDisconnect(t *testing.T) {
	t.Parallel()

	h := newSubscriptionHandler(t, 0) // no per-principal limit

	body := mcpBody{method: protocol.MethodSubscriptionsListen}.build(t)
	// A request whose context is already canceled makes Listen return promptly
	// after the ack, so the test is deterministic and never hangs.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := newMCPRequest(t, body, protocol.MethodSubscriptionsListen, "").WithContext(ctx)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	// The SSE stream head is written with status 200 before it drains.
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
}

func TestHandler_SubscriptionNegotiatedVersion(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler

	// nil route => downstream version passes through.
	assert.Equal(t, "v1", h.subscriptionNegotiatedVersion(nil, "v1"))

	// route with a known upstream => negotiated via the upstream config.
	route := &config.MCPRoute{Upstreams: []string{testUpstreamName}}
	assert.Equal(t, "v2", h.subscriptionNegotiatedVersion(route, "v2"))

	// route referencing an unknown upstream => downstream version passthrough.
	route2 := &config.MCPRoute{Upstreams: []string{"missing"}}
	assert.Equal(t, "v3", h.subscriptionNegotiatedVersion(route2, "v3"))
}

func TestHandler_SubscriptionUpstreamMeta(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler
	body := mcpBody{method: protocol.MethodSubscriptionsListen}.build(t)
	r := newMCPRequest(t, body, protocol.MethodSubscriptionsListen, "")

	mr, ok := h.parseAndValidate(httptest.NewRecorder(), r)
	require.True(t, ok)

	route := &config.MCPRoute{Upstreams: []string{testUpstreamName}}
	raw := h.subscriptionUpstreamMeta(mr, route)
	assert.NotNil(t, raw)
}
