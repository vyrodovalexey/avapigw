package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	icache "github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	mcpcache "github.com/vyrodovalexey/avapigw/internal/mcp/cache"
	"github.com/vyrodovalexey/avapigw/internal/mcp/headers"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	"github.com/vyrodovalexey/avapigw/internal/mcp/protocol"
)

// memBackend is a minimal in-memory icache.Cache for tests.
type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: make(map[string][]byte)} }

func (m *memBackend) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, icache.ErrCacheMiss
	}
	return v, nil
}

func (m *memBackend) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *memBackend) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memBackend) Exists(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.data[key]
	return ok, nil
}

func (m *memBackend) Close() error { return nil }

// newCachingHandler builds a handler with a real ResultCache over an in-memory
// backend.
func newCachingHandler(t *testing.T, hub *fakeHub) *MCPHandler {
	t.Helper()

	cache, err := mcpcache.New(newMemBackend(), mcpcache.Config{})
	require.NoError(t, err)

	reg := &fakeBackendRegistry{backends: map[string]backend.Backend{
		testUpstreamName: newServiceBackend(t, testUpstreamName),
	}}
	routes := []config.MCPRoute{{Name: "catch-all", Upstreams: []string{testUpstreamName}}}
	upstreams := map[string]config.MCPBackend{
		testUpstreamName: {Name: testUpstreamName, NamespacePrefix: testNamespacePrefix},
	}
	h, err := NewMCPHandler(
		WithMCPHandlerBackendRegistry(reg),
		WithMCPHandlerHub(hub),
		WithMCPHandlerConfig(routes, upstreams, &config.MCPConfig{}),
		WithMCPHandlerServerInfo(mustServerInfo()),
		WithMCPHandlerCache(cache),
	)
	require.NoError(t, err)
	return h
}

func TestMCPHandler_ResourcesRead_CacheMissThenHit(t *testing.T) {
	t.Parallel()

	readResult := map[string]any{
		"contents": []any{map[string]any{"uri": "file://x", "text": "data"}},
		"ttlMs":    60000,
	}
	resp, err := jsonrpc.NewResponse(json.RawMessage(`1`), readResult)
	require.NoError(t, err)
	hub := &fakeHub{resp: resp}
	h := newCachingHandler(t, hub)

	nsURI := testNamespacePrefix + "." + "file://x"
	doRead := func() *httptest.ResponseRecorder {
		body := mcpBody{method: protocol.MethodResourcesRead, extra: map[string]any{"uri": nsURI}}.build(t)
		r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		r.Header.Set(headers.HeaderMcpProtocolVersion, testProtocolVersion)
		r.Header.Set(headers.HeaderMcpMethod, protocol.MethodResourcesRead)
		r.Header.Set(headers.HeaderMcpName, nsURI)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	// First call: cache miss => upstream is called and result stored.
	rec1 := doRead()
	require.Equal(t, http.StatusOK, rec1.Code)
	assert.Equal(t, 1, hub.callCount)

	// Second identical call: served from cache => upstream not called again.
	rec2 := doRead()
	require.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, 1, hub.callCount, "second read must be served from cache")
}

func TestMCPHandler_InvalidateCache(t *testing.T) {
	t.Parallel()

	hub := &fakeHub{resp: okListResponse(t)}
	h := newCachingHandler(t, hub)
	// Invalidate is a no-op-safe hook; exercise it for coverage.
	assert.NotPanics(t, func() {
		h.InvalidateCache(context.Background(), testUpstreamName, "resources", "file://x")
	})
}

func TestMCPHandler_InvalidateCache_Disabled(t *testing.T) {
	t.Parallel()

	h := newTestHandler(t, &fakeHub{}).handler // no cache configured
	assert.NotPanics(t, func() {
		h.InvalidateCache(context.Background(), testUpstreamName, "resources", "file://x")
	})
}
