package era

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/mcp/jsonrpc"
	mcpproxy "github.com/vyrodovalexey/avapigw/internal/mcp/proxy"
)

// ---------------------------------------------------------------------------
// fakeTransport implements LegacyTransport with programmable funcs + counters.
// ---------------------------------------------------------------------------

type fakeTransport struct {
	mu sync.Mutex

	postRequestFn      func(ctx context.Context, upstreamID string, req *jsonrpc.Request, sessionID string) (*jsonrpc.Response, string, error)
	postNotificationFn func(ctx context.Context, upstreamID string, note *jsonrpc.Request, sessionID string) error
	openServerStreamFn func(ctx context.Context, upstreamID, sessionID, lastEventID string, handler mcpproxy.SSEEventHandler) error

	postRequestCalls      int
	postNotificationCalls int
	openServerStreamCalls int

	lastPostSessionID string
	lastNote          *jsonrpc.Request
}

func (f *fakeTransport) PostRequest(
	ctx context.Context, upstreamID string, req *jsonrpc.Request, sessionID string,
) (*jsonrpc.Response, string, error) {
	f.mu.Lock()
	f.postRequestCalls++
	f.lastPostSessionID = sessionID
	fn := f.postRequestFn
	f.mu.Unlock()
	if fn == nil {
		return &jsonrpc.Response{JSONRPC: jsonrpc.Version}, "", nil
	}
	return fn(ctx, upstreamID, req, sessionID)
}

func (f *fakeTransport) PostNotification(
	ctx context.Context, upstreamID string, note *jsonrpc.Request, sessionID string,
) error {
	f.mu.Lock()
	f.postNotificationCalls++
	f.lastNote = note
	fn := f.postNotificationFn
	f.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, upstreamID, note, sessionID)
}

func (f *fakeTransport) OpenServerStream(
	ctx context.Context, upstreamID, sessionID, lastEventID string, handler mcpproxy.SSEEventHandler,
) error {
	f.mu.Lock()
	f.openServerStreamCalls++
	fn := f.openServerStreamFn
	f.mu.Unlock()
	if fn == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	return fn(ctx, upstreamID, sessionID, lastEventID, handler)
}

func (f *fakeTransport) calls() (post, note, stream int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.postRequestCalls, f.postNotificationCalls, f.openServerStreamCalls
}

// ---------------------------------------------------------------------------
// fakeFactory implements SessionFactory.
// ---------------------------------------------------------------------------

type fakeFactory struct {
	params  InitializeParams
	handler ServerRequestFunc
}

func (f *fakeFactory) InitParams(_ string) InitializeParams { return f.params }
func (f *fakeFactory) ServerRequestHandler(_ string) ServerRequestFunc {
	return f.handler
}

// ---------------------------------------------------------------------------
// fakeInfo implements UpstreamInfoProvider.
// ---------------------------------------------------------------------------

type fakeInfo struct {
	info UpstreamEraInfo
	ok   bool
}

func (f *fakeInfo) UpstreamEraInfo(_ string) (UpstreamEraInfo, bool) {
	return f.info, f.ok
}

// ---------------------------------------------------------------------------
// fakeInner implements mcpproxy.HubClient with counters.
// ---------------------------------------------------------------------------

type fakeInner struct {
	callCount   int
	streamCount int
	callResp    *jsonrpc.Response
	callErr     error
	streamErr   error
}

func (f *fakeInner) Call(
	_ context.Context, _ *backend.ServiceBackend, _ string, _ *jsonrpc.Request, _ http.Header,
) (*jsonrpc.Response, error) {
	f.callCount++
	return f.callResp, f.callErr
}

func (f *fakeInner) Stream(
	_ context.Context, _ *backend.ServiceBackend, _ string, _ *jsonrpc.Request, _ http.Header, _ mcpproxy.SSEEventHandler,
) error {
	f.streamCount++
	return f.streamErr
}

// ---------------------------------------------------------------------------
// fakeCache implements icache.Cache (map-backed, programmable errors).
// ---------------------------------------------------------------------------

type fakeCache struct {
	mu sync.Mutex

	data map[string][]byte

	getErr    error
	setErr    error
	deleteErr error
	existsErr error

	existsOverride *bool // when set, Exists returns this regardless of data

	lastSetKey string
	lastSetTTL time.Duration
}

func newFakeCache() *fakeCache {
	return &fakeCache{data: make(map[string][]byte)}
}

func (c *fakeCache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.getErr != nil {
		return nil, c.getErr
	}
	v, ok := c.data[key]
	if !ok {
		return nil, errors.New("cache miss")
	}
	return v, nil
}

func (c *fakeCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.setErr != nil {
		return c.setErr
	}
	c.data[key] = value
	c.lastSetKey = key
	c.lastSetTTL = ttl
	return nil
}

func (c *fakeCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deleteErr != nil {
		return c.deleteErr
	}
	delete(c.data, key)
	return nil
}

func (c *fakeCache) Exists(_ context.Context, key string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.existsErr != nil {
		return false, c.existsErr
	}
	if c.existsOverride != nil {
		return *c.existsOverride, nil
	}
	_, ok := c.data[key]
	return ok, nil
}

func (c *fakeCache) Close() error { return nil }

// ---------------------------------------------------------------------------
// fakeSealer implements envelope.Sealer to force Seal/Open/Consume errors.
// ---------------------------------------------------------------------------

type fakeSealer struct {
	sealFn    func(ctx context.Context, e *envelope.Envelope) (string, error)
	openFn    func(ctx context.Context, token string) (*envelope.Envelope, error)
	consumeFn func(ctx context.Context, nonce []byte) error
}

func (s *fakeSealer) Seal(ctx context.Context, e *envelope.Envelope) (string, error) {
	if s.sealFn != nil {
		return s.sealFn(ctx, e)
	}
	return "token", nil
}

func (s *fakeSealer) Open(ctx context.Context, token string) (*envelope.Envelope, error) {
	if s.openFn != nil {
		return s.openFn(ctx, token)
	}
	return &envelope.Envelope{}, nil
}

func (s *fakeSealer) Consume(ctx context.Context, nonce []byte) error {
	if s.consumeFn != nil {
		return s.consumeFn(ctx, nonce)
	}
	return nil
}

func boolPtr(b bool) *bool { return &b }

// realSealer builds a real AEADSealer with a fixed 32-byte key.
func realSealer() *envelope.AEADSealer {
	key := make([]byte, envelope.KeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	s, err := envelope.NewAEADSealer(key)
	if err != nil {
		panic(err)
	}
	return s
}
