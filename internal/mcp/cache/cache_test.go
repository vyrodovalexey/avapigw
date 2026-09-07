package cache

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	icache "github.com/vyrodovalexey/avapigw/internal/cache"
)

// fakeBackend is an in-memory icache.Cache for tests.
type fakeBackend struct {
	mu      sync.Mutex
	data    map[string][]byte
	getErr  error
	setErr  error
	deletes []string
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{data: make(map[string][]byte)}
}

func (f *fakeBackend) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.data[key]
	if !ok {
		return nil, icache.ErrCacheMiss
	}
	return v, nil
}

func (f *fakeBackend) Set(_ context.Context, key string, value []byte, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.data[key] = value
	return nil
}

func (f *fakeBackend) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, key)
	delete(f.data, key)
	return nil
}

func (f *fakeBackend) Exists(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.data[key]
	return ok, nil
}

func (f *fakeBackend) Close() error { return nil }

func newTestCache(t *testing.T, cfg Config) (*ResultCache, *fakeBackend) {
	t.Helper()
	b := newFakeBackend()
	c, err := New(b, cfg)
	require.NoError(t, err)
	return c, b
}

func TestNewNilBackend(t *testing.T) {
	t.Parallel()
	_, err := New(nil, Config{})
	assert.ErrorIs(t, err, ErrNilBackend)
}

func TestConfigDefaulted(t *testing.T) {
	t.Parallel()
	c := Config{}.defaulted()
	assert.Equal(t, DefaultMinTTL, c.TTLMin)
	assert.Equal(t, DefaultMaxTTL, c.TTLMax)

	// Max below min falls back to default max.
	c2 := Config{TTLMin: 10 * time.Second, TTLMax: time.Second}.defaulted()
	assert.Equal(t, 10*time.Second, c2.TTLMin)
	assert.Equal(t, DefaultMaxTTL, c2.TTLMax)
}

func TestClampTTL(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, Config{TTLMin: time.Second, TTLMax: 10 * time.Second})
	assert.Equal(t, int64(1000), c.ClampTTL(500))    // below min
	assert.Equal(t, int64(10000), c.ClampTTL(50000)) // above max
	assert.Equal(t, int64(5000), c.ClampTTL(5000))   // within window
}

func TestAggregateTTLMs(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, Config{TTLMin: time.Second, TTLMax: 60 * time.Second})

	// Min across contributors, then clamped.
	assert.Equal(t, int64(2000), c.AggregateTTLMs([]int64{5000, 2000, 9000}))
	// Empty -> min clamp.
	assert.Equal(t, int64(1000), c.AggregateTTLMs(nil))
	// Below-min min gets clamped up.
	assert.Equal(t, int64(1000), c.AggregateTTLMs([]int64{500, 3000}))
	// Above-max min gets clamped down.
	assert.Equal(t, int64(60000), c.AggregateTTLMs([]int64{120000}))
}

func TestAggregateScope(t *testing.T) {
	t.Parallel()
	assert.Equal(t, scopePrivate, AggregateScope(nil, true))
	assert.Equal(t, scopePrivate, AggregateScope([]string{"public", "private"}, false))
	assert.Equal(t, scopePublic, AggregateScope([]string{"public", "public"}, false))
	assert.Equal(t, scopePublic, AggregateScope(nil, false))
}

func TestAuthContextKeyDeterministicAndOrderIndependent(t *testing.T) {
	t.Parallel()
	k1 := AuthContextKey("alice", []string{"a", "b"})
	k2 := AuthContextKey("alice", []string{"b", "a"})
	assert.Equal(t, k1, k2, "scope ordering must not change the key")

	k3 := AuthContextKey("bob", []string{"a", "b"})
	assert.NotEqual(t, k1, k3, "different principal must change the key")
	assert.NotEmpty(t, k1)
}

func TestSetGetPublicRoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, Config{})
	parts := KeyParts{Upstream: "up1", Method: "tools/list"}
	entry := &Entry{Result: json.RawMessage(`{"tools":[]}`), TTLMs: 30000, CacheScope: scopePublic}
	require.NoError(t, c.Set(context.Background(), parts, "auth-ctx", entry))

	// A public entry does not fold in the auth context, so a different
	// context still hits it.
	got, ok := c.Get(context.Background(), parts, "different-ctx", false)
	require.True(t, ok)
	assert.JSONEq(t, `{"tools":[]}`, string(got.Result))
	assert.LessOrEqual(t, got.TTLMs, int64(30000))
}

func TestPrivateEntryNotReusedAcrossContexts(t *testing.T) {
	t.Parallel()
	c, _ := newTestCache(t, Config{})
	parts := KeyParts{Upstream: "up1", Method: "tools/list"}
	entry := &Entry{Result: json.RawMessage(`{"secret":1}`), TTLMs: 30000, CacheScope: scopePrivate}
	require.NoError(t, c.Set(context.Background(), parts, "ctx-alice", entry))

	// Same context: hit.
	_, ok := c.Get(context.Background(), parts, "ctx-alice", true)
	assert.True(t, ok)

	// Different context: miss (private isolation, HUB-183).
	_, ok = c.Get(context.Background(), parts, "ctx-bob", true)
	assert.False(t, ok)
}

func TestSetNilEntryNoop(t *testing.T) {
	t.Parallel()
	c, b := newTestCache(t, Config{})
	require.NoError(t, c.Set(context.Background(), KeyParts{Method: "m"}, "", nil))
	assert.Empty(t, b.data)
}

func TestSetBackendError(t *testing.T) {
	t.Parallel()
	c, b := newTestCache(t, Config{})
	b.setErr = errors.New("boom")
	err := c.Set(context.Background(), KeyParts{Method: "m"}, "", &Entry{TTLMs: 1000})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store entry")
}

func TestGetBackendErrorMiss(t *testing.T) {
	t.Parallel()
	c, b := newTestCache(t, Config{})
	b.getErr = errors.New("down")
	_, ok := c.Get(context.Background(), KeyParts{Method: "m"}, "", false)
	assert.False(t, ok)
}

func TestGetCorruptEntryMiss(t *testing.T) {
	t.Parallel()
	c, b := newTestCache(t, Config{})
	// Write raw non-Entry JSON directly under the computed key.
	key := c.buildKey(KeyParts{Upstream: "up1", Method: "m"}, "", false)
	b.data[key] = []byte("not-json")
	_, ok := c.Get(context.Background(), KeyParts{Upstream: "up1", Method: "m"}, "", false)
	assert.False(t, ok)
}

func TestGetTTLDecays(t *testing.T) {
	t.Parallel()
	c, b := newTestCache(t, Config{})
	parts := KeyParts{Upstream: "up1", Method: "tools/list"}
	// Store an entry that was written 100ms in the past.
	entry := &Entry{Result: json.RawMessage(`{}`), TTLMs: 30000, StoredAt: time.Now().Add(-100 * time.Millisecond)}
	payload, err := json.Marshal(entry)
	require.NoError(t, err)
	b.data[c.buildKey(parts, "", false)] = payload

	got, ok := c.Get(context.Background(), parts, "", false)
	require.True(t, ok)
	assert.Less(t, got.TTLMs, int64(30000))
}

func TestInvalidateListAndResource(t *testing.T) {
	t.Parallel()
	c, b := newTestCache(t, Config{})
	c.Invalidate(context.Background(), "up1", "tools", "")
	assert.Len(t, b.deletes, 1, "tools invalidation deletes tools/list key")

	b.deletes = nil
	c.Invalidate(context.Background(), "up1", "resources", "res://x")
	// resources/list key + resources/read(uri) key.
	assert.Len(t, b.deletes, 2)
}

func TestInvalidateUnknownKind(t *testing.T) {
	t.Parallel()
	c, b := newTestCache(t, Config{})
	c.Invalidate(context.Background(), "up1", "unknown", "")
	assert.Empty(t, b.deletes, "unknown kind and empty uri delete nothing")
}

func TestListMethodForKind(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "tools/list", listMethodForKind("tools"))
	assert.Equal(t, "prompts/list", listMethodForKind("prompts"))
	assert.Equal(t, "resources/list", listMethodForKind("resources"))
	assert.Equal(t, "", listMethodForKind("other"))
}

func TestRemainingTTLMs(t *testing.T) {
	t.Parallel()
	// Zero StoredAt returns TTLMs verbatim.
	assert.Equal(t, int64(5000), remainingTTLMs(&Entry{TTLMs: 5000}))
	// Elapsed beyond TTL floors at zero.
	assert.Equal(t, int64(0), remainingTTLMs(&Entry{TTLMs: 10, StoredAt: time.Now().Add(-time.Second)}))
}

func TestJitteredTTL(t *testing.T) {
	t.Parallel()
	// Non-positive base yields a tiny positive TTL.
	assert.Equal(t, time.Millisecond, jitteredTTL(0))
	assert.Equal(t, time.Millisecond, jitteredTTL(-time.Second))
	// Positive base stays within [base, base*1.1].
	base := time.Second
	for i := 0; i < 50; i++ {
		got := jitteredTTL(base)
		assert.GreaterOrEqual(t, got, base)
		assert.LessOrEqual(t, got, base+time.Duration(jitterFraction*float64(base)))
	}
}

func TestWithLoggerAndWithMetricsNoPanic(t *testing.T) {
	t.Parallel()
	b := newFakeBackend()
	_, err := New(b, Config{}, WithLogger(nil), WithMetrics(nil))
	require.NoError(t, err)
}
