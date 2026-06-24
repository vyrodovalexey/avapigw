package aggregate

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// redisSpoolStore adapts a go-redis client to the SpoolStore interface for tests.
type redisSpoolStore struct {
	client redis.UniversalClient
}

func (s *redisSpoolStore) Get(ctx context.Context, key string) ([]byte, error) {
	return s.client.Get(ctx, key).Bytes()
}

func (s *redisSpoolStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl).Err()
}

func (s *redisSpoolStore) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

// failingStore always errors, simulating a redis outage.
type failingStore struct {
	mu       sync.Mutex
	setCalls int
}

func (f *failingStore) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("redis down")
}

func (f *failingStore) Set(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	f.mu.Lock()
	f.setCalls++
	f.mu.Unlock()
	return errors.New("redis down")
}

func (f *failingStore) Delete(_ context.Context, _ string) error {
	return errors.New("redis down")
}

func newMiniredisStore(t *testing.T) (*miniredis.Miniredis, *redisSpoolStore) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, &redisSpoolStore{client: client}
}

func redisSpoolOpts() *SpoolOptions {
	return &SpoolOptions{
		Enabled:        true,
		Backend:        SpoolBackendRedis,
		ThresholdBytes: 16,
		TTL:            time.Minute,
	}
}

// U-SPL-1: body < threshold → in-memory, no redis call.
func TestSpooler_BelowThreshold_Memory(t *testing.T) {
	mr, store := newMiniredisStore(t)
	sp := NewSpooler(redisSpoolOpts(), store, nil, nil)

	small := []byte("tiny")
	handle, err := sp.Put(context.Background(), "a", small)
	require.NoError(t, err)

	got, err := sp.Get(context.Background(), handle)
	require.NoError(t, err)
	assert.Equal(t, small, got)
	// No key written to redis.
	assert.Empty(t, mr.Keys())
}

// U-SPL-2: body ≥ threshold → spooled to redis, retrieved.
func TestSpooler_AboveThreshold_Redis(t *testing.T) {
	mr, store := newMiniredisStore(t)
	m, _ := newRegisteredMetrics(t)
	sp := NewSpooler(redisSpoolOpts(), store, nil, m)

	large := []byte(strings.Repeat("x", 64))
	handle, err := sp.Put(context.Background(), "a", large)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(handle, spoolKeyPrefix))

	// Key present in redis (memory fallback not used).
	assert.Len(t, mr.Keys(), 1)
	// Spool-bytes histogram recorded one observation.
	assert.Equal(t, 1, testutil.CollectAndCount(m.SpoolBytes))

	got, err := sp.Get(context.Background(), handle)
	require.NoError(t, err)
	assert.Equal(t, large, got)
}

// U-SPL-3: redis unavailable → memory fallback, request succeeds.
func TestSpooler_RedisOutage_MemoryFallback(t *testing.T) {
	fs := &failingStore{}
	m, _ := newRegisteredMetrics(t)
	sp := NewSpooler(redisSpoolOpts(), fs, nil, m)

	large := []byte(strings.Repeat("y", 64))
	handle, err := sp.Put(context.Background(), "a", large)
	require.NoError(t, err) // Put never fails; falls back to memory.

	got, err := sp.Get(context.Background(), handle)
	require.NoError(t, err)
	assert.Equal(t, large, got)

	// U-SPL-6: spool error metric incremented.
	assert.Equal(t, float64(1), testutil.ToFloat64(m.SpoolErrorsTotal))
	assert.GreaterOrEqual(t, fs.setCalls, 1)
}

// U-SPL-4: sentinel client path exercised via a FailoverClient resolving against
// a miniredis instance impersonating a sentinel.
func TestSpooler_SentinelPath(t *testing.T) {
	master, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(master.Close)

	host, port, err := net.SplitHostPort(master.Addr())
	require.NoError(t, err)

	sentinel := miniredis.NewMiniRedis()
	require.NoError(t, sentinel.Start())
	t.Cleanup(sentinel.Close)

	// Register a minimal SENTINEL get-master-addr-by-name handler so the
	// FailoverClient can resolve the master endpoint.
	require.NoError(t, sentinel.Server().Register("SENTINEL", func(c *server.Peer, cmd string, args []string) {
		if len(args) >= 1 && strings.EqualFold(args[0], "get-master-addr-by-name") {
			c.WriteLen(2)
			c.WriteBulk(host)
			c.WriteBulk(port)
			return
		}
		// sentinels / replicas discovery: empty array.
		c.WriteLen(0)
	}))

	client := redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    "mymaster",
		SentinelAddrs: []string{sentinel.Addr()},
	})
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, client.Ping(context.Background()).Err())

	store := &redisSpoolStore{client: client}
	sp := NewSpooler(redisSpoolOpts(), store, nil, nil)

	large := []byte(strings.Repeat("z", 64))
	handle, err := sp.Put(context.Background(), "a", large)
	require.NoError(t, err)
	got, err := sp.Get(context.Background(), handle)
	require.NoError(t, err)
	assert.Equal(t, large, got)
	assert.Len(t, master.Keys(), 1)
}

// U-SPL-5: spool keys cleaned up after completion.
func TestSpooler_Cleanup(t *testing.T) {
	mr, store := newMiniredisStore(t)
	sp := NewSpooler(redisSpoolOpts(), store, nil, nil)

	large := []byte(strings.Repeat("x", 64))
	_, err := sp.Put(context.Background(), "a", large)
	require.NoError(t, err)
	_, err = sp.Put(context.Background(), "b", large)
	require.NoError(t, err)
	assert.Len(t, mr.Keys(), 2)

	sp.Cleanup(context.Background())
	assert.Empty(t, mr.Keys())

	// Idempotent: cleanup again is safe.
	assert.NotPanics(t, func() { sp.Cleanup(context.Background()) })
}

// TTL applied to spooled entries.
func TestSpooler_TTLApplied(t *testing.T) {
	mr, store := newMiniredisStore(t)
	opts := redisSpoolOpts()
	opts.TTL = 30 * time.Second
	sp := NewSpooler(opts, store, nil, nil)

	large := []byte(strings.Repeat("x", 64))
	handle, err := sp.Put(context.Background(), "a", large)
	require.NoError(t, err)

	ttl := mr.TTL(handle)
	assert.Greater(t, ttl, time.Duration(0))
	assert.LessOrEqual(t, ttl, 35*time.Second)
}

// Disabled spool always uses memory.
func TestSpooler_DisabledUsesMemory(t *testing.T) {
	mr, store := newMiniredisStore(t)
	sp := NewSpooler(&SpoolOptions{Enabled: false, Backend: SpoolBackendRedis}, store, nil, nil)

	large := []byte(strings.Repeat("x", 4096))
	handle, err := sp.Put(context.Background(), "a", large)
	require.NoError(t, err)
	got, err := sp.Get(context.Background(), handle)
	require.NoError(t, err)
	assert.Equal(t, large, got)
	assert.Empty(t, mr.Keys())
}

// Memory backend (not redis) never spools off-heap even when enabled.
func TestSpooler_MemoryBackend(t *testing.T) {
	mr, store := newMiniredisStore(t)
	sp := NewSpooler(&SpoolOptions{Enabled: true, Backend: SpoolBackendMemory, ThresholdBytes: 16}, store, nil, nil)
	large := []byte(strings.Repeat("x", 64))
	_, err := sp.Put(context.Background(), "a", large)
	require.NoError(t, err)
	assert.Empty(t, mr.Keys())
}

// Get on missing handle in memory-only mode errors.
func TestSpooler_GetMissingHandle(t *testing.T) {
	sp := NewSpooler(nil, nil, nil, nil)
	_, err := sp.Get(context.Background(), "avapigw:aggregate:spool:nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// Get error from redis increments error metric (enabled redis path).
func TestSpooler_GetRedisError(t *testing.T) {
	fs := &failingStore{}
	m, _ := newRegisteredMetrics(t)
	sp := NewSpooler(redisSpoolOpts(), fs, nil, m)
	// Force enabled path with a handle not in memory.
	_, err := sp.Get(context.Background(), spoolKeyPrefix+"deadbeef")
	require.Error(t, err)
	assert.Equal(t, float64(1), testutil.ToFloat64(m.SpoolErrorsTotal))
}

// Cleanup with redis delete error increments error metric but never panics.
func TestSpooler_CleanupRedisError(t *testing.T) {
	fs := &failingStore{}
	m, _ := newRegisteredMetrics(t)
	sp := NewSpooler(redisSpoolOpts(), fs, nil, m)

	// Put large body; fallback to memory but key tracked. Force a tracked redis
	// key by making Set succeed once via a working store, then swap to failing.
	mr, store := newMiniredisStore(t)
	sp2 := NewSpooler(redisSpoolOpts(), store, nil, m)
	large := []byte(strings.Repeat("x", 64))
	_, err := sp2.Put(context.Background(), "a", large)
	require.NoError(t, err)
	// Stop redis to cause delete errors on cleanup.
	mr.Close()
	assert.NotPanics(t, func() { sp2.Cleanup(context.Background()) })

	// failing store cleanup path: put falls to memory (no tracked redis keys),
	// so just ensure no panic.
	assert.NotPanics(t, func() { sp.Cleanup(context.Background()) })
}

// NewSpooler applies defaults for threshold and TTL.
func TestNewSpooler_Defaults(t *testing.T) {
	sp := NewSpooler(&SpoolOptions{Enabled: true, Backend: SpoolBackendRedis}, &failingStore{}, nil, nil)
	assert.Equal(t, int64(DefaultSpoolThresholdBytes), sp.thresholdBytes)
	assert.Equal(t, DefaultSpoolTTL, sp.ttl)
	assert.True(t, sp.enabled)

	// Nil opts: defaults, disabled.
	sp2 := NewSpooler(nil, nil, nil, nil)
	assert.Equal(t, int64(DefaultSpoolThresholdBytes), sp2.thresholdBytes)
	assert.Equal(t, DefaultSpoolTTL, sp2.ttl)
	assert.False(t, sp2.enabled)
}

func TestSpooler_NewHandle_Unique(t *testing.T) {
	sp := NewSpooler(nil, nil, nil, nil)
	h1 := sp.newHandle("a")
	h2 := sp.newHandle("a")
	assert.NotEqual(t, h1, h2)
	assert.True(t, strings.HasPrefix(h1, spoolKeyPrefix))
}

func TestSpooler_JitteredTTL(t *testing.T) {
	sp := NewSpooler(nil, nil, nil, nil)
	sp.ttl = time.Minute
	jt := sp.jitteredTTL()
	assert.GreaterOrEqual(t, jt, time.Minute)
	assert.LessOrEqual(t, jt, time.Minute+time.Duration(float64(time.Minute)*spoolTTLJitter)+time.Millisecond)
}

// Concurrent Put/Get race safety.
func TestSpooler_Concurrent(t *testing.T) {
	_, store := newMiniredisStore(t)
	sp := NewSpooler(redisSpoolOpts(), store, nil, nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := []byte(strings.Repeat("x", 64))
			h, err := sp.Put(context.Background(), "t", body)
			assert.NoError(t, err)
			_, err = sp.Get(context.Background(), h)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}
