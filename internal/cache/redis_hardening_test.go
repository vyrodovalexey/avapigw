package cache

// Tests for the WP14-redis hardening cluster:
//   - B13: retry classification (transient-only retries);
//   - D5:  privacy-safe (hashed) keys in span attributes and logs;
//   - E2:  metric parity for GetWithTTL / SetNX / Expire;
//   - C7:  caller-context plumbing in readVaultPassword / pingRedis.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// --- Test doubles ---

// fakeRedisServerError mimics a Redis server reply error (implements the
// redis.Error marker interface like proto.RedisError does).
type fakeRedisServerError string

func (e fakeRedisServerError) Error() string { return string(e) }

// RedisError marks the type as a Redis server reply error.
func (e fakeRedisServerError) RedisError() {}

// countingHook counts client-level invocations of a single command name
// (connection-handshake commands like HELLO / CLIENT SETINFO are ignored).
// With the client's internal retries disabled (MaxRetries: -1), each counted
// invocation corresponds to exactly one attempt of the cache retry helper.
type countingHook struct {
	cmdName      string
	processCalls atomic.Int64
}

func (h *countingHook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h *countingHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == h.cmdName {
			h.processCalls.Add(1)
		}
		return next(ctx, cmd)
	}
}

func (h *countingHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			if cmd.Name() == h.cmdName {
				h.processCalls.Add(1)
				break
			}
		}
		return next(ctx, cmds)
	}
}

// capturedLogEntry is a single log record captured by capturingLogger.
type capturedLogEntry struct {
	level  string
	msg    string
	fields []observability.Field
}

// capturingLogger is an observability.Logger that records entries so tests
// can assert on emitted log fields.
type capturingLogger struct {
	mu      sync.Mutex
	entries []capturedLogEntry
}

func (l *capturingLogger) record(level, msg string, fields []observability.Field) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, capturedLogEntry{level: level, msg: msg, fields: fields})
}

func (l *capturingLogger) Debug(msg string, fields ...observability.Field) {
	l.record("debug", msg, fields)
}

func (l *capturingLogger) Info(msg string, fields ...observability.Field) {
	l.record("info", msg, fields)
}

func (l *capturingLogger) Warn(msg string, fields ...observability.Field) {
	l.record("warn", msg, fields)
}

func (l *capturingLogger) Error(msg string, fields ...observability.Field) {
	l.record("error", msg, fields)
}

func (l *capturingLogger) Fatal(msg string, fields ...observability.Field) {
	l.record("fatal", msg, fields)
}

func (l *capturingLogger) With(_ ...observability.Field) observability.Logger { return l }
func (l *capturingLogger) WithContext(_ context.Context) observability.Logger { return l }
func (l *capturingLogger) Sync() error                                        { return nil }

// keyFieldValues returns every value logged under the "key" field.
func (l *capturingLogger) keyFieldValues() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var values []string
	for _, entry := range l.entries {
		for _, field := range entry.fields {
			if field.Key == "key" {
				values = append(values, field.String)
			}
		}
	}
	return values
}

// debugMessages returns the messages of all captured debug entries.
func (l *capturingLogger) debugMessages() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var msgs []string
	for _, entry := range l.entries {
		if entry.level == "debug" {
			msgs = append(msgs, entry.msg)
		}
	}
	return msgs
}

// ctxAwareKVClient is a mock KV client that honors context cancellation,
// mimicking a real Vault client.
type ctxAwareKVClient struct {
	mockKVClient
}

func (m *ctxAwareKVClient) Read(
	ctx context.Context, mount, path string,
) (map[string]interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.mockKVClient.Read(ctx, mount, path)
}

// --- Test helpers ---

// newTestRedisCache builds a redisCache through the real constructor against
// the given miniredis instance and registers cleanup.
func newTestRedisCache(
	t *testing.T, mr *miniredis.Miniredis, hashKeys bool, logger observability.Logger,
) *redisCache {
	t.Helper()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       "redis://" + mr.Addr(),
			KeyPrefix: "test:",
			HashKeys:  hashKeys,
		},
	}

	c, err := newRedisCache(context.Background(), cfg, logger, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// newHookedRedisCache builds a redisCache around a manually configured client
// with the client's internal retries disabled and a counting hook attached
// (counting cmdName invocations), so that counted command attempts equal
// cache-level retry attempts.
func newHookedRedisCache(
	t *testing.T, addr, cmdName string, hashKeys bool, logger observability.Logger,
) (*redisCache, *countingHook) {
	t.Helper()

	client := redis.NewClient(&redis.Options{
		Addr:        addr,
		MaxRetries:  -1, // disable go-redis internal retries
		DialTimeout: 200 * time.Millisecond,
	})
	hook := &countingHook{cmdName: cmdName}
	client.AddHook(hook)

	c := &redisCache{
		logger:     logger,
		client:     client,
		keyPrefix:  "test:",
		defaultTTL: time.Minute,
		hashKeys:   hashKeys,
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, hook
}

// histogramSampleCount returns the number of observations recorded in the
// cache operation duration histogram for the given backend/operation pair.
func histogramSampleCount(t *testing.T, backend, operation string) uint64 {
	t.Helper()

	observer, err := GetCacheMetrics().operationDuration.GetMetricWithLabelValues(backend, operation)
	require.NoError(t, err)

	metric, ok := observer.(prometheus.Metric)
	require.True(t, ok, "histogram observer must implement prometheus.Metric")

	pb := &dto.Metric{}
	require.NoError(t, metric.Write(pb))
	return pb.GetHistogram().GetSampleCount()
}

// --- B13: retry classification ---

func TestIsRetryableRedisError_ServerReplyClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		reply     string
		retryable bool
	}{
		{"WRONGTYPE is permanent", "WRONGTYPE Operation against a key holding the wrong kind of value", false},
		{"OOM is permanent", "OOM command not allowed when used memory > 'maxmemory'", false},
		{"NOAUTH is permanent", "NOAUTH Authentication required.", false},
		{"ERR syntax is permanent", "ERR syntax error", false},
		{"MOVED is permanent", "MOVED 3999 127.0.0.1:6381", false},
		{"ASK is permanent", "ASK 3999 127.0.0.1:6381", false},
		{"EXECABORT is permanent", "EXECABORT Transaction discarded because of previous errors.", false},
		{"LOADING is transient", "LOADING Redis is loading the dataset in memory", true},
		{"READONLY is transient (failover window)", "READONLY You can't write against a read only replica.", true},
		{"CLUSTERDOWN is transient", "CLUSTERDOWN The cluster is down", true},
		{"TRYAGAIN is transient", "TRYAGAIN Multiple keys request during rehashing of slot", true},
		{"MASTERDOWN is transient", "MASTERDOWN Link with MASTER is down", true},
		{"max clients is transient", "ERR max number of clients reached", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := fakeRedisServerError(tt.reply)
			assert.Equal(t, tt.retryable, isRetryableRedisError(err))

			// Classification must survive error wrapping.
			wrapped := fmt.Errorf("redis command failed: %w", err)
			assert.Equal(t, tt.retryable, isRetryableRedisError(wrapped))
		})
	}
}

func TestIsRetryableRedisError_NetworkClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "net.Error timeout is retryable",
			err:       os.ErrDeadlineExceeded,
			retryable: true,
		},
		{
			name: "net.OpError dial refused is retryable",
			err: &net.OpError{
				Op: "dial", Net: "tcp",
				Err: syscall.ECONNREFUSED,
			},
			retryable: true,
		},
		{
			name:      "io.EOF is retryable",
			err:       io.EOF,
			retryable: true,
		},
		{
			name:      "io.ErrUnexpectedEOF is retryable",
			err:       io.ErrUnexpectedEOF,
			retryable: true,
		},
		{
			name:      "wrapped ECONNRESET is retryable",
			err:       fmt.Errorf("read tcp 127.0.0.1:6379: %w", syscall.ECONNRESET),
			retryable: true,
		},
		{
			name:      "wrapped broken pipe is retryable",
			err:       fmt.Errorf("write: %w", syscall.EPIPE),
			retryable: true,
		},
		{
			name:      "pool timeout text is retryable",
			err:       errors.New("redis: connection pool timeout"),
			retryable: true,
		},
		{
			name:      "unrelated error is not retryable",
			err:       errors.New("marshal failure"),
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.retryable, isRetryableRedisError(tt.err))
		})
	}
}

func TestRedisCache_Get_WrongTypeNotRetried(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	c, hook := newHookedRedisCache(t, mr.Addr(), "get", false, observability.NopLogger())

	// GET on a list key returns a WRONGTYPE server reply.
	mr.Lpush("test:wrongtype", "element")

	_, err := c.Get(context.Background(), "wrongtype")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrCacheMiss)
	assert.Contains(t, err.Error(), "WRONGTYPE")
	assert.Equal(t, int64(1), hook.processCalls.Load(),
		"permanent server replies must not be retried (single attempt)")
}

func TestRedisCache_Get_NetworkErrorIsRetried(t *testing.T) {
	// Closed port: every attempt fails with a transient connection error.
	logger := &capturingLogger{}
	c, hook := newHookedRedisCache(t, "127.0.0.1:1", "get", true, logger)

	_, err := c.Get(context.Background(), "some-key")
	require.Error(t, err)

	wantAttempts := int64(redisRetryConfig().MaxRetries + 1)
	assert.Equal(t, wantAttempts, hook.processCalls.Load(),
		"transient network errors must be retried with backoff")

	// D5: the retry/error logs must carry the hashed key, never the raw key.
	require.Contains(t, logger.debugMessages(), "retrying redis get")
	values := logger.keyFieldValues()
	require.NotEmpty(t, values)
	for _, v := range values {
		assert.Equal(t, HashKey("some-key"), v)
		assert.NotContains(t, v, "some-key")
	}
}

// --- D5: privacy-safe keys in spans and logs ---

func TestRedisCache_HashKeys_SpanAndLogsUseHashedKey(t *testing.T) {
	// Swap the global tracer provider for a recording one (not parallel).
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	})

	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	logger := &capturingLogger{}
	c := newTestRedisCache(t, mr, true, logger)

	ctx := context.Background()
	const rawKey = "user/token/super-secret-raw-key"
	hashedKey := HashKey(rawKey)

	require.NoError(t, c.Set(ctx, rawKey, []byte("v"), time.Minute))
	_, err := c.Get(ctx, rawKey)
	require.NoError(t, err)
	_, _, err = c.GetWithTTL(ctx, rawKey)
	require.NoError(t, err)
	require.NoError(t, c.Expire(ctx, rawKey, time.Minute))
	require.NoError(t, c.Delete(ctx, rawKey))

	// Every cache.key span attribute must carry the hashed key.
	var checkedSpans int
	for _, span := range recorder.Ended() {
		for _, attr := range span.Attributes() {
			if string(attr.Key) != "cache.key" {
				continue
			}
			checkedSpans++
			assert.Equal(t, hashedKey, attr.Value.AsString(),
				"span %s must record the hashed key", span.Name())
			assert.NotContains(t, attr.Value.AsString(), rawKey,
				"span %s must not leak the raw key", span.Name())
		}
	}
	require.GreaterOrEqual(t, checkedSpans, 5,
		"expected cache.key attributes on Set/Get/GetWithTTL/Expire/Delete spans")

	// Every "key" log field must carry the hashed key.
	values := logger.keyFieldValues()
	require.NotEmpty(t, values, "expected debug logs with a key field")
	for _, v := range values {
		assert.Equal(t, hashedKey, v)
		assert.NotContains(t, v, rawKey)
	}
}

func TestRedisCache_NoHashKeys_LogsRawKey(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	logger := &capturingLogger{}
	c := newTestRedisCache(t, mr, false, logger)

	require.NoError(t, c.Set(context.Background(), "plain-key", []byte("v"), time.Minute))

	values := logger.keyFieldValues()
	require.NotEmpty(t, values)
	assert.Contains(t, values, "plain-key",
		"without hashKeys the raw key remains visible in logs")
}

// --- E2: metric parity for GetWithTTL / SetNX / Expire ---

func TestRedisCache_GetWithTTL_RecordsMetrics(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	c := newTestRedisCache(t, mr, false, observability.NopLogger())
	ctx := context.Background()
	m := GetCacheMetrics()

	hitsBefore := testutil.ToFloat64(m.hitsTotal.WithLabelValues(redisBackend))
	missesBefore := testutil.ToFloat64(m.missesTotal.WithLabelValues(redisBackend))
	errorsBefore := testutil.ToFloat64(m.errorsTotal.WithLabelValues(redisBackend, opGetWithTTL))
	durationBefore := histogramSampleCount(t, redisBackend, opGetWithTTL)
	statsBefore := c.Stats()

	require.NoError(t, c.Set(ctx, "present", []byte("v"), time.Minute))

	_, _, err := c.GetWithTTL(ctx, "present") // hit
	require.NoError(t, err)

	_, _, err = c.GetWithTTL(ctx, "absent") // miss
	require.ErrorIs(t, err, ErrCacheMiss)

	mr.SetError("ERR forced error") // permanent reply -> error metric
	_, _, err = c.GetWithTTL(ctx, "present")
	require.Error(t, err)
	mr.SetError("")

	assert.Equal(t, hitsBefore+1,
		testutil.ToFloat64(m.hitsTotal.WithLabelValues(redisBackend)),
		"GetWithTTL must record prometheus hit counter")
	assert.Equal(t, missesBefore+1,
		testutil.ToFloat64(m.missesTotal.WithLabelValues(redisBackend)),
		"GetWithTTL must record prometheus miss counter")
	assert.Equal(t, errorsBefore+1,
		testutil.ToFloat64(m.errorsTotal.WithLabelValues(redisBackend, opGetWithTTL)),
		"GetWithTTL must record error counter")
	assert.Equal(t, durationBefore+3, histogramSampleCount(t, redisBackend, opGetWithTTL),
		"GetWithTTL must observe operation duration for every call")

	statsAfter := c.Stats()
	assert.Equal(t, statsBefore.Hits+1, statsAfter.Hits, "internal hit stats must mirror Get")
	assert.Equal(t, statsBefore.Misses+1, statsAfter.Misses, "internal miss stats must mirror Get")
}

func TestRedisCache_SetNX_RecordsMetrics(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	c := newTestRedisCache(t, mr, false, observability.NopLogger())
	ctx := context.Background()
	m := GetCacheMetrics()

	errorsBefore := testutil.ToFloat64(m.errorsTotal.WithLabelValues(redisBackend, opSetNX))
	durationBefore := histogramSampleCount(t, redisBackend, opSetNX)

	acquired, err := c.SetNX(ctx, "nx-key", []byte("v"), time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)

	mr.SetError("ERR forced error")
	_, err = c.SetNX(ctx, "nx-key-2", []byte("v"), time.Minute)
	require.Error(t, err)
	mr.SetError("")

	assert.Equal(t, errorsBefore+1,
		testutil.ToFloat64(m.errorsTotal.WithLabelValues(redisBackend, opSetNX)),
		"SetNX must record error counter")
	assert.Equal(t, durationBefore+2, histogramSampleCount(t, redisBackend, opSetNX),
		"SetNX must observe operation duration for every call")
}

func TestRedisCache_Expire_RecordsMetrics(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	c := newTestRedisCache(t, mr, false, observability.NopLogger())
	ctx := context.Background()
	m := GetCacheMetrics()

	errorsBefore := testutil.ToFloat64(m.errorsTotal.WithLabelValues(redisBackend, opExpire))
	durationBefore := histogramSampleCount(t, redisBackend, opExpire)

	require.NoError(t, c.Set(ctx, "expire-key", []byte("v"), time.Hour))
	require.NoError(t, c.Expire(ctx, "expire-key", time.Minute))

	mr.SetError("ERR forced error")
	err := c.Expire(ctx, "expire-key", time.Minute)
	require.Error(t, err)
	mr.SetError("")

	assert.Equal(t, errorsBefore+1,
		testutil.ToFloat64(m.errorsTotal.WithLabelValues(redisBackend, opExpire)),
		"Expire must record error counter")
	assert.Equal(t, durationBefore+2, histogramSampleCount(t, redisBackend, opExpire),
		"Expire must observe operation duration for every call")
}

// --- C7: caller-context plumbing ---

func TestReadVaultPassword_HonorsCallerCancellation(t *testing.T) {
	t.Parallel()

	kvClient := &ctxAwareKVClient{mockKVClient: mockKVClient{
		readData: map[string]map[string]interface{}{
			"secret/redis": {"password": "pw"},
		},
	}}
	client := &mockVaultClient{enabled: true, kv: kvClient}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := readVaultPassword(ctx, client, "secret/redis")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled,
		"caller cancellation must propagate into the vault read")

	// Sanity: the same client succeeds with a live context.
	pw, err := readVaultPassword(context.Background(), client, "secret/redis")
	require.NoError(t, err)
	assert.Equal(t, "pw", pw)
}

func TestPingRedis_HonorsCallerCancellation(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := pingRedis(ctx, client)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled,
		"caller cancellation must propagate into the ping")

	require.NoError(t, pingRedis(context.Background(), client))
}

func TestNewRedisCache_HonorsCallerCancellation(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache, err := newRedisCache(ctx, cfg, observability.NopLogger(), nil)
	require.Error(t, err)
	assert.Nil(t, cache)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestNewRedisCache_VaultReadHonorsCallerCancellation(t *testing.T) {
	kvClient := &ctxAwareKVClient{mockKVClient: mockKVClient{
		readData: map[string]map[string]interface{}{
			"secret/redis": {"password": "pw"},
		},
	}}
	client := &mockVaultClient{enabled: true, kv: kvClient}

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:               "redis://127.0.0.1:6379",
			PasswordVaultPath: "secret/redis",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cache, err := newRedisCache(ctx, cfg, observability.NopLogger(), &cacheOptions{vaultClient: client})
	require.Error(t, err)
	assert.Nil(t, cache)
	assert.ErrorIs(t, err, context.Canceled,
		"cancellation must abort vault password resolution")
}

func TestCacheOptions_WithRedisDialerAndVaultClient(t *testing.T) {
	t.Parallel()

	dialer := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, errors.New("dialer is not expected to be invoked here")
	}
	vaultClient := &mockVaultClient{enabled: true}

	opts := &cacheOptions{}
	WithRedisDialer(dialer)(opts)
	WithVaultClient(vaultClient)(opts)

	assert.NotNil(t, opts.redisDialer, "WithRedisDialer must set the dialer")
	assert.Same(t, vaultClient, opts.vaultClient, "WithVaultClient must set the client")
}

func TestNew_RedisTypeCreatesCacheWithBoundedInit(t *testing.T) {
	mr, cleanup := setupMiniRedis(t)
	defer cleanup()

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(time.Minute),
		Redis: &config.RedisCacheConfig{
			URL: "redis://" + mr.Addr(),
		},
	}

	c, err := New(cfg, observability.NopLogger())
	require.NoError(t, err)
	require.NotNil(t, c)

	// The bounded init context must not leak into operations: calls made
	// after construction use their own caller context.
	require.NoError(t, c.Set(context.Background(), "k", []byte("v"), time.Minute))
	val, err := c.Get(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), val)

	require.NoError(t, c.Close())
}
