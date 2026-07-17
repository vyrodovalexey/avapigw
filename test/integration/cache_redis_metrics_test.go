//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

// redisOpsCache is the Redis-only operation surface added on top of the
// generic Cache interface. Asserted structurally so this test stays
// black-box against the package API.
type redisOpsCache interface {
	GetWithTTL(ctx context.Context, key string) ([]byte, time.Duration, error)
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
}

// operationSampleCount returns the cumulative sample count of the
// gateway_cache_operation_duration_seconds histogram for the given
// backend/operation label pair, gathered from the default Prometheus
// registry (cache metrics are registered via promauto).
func operationSampleCount(t *testing.T, backend, operation string) uint64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if family.GetName() != "gateway_cache_operation_duration_seconds" {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := make(map[string]string, len(metric.GetLabel()))
			for _, pair := range metric.GetLabel() {
				labels[pair.GetName()] = pair.GetValue()
			}
			if labels["backend"] == backend && labels["operation"] == operation {
				return metric.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

// gatherFamily returns the metric family with the given name, or nil.
func gatherFamily(t *testing.T, name string) *dto.MetricFamily {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}
	return nil
}

// TestIntegration_Cache_Redis_OperationMetricsParity verifies that the
// Redis-only operations (GetWithTTL, SetNX, Expire) record the same
// operation-duration metrics as the base operations, using their own
// operation label values (metric parity added alongside the ops).
func TestIntegration_Cache_Redis_OperationMetricsParity(t *testing.T) {
	helpers.SkipIfRedisUnavailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := observability.NopLogger()
	keyPrefix := helpers.GenerateTestKeyPrefix("redis_op_metrics")

	cfg := &config.CacheConfig{
		Enabled: true,
		Type:    config.CacheTypeRedis,
		TTL:     config.Duration(5 * time.Minute),
		Redis: &config.RedisCacheConfig{
			URL:       helpers.GetRedisURL(),
			KeyPrefix: keyPrefix,
		},
	}

	c, err := cache.New(cfg, logger)
	require.NoError(t, err)
	defer c.Close()

	redisClient, err := helpers.CreateRedisClient()
	require.NoError(t, err)
	defer redisClient.Close()
	defer func() {
		_ = helpers.CleanupRedis(redisClient, keyPrefix)
	}()

	ops, ok := c.(redisOpsCache)
	require.True(t, ok, "redis cache must expose GetWithTTL/SetNX/Expire")

	// Snapshot histogram sample counts before driving traffic; the metrics
	// singleton is shared process-wide, so assertions are delta-based.
	before := map[string]uint64{
		"get_with_ttl": operationSampleCount(t, "redis", "get_with_ttl"),
		"setnx":        operationSampleCount(t, "redis", "setnx"),
		"expire":       operationSampleCount(t, "redis", "expire"),
	}

	t.Run("drive redis-only operations", func(t *testing.T) {
		const key = "op-metrics-key"
		value := []byte("op-metrics-value")

		require.NoError(t, c.Set(ctx, key, value, 5*time.Minute))

		got, ttl, err := ops.GetWithTTL(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, value, got)
		assert.Greater(t, ttl, time.Duration(0))

		acquired, err := ops.SetNX(ctx, key+"-nx", value, time.Minute)
		require.NoError(t, err)
		assert.True(t, acquired)

		require.NoError(t, ops.Expire(ctx, key, 2*time.Minute))
	})

	t.Run("operation duration histogram gains samples per op label", func(t *testing.T) {
		for _, op := range []string{"get_with_ttl", "setnx", "expire"} {
			after := operationSampleCount(t, "redis", op)
			assert.Greater(t, after, before[op],
				"gateway_cache_operation_duration_seconds{backend=redis,operation=%s} must record samples", op)
			t.Logf("operation %q histogram samples: %d -> %d", op, before[op], after)
		}
	})

	t.Run("errors counter exposes the new operation labels", func(t *testing.T) {
		// Init() pre-creates all label combinations, including the
		// redis-only operations, so dashboards can rely on their presence.
		cache.GetCacheMetrics().Init()

		family := gatherFamily(t, "gateway_cache_errors_total")
		require.NotNil(t, family, "gateway_cache_errors_total must be registered")

		found := map[string]bool{}
		for _, metric := range family.GetMetric() {
			labels := make(map[string]string, len(metric.GetLabel()))
			for _, pair := range metric.GetLabel() {
				labels[pair.GetName()] = pair.GetValue()
			}
			if labels["backend"] == "redis" {
				found[labels["operation"]] = true
			}
		}
		for _, op := range []string{"get_with_ttl", "setnx", "expire"} {
			assert.True(t, found[op],
				"errors_total must pre-initialize redis operation label %q", op)
		}
	})
}
