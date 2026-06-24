package aggregate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestFromConfig_NilAndDisabled(t *testing.T) {
	assert.Nil(t, FromConfig(nil))
	assert.Nil(t, FromConfig(&config.AggregateConfig{Enabled: false}))
}

func TestFromConfig_FullMapping(t *testing.T) {
	cfg := &config.AggregateConfig{
		Enabled:         true,
		FailMode:        config.FailModeQuorum,
		QuorumCount:     2,
		MaxParallel:     4,
		PerMessageMerge: true,
		Targets: []config.AggregateTarget{
			{
				Name:        "a",
				Destination: config.Destination{Host: "a.svc", Port: 8080},
				Timeout:     config.Duration(5 * time.Second),
				Retries:     2,
				TLS:         &config.BackendTLSConfig{Enabled: true},
				Authentication: &config.BackendAuthConfig{
					Type:  "basic",
					Basic: &config.BackendBasicAuthConfig{Enabled: true, Username: "u"},
				},
			},
			{
				Name:        "b",
				Destination: config.Destination{Host: "b.svc", Port: 8081},
			},
		},
		Merge: &config.MergeOptions{Enabled: true, Strategy: config.MergeStrategyShallow},
		Spool: &config.SpoolOptions{
			Enabled:        true,
			Backend:        config.SpoolBackendRedis,
			ThresholdBytes: 2048,
			TTL:            config.Duration(time.Minute),
		},
	}

	out := FromConfig(cfg)
	require.NotNil(t, out)
	assert.True(t, out.Enabled)
	assert.Equal(t, FailMode("quorum"), out.FailMode)
	assert.Equal(t, 2, out.QuorumCount)
	assert.True(t, out.PerMessageMerge)

	require.Len(t, out.Targets, 2)
	assert.Equal(t, "a", out.Targets[0].Name)
	assert.Equal(t, "a.svc", out.Targets[0].Host)
	assert.Equal(t, 8080, out.Targets[0].Port)
	assert.Equal(t, 5*time.Second, out.Targets[0].Timeout)
	assert.Equal(t, 2, out.Targets[0].Retries)
	require.NotNil(t, out.Targets[0].TLS)
	require.NotNil(t, out.Targets[0].Auth)

	require.NotNil(t, out.Merge)
	assert.True(t, out.Merge.Enabled)
	assert.Equal(t, config.MergeStrategyShallow, out.Merge.Strategy)

	require.NotNil(t, out.Spool)
	assert.True(t, out.Spool.Enabled)
	assert.Equal(t, SpoolBackendRedis, out.Spool.Backend)
	assert.Equal(t, int64(2048), out.Spool.ThresholdBytes)
	assert.Equal(t, time.Minute, out.Spool.TTL)
}

func TestFromConfig_TargetTimeoutDefault(t *testing.T) {
	cfg := &config.AggregateConfig{
		Enabled: true,
		Targets: []config.AggregateTarget{
			{Name: "a", Destination: config.Destination{Host: "h", Port: 80}},
		},
	}
	out := FromConfig(cfg)
	require.NotNil(t, out)
	assert.Equal(t, DefaultTargetTimeout, out.Targets[0].Timeout)
}

func TestFromConfig_MergeStrategyDefaultWhenEnabled(t *testing.T) {
	cfg := &config.AggregateConfig{
		Enabled: true,
		Targets: []config.AggregateTarget{{Name: "a", Destination: config.Destination{Host: "h", Port: 80}}},
		Merge:   &config.MergeOptions{Enabled: true},
	}
	out := FromConfig(cfg)
	require.NotNil(t, out.Merge)
	assert.Equal(t, config.MergeStrategyDeep, out.Merge.Strategy)
}

func TestFromConfig_NilMergeAndSpool(t *testing.T) {
	cfg := &config.AggregateConfig{
		Enabled: true,
		Targets: []config.AggregateTarget{{Name: "a", Destination: config.Destination{Host: "h", Port: 80}}},
	}
	out := FromConfig(cfg)
	require.NotNil(t, out)
	assert.Nil(t, out.Merge)
	assert.Nil(t, out.Spool)
}

func TestFromConfig_SpoolBackendDefaultMemory(t *testing.T) {
	cfg := &config.AggregateConfig{
		Enabled: true,
		Targets: []config.AggregateTarget{{Name: "a", Destination: config.Destination{Host: "h", Port: 80}}},
		Spool:   &config.SpoolOptions{Enabled: true},
	}
	out := FromConfig(cfg)
	require.NotNil(t, out.Spool)
	assert.Equal(t, SpoolBackendMemory, out.Spool.Backend)
	assert.Equal(t, DefaultSpoolTTL, out.Spool.TTL)
}

func TestMapTargets_Empty(t *testing.T) {
	assert.Nil(t, mapTargets(nil))
	assert.Nil(t, mapTargets([]config.AggregateTarget{}))
}

func TestMapMerge_Nil(t *testing.T) {
	assert.Nil(t, mapMerge(nil))
}
