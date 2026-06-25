package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// validTarget returns a minimal valid aggregate target for tests.
func validTarget(name string) AggregateTarget {
	return AggregateTarget{
		Name:        name,
		Destination: Destination{Host: "backend", Port: 8080},
	}
}

// U-CFG-1 happy: valid AggregateConfig parses (YAML + JSON), defaults applied.
func TestAggregateConfig_YAMLRoundTrip(t *testing.T) {
	in := `
enabled: true
failMode: quorum
quorumCount: 2
maxParallel: 4
perMessageMerge: true
targets:
  - name: a
    destination:
      host: a.svc
      port: 8080
    timeout: 5s
    retries: 2
  - name: b
    destination:
      host: b.svc
      port: 8081
merge:
  enabled: true
  strategy: shallow
spool:
  enabled: true
  backend: redis
  thresholdBytes: 2048
  ttl: 1m
  redisRef:
    address: localhost:6379
`
	var cfg AggregateConfig
	require.NoError(t, yaml.Unmarshal([]byte(in), &cfg))

	assert.True(t, cfg.Enabled)
	assert.Equal(t, FailModeQuorum, cfg.FailMode)
	assert.Equal(t, 2, cfg.QuorumCount)
	assert.Equal(t, 4, cfg.MaxParallel)
	assert.True(t, cfg.PerMessageMerge)
	require.Len(t, cfg.Targets, 2)
	assert.Equal(t, "a", cfg.Targets[0].Name)
	assert.Equal(t, 5*time.Second, cfg.Targets[0].Timeout.Duration())
	assert.Equal(t, 2, cfg.Targets[0].Retries)
	require.NotNil(t, cfg.Merge)
	assert.Equal(t, "shallow", cfg.Merge.Strategy)
	require.NotNil(t, cfg.Spool)
	assert.Equal(t, SpoolBackendRedis, cfg.Spool.Backend)
	assert.Equal(t, int64(2048), cfg.Spool.ThresholdBytes)
	require.NotNil(t, cfg.Spool.RedisRef)
	assert.Equal(t, "localhost:6379", cfg.Spool.RedisRef.Address)

	// Round-trip back to YAML and re-parse.
	out, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	var cfg2 AggregateConfig
	require.NoError(t, yaml.Unmarshal(out, &cfg2))
	assert.Equal(t, cfg, cfg2)
}

func TestAggregateConfig_JSONRoundTrip(t *testing.T) {
	cfg := AggregateConfig{
		Enabled:  true,
		FailMode: FailModeAny,
		Targets:  []AggregateTarget{validTarget("a"), validTarget("b")},
		Merge:    &MergeOptions{Enabled: true, Strategy: MergeStrategyDeep},
	}
	data, err := json.Marshal(&cfg)
	require.NoError(t, err)
	var cfg2 AggregateConfig
	require.NoError(t, json.Unmarshal(data, &cfg2))
	assert.Equal(t, cfg, cfg2)
}

// U-CFG-1: defaults applied.
func TestAggregateConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *AggregateConfig
		verify func(t *testing.T, c *AggregateConfig)
	}{
		{
			name: "fail mode and parallel defaults",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
			},
			verify: func(t *testing.T, c *AggregateConfig) {
				assert.Equal(t, FailModeAll, c.FailMode)
				assert.Equal(t, DefaultAggregateMaxParallel, c.MaxParallel)
				assert.Equal(t, Duration(DefaultAggregateTargetTimeout), c.Targets[0].Timeout)
			},
		},
		{
			name: "merge strategy default when enabled",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: true},
			},
			verify: func(t *testing.T, c *AggregateConfig) {
				assert.Equal(t, MergeStrategyDeep, c.Merge.Strategy)
			},
		},
		{
			name: "merge strategy untouched when disabled",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: false},
			},
			verify: func(t *testing.T, c *AggregateConfig) {
				assert.Empty(t, c.Merge.Strategy)
			},
		},
		{
			name: "ndjson defaults TimeField to _time when empty",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: true, Strategy: MergeStrategyNDJSON},
			},
			verify: func(t *testing.T, c *AggregateConfig) {
				assert.Equal(t, MergeStrategyNDJSON, c.Merge.Strategy)
				assert.Equal(t, "_time", c.Merge.TimeField)
			},
		},
		{
			name: "ndjson keeps explicit TimeField",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: true, Strategy: MergeStrategyNDJSON, TimeField: "ts"},
			},
			verify: func(t *testing.T, c *AggregateConfig) {
				assert.Equal(t, "ts", c.Merge.TimeField)
			},
		},
		{
			name: "deep strategy does not set TimeField",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: true, Strategy: MergeStrategyDeep},
			},
			verify: func(t *testing.T, c *AggregateConfig) {
				assert.Equal(t, MergeStrategyDeep, c.Merge.Strategy)
				assert.Empty(t, c.Merge.TimeField)
			},
		},
		{
			name: "spool defaults",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Spool:   &SpoolOptions{Enabled: true},
			},
			verify: func(t *testing.T, c *AggregateConfig) {
				assert.Equal(t, SpoolBackendMemory, c.Spool.Backend)
				assert.Equal(t, int64(DefaultAggregateSpoolThresholdBytes), c.Spool.ThresholdBytes)
				assert.Equal(t, Duration(DefaultCacheTTL), c.Spool.TTL)
			},
		},
		{
			name:   "nil receiver is a no-op",
			cfg:    nil,
			verify: func(_ *testing.T, _ *AggregateConfig) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.ApplyDefaults()
			tt.verify(t, tt.cfg)
		})
	}
}

// U-CFG-2/3/4 + R-1: validation matrix.
func TestAggregateConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *AggregateConfig
		wantErr string
	}{
		{
			name: "valid multi-target",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a"), validTarget("b")},
			},
		},
		{
			name: "single target is valid (degenerate fan-out)",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("only")},
			},
		},
		{
			name:    "nil config is valid no-op",
			cfg:     nil,
			wantErr: "",
		},
		{
			name: "disabled config skips validation",
			cfg: &AggregateConfig{
				Enabled: false,
				Targets: nil,
			},
		},
		{
			name: "empty targets",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: nil,
			},
			wantErr: "at least 1 target is required",
		},
		{
			name: "invalid fail mode",
			cfg: &AggregateConfig{
				Enabled:  true,
				FailMode: "sometimes",
				Targets:  []AggregateTarget{validTarget("a")},
			},
			wantErr: "invalid failMode",
		},
		{
			name: "quorum count exceeds targets",
			cfg: &AggregateConfig{
				Enabled:     true,
				FailMode:    FailModeQuorum,
				QuorumCount: 5,
				Targets:     []AggregateTarget{validTarget("a")},
			},
			wantErr: "exceeds target count",
		},
		{
			name: "missing target name",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{{Destination: Destination{Host: "h", Port: 80}}},
			},
			wantErr: "name is required",
		},
		{
			name: "duplicate target name",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("dup"), validTarget("dup")},
			},
			wantErr: "duplicate target name",
		},
		{
			name: "missing host",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{{Name: "a", Destination: Destination{Port: 80}}},
			},
			wantErr: "host is required",
		},
		{
			name: "invalid port low",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{{Name: "a", Destination: Destination{Host: "h", Port: 0}}},
			},
			wantErr: "port must be between",
		},
		{
			name: "invalid port high",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{{Name: "a", Destination: Destination{Host: "h", Port: 70000}}},
			},
			wantErr: "port must be between",
		},
		{
			name: "negative retries",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{{Name: "a", Destination: Destination{Host: "h", Port: 80}, Retries: -1}},
			},
			wantErr: "retries must be non-negative",
		},
		{
			name: "invalid auth",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{{
					Name:           "a",
					Destination:    Destination{Host: "h", Port: 80},
					Authentication: &BackendAuthConfig{Type: "weird"},
				}},
			},
			wantErr: "authentication",
		},
		{
			name: "invalid tls",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{{
					Name:        "a",
					Destination: Destination{Host: "h", Port: 80},
					TLS:         &BackendTLSConfig{Enabled: true, MinVersion: "bogus"},
				}},
			},
			wantErr: "tls",
		},
		{
			name: "invalid merge strategy",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: true, Strategy: "nope"},
			},
			wantErr: "invalid merge.strategy",
		},
		{
			name: "ndjson merge strategy accepted",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: true, Strategy: MergeStrategyNDJSON},
			},
		},
		{
			name: "ndjson with knobs accepted",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge: &MergeOptions{
					Enabled:   true,
					Strategy:  MergeStrategyNDJSON,
					TimeField: "ts",
					KeyField:  "id",
					Limit:     10,
				},
			},
		},
		{
			name: "negative merge limit rejected",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: true, Strategy: MergeStrategyNDJSON, Limit: -1},
			},
			wantErr: "merge.limit must be non-negative",
		},
		{
			name: "invalid strategy error lists ndjson",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: true, Strategy: "bogus"},
			},
			wantErr: "ndjson",
		},
		{
			name: "invalid spool backend",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Spool:   &SpoolOptions{Enabled: true, Backend: "elasticsearch"},
			},
			wantErr: "invalid spool.backend",
		},
		{
			name: "redis spool missing ref",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Spool:   &SpoolOptions{Enabled: true, Backend: SpoolBackendRedis},
			},
			wantErr: "redisRef is required",
		},
		{
			name: "redis spool ref without addr or sentinel",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Spool: &SpoolOptions{
					Enabled: true, Backend: SpoolBackendRedis,
					RedisRef: &AggregateRedisRef{},
				},
			},
			wantErr: "either address or sentinel",
		},
		{
			name: "redis spool ref with both addr and sentinel",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Spool: &SpoolOptions{
					Enabled: true, Backend: SpoolBackendRedis,
					RedisRef: &AggregateRedisRef{
						Address:  "localhost:6379",
						Sentinel: &RedisSentinelConfig{MasterName: "mymaster"},
					},
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "redis spool sentinel ok",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Spool: &SpoolOptions{
					Enabled: true, Backend: SpoolBackendRedis,
					RedisRef: &AggregateRedisRef{
						Sentinel: &RedisSentinelConfig{MasterName: "mymaster"},
					},
				},
			},
		},
		{
			name: "memory spool backend ok",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Spool:   &SpoolOptions{Enabled: true, Backend: SpoolBackendMemory},
			},
		},
		{
			name: "disabled merge skips strategy validation",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Merge:   &MergeOptions{Enabled: false, Strategy: "garbage"},
			},
		},
		{
			name: "disabled spool skips backend validation",
			cfg: &AggregateConfig{
				Enabled: true,
				Targets: []AggregateTarget{validTarget("a")},
				Spool:   &SpoolOptions{Enabled: false, Backend: "garbage"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// NDJSON merge knobs round-trip through YAML.
func TestAggregateConfig_NDJSONYAMLRoundTrip(t *testing.T) {
	in := `
enabled: true
targets:
  - name: a
    destination:
      host: a.svc
      port: 8080
merge:
  enabled: true
  strategy: ndjson
  timeField: ts
  keyField: id
  limit: 100
`
	var cfg AggregateConfig
	require.NoError(t, yaml.Unmarshal([]byte(in), &cfg))
	require.NotNil(t, cfg.Merge)
	assert.Equal(t, MergeStrategyNDJSON, cfg.Merge.Strategy)
	assert.Equal(t, "ts", cfg.Merge.TimeField)
	assert.Equal(t, "id", cfg.Merge.KeyField)
	assert.Equal(t, 100, cfg.Merge.Limit)

	out, err := yaml.Marshal(&cfg)
	require.NoError(t, err)
	var cfg2 AggregateConfig
	require.NoError(t, yaml.Unmarshal(out, &cfg2))
	assert.Equal(t, cfg, cfg2)
}

// MergeStrategyNDJSON constant has the canonical value.
func TestMergeStrategyNDJSON_Constant(t *testing.T) {
	assert.Equal(t, "ndjson", MergeStrategyNDJSON)
}

// U-CFG-6: Vault ref for per-target auth is preserved.
func TestAggregateConfig_VaultRefPreserved(t *testing.T) {
	cfg := &AggregateConfig{
		Enabled: true,
		Targets: []AggregateTarget{{
			Name:        "secure",
			Destination: Destination{Host: "h", Port: 443},
			Authentication: &BackendAuthConfig{
				Type: "basic",
				Basic: &BackendBasicAuthConfig{
					Enabled:   true,
					VaultPath: "secret/data/backend-creds",
				},
			},
		}},
	}
	require.NoError(t, cfg.Validate())
	assert.Equal(t, "secret/data/backend-creds", cfg.Targets[0].Authentication.Basic.VaultPath)

	// Spool redis password vault path round-trips.
	ref := &AggregateRedisRef{PasswordVaultPath: "secret/data/redis"}
	cfg.Spool = &SpoolOptions{Enabled: true, Backend: SpoolBackendRedis, RedisRef: ref}
	ref.Address = "localhost:6379"
	require.NoError(t, cfg.Validate())
	assert.Equal(t, "secret/data/redis", cfg.Spool.RedisRef.PasswordVaultPath)
}

func TestAggregateConfig_IsEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  *AggregateConfig
		want bool
	}{
		{"nil", nil, false},
		{"disabled", &AggregateConfig{Enabled: false, Targets: []AggregateTarget{validTarget("a")}}, false},
		{"enabled no targets", &AggregateConfig{Enabled: true}, false},
		{"enabled with targets", &AggregateConfig{Enabled: true, Targets: []AggregateTarget{validTarget("a")}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cfg.IsEnabled())
		})
	}
}

func TestAggregateConfig_GetFailMode(t *testing.T) {
	tests := []struct {
		name string
		cfg  *AggregateConfig
		want FailMode
	}{
		{"nil defaults all", nil, FailModeAll},
		{"empty defaults all", &AggregateConfig{}, FailModeAll},
		{"explicit any", &AggregateConfig{FailMode: FailModeAny}, FailModeAny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cfg.GetFailMode())
		})
	}
}

// U-CFG-5: ENV override beats file value (ENV priority).
func TestAggregateConfig_GetMaxParallel_ENVPriority(t *testing.T) {
	t.Run("file value when no env", func(t *testing.T) {
		cfg := &AggregateConfig{MaxParallel: 3}
		assert.Equal(t, 3, cfg.GetMaxParallel())
	})

	t.Run("default when nil", func(t *testing.T) {
		var cfg *AggregateConfig
		assert.Equal(t, DefaultAggregateMaxParallel, cfg.GetMaxParallel())
	})

	t.Run("env overrides file", func(t *testing.T) {
		t.Setenv(envAggregateMaxParallel, "16")
		cfg := &AggregateConfig{MaxParallel: 3}
		assert.Equal(t, 16, cfg.GetMaxParallel())
	})

	t.Run("invalid env ignored", func(t *testing.T) {
		t.Setenv(envAggregateMaxParallel, "not-a-number")
		cfg := &AggregateConfig{MaxParallel: 3}
		assert.Equal(t, 3, cfg.GetMaxParallel())
	})

	t.Run("non-positive env ignored", func(t *testing.T) {
		t.Setenv(envAggregateMaxParallel, "0")
		cfg := &AggregateConfig{MaxParallel: 7}
		assert.Equal(t, 7, cfg.GetMaxParallel())
	})
}

// U-CFG-5: ENV override for spool threshold.
func TestAggregateConfig_GetSpoolThresholdBytes_ENVPriority(t *testing.T) {
	t.Run("default when nil", func(t *testing.T) {
		var cfg *AggregateConfig
		assert.Equal(t, int64(DefaultAggregateSpoolThresholdBytes), cfg.GetSpoolThresholdBytes())
	})

	t.Run("file value", func(t *testing.T) {
		cfg := &AggregateConfig{Spool: &SpoolOptions{ThresholdBytes: 4096}}
		assert.Equal(t, int64(4096), cfg.GetSpoolThresholdBytes())
	})

	t.Run("env overrides file", func(t *testing.T) {
		t.Setenv(envAggregateSpoolThreshold, "9999")
		cfg := &AggregateConfig{Spool: &SpoolOptions{ThresholdBytes: 4096}}
		assert.Equal(t, int64(9999), cfg.GetSpoolThresholdBytes())
	})

	t.Run("invalid env ignored", func(t *testing.T) {
		t.Setenv(envAggregateSpoolThreshold, "abc")
		cfg := &AggregateConfig{Spool: &SpoolOptions{ThresholdBytes: 4096}}
		assert.Equal(t, int64(4096), cfg.GetSpoolThresholdBytes())
	})
}

func TestEnvIntHelpers(t *testing.T) {
	t.Run("envInt missing", func(t *testing.T) {
		_, ok := envInt("AVAPIGW_TEST_MISSING_INT")
		assert.False(t, ok)
	})
	t.Run("envInt empty", func(t *testing.T) {
		t.Setenv("AVAPIGW_TEST_EMPTY_INT", "")
		_, ok := envInt("AVAPIGW_TEST_EMPTY_INT")
		assert.False(t, ok)
	})
	t.Run("envInt valid", func(t *testing.T) {
		t.Setenv("AVAPIGW_TEST_VALID_INT", "42")
		v, ok := envInt("AVAPIGW_TEST_VALID_INT")
		assert.True(t, ok)
		assert.Equal(t, 42, v)
	})
	t.Run("envInt64 missing", func(t *testing.T) {
		_, ok := envInt64("AVAPIGW_TEST_MISSING_INT64")
		assert.False(t, ok)
	})
	t.Run("envInt64 empty", func(t *testing.T) {
		t.Setenv("AVAPIGW_TEST_EMPTY_INT64", "")
		_, ok := envInt64("AVAPIGW_TEST_EMPTY_INT64")
		assert.False(t, ok)
	})
	t.Run("envInt64 invalid", func(t *testing.T) {
		t.Setenv("AVAPIGW_TEST_BAD_INT64", "xyz")
		_, ok := envInt64("AVAPIGW_TEST_BAD_INT64")
		assert.False(t, ok)
	})
	t.Run("envInt64 valid", func(t *testing.T) {
		t.Setenv("AVAPIGW_TEST_OK_INT64", "9000000000")
		v, ok := envInt64("AVAPIGW_TEST_OK_INT64")
		assert.True(t, ok)
		assert.Equal(t, int64(9000000000), v)
	})
}

// U-CFG-7 regression: existing MirrorConfig round-trips unchanged.
func TestMirrorConfig_RegressionUnchanged(t *testing.T) {
	in := `
destination:
  host: shadow.svc
  port: 9090
percentage: 10.5
`
	var mc MirrorConfig
	require.NoError(t, yaml.Unmarshal([]byte(in), &mc))
	assert.Equal(t, "shadow.svc", mc.Destination.Host)
	assert.Equal(t, 9090, mc.Destination.Port)
	assert.InDelta(t, 10.5, mc.Percentage, 0.001)

	out, err := yaml.Marshal(&mc)
	require.NoError(t, err)
	var mc2 MirrorConfig
	require.NoError(t, yaml.Unmarshal(out, &mc2))
	assert.Equal(t, mc, mc2)
}

// Regression: aggregate is additive and distinct from mirror on a Route.
func TestRoute_MirrorAndAggregateCoexist(t *testing.T) {
	r := Route{
		Mirror:    &MirrorConfig{Destination: Destination{Host: "shadow", Port: 80}, Percentage: 5},
		Aggregate: &AggregateConfig{Enabled: true, Targets: []AggregateTarget{validTarget("a")}},
	}
	require.NotNil(t, r.Mirror)
	require.NotNil(t, r.Aggregate)
	assert.True(t, r.Aggregate.IsEnabled())
	assert.Equal(t, "shadow", r.Mirror.Destination.Host)
}
