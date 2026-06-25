package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

func aggTarget(name string) avapigwv1alpha1.AggregateTarget {
	return avapigwv1alpha1.AggregateTarget{
		Name:        name,
		Destination: avapigwv1alpha1.Destination{Host: "backend", Port: 8080},
	}
}

func TestValidateAggregate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *avapigwv1alpha1.AggregateConfig
		streaming bool
		wantErr   string
	}{
		{
			name: "valid minimal",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
			},
		},
		{
			name:    "nil config ok",
			cfg:     nil,
			wantErr: "",
		},
		{
			name: "disabled config skips validation",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: false,
				Targets: nil,
			},
		},
		// U-WHK-1: ≥1 target enforced.
		{
			name: "no targets rejected",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: nil,
			},
			wantErr: "at least 1 target is required",
		},
		// U-WHK-2: enum validation (failMode).
		{
			name: "invalid fail mode",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled:  true,
				FailMode: "perhaps",
				Targets:  []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
			},
			wantErr: "invalid failMode",
		},
		{
			name: "empty fail mode allowed (defaulted)",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled:  true,
				FailMode: "",
				Targets:  []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
			},
		},
		{
			name: "negative quorum count",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled:     true,
				FailMode:    "quorum",
				QuorumCount: -1,
				Targets:     []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
			},
			wantErr: "quorumCount must be non-negative",
		},
		{
			name: "quorum exceeds targets",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled:     true,
				FailMode:    "quorum",
				QuorumCount: 5,
				Targets:     []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
			},
			wantErr: "exceeds target count",
		},
		{
			name: "negative max parallel",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled:     true,
				MaxParallel: -1,
				Targets:     []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
			},
			wantErr: "maxParallel must be between",
		},
		{
			name: "max parallel too large",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled:     true,
				MaxParallel: MaxAggregateMaxParallel + 1,
				Targets:     []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
			},
			wantErr: "maxParallel must be between",
		},
		{
			name: "missing target name",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{
					{Destination: avapigwv1alpha1.Destination{Host: "h", Port: 80}},
				},
			},
			wantErr: "name is required",
		},
		{
			name: "duplicate target name",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("dup"), aggTarget("dup")},
			},
			wantErr: "duplicate target name",
		},
		{
			name: "missing host",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{
					{Name: "a", Destination: avapigwv1alpha1.Destination{Port: 80}},
				},
			},
			wantErr: "host is required",
		},
		{
			name: "invalid port",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{
					{Name: "a", Destination: avapigwv1alpha1.Destination{Host: "h", Port: 99999}},
				},
			},
			wantErr: "port must be between",
		},
		{
			name: "invalid target timeout",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{
					{Name: "a", Destination: avapigwv1alpha1.Destination{Host: "h", Port: 80}, Timeout: "not-a-duration"},
				},
			},
			wantErr: "timeout",
		},
		{
			name: "valid target timeout",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{
					{Name: "a", Destination: avapigwv1alpha1.Destination{Host: "h", Port: 80}, Timeout: "5s"},
				},
			},
		},
		{
			name: "invalid target auth type",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{
					{
						Name:           "a",
						Destination:    avapigwv1alpha1.Destination{Host: "h", Port: 80},
						Authentication: &avapigwv1alpha1.BackendAuthConfig{Type: "kerberos"},
					},
				},
			},
			wantErr: "authentication.type",
		},
		{
			name: "valid target auth types",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{
					{
						Name:           "a",
						Destination:    avapigwv1alpha1.Destination{Host: "h", Port: 80},
						Authentication: &avapigwv1alpha1.BackendAuthConfig{Type: "mtls"},
					},
				},
			},
		},
		// U-WHK-2: merge strategy enum.
		{
			name: "invalid merge strategy",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Merge:   &avapigwv1alpha1.MergeOptions{Enabled: true, Strategy: "fuzzy"},
			},
			wantErr: "invalid merge.strategy",
		},
		{
			name: "valid merge strategy",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Merge:   &avapigwv1alpha1.MergeOptions{Enabled: true, Strategy: "shallow"},
			},
		},
		{
			name: "ndjson merge strategy accepted",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Merge:   &avapigwv1alpha1.MergeOptions{Enabled: true, Strategy: "ndjson"},
			},
		},
		{
			name: "ndjson with knobs accepted",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Merge: &avapigwv1alpha1.MergeOptions{
					Enabled:   true,
					Strategy:  "ndjson",
					TimeField: "ts",
					KeyField:  "id",
					Limit:     50,
				},
			},
		},
		{
			name: "negative merge limit rejected",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Merge:   &avapigwv1alpha1.MergeOptions{Enabled: true, Strategy: "ndjson", Limit: -1},
			},
			wantErr: "merge.limit must be non-negative",
		},
		{
			name: "invalid merge strategy error lists ndjson",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Merge:   &avapigwv1alpha1.MergeOptions{Enabled: true, Strategy: "weird"},
			},
			wantErr: "ndjson",
		},
		{
			name: "disabled merge skips strategy check",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Merge:   &avapigwv1alpha1.MergeOptions{Enabled: false, Strategy: "garbage"},
			},
		},
		// U-WHK-4: merge on pure streaming rejected.
		{
			name: "merge on pure streaming rejected",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Merge:   &avapigwv1alpha1.MergeOptions{Enabled: true, Strategy: "deep"},
			},
			streaming: true,
			wantErr:   "merge cannot be enabled on a pure-streaming route",
		},
		{
			name: "disabled merge ok on streaming",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Merge:   &avapigwv1alpha1.MergeOptions{Enabled: false},
			},
			streaming: true,
		},
		// U-WHK-2: spool backend enum.
		{
			name: "invalid spool backend",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Spool:   &avapigwv1alpha1.SpoolOptions{Enabled: true, Backend: "cassandra"},
			},
			wantErr: "invalid spool.backend",
		},
		{
			name: "negative threshold bytes",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Spool:   &avapigwv1alpha1.SpoolOptions{Enabled: true, ThresholdBytes: -1},
			},
			wantErr: "thresholdBytes must be non-negative",
		},
		{
			name: "memory spool ok",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Spool:   &avapigwv1alpha1.SpoolOptions{Enabled: true, Backend: "memory"},
			},
		},
		// U-WHK-3: redis ref required when spool=redis.
		{
			name: "redis spool missing ref",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Spool:   &avapigwv1alpha1.SpoolOptions{Enabled: true, Backend: "redis"},
			},
			wantErr: "redisRef is required",
		},
		{
			name: "redis spool ref without addr/sentinel",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Spool: &avapigwv1alpha1.SpoolOptions{
					Enabled: true, Backend: "redis",
					RedisRef: &avapigwv1alpha1.AggregateRedisRef{},
				},
			},
			wantErr: "either address or sentinel",
		},
		{
			name: "redis spool ref both addr and sentinel",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Spool: &avapigwv1alpha1.SpoolOptions{
					Enabled: true, Backend: "redis",
					RedisRef: &avapigwv1alpha1.AggregateRedisRef{
						Address:  "redis:6379",
						Sentinel: &avapigwv1alpha1.RedisSentinelSpec{MasterName: "m"},
					},
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "redis spool with address ok",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Spool: &avapigwv1alpha1.SpoolOptions{
					Enabled: true, Backend: "redis",
					RedisRef: &avapigwv1alpha1.AggregateRedisRef{Address: "redis:6379"},
				},
			},
		},
		{
			name: "redis spool with sentinel ok",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Spool: &avapigwv1alpha1.SpoolOptions{
					Enabled: true, Backend: "redis",
					RedisRef: &avapigwv1alpha1.AggregateRedisRef{
						Sentinel: &avapigwv1alpha1.RedisSentinelSpec{MasterName: "m"},
					},
				},
			},
		},
		{
			name: "disabled spool skips validation",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled: true,
				Targets: []avapigwv1alpha1.AggregateTarget{aggTarget("a")},
				Spool:   &avapigwv1alpha1.SpoolOptions{Enabled: false, Backend: "garbage"},
			},
		},
		// U-WHK-5: fully valid complex config admitted.
		{
			name: "valid full config admitted",
			cfg: &avapigwv1alpha1.AggregateConfig{
				Enabled:     true,
				FailMode:    "quorum",
				QuorumCount: 2,
				MaxParallel: 4,
				Targets: []avapigwv1alpha1.AggregateTarget{
					{
						Name:           "a",
						Destination:    avapigwv1alpha1.Destination{Host: "a.svc", Port: 8080},
						Timeout:        "5s",
						Authentication: &avapigwv1alpha1.BackendAuthConfig{Type: "basic"},
					},
					aggTarget("b"),
					aggTarget("c"),
				},
				Merge: &avapigwv1alpha1.MergeOptions{Enabled: true, Strategy: "deep"},
				Spool: &avapigwv1alpha1.SpoolOptions{
					Enabled: true, Backend: "redis", ThresholdBytes: 2048,
					RedisRef: &avapigwv1alpha1.AggregateRedisRef{Address: "redis:6379"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAggregate(tt.cfg, tt.streaming)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestValidateAggregateTargetAuth_EmptyType(t *testing.T) {
	target := &avapigwv1alpha1.AggregateTarget{
		Name:           "a",
		Authentication: &avapigwv1alpha1.BackendAuthConfig{Type: ""},
	}
	assert.NoError(t, validateAggregateTargetAuth(0, target))
}

func TestValidateAggregateTargetAuth_Nil(t *testing.T) {
	target := &avapigwv1alpha1.AggregateTarget{Name: "a"}
	assert.NoError(t, validateAggregateTargetAuth(0, target))
}
