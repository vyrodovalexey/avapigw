// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fullAggregateConfig returns a deeply-populated AggregateConfig exercising all
// pointer fields and nested types for deepcopy round-trip verification.
func fullAggregateConfig() *AggregateConfig {
	return &AggregateConfig{
		Enabled:         true,
		FailMode:        "quorum",
		QuorumCount:     2,
		MaxParallel:     16,
		PerMessageMerge: true,
		Targets: []AggregateTarget{
			{
				Name:        "primary",
				Destination: Destination{Host: "a.svc", Port: 8080},
				Timeout:     Duration("5s"),
				Retries:     3,
				TLS: &BackendTLSConfig{
					Enabled:  true,
					Mode:     "MUTUAL",
					CertFile: "/certs/tls.crt",
					KeyFile:  "/certs/tls.key",
				},
				Authentication: &BackendAuthConfig{
					Type: "basic",
					Basic: &BackendBasicAuthConfig{
						Enabled:   true,
						VaultPath: "secret/data/creds",
					},
				},
			},
			{
				Name:        "secondary",
				Destination: Destination{Host: "b.svc", Port: 8081},
			},
		},
		Merge: &MergeOptions{Enabled: true, Strategy: "shallow"},
		Spool: &SpoolOptions{
			Enabled:        true,
			Backend:        "redis",
			ThresholdBytes: 4096,
			TTL:            Duration("2m"),
			RedisRef: &AggregateRedisRef{
				Address:           "redis:6379",
				DB:                1,
				PasswordVaultPath: "secret/data/redis",
				Sentinel: &RedisSentinelSpec{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"s1:26379", "s2:26379"},
				},
			},
		},
	}
}

// U-CFG-8: deepcopy round-trip equality for AggregateConfig and all nested types.
func TestAggregateConfig_DeepCopy(t *testing.T) {
	original := fullAggregateConfig()

	clone := original.DeepCopy()
	require.NotNil(t, clone)
	assert.True(t, reflect.DeepEqual(original, clone), "deep copy must be equal to original")
	assert.NotSame(t, original, clone)

	// Mutating the clone must not affect the original (deep independence).
	clone.Targets[0].Name = "mutated"
	clone.Targets[0].TLS.CertFile = "/other"
	clone.Spool.RedisRef.Sentinel.SentinelAddrs[0] = "changed"
	clone.Merge.Strategy = "replace"

	assert.Equal(t, "primary", original.Targets[0].Name)
	assert.Equal(t, "/certs/tls.crt", original.Targets[0].TLS.CertFile)
	assert.Equal(t, "s1:26379", original.Spool.RedisRef.Sentinel.SentinelAddrs[0])
	assert.Equal(t, "shallow", original.Merge.Strategy)
}

func TestAggregateConfig_DeepCopyInto(t *testing.T) {
	original := fullAggregateConfig()
	var dst AggregateConfig
	original.DeepCopyInto(&dst)
	assert.True(t, reflect.DeepEqual(original, &dst))
}

func TestAggregateConfig_DeepCopy_NilSlicesAndPointers(t *testing.T) {
	minimal := &AggregateConfig{
		Enabled: true,
		Targets: []AggregateTarget{{Name: "a", Destination: Destination{Host: "h", Port: 80}}},
	}
	clone := minimal.DeepCopy()
	require.NotNil(t, clone)
	assert.True(t, reflect.DeepEqual(minimal, clone))
	assert.Nil(t, clone.Merge)
	assert.Nil(t, clone.Spool)
}

func TestAggregateConfig_DeepCopy_NilReceiver(t *testing.T) {
	var nilCfg *AggregateConfig
	assert.Nil(t, nilCfg.DeepCopy())
}

func TestAggregateTarget_DeepCopy(t *testing.T) {
	original := &AggregateTarget{
		Name:        "t",
		Destination: Destination{Host: "h", Port: 8080},
		Timeout:     Duration("10s"),
		Retries:     2,
		TLS:         &BackendTLSConfig{Enabled: true},
		Authentication: &BackendAuthConfig{
			Type: "jwt",
			JWT:  &BackendJWTAuthConfig{Enabled: true, TokenSource: "static", StaticToken: "tok"},
		},
	}
	clone := original.DeepCopy()
	require.NotNil(t, clone)
	assert.True(t, reflect.DeepEqual(original, clone))

	clone.Authentication.JWT.StaticToken = "other"
	assert.Equal(t, "tok", original.Authentication.JWT.StaticToken)

	var nilTarget *AggregateTarget
	assert.Nil(t, nilTarget.DeepCopy())
}

func TestMergeOptions_DeepCopy(t *testing.T) {
	original := &MergeOptions{Enabled: true, Strategy: "deep"}
	clone := original.DeepCopy()
	require.NotNil(t, clone)
	assert.Equal(t, *original, *clone)
	assert.NotSame(t, original, clone)

	var nilMerge *MergeOptions
	assert.Nil(t, nilMerge.DeepCopy())
}

// DeepCopy preserves the NDJSON knobs (timeField/keyField/limit).
func TestMergeOptions_DeepCopy_NDJSONFields(t *testing.T) {
	original := &MergeOptions{
		Enabled:   true,
		Strategy:  "ndjson",
		TimeField: "ts",
		KeyField:  "id",
		Limit:     42,
	}
	clone := original.DeepCopy()
	require.NotNil(t, clone)
	assert.Equal(t, *original, *clone)
	assert.NotSame(t, original, clone)
	assert.Equal(t, "ndjson", clone.Strategy)
	assert.Equal(t, "ts", clone.TimeField)
	assert.Equal(t, "id", clone.KeyField)
	assert.Equal(t, 42, clone.Limit)

	// Mutating the clone must not affect the original (value-copy independence).
	clone.TimeField = "other"
	clone.Limit = 0
	assert.Equal(t, "ts", original.TimeField)
	assert.Equal(t, 42, original.Limit)
}

func TestSpoolOptions_DeepCopy(t *testing.T) {
	original := &SpoolOptions{
		Enabled:        true,
		Backend:        "redis",
		ThresholdBytes: 1024,
		TTL:            Duration("1m"),
		RedisRef:       &AggregateRedisRef{Address: "redis:6379"},
	}
	clone := original.DeepCopy()
	require.NotNil(t, clone)
	assert.True(t, reflect.DeepEqual(original, clone))

	clone.RedisRef.Address = "other:6379"
	assert.Equal(t, "redis:6379", original.RedisRef.Address)

	var nilSpool *SpoolOptions
	assert.Nil(t, nilSpool.DeepCopy())
}

func TestAggregateRedisRef_DeepCopy(t *testing.T) {
	original := &AggregateRedisRef{
		Address:           "redis:6379",
		DB:                3,
		Password:          "pw",
		PasswordVaultPath: "secret/data/redis",
		Sentinel: &RedisSentinelSpec{
			MasterName:    "mymaster",
			SentinelAddrs: []string{"s1:26379"},
		},
	}
	clone := original.DeepCopy()
	require.NotNil(t, clone)
	assert.True(t, reflect.DeepEqual(original, clone))

	clone.Sentinel.SentinelAddrs = append(clone.Sentinel.SentinelAddrs, "s2:26379")
	assert.Len(t, original.Sentinel.SentinelAddrs, 1)

	var nilRef *AggregateRedisRef
	assert.Nil(t, nilRef.DeepCopy())
}
