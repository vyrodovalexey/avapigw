// Package main: WP14-env tests proving that invalid environment variable
// values are no longer silently ignored — a warning naming the variable and
// the offending value is logged and the default/previous value is kept.
package main

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// warnRecorder is a minimal observability.Logger that records Warn calls.
type warnRecorder struct {
	mu    sync.Mutex
	warns []recordedWarn
}

type recordedWarn struct {
	msg    string
	fields []observability.Field
}

func (r *warnRecorder) Debug(string, ...observability.Field) {}
func (r *warnRecorder) Info(string, ...observability.Field)  {}

func (r *warnRecorder) Warn(msg string, fields ...observability.Field) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warns = append(r.warns, recordedWarn{msg: msg, fields: fields})
}

func (r *warnRecorder) Error(string, ...observability.Field)             {}
func (r *warnRecorder) Fatal(string, ...observability.Field)             {}
func (r *warnRecorder) With(...observability.Field) observability.Logger { return r }
func (r *warnRecorder) WithContext(context.Context) observability.Logger { return r }
func (r *warnRecorder) Sync() error                                      { return nil }

// warnings returns a copy of the recorded warnings.
func (r *warnRecorder) warnings() []recordedWarn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedWarn(nil), r.warns...)
}

// fieldString extracts the string value of a named zap field, if present.
func fieldString(fields []observability.Field, key string) (string, bool) {
	for _, f := range fields {
		if f.Key == key {
			return f.String, true
		}
	}
	return "", false
}

// requireSingleEnvWarn asserts exactly one invalid-env warning was recorded
// for the given variable/value pair.
func requireSingleEnvWarn(t *testing.T, rec *warnRecorder, variable, value string) {
	t.Helper()

	warns := rec.warnings()
	require.Len(t, warns, 1, "exactly one warning expected")
	assert.Equal(t, warnInvalidEnvValue, warns[0].msg)

	gotVar, ok := fieldString(warns[0].fields, "variable")
	require.True(t, ok, "warning must name the variable")
	assert.Equal(t, variable, gotVar)

	gotVal, ok := fieldString(warns[0].fields, "value")
	require.True(t, ok, "warning must include the invalid value")
	assert.Equal(t, value, gotVal)
}

func TestApplyRedisFeatureEnv_InvalidTTLJitter_WarnsAndKeepsDefault(t *testing.T) {
	t.Setenv(envRedisTTLJitter, "not-a-number")

	rec := &warnRecorder{}
	cfg := &config.RedisCacheConfig{TTLJitter: 0.5}

	applyRedisFeatureEnv(cfg, rec)

	assert.InDelta(t, 0.5, cfg.TTLJitter, 0.001,
		"invalid value must not change the existing config")
	requireSingleEnvWarn(t, rec, envRedisTTLJitter, "not-a-number")
}

func TestApplyRedisFeatureEnv_InvalidHashKeysBool_WarnsAndKeepsDefault(t *testing.T) {
	t.Setenv(envRedisHashKeys, "banana")

	rec := &warnRecorder{}
	cfg := &config.RedisCacheConfig{HashKeys: true}

	applyRedisFeatureEnv(cfg, rec)

	assert.True(t, cfg.HashKeys,
		"invalid boolean must not change the existing config")
	requireSingleEnvWarn(t, rec, envRedisHashKeys, "banana")
}

func TestApplyRedisFeatureEnv_ValidValues_NoWarnings(t *testing.T) {
	t.Setenv(envRedisTTLJitter, "0.25")
	t.Setenv(envRedisHashKeys, "true")

	rec := &warnRecorder{}
	cfg := &config.RedisCacheConfig{}

	applyRedisFeatureEnv(cfg, rec)

	assert.InDelta(t, 0.25, cfg.TTLJitter, 0.001)
	assert.True(t, cfg.HashKeys)
	assert.Empty(t, rec.warnings(), "valid values must not warn")
}

func TestGetEnvBool_InvalidValue_WarnsAndUsesDefault(t *testing.T) {
	const key = "TEST_GETENVBOOL_WARN"
	t.Setenv(key, "maybe")

	rec := &warnRecorder{}

	assert.True(t, getEnvBool(key, true, rec))
	requireSingleEnvWarn(t, rec, key, "maybe")
}

func TestGetEnvBool_ValidAndEmptyValues_NoWarnings(t *testing.T) {
	const key = "TEST_GETENVBOOL_NOWARN"
	rec := &warnRecorder{}

	// Unset: default, no warning.
	assert.True(t, getEnvBool(key, true, rec))

	// Valid: parsed, no warning.
	t.Setenv(key, "false")
	assert.False(t, getEnvBool(key, true, rec))

	assert.Empty(t, rec.warnings())
}

func TestApplyRedisSentinelEnvToConfig_InvalidJitter_WarnsPerRedisRoute(t *testing.T) {
	t.Setenv(envRedisTTLJitter, "nan-ish")

	rec := &warnRecorder{}
	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Routes: []config.Route{
				{
					Name: "redis-route",
					Cache: &config.CacheConfig{
						Enabled: true,
						Type:    config.CacheTypeRedis,
						Redis:   &config.RedisCacheConfig{TTLJitter: 0.1},
					},
				},
			},
		},
	}

	applyRedisSentinelEnvToConfig(cfg, rec)

	assert.InDelta(t, 0.1, cfg.Spec.Routes[0].Cache.Redis.TTLJitter, 0.001)
	requireSingleEnvWarn(t, rec, envRedisTTLJitter, "nan-ish")
}

func TestEnsureEnvLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	assert.Same(t, logger, ensureEnvLogger(logger),
		"non-nil logger must be returned unchanged")
	assert.NotNil(t, ensureEnvLogger(nil),
		"nil logger must fall back to the process-wide logger")
}
