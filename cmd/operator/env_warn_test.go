// Package main contains tests for environment variable parse warnings:
// invalid values must keep the current setting AND surface a warning
// (parity with the gateway's env handling) instead of being silently
// swallowed.
package main

import (
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Warning-returning env appliers
// ============================================================================

func TestApplyIntEnv_InvalidValue_Warns(t *testing.T) {
	t.Setenv("TEST_WARN_INT", "not-a-number")

	target := 42
	warning := applyIntEnv(&target, "TEST_WARN_INT")

	require.NotNil(t, warning, "invalid integer must produce a warning")
	assert.Equal(t, "TEST_WARN_INT", warning.key)
	assert.Equal(t, "not-a-number", warning.value)
	assert.Contains(t, warning.reason, "integer")
	assert.Equal(t, 42, target, "invalid value must keep the current setting")
}

func TestApplyIntEnv_ValidValue_NoWarning(t *testing.T) {
	t.Setenv("TEST_WARN_INT_OK", "9999")

	target := 42
	assert.Nil(t, applyIntEnv(&target, "TEST_WARN_INT_OK"))
	assert.Equal(t, 9999, target)
}

func TestApplyIntEnv_Unset_NoWarning(t *testing.T) {
	target := 42
	assert.Nil(t, applyIntEnv(&target, "TEST_WARN_INT_UNSET"))
	assert.Equal(t, 42, target)
}

func TestApplyFloat64Env_InvalidValue_Warns(t *testing.T) {
	t.Setenv("TEST_WARN_FLOAT", "half")

	target := 0.5
	warning := applyFloat64Env(&target, "TEST_WARN_FLOAT")

	require.NotNil(t, warning)
	assert.Equal(t, "TEST_WARN_FLOAT", warning.key)
	assert.Contains(t, warning.reason, "number")
	assert.InDelta(t, 0.5, target, 0.0001)
}

func TestApplyDurationEnv_InvalidValue_Warns(t *testing.T) {
	t.Setenv("TEST_WARN_DURATION", "30") // bare integer is not a duration

	target := 10 * time.Second
	warning := applyDurationEnv(&target, "TEST_WARN_DURATION")

	require.NotNil(t, warning)
	assert.Equal(t, "TEST_WARN_DURATION", warning.key)
	assert.Contains(t, warning.reason, "duration")
	assert.Equal(t, 10*time.Second, target)
}

func TestApplyBoolEnv_InvalidValue_Warns(t *testing.T) {
	t.Setenv("TEST_WARN_BOOL", "maybe")

	target := true
	warning := applyBoolEnv(&target, "TEST_WARN_BOOL")

	require.NotNil(t, warning)
	assert.Equal(t, "TEST_WARN_BOOL", warning.key)
	assert.Contains(t, warning.reason, "boolean")
	assert.True(t, target, "invalid value must keep the current setting")
}

func TestApplyBoolEnv_ValidValues_NoWarning(t *testing.T) {
	for _, v := range []string{"true", "1", "yes", "false", "0", "no", "TRUE", "No"} {
		t.Setenv("TEST_WARN_BOOL_OK", v)
		target := false
		assert.Nil(t, applyBoolEnv(&target, "TEST_WARN_BOOL_OK"), "value %q must not warn", v)
	}
}

// ============================================================================
// applyEnvOverrides — warnings collected on the Config
// ============================================================================

func TestApplyEnvOverrides_CollectsWarnings(t *testing.T) {
	t.Setenv("GRPC_PORT", "not-a-port")
	t.Setenv("TRACING_SAMPLING_RATE", "lots")
	t.Setenv("VAULT_INIT_TIMEOUT", "soon")
	t.Setenv("LEADER_ELECT", "sometimes")

	cfg := &Config{GRPCPort: 9444, TracingSamplingRate: 1.0, VaultInitTimeout: 30 * time.Second}
	applyEnvOverrides(cfg)

	require.Len(t, cfg.envWarnings, 4, "each invalid env var must be recorded")

	keys := make([]string, 0, len(cfg.envWarnings))
	for _, w := range cfg.envWarnings {
		keys = append(keys, w.key)
	}
	assert.ElementsMatch(t,
		[]string{"GRPC_PORT", "TRACING_SAMPLING_RATE", "VAULT_INIT_TIMEOUT", "LEADER_ELECT"}, keys)

	// Defaults kept in effect.
	assert.Equal(t, 9444, cfg.GRPCPort)
	assert.InDelta(t, 1.0, cfg.TracingSamplingRate, 0.0001)
	assert.Equal(t, 30*time.Second, cfg.VaultInitTimeout)
	assert.False(t, cfg.EnableLeaderElection)
}

func TestApplyEnvOverrides_NoWarningsOnValidValues(t *testing.T) {
	t.Setenv("GRPC_PORT", "9555")
	t.Setenv("LEADER_ELECT", "true")

	cfg := &Config{GRPCPort: 9444}
	applyEnvOverrides(cfg)

	assert.Empty(t, cfg.envWarnings)
	assert.Equal(t, 9555, cfg.GRPCPort)
	assert.True(t, cfg.EnableLeaderElection)
}

// spyLogEntry is a single Info call captured by spyLogSink.
type spyLogEntry struct {
	msg string
	kv  []interface{}
}

// spyLogSink is a minimal logr.LogSink capturing Info calls so tests can
// assert on log output without a real logging backend.
type spyLogSink struct {
	mu      sync.Mutex
	entries []spyLogEntry
}

func (s *spyLogSink) Init(logr.RuntimeInfo) {}
func (s *spyLogSink) Enabled(int) bool      { return true }

func (s *spyLogSink) Info(_ int, msg string, kv ...interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, spyLogEntry{msg: msg, kv: kv})
}

func (s *spyLogSink) Error(_ error, _ string, _ ...interface{}) {}

func (s *spyLogSink) WithValues(...interface{}) logr.LogSink { return s }
func (s *spyLogSink) WithName(string) logr.LogSink           { return s }

// all returns a snapshot of the captured entries.
func (s *spyLogSink) all() []spyLogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]spyLogEntry(nil), s.entries...)
}

// assertLogKV asserts the key/value list contains the given pair.
func assertLogKV(t *testing.T, kv []interface{}, key string, want interface{}) {
	t.Helper()

	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i] == key {
			assert.Equal(t, want, kv[i+1], "log field %q", key)
			return
		}
	}
	t.Errorf("log entry is missing field %q (kv=%v)", key, kv)
}

// TestLogEnvWarnings covers the post-logger-setup warning emission path:
// exactly one warning line per recorded entry, carrying the env key, the
// rejected value, and the parse reason.
func TestLogEnvWarnings(t *testing.T) {
	spy := &spyLogSink{}
	original := setupLog
	setupLog = logr.New(spy)
	t.Cleanup(func() { setupLog = original })

	// No recorded warnings → no output.
	logEnvWarnings(&Config{})
	assert.Empty(t, spy.all(), "a config without warnings must not log anything")

	logEnvWarnings(&Config{envWarnings: []envWarning{
		{key: "GRPC_PORT", value: "x", reason: "not a valid integer"},
		{key: "LEADER_ELECT", value: "maybe", reason: "not a valid boolean"},
	}})

	entries := spy.all()
	require.Len(t, entries, 2, "one warning line per recorded env warning")

	assert.Contains(t, entries[0].msg, "ignoring invalid environment variable value")
	assertLogKV(t, entries[0].kv, "env", "GRPC_PORT")
	assertLogKV(t, entries[0].kv, "value", "x")
	assertLogKV(t, entries[0].kv, "reason", "not a valid integer")

	assertLogKV(t, entries[1].kv, "env", "LEADER_ELECT")
	assertLogKV(t, entries[1].kv, "value", "maybe")
	assertLogKV(t, entries[1].kv, "reason", "not a valid boolean")
}
