package proxy

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/grpc/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// observedDirectorLogger adapts a zap observer core to observability.Logger
// so tests can assert log volume by level and message.
type observedDirectorLogger struct{ z *zap.Logger }

func newObservedDirectorLogger(level zapcore.Level) (observability.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(level)
	return &observedDirectorLogger{z: zap.New(core)}, logs
}

func (l *observedDirectorLogger) Debug(msg string, fields ...observability.Field) {
	l.z.Debug(msg, fields...)
}
func (l *observedDirectorLogger) Info(msg string, fields ...observability.Field) {
	l.z.Info(msg, fields...)
}
func (l *observedDirectorLogger) Warn(msg string, fields ...observability.Field) {
	l.z.Warn(msg, fields...)
}
func (l *observedDirectorLogger) Error(msg string, fields ...observability.Field) {
	l.z.Error(msg, fields...)
}
func (l *observedDirectorLogger) Fatal(msg string, fields ...observability.Field) {
	l.z.Fatal(msg, fields...)
}
func (l *observedDirectorLogger) With(...observability.Field) observability.Logger { return l }
func (l *observedDirectorLogger) WithContext(context.Context) observability.Logger { return l }
func (l *observedDirectorLogger) Sync() error                                      { return nil }

// registerAddressBackend creates and registers a backend with a single host.
func registerAddressBackend(
	t *testing.T, registry *backend.Registry, name, address string, port int,
) *backend.ServiceBackend {
	t.Helper()
	b, err := backend.NewBackend(config.Backend{
		Name:  name,
		Hosts: []config.BackendHost{{Address: address, Port: port, Weight: 1}},
	}, backend.WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)
	require.NoError(t, registry.Register(b))
	return b
}

// TestRouterDirector_ResolveTarget_AddressMatch is the address-match matrix
// for the backend feature-attach fix: name match (existing behavior),
// address match (fallback), no match (plain dial + one warn), and
// ambiguous multi-backend match (deterministic choice + one warn).
func TestRouterDirector_ResolveTarget_AddressMatch(t *testing.T) {
	t.Parallel()

	t.Run("name match keeps existing behavior", func(t *testing.T) {
		t.Parallel()
		registry := backend.NewRegistry(observability.NopLogger())
		registerAddressBackend(t, registry, "grpc-backend-mtls", "10.0.0.1", 8813)

		pool := NewConnectionPool()
		defer pool.Close()
		director := NewRouterDirector(router.New(), pool,
			WithDirectorBackendRegistry(registry))

		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "grpc-backend-mtls", Port: 9999},
		}
		target, host, sb, err := director.resolveTarget("mtls-route", dest)
		require.NoError(t, err)
		require.NotNil(t, sb)
		assert.Equal(t, "grpc-backend-mtls", sb.Name())
		assert.Equal(t, "10.0.0.1:8813", target)
		sb.ReleaseHost(host)
	})

	t.Run("address match attaches backend features", func(t *testing.T) {
		t.Parallel()
		registry := backend.NewRegistry(observability.NopLogger())
		registerAddressBackend(t, registry, "grpc-backend-mtls", "host.docker.internal", 8813)

		logger, logs := newObservedDirectorLogger(zapcore.DebugLevel)
		pool := NewConnectionPool()
		defer pool.Close()
		director := NewRouterDirector(router.New(), pool,
			WithDirectorLogger(logger),
			WithDirectorBackendRegistry(registry))

		// Destination uses the literal host:port, NOT the backend name.
		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "host.docker.internal", Port: 8813},
		}
		target, host, sb, err := director.resolveTarget("mtls-route", dest)
		require.NoError(t, err)
		require.NotNil(t, sb, "literal-host destination must attach the backend declaring the endpoint")
		assert.Equal(t, "grpc-backend-mtls", sb.Name())
		assert.Equal(t, "host.docker.internal:8813", target)
		sb.ReleaseHost(host)

		// Address-based resolution is logged at debug, without warns.
		assert.Equal(t, 1,
			logs.FilterMessageSnippet("resolved gRPC backend by host address").Len())
		assert.Zero(t, logs.FilterLevelExact(zapcore.WarnLevel).Len())
	})

	t.Run("address match with different port stays plain", func(t *testing.T) {
		t.Parallel()
		registry := backend.NewRegistry(observability.NopLogger())
		registerAddressBackend(t, registry, "grpc-backend-mtls", "host.docker.internal", 8813)

		pool := NewConnectionPool()
		defer pool.Close()
		director := NewRouterDirector(router.New(), pool,
			WithDirectorBackendRegistry(registry))

		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "host.docker.internal", Port: 8811},
		}
		target, host, sb, err := director.resolveTarget("plain-route", dest)
		require.NoError(t, err)
		assert.Nil(t, sb)
		assert.Nil(t, host)
		assert.Equal(t, "host.docker.internal:8811", target)
	})

	t.Run("no match warns once per route and destination", func(t *testing.T) {
		t.Parallel()
		registry := backend.NewRegistry(observability.NopLogger())

		logger, logs := newObservedDirectorLogger(zapcore.DebugLevel)
		pool := NewConnectionPool()
		defer pool.Close()
		director := NewRouterDirector(router.New(), pool,
			WithDirectorLogger(logger),
			WithDirectorBackendRegistry(registry))

		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "unmatched.example.com", Port: 9000},
		}
		for i := 0; i < 3; i++ {
			target, host, sb, err := director.resolveTarget("plain-route", dest)
			require.NoError(t, err)
			assert.Nil(t, sb)
			assert.Nil(t, host)
			assert.Equal(t, "unmatched.example.com:9000", target)
		}

		warns := logs.FilterMessageSnippet("no backend matches gRPC route destination")
		assert.Equal(t, 1, warns.Len(), "plain-dial warn must be deduplicated per route+destination")

		// A different route to the same destination gets its own warn.
		_, _, _, err := director.resolveTarget("other-route", dest)
		require.NoError(t, err)
		assert.Equal(t, 2,
			logs.FilterMessageSnippet("no backend matches gRPC route destination").Len())
	})

	t.Run("no registry never warns", func(t *testing.T) {
		t.Parallel()
		logger, logs := newObservedDirectorLogger(zapcore.DebugLevel)
		pool := NewConnectionPool()
		defer pool.Close()
		director := NewRouterDirector(router.New(), pool, WithDirectorLogger(logger))

		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "file-mode.example.com", Port: 9000},
		}
		target, _, sb, err := director.resolveTarget("file-route", dest)
		require.NoError(t, err)
		assert.Nil(t, sb)
		assert.Equal(t, "file-mode.example.com:9000", target)
		assert.Zero(t, logs.FilterLevelExact(zapcore.WarnLevel).Len(),
			"file-mode deployments without a registry must stay quiet")
	})

	t.Run("ambiguous multiple backends deterministic choice with warn", func(t *testing.T) {
		t.Parallel()
		registry := backend.NewRegistry(observability.NopLogger())
		// Registered in reverse-lexicographic order on purpose.
		registerAddressBackend(t, registry, "zeta-backend", "10.0.0.9", 50051)
		registerAddressBackend(t, registry, "alpha-backend", "10.0.0.9", 50051)

		logger, logs := newObservedDirectorLogger(zapcore.DebugLevel)
		pool := NewConnectionPool()
		defer pool.Close()
		director := NewRouterDirector(router.New(), pool,
			WithDirectorLogger(logger),
			WithDirectorBackendRegistry(registry))

		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "10.0.0.9", Port: 50051},
		}
		for i := 0; i < 3; i++ {
			_, host, sb, err := director.resolveTarget("ambiguous-route", dest)
			require.NoError(t, err)
			require.NotNil(t, sb)
			assert.Equal(t, "alpha-backend", sb.Name(),
				"ambiguous endpoint must resolve deterministically to the smallest name")
			sb.ReleaseHost(host)
		}

		warns := logs.FilterMessageSnippet("multiple gRPC backends declare the destination endpoint")
		assert.Equal(t, 1, warns.Len(), "ambiguity warn must be deduplicated per route+destination")
	})
}

// TestRouterDirector_ResolveTarget_AddressMatch_TLSFeatures verifies the
// data-path consequence of the fix: a TLS-enabled backend matched by
// address exposes its TLS config to the connection pool exactly as a
// name-matched backend does (previously literal-host destinations dialed
// plaintext and silently dropped mTLS).
func TestRouterDirector_ResolveTarget_AddressMatch_TLSFeatures(t *testing.T) {
	t.Parallel()

	registry := backend.NewRegistry(observability.NopLogger())
	b, err := backend.NewBackend(config.Backend{
		Name:  "tls-backend",
		Hosts: []config.BackendHost{{Address: "10.0.0.5", Port: 8813, Weight: 1}},
		TLS: &config.BackendTLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
		},
	}, backend.WithBackendLogger(observability.NopLogger()))
	require.NoError(t, err)
	require.NoError(t, registry.Register(b))

	pool := NewConnectionPool()
	defer pool.Close()
	director := NewRouterDirector(router.New(), pool,
		WithDirectorBackendRegistry(registry))

	dest := &config.RouteDestination{
		Destination: config.Destination{Host: "10.0.0.5", Port: 8813},
	}
	_, host, sb, err := director.resolveTarget("tls-route", dest)
	require.NoError(t, err)
	require.NotNil(t, sb)
	defer sb.ReleaseHost(host)

	var tlsCfg *tls.Config = sb.TLSConfig()
	require.NotNil(t, tlsCfg, "address-matched backend must expose its TLS config for the dial")
	assert.True(t, sb.IsTLSEnabled())
}
