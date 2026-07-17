package grpcadapter

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// ----------------------------------------------------------------------------
// WP14-invoker B12 — outgoing metadata keys must be lowercased (gRPC contract).
// ----------------------------------------------------------------------------

func TestOutgoingMetadata_LowercasesMixedCaseKeys(t *testing.T) {
	t.Parallel()

	req := &aggregate.Request{
		Headers: map[string][]string{
			"X-Custom-Header": {"v1", "v2"},
			"Content-Type":    {"application/grpc"},
			"lowercase-key":   {"v3"},
		},
	}

	md := outgoingMetadata(req, &aggregate.Target{Name: "t1"})

	assert.Equal(t, []string{"v1", "v2"}, md["x-custom-header"])
	assert.Equal(t, []string{"application/grpc"}, md["content-type"])
	assert.Equal(t, []string{"v3"}, md["lowercase-key"])

	// The mixed-case originals must not survive as separate raw map keys.
	_, mixedCustom := md["X-Custom-Header"]
	assert.False(t, mixedCustom, "mixed-case key must not be stored verbatim")
	_, mixedCT := md["Content-Type"]
	assert.False(t, mixedCT, "mixed-case key must not be stored verbatim")
}

func TestOutgoingMetadata_EmptyHeaders(t *testing.T) {
	t.Parallel()

	md := outgoingMetadata(&aggregate.Request{}, &aggregate.Target{Name: "t1"})
	assert.Empty(t, md)
}

func TestOutgoingContext_ForwardsMetadataAndBasicAuth(t *testing.T) {
	t.Parallel()

	inv := NewInvoker(nil, "/pkg.Svc/Method")
	req := &aggregate.Request{
		Headers: map[string][]string{"X-Request-ID": {"abc"}},
	}
	target := &aggregate.Target{
		Name: "t1",
		Auth: &config.BackendAuthConfig{
			Type: "basic",
			Basic: &config.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
		},
	}

	ctx := inv.outgoingContext(context.Background(), req, target)
	md, ok := metadata.FromOutgoingContext(ctx)
	require.True(t, ok)

	assert.Equal(t, []string{"abc"}, md.Get("x-request-id"))
	auth := md.Get(authHeaderKey)
	require.Len(t, auth, 1)
	// base64("user:pass") == "dXNlcjpwYXNz"
	assert.Equal(t, "Basic dXNlcjpwYXNz", auth[0])
}

// ----------------------------------------------------------------------------
// WP14-invoker C6 — TLS cache keyed by name + config fingerprint.
// ----------------------------------------------------------------------------

func TestTLSConfigFor_CacheReuseAndInvalidation(t *testing.T) {
	t.Parallel()

	inv := NewInvoker(nil, "/pkg.Svc/Method")
	target := aggregate.Target{
		Name: "secure-target",
		TLS: &config.BackendTLSConfig{
			Enabled:            true,
			InsecureSkipVerify: true,
			ServerName:         "a.example.com",
		},
	}

	first, err := inv.tlsConfigFor(&target)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Equal(t, "a.example.com", first.ServerName)
	assert.Contains(t, first.NextProtos, "h2")

	// Same name + same config: the cached entry is reused.
	second, err := inv.tlsConfigFor(&target)
	require.NoError(t, err)
	assert.Same(t, first, second, "unchanged config must hit the cache")

	// Same name + changed config (simulated route/backend reload): the stale
	// entry misses on the fingerprint and a fresh config is built.
	target.TLS = &config.BackendTLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
		ServerName:         "b.example.com",
	}
	third, err := inv.tlsConfigFor(&target)
	require.NoError(t, err)
	require.NotNil(t, third)
	assert.NotSame(t, first, third, "changed config must miss the stale entry")
	assert.Equal(t, "b.example.com", third.ServerName)

	// The rebuilt entry replaced the stale one (one entry per target name).
	fourth, err := inv.tlsConfigFor(&target)
	require.NoError(t, err)
	assert.Same(t, third, fourth)

	entries := 0
	inv.tlsCache.Range(func(_, _ any) bool {
		entries++
		return true
	})
	assert.Equal(t, 1, entries, "cache must keep at most one entry per target")
}

func TestTLSConfigFor_DisabledReturnsNil(t *testing.T) {
	t.Parallel()

	inv := NewInvoker(nil, "/pkg.Svc/Method")

	cfg, err := inv.tlsConfigFor(&aggregate.Target{Name: "plain"})
	require.NoError(t, err)
	assert.Nil(t, cfg)

	cfg, err = inv.tlsConfigFor(&aggregate.Target{
		Name: "disabled",
		TLS:  &config.BackendTLSConfig{Enabled: false},
	})
	require.NoError(t, err)
	assert.Nil(t, cfg)
}

func TestTLSConfigFingerprint_DeterministicAndSensitive(t *testing.T) {
	t.Parallel()

	base := &config.BackendTLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
		ServerName:         "a.example.com",
	}
	same := &config.BackendTLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
		ServerName:         "a.example.com",
	}
	changed := &config.BackendTLSConfig{
		Enabled:            true,
		InsecureSkipVerify: false,
		ServerName:         "a.example.com",
		CAFile:             "/etc/ssl/ca.pem",
	}

	fpBase, err := tlsConfigFingerprint(base)
	require.NoError(t, err)
	fpSame, err := tlsConfigFingerprint(same)
	require.NoError(t, err)
	fpChanged, err := tlsConfigFingerprint(changed)
	require.NoError(t, err)

	assert.Equal(t, fpBase, fpSame, "equal configs must fingerprint equally")
	assert.NotEqual(t, fpBase, fpChanged, "changed config must change the fingerprint")
}
