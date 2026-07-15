package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// TestNewReverseProxy_DefaultPooledTransport verifies plaintext backends get
// a pooled transport instead of http.DefaultTransport (whose 2 idle
// connections per host exhaust ephemeral ports at load).
func TestNewReverseProxy_DefaultPooledTransport(t *testing.T) {
	t.Parallel()

	r := router.New()
	registry := backend.NewRegistry(observability.NopLogger())
	p := NewReverseProxy(r, registry)

	rt := p.Transport()
	require.NotNil(t, rt, "plaintext transport must be pooled, not nil")
	assert.NotSame(t, http.DefaultTransport, rt,
		"plaintext backends must not share http.DefaultTransport")

	transport, ok := rt.(*http.Transport)
	require.True(t, ok, "default transport must be an *http.Transport")

	assert.Equal(t, defaultProxyMaxIdleConns, transport.MaxIdleConns)
	assert.Equal(t, defaultProxyMaxIdleConnsPerHost, transport.MaxIdleConnsPerHost)
	assert.Equal(t, defaultProxyIdleConnTimeout, transport.IdleConnTimeout)
	assert.Equal(t, defaultProxyTLSHandshakeTimeout, transport.TLSHandshakeTimeout)
	assert.Equal(t, defaultProxyExpectContinueTimeout, transport.ExpectContinueTimeout)
	assert.True(t, transport.ForceAttemptHTTP2, "H2 must stay enabled like DefaultTransport")
	assert.NotNil(t, transport.DialContext, "pooled dialer must be configured")
	assert.NotNil(t, transport.Proxy, "environment proxy support must be preserved")
	assert.Zero(t, transport.ResponseHeaderTimeout,
		"streaming responses must not be cut off by a header timeout")
}

// TestNewReverseProxy_CustomTransportPreserved verifies WithTransport still
// overrides the pooled default.
func TestNewReverseProxy_CustomTransportPreserved(t *testing.T) {
	t.Parallel()

	custom := &http.Transport{MaxIdleConnsPerHost: 7, IdleConnTimeout: 5 * time.Second}
	r := router.New()
	registry := backend.NewRegistry(observability.NopLogger())
	p := NewReverseProxy(r, registry, WithTransport(custom))

	assert.Same(t, custom, p.Transport())
}

// TestDefaultPooledTransport_SizedLikeTLSPath verifies the plaintext pool is
// at least as generous as the TLS backend pool so plaintext backends are not
// the connection-churn outlier.
func TestDefaultPooledTransport_SizedLikeTLSPath(t *testing.T) {
	t.Parallel()

	transport := newDefaultPooledTransport()
	tlsPool := backend.DefaultPoolConfig()

	assert.GreaterOrEqual(t, transport.MaxIdleConns, tlsPool.MaxIdleConns)
	assert.GreaterOrEqual(t, transport.MaxIdleConnsPerHost, tlsPool.MaxIdleConnsPerHost)
	assert.Equal(t, tlsPool.IdleConnTimeout, transport.IdleConnTimeout)
}
