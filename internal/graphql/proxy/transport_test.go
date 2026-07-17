package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew_DefaultTransportPooling verifies the GraphQL proxy's default
// transport keeps enough warm connections per backend host (the previous
// MaxIdleConnsPerHost of 10 forced per-request dials at load).
func TestNew_DefaultTransportPooling(t *testing.T) {
	t.Parallel()

	p := New()

	rt := p.Transport()
	require.NotNil(t, rt)

	transport, ok := rt.(*http.Transport)
	require.True(t, ok, "default transport must be an *http.Transport")

	assert.Equal(t, defaultMaxIdleConns, transport.MaxIdleConns)
	assert.Equal(t, defaultMaxIdleConnsPerHost, transport.MaxIdleConnsPerHost)
	assert.GreaterOrEqual(t, transport.MaxIdleConnsPerHost, 100,
		"per-host idle pool must be sized for load, not the old 10")
	assert.Equal(t, defaultIdleConnTimeout, transport.IdleConnTimeout)
	assert.Equal(t, defaultTLSHandshakeTimeout, transport.TLSHandshakeTimeout)
	assert.Equal(t, defaultExpectContinueTimeout, transport.ExpectContinueTimeout)
	assert.True(t, transport.ForceAttemptHTTP2)
	assert.NotNil(t, transport.DialContext)
	assert.NotNil(t, transport.Proxy)
}

// TestNew_CustomTransportPreserved verifies WithTransport still overrides
// the pooled default.
func TestNew_CustomTransportPreserved(t *testing.T) {
	t.Parallel()

	custom := &http.Transport{MaxIdleConnsPerHost: 3, IdleConnTimeout: time.Second}
	p := New(WithTransport(custom))

	assert.Same(t, custom, p.Transport())
}
