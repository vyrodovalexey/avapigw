package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// connCountingServer wraps an httptest.Server counting distinct accepted
// TCP connections via the ConnState hook.
type connCountingServer struct {
	*httptest.Server
	mu    sync.Mutex
	conns map[string]struct{}
}

// newConnCountingServer starts an HTTP server that records every new
// client connection's remote address.
func newConnCountingServer(t *testing.T, handler http.Handler) *connCountingServer {
	t.Helper()
	s := &connCountingServer{conns: make(map[string]struct{})}
	s.Server = httptest.NewUnstartedServer(handler)
	s.Server.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			s.mu.Lock()
			s.conns[c.RemoteAddr().String()] = struct{}{}
			s.mu.Unlock()
		}
	}
	s.Server.Start()
	t.Cleanup(s.Server.Close)
	return s
}

// count returns the number of distinct client connections accepted.
func (s *connCountingServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// backendFor builds a single-host GraphQL backend config pointing at the
// counting server.
func (s *connCountingServer) backendFor(t *testing.T, name string) config.GraphQLBackend {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(s.URL, "http://"))
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return config.GraphQLBackend{
		Name:  name,
		Hosts: []config.BackendHost{{Address: host, Port: port}},
	}
}

// TestForward_ReusesPooledConnections is the regression test for the
// PT-05/06 dial-storm: Forward previously canceled the per-request timeout
// context via `defer cancel()` BEFORE the caller read the response body, so
// net/http closed the connection instead of recycling it — N requests took
// ~N dials. With cancel tied to Body.Close, N sequential forwards must
// reuse a handful of connections.
func TestForward_ReusesPooledConnections(t *testing.T) {
	srv := newConnCountingServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))

	p := New() // default pooled transport
	t.Cleanup(p.Close)
	p.UpdateBackends([]config.GraphQLBackend{srv.backendFor(t, "counting-backend")})

	const requests = 50
	for i := 0; i < requests; i++ {
		req := httptest.NewRequest(http.MethodPost, "/graphql",
			strings.NewReader(`{"query":"{ ok }"}`))
		req.Header.Set("Content-Type", "application/json")

		resp, err := p.Forward(context.Background(), "counting-backend", req)
		require.NoError(t, err)

		// Mirror the gateway handler: read the body fully, then close.
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	}

	assert.LessOrEqual(t, srv.count(), 3,
		"sequential forwards must reuse pooled connections, got %d distinct conns for %d requests",
		srv.count(), requests)
}

// TestForward_BodyReadableAfterForwardReturns verifies the response body
// remains fully readable after Forward returns (the context must not be
// canceled until the caller closes the body).
func TestForward_BodyReadableAfterForwardReturns(t *testing.T) {
	const payload = `{"data":{"large":"` // + filler + `"}}`
	filler := strings.Repeat("x", 256*1024)
	srv := newConnCountingServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload + filler + `"}}`))
	}))

	p := New()
	t.Cleanup(p.Close)
	p.UpdateBackends([]config.GraphQLBackend{srv.backendFor(t, "body-backend")})

	req := httptest.NewRequest(http.MethodPost, "/graphql",
		strings.NewReader(`{"query":"{ big }"}`))

	resp, err := p.Forward(context.Background(), "body-backend", req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "body must be readable after Forward returns")
	assert.Len(t, body, len(payload)+len(filler)+len(`"}}`))
}

// TestCancelOnCloseBody_DoubleCloseSafe verifies Close is idempotent (the
// gateway handler and error paths may both close).
func TestCancelOnCloseBody_DoubleCloseSafe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	b := &cancelOnCloseBody{
		ReadCloser: io.NopCloser(strings.NewReader("x")),
		cancel:     cancel,
	}
	require.NoError(t, b.Close())
	require.NoError(t, b.Close())
	select {
	case <-ctx.Done():
		// context released as expected
	default:
		t.Fatal("Close must release the request context")
	}
}
