// Connection-reuse regression test for the GraphQL forward path (PT-05/06
// Finding 1): the gateway's GraphQLHandler must reuse pooled backend
// connections across sequential requests instead of dialing per request.
package gateway

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// TestGraphQLHandler_ForwardReusesBackendConnections drives N sequential
// GraphQL requests through the ACTUAL handler forward path (parse -> match ->
// route middleware -> proxy.Forward -> body copy -> Close) and asserts the
// backend saw a handful of connections, not N. Before the fix, the proxy's
// `defer cancel()` released the per-request context while the handler was
// still copying the body, so net/http closed every pooled connection
// (~1 dial/request -> ephemeral-port exhaustion at load).
func TestGraphQLHandler_ForwardReusesBackendConnections(t *testing.T) {
	var mu sync.Mutex
	conns := make(map[string]struct{})

	backend := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
		}))
	backend.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			conns[c.RemoteAddr().String()] = struct{}{}
			mu.Unlock()
		}
	}
	backend.Start()
	t.Cleanup(backend.Close)

	handler, _ := newGraphQLTestHandler(t,
		[]config.GraphQLRoute{gqlRoute("conn-reuse-route", nil)},
		backend.URL,
	)

	const requests = 50
	for i := 0; i < requests; i++ {
		rec := postGraphQL(handler, nil)
		require.Equal(t, http.StatusOK, rec.Code, "request %d must succeed", i)
		require.JSONEq(t, `{"data":{"ok":true}}`, rec.Body.String(),
			"request %d must return the full backend body", i)
	}

	mu.Lock()
	distinct := len(conns)
	mu.Unlock()
	assert.LessOrEqual(t, distinct, 3,
		"handler forwards must reuse pooled backend connections, got %d distinct conns for %d requests",
		distinct, requests)
}
