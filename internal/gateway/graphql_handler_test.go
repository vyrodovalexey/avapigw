// Package gateway tests for the GraphQL endpoint middleware enforcement fix:
// GraphQL routes must enforce the SAME route-level middleware (auth, rate
// limiting incl. redis store, CORS, header manipulation) as HTTP routes, and
// graphql-ws subscription upgrades must pass the middleware chain while the
// relay keeps working through the wrapped handler.
package gateway

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	graphqlproxy "github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

const testGraphQLBackendName = "gql-test-backend"

// recordingMetrics is a GraphQLMetricsRecorder capturing calls for assertions.
type recordingMetrics struct {
	mu       sync.Mutex
	requests []recordedRequest
	errors   []recordedError
}

type recordedRequest struct {
	backend string
	opType  string
	status  int
}

type recordedError struct {
	backend   string
	opType    string
	errorType string
}

func (m *recordingMetrics) RecordRequest(backend, operationType string, statusCode int, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, recordedRequest{backend, operationType, statusCode})
}

func (m *recordingMetrics) RecordError(backend, operationType, errorType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors = append(m.errors, recordedError{backend, operationType, errorType})
}

func (m *recordingMetrics) lastRequest(t *testing.T) recordedRequest {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	require.NotEmpty(t, m.requests, "expected at least one recorded request")
	return m.requests[len(m.requests)-1]
}

// backendHostFromURL splits an httptest server URL into a BackendHost.
func backendHostFromURL(t *testing.T, rawURL string) config.BackendHost {
	t.Helper()
	trimmed := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "ws://")
	host, portStr, err := net.SplitHostPort(trimmed)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return config.BackendHost{Address: host, Port: port}
}

// newGraphQLTestHandler builds a GraphQLHandler over the given routes and
// backend server, wired with a real RouteMiddlewareManager.
func newGraphQLTestHandler(
	t *testing.T,
	routes []config.GraphQLRoute,
	backendURL string,
	opts ...GraphQLHandlerOption,
) (*GraphQLHandler, *RouteMiddlewareManager) {
	t.Helper()

	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	require.NoError(t, router.LoadRoutes(routes))

	proxy := graphqlproxy.New(graphqlproxy.WithLogger(observability.NopLogger()))
	if backendURL != "" {
		proxy.UpdateBackends([]config.GraphQLBackend{
			{Name: testGraphQLBackendName, Hosts: []config.BackendHost{backendHostFromURL(t, backendURL)}},
		})
	}

	mgr := NewRouteMiddlewareManager(nil, observability.NopLogger())
	t.Cleanup(mgr.Stop)

	handlerOpts := append([]GraphQLHandlerOption{
		WithGraphQLHandlerLogger(observability.NopLogger()),
		WithGraphQLHandlerRouteMiddleware(mgr),
	}, opts...)

	handler, err := NewGraphQLHandler(router, proxy, handlerOpts...)
	require.NoError(t, err)
	t.Cleanup(handler.Close)

	return handler, mgr
}

// gqlRoute builds a catch-all GraphQL route to the test backend.
func gqlRoute(name string, mutate func(*config.GraphQLRoute)) config.GraphQLRoute {
	route := config.GraphQLRoute{
		Name: name,
		Route: []config.RouteDestination{
			{Destination: config.Destination{Host: testGraphQLBackendName}},
		},
	}
	if mutate != nil {
		mutate(&route)
	}
	return route
}

// postGraphQL performs a POST with a trivial query and returns the recorder.
func postGraphQL(handler http.Handler, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ ok }"}`))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// okBackend returns an httptest GraphQL backend answering 200 with data.
func okBackend(t *testing.T, inspect func(r *http.Request)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if inspect != nil {
			inspect(r)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	t.Cleanup(server.Close)
	return server
}

// ============================================================================
// Route-level authentication enforcement (perf finding: bad tokens got 200)
// ============================================================================

func TestGraphQLHandler_RouteAuth_BadTokenRejected(t *testing.T) {
	backend := okBackend(t, nil)

	routes := []config.GraphQLRoute{gqlRoute("auth-route", func(r *config.GraphQLRoute) {
		r.Authentication = &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled:   true,
				Secret:    "graphql-route-secret",
				Algorithm: "HS256",
			},
		}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	// Bad bearer token → 401 from the route auth middleware.
	rec := postGraphQL(handler, map[string]string{"Authorization": "Bearer definitely-not-a-jwt"})
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "bad token must be rejected by route auth")

	// Missing credentials → 401 as well.
	rec = postGraphQL(handler, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "missing credentials must be rejected")
}

func TestGraphQLHandler_NoAuthRoute_Passes(t *testing.T) {
	backend := okBackend(t, nil)
	handler, _ := newGraphQLTestHandler(t, []config.GraphQLRoute{gqlRoute("open-route", nil)}, backend.URL)

	rec := postGraphQL(handler, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"ok":true`)
}

// ============================================================================
// Route-level rate limiting (perf finding: 0×429 across 1.3M requests)
// ============================================================================

func TestGraphQLHandler_RouteRateLimit_MemoryStore(t *testing.T) {
	backend := okBackend(t, nil)

	routes := []config.GraphQLRoute{gqlRoute("rl-mem-route", func(r *config.GraphQLRoute) {
		// 1 rps refills a token only after a full second: the third
		// back-to-back request deterministically exceeds the burst even
		// under -race scheduling gaps (100 rps refilled every 10ms and
		// flaked under parallel package load).
		r.RateLimit = &config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 2}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	for i := 0; i < 2; i++ {
		rec := postGraphQL(handler, nil)
		require.Equal(t, http.StatusOK, rec.Code, "request %d within burst must pass", i+1)
	}
	rec := postGraphQL(handler, nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "route rate limit must throttle with 429")
}

func TestGraphQLHandler_RouteRateLimit_RedisStore(t *testing.T) {
	mr := miniredis.RunT(t)
	backend := okBackend(t, nil)

	routes := []config.GraphQLRoute{gqlRoute("rl-redis-route", func(r *config.GraphQLRoute) {
		// 1 rps for a deterministic third-request 429 (see the memory-store
		// test above for the flake rationale).
		r.RateLimit = &config.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1,
			Burst:             2,
			Store:             config.RateLimitStoreRedis,
			Redis: &config.RateLimitRedisConfig{
				URL: "redis://" + mr.Addr(),
				Retry: &config.RedisRetryConfig{
					MaxRetries:     1,
					InitialBackoff: config.Duration(time.Millisecond),
				},
			},
		}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	for i := 0; i < 2; i++ {
		rec := postGraphQL(handler, nil)
		require.Equal(t, http.StatusOK, rec.Code, "request %d within burst must pass", i+1)
	}
	rec := postGraphQL(handler, nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "redis-backed route rate limit must throttle")

	// The distributed bucket lives under the graphql-scoped route name so
	// GraphQL and HTTP routes sharing a name never share a bucket.
	assert.True(t, mr.Exists("avapigw:ratelimit:"+graphqlChainScope+"rl-redis-route"),
		"redis bucket key for the graphql route scope must exist")
}

// ============================================================================
// Route-level CORS (perf finding: CORS unenforced)
// ============================================================================

func TestGraphQLHandler_RouteCORS_PreflightHonored(t *testing.T) {
	backend := okBackend(t, nil)

	routes := []config.GraphQLRoute{gqlRoute("cors-route", func(r *config.GraphQLRoute) {
		r.CORS = &config.CORSConfig{
			AllowOrigins: []string{"https://app.example.com"},
			AllowMethods: []string{"POST", "OPTIONS"},
			AllowHeaders: []string{"Content-Type", "Authorization"},
			MaxAge:       3600,
		}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"),
		"preflight must be answered with the route's CORS policy")
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Less(t, rec.Code, 300, "preflight must not be an error")
}

func TestGraphQLHandler_RouteCORS_ActualRequestCarriesHeaders(t *testing.T) {
	backend := okBackend(t, nil)

	routes := []config.GraphQLRoute{gqlRoute("cors-route", func(r *config.GraphQLRoute) {
		r.CORS = &config.CORSConfig{
			AllowOrigins: []string{"https://app.example.com"},
			AllowMethods: []string{"POST"},
		}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	rec := postGraphQL(handler, map[string]string{"Origin": "https://app.example.com"})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestGraphQLHandler_Preflight_NoMatchingRoute(t *testing.T) {
	backend := okBackend(t, nil)

	// Route matches only a different path, so the preflight cannot match.
	routes := []config.GraphQLRoute{gqlRoute("path-route", func(r *config.GraphQLRoute) {
		r.Match = []config.GraphQLRouteMatch{{Path: &config.StringMatch{Exact: "/other"}}}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGraphQLHandler_Preflight_NoCORSConfigured_NoContent(t *testing.T) {
	backend := okBackend(t, nil)
	handler, _ := newGraphQLTestHandler(t, []config.GraphQLRoute{gqlRoute("plain", nil)}, backend.URL)

	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

// ============================================================================
// Route-level header manipulation (transform scenario)
// ============================================================================

func TestGraphQLHandler_RouteHeaders_AppliedToBackendRequest(t *testing.T) {
	var gotHeader string
	backend := okBackend(t, func(r *http.Request) {
		gotHeader = r.Header.Get("X-Gateway")
	})

	routes := []config.GraphQLRoute{gqlRoute("headers-route", func(r *config.GraphQLRoute) {
		r.Headers = &config.HeaderManipulation{
			Request: &config.HeaderOperation{Set: map[string]string{"X-Gateway": "avapigw"}},
		}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	rec := postGraphQL(handler, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "avapigw", gotHeader,
		"route header manipulation must be applied to the forwarded request")
}

// ============================================================================
// Metrics recording (FIX: avapigw_graphql_requests_total stayed 0)
// ============================================================================

func TestGraphQLHandler_MetricsRecorded_Success(t *testing.T) {
	backend := okBackend(t, nil)
	metrics := &recordingMetrics{}
	handler, _ := newGraphQLTestHandler(t, []config.GraphQLRoute{gqlRoute("m-route", nil)}, backend.URL,
		WithGraphQLHandlerMetrics(metrics))

	rec := postGraphQL(handler, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	got := metrics.lastRequest(t)
	assert.Equal(t, testGraphQLBackendName, got.backend)
	assert.Equal(t, "query", got.opType)
	assert.Equal(t, http.StatusOK, got.status)
}

func TestGraphQLHandler_MetricsRecorded_MiddlewareRejection(t *testing.T) {
	backend := okBackend(t, nil)
	metrics := &recordingMetrics{}
	routes := []config.GraphQLRoute{gqlRoute("m-rl-route", func(r *config.GraphQLRoute) {
		r.RateLimit = &config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL, WithGraphQLHandlerMetrics(metrics))

	_ = postGraphQL(handler, nil)
	rec := postGraphQL(handler, nil)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)

	got := metrics.lastRequest(t)
	assert.Equal(t, http.StatusTooManyRequests, got.status,
		"middleware rejections must be visible in request metrics")
}

func TestGraphQLHandler_MetricsRecorded_NoRoute(t *testing.T) {
	backend := okBackend(t, nil)
	metrics := &recordingMetrics{}
	routes := []config.GraphQLRoute{gqlRoute("mutations-only", func(r *config.GraphQLRoute) {
		r.Match = []config.GraphQLRouteMatch{{OperationType: "mutation"}}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL, WithGraphQLHandlerMetrics(metrics))

	rec := postGraphQL(handler, nil)
	require.Equal(t, http.StatusNotFound, rec.Code)

	got := metrics.lastRequest(t)
	assert.Equal(t, http.StatusNotFound, got.status)
	assert.Equal(t, graphqlOpUnknown, got.opType)

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	require.NotEmpty(t, metrics.errors)
	assert.Equal(t, graphqlErrNoRoute, metrics.errors[0].errorType)
}

func TestGraphQLHandler_MetricsRecorded_BackendError(t *testing.T) {
	metrics := &recordingMetrics{}
	// No backend registered → proxy Forward fails → 502.
	handler, _ := newGraphQLTestHandler(t, []config.GraphQLRoute{gqlRoute("no-backend", nil)}, "",
		WithGraphQLHandlerMetrics(metrics))

	rec := postGraphQL(handler, nil)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Contains(t, rec.Body.String(), "backend error")

	got := metrics.lastRequest(t)
	assert.Equal(t, http.StatusBadGateway, got.status)

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	require.NotEmpty(t, metrics.errors)
	assert.Equal(t, graphqlErrTransport, metrics.errors[0].errorType)
}

// ============================================================================
// graphql-ws subscriptions through the wrapped handler
// ============================================================================

// wsEchoBackend serves a WebSocket echo endpoint at /graphql.
func wsEchoBackend(t *testing.T) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			http.NotFound(w, r)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(msgType, msg); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestGraphQLHandler_Subscription_RelayThroughWrappedHandler(t *testing.T) {
	backend := wsEchoBackend(t)

	routes := []config.GraphQLRoute{gqlRoute("sub-route", nil)}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	front := httptest.NewServer(handler)
	defer front.Close()

	wsURL := "ws" + strings.TrimPrefix(front.URL, "http") + "/graphql"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err, "subscription upgrade through the wrapped handler must succeed")
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	defer conn.Close()

	// The relay must forward frames in both directions.
	payload := `{"type":"subscribe","id":"1"}`
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(payload)))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, echoed, err := conn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, payload, string(echoed))
}

func TestGraphQLHandler_Subscription_AuthEnforcedOnUpgrade(t *testing.T) {
	backend := wsEchoBackend(t)

	routes := []config.GraphQLRoute{gqlRoute("sub-auth-route", func(r *config.GraphQLRoute) {
		r.Authentication = &config.AuthenticationConfig{
			Enabled: true,
			JWT: &config.JWTAuthConfig{
				Enabled:   true,
				Secret:    "subscription-secret",
				Algorithm: "HS256",
			},
		}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	front := httptest.NewServer(handler)
	defer front.Close()

	wsURL := "ws" + strings.TrimPrefix(front.URL, "http") + "/graphql"
	header := http.Header{"Authorization": []string{"Bearer bad-token"}}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	require.Error(t, err, "upgrade with a bad token must be rejected before the relay starts")
	if conn != nil {
		_ = conn.Close()
	}
	require.NotNil(t, resp)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"route auth middleware must run on the HTTP upgrade request")
}

func TestGraphQLHandler_Subscription_NoMatchingRoute(t *testing.T) {
	backend := wsEchoBackend(t)

	routes := []config.GraphQLRoute{gqlRoute("query-only", func(r *config.GraphQLRoute) {
		r.Match = []config.GraphQLRouteMatch{{OperationType: "query"}}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL)

	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"upgrade requests match with the subscription operation type")
}

func TestGraphQLHandler_Subscription_BackendFailure_Recorded(t *testing.T) {
	metrics := &recordingMetrics{}
	// Backend registered but unreachable (closed server). The client-side
	// upgrade happens BEFORE the backend dial, so the client observes a
	// successful handshake followed by an immediate close.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	handler, _ := newGraphQLTestHandler(t, []config.GraphQLRoute{gqlRoute("sub-dead", nil)}, deadURL,
		WithGraphQLHandlerMetrics(metrics))

	front := httptest.NewServer(handler)
	defer front.Close()

	wsURL := "ws" + strings.TrimPrefix(front.URL, "http") + "/graphql"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		// Handshake succeeded; the connection must be closed by the failed
		// backend dial almost immediately.
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, _, readErr := conn.ReadMessage()
		require.Error(t, readErr, "socket must close after the backend dial fails")
		_ = conn.Close()
	}

	require.Eventually(t, func() bool {
		metrics.mu.Lock()
		defer metrics.mu.Unlock()
		return len(metrics.errors) > 0 &&
			metrics.errors[len(metrics.errors)-1].errorType == graphqlErrSubscription
	}, 5*time.Second, 10*time.Millisecond, "subscription failure must be recorded")
}

// ============================================================================
// Handler construction and plumbing
// ============================================================================

func TestNewGraphQLHandler_RequiresRouterAndProxy(t *testing.T) {
	router := graphqlrouter.New()
	proxy := graphqlproxy.New()

	_, err := NewGraphQLHandler(nil, proxy)
	require.Error(t, err)

	_, err = NewGraphQLHandler(router, nil)
	require.Error(t, err)

	h, err := NewGraphQLHandler(router, proxy)
	require.NoError(t, err)
	assert.NotNil(t, h)
	h.Close()
}

func TestGraphQLHandler_MaxBodySizeOption(t *testing.T) {
	backend := okBackend(t, nil)
	handler, _ := newGraphQLTestHandler(t, []config.GraphQLRoute{gqlRoute("small", nil)}, backend.URL,
		WithGraphQLHandlerMaxBodySize(10))

	rec := postGraphQL(handler, nil) // body is longer than 10 bytes
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

	// Non-positive sizes keep the default.
	h2, _ := newGraphQLTestHandler(t, []config.GraphQLRoute{gqlRoute("dflt", nil)}, backend.URL,
		WithGraphQLHandlerMaxBodySize(0))
	assert.Equal(t, int64(defaultGraphQLMaxBodySize), h2.maxBodySize)
}

func TestGraphQLHandler_ApplyRouteMiddleware_NilSafe(t *testing.T) {
	router := graphqlrouter.New()
	proxy := graphqlproxy.New()
	handler, err := NewGraphQLHandler(router, proxy)
	require.NoError(t, err)
	defer handler.Close()

	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })

	// No middleware manager configured → terminal returned unchanged.
	wrapped := handler.applyRouteMiddleware(terminal, &config.GraphQLRoute{Name: "x"})
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql", nil))
	assert.Equal(t, http.StatusTeapot, rec.Code)

	// Nil route → terminal returned unchanged.
	wrapped = handler.applyRouteMiddleware(terminal, nil)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql", nil))
	assert.Equal(t, http.StatusTeapot, rec.Code)
}

func TestHijackTrackingResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	hw := newHijackTrackingResponseWriter(rec)

	assert.False(t, hw.wroteOrHijacked())

	hw.WriteHeader(http.StatusAccepted)
	assert.True(t, hw.wroteOrHijacked())
	assert.Equal(t, http.StatusAccepted, rec.Code)

	n, err := hw.Write([]byte("x"))
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	// httptest.ResponseRecorder does not implement Hijacker.
	_, _, err = hw.Hijack()
	require.Error(t, err)
}

func TestGraphQLHandler_WriteError_Format(t *testing.T) {
	router := graphqlrouter.New()
	proxy := graphqlproxy.New()
	handler, err := NewGraphQLHandler(router, proxy)
	require.NoError(t, err)
	defer handler.Close()

	rec := httptest.NewRecorder()
	handler.writeError(rec, http.StatusBadRequest, "boom")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.JSONEq(t, `{"errors":[{"message":"boom"}]}`, rec.Body.String())
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}

// ============================================================================
// GraphQLPathDispatcher
// ============================================================================

func TestGraphQLPathDispatcher(t *testing.T) {
	graphql := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })

	tests := []struct {
		name       string
		dispatcher *GraphQLPathDispatcher
		method     string
		path       string
		wantStatus int
	}{
		{"post graphql path → graphql", NewGraphQLPathDispatcher("/graphql", graphql, next),
			http.MethodPost, "/graphql", http.StatusOK},
		{"get graphql path → graphql", NewGraphQLPathDispatcher("/graphql", graphql, next),
			http.MethodGet, "/graphql", http.StatusOK},
		{"options graphql path → graphql", NewGraphQLPathDispatcher("/graphql", graphql, next),
			http.MethodOptions, "/graphql", http.StatusOK},
		{"put graphql path → next", NewGraphQLPathDispatcher("/graphql", graphql, next),
			http.MethodPut, "/graphql", http.StatusBadGateway},
		{"other path → next", NewGraphQLPathDispatcher("/graphql", graphql, next),
			http.MethodPost, "/api/users", http.StatusBadGateway},
		{"nil graphql handler → next", NewGraphQLPathDispatcher("/graphql", nil, next),
			http.MethodPost, "/graphql", http.StatusBadGateway},
		{"empty path defaults to /graphql", NewGraphQLPathDispatcher("", graphql, next),
			http.MethodPost, "/graphql", http.StatusOK},
		{"custom path", NewGraphQLPathDispatcher("/api/gql", graphql, next),
			http.MethodPost, "/api/gql", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader("{}"))
			rec := httptest.NewRecorder()
			tt.dispatcher.ServeHTTP(rec, req)
			assert.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

func TestGraphQLPathFromConfig(t *testing.T) {
	assert.Equal(t, "/graphql", GraphQLPathFromConfig(nil))
	assert.Equal(t, "/graphql", GraphQLPathFromConfig(&config.GatewayConfig{}))
	assert.Equal(t, "/custom", GraphQLPathFromConfig(&config.GatewayConfig{
		Spec: config.GatewaySpec{GraphQL: &config.GraphQLConfig{Path: "/custom"}},
	}))
}

// ============================================================================
// Global middleware composition proof: dispatcher inside the chain
// ============================================================================

// TestGraphQLDispatcher_GlobalMiddlewareApplies proves that middleware
// wrapped AROUND the dispatcher (as cmd/gateway composes the global chain)
// now runs for GraphQL endpoint requests.
func TestGraphQLDispatcher_GlobalMiddlewareApplies(t *testing.T) {
	backend := okBackend(t, nil)
	handler, _ := newGraphQLTestHandler(t, []config.GraphQLRoute{gqlRoute("global", nil)}, backend.URL)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	dispatcher := NewGraphQLPathDispatcher("/graphql", handler, next)

	var globalSaw bool
	global := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		globalSaw = true
		if r.Header.Get("X-Block") == "yes" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		dispatcher.ServeHTTP(w, r)
	})

	// Global middleware observes and can reject GraphQL traffic.
	rec := postGraphQL(global, map[string]string{"X-Block": "yes"})
	assert.True(t, globalSaw)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// And passes it through to the GraphQL pipeline otherwise.
	rec = postGraphQL(global, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestGraphQLHandler_ChainCacheScopedName verifies the middleware chain is
// cached under the graphql-scoped name inside the shared manager.
func TestGraphQLHandler_ChainCacheScopedName(t *testing.T) {
	backend := okBackend(t, nil)
	routes := []config.GraphQLRoute{gqlRoute("scoped", func(r *config.GraphQLRoute) {
		r.CORS = &config.CORSConfig{AllowOrigins: []string{"*"}}
	})}
	handler, mgr := newGraphQLTestHandler(t, routes, backend.URL)

	rec := postGraphQL(handler, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	mgr.mu.RLock()
	_, scoped := mgr.middlewareCache[graphqlChainScope+"scoped"]
	_, unscoped := mgr.middlewareCache["scoped"]
	mgr.mu.RUnlock()
	assert.True(t, scoped, "chain must be cached under the graphql-scoped name")
	assert.False(t, unscoped, "chain must not collide with HTTP route names")
}

// TestGraphQLHandler_AggregateRoute verifies aggregate-enabled routes are
// fanned out through the aggregator and wrapped by route middleware.
func TestGraphQLHandler_AggregateRoute(t *testing.T) {
	backend := okBackend(t, nil)

	agg := &stubGraphQLAggregator{}
	routes := []config.GraphQLRoute{gqlRoute("agg-route", func(r *config.GraphQLRoute) {
		r.Aggregate = &config.AggregateConfig{
			Enabled: true,
			Targets: []config.AggregateTarget{{Name: "t1"}},
		}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL,
		WithGraphQLHandlerAggregator(agg))

	rec := postGraphQL(handler, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, agg.called, "aggregate handler must be invoked for aggregate routes")
}

func TestGraphQLHandler_AggregateRoute_Error502(t *testing.T) {
	backend := okBackend(t, nil)

	agg := &stubGraphQLAggregator{err: fmt.Errorf("fan-out exploded")}
	routes := []config.GraphQLRoute{gqlRoute("agg-err", func(r *config.GraphQLRoute) {
		r.Aggregate = &config.AggregateConfig{
			Enabled: true,
			Targets: []config.AggregateTarget{{Name: "t1"}},
		}
	})}
	handler, _ := newGraphQLTestHandler(t, routes, backend.URL,
		WithGraphQLHandlerAggregator(agg))

	rec := postGraphQL(handler, nil)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Contains(t, rec.Body.String(), "aggregate error")
}

// stubGraphQLAggregator is a test double for GraphQLAggregateHandler.
type stubGraphQLAggregator struct {
	called bool
	err    error
}

func (s *stubGraphQLAggregator) ServeAggregate(
	w http.ResponseWriter, _ *http.Request, _ *config.AggregateConfig,
) error {
	s.called = true
	if s.err != nil {
		return s.err
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"data":{}}`))
	return nil
}
