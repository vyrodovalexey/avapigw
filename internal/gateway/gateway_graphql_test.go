package gateway

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	graphqlproxy "github.com/vyrodovalexey/avapigw/internal/graphql/proxy"
	graphqlrouter "github.com/vyrodovalexey/avapigw/internal/graphql/router"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// handleGraphQL Tests
// ============================================================================

func setupGraphQLGateway(t *testing.T, cfg *config.GatewayConfig, backendServer *httptest.Server) (*Gateway, *gin.Engine) {
	t.Helper()

	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	err := router.LoadRoutes(cfg.Spec.GraphQLRoutes)
	require.NoError(t, err)

	proxy := graphqlproxy.New(
		graphqlproxy.WithLogger(observability.NopLogger()),
	)

	if backendServer != nil {
		host := backendServer.Listener.Addr().String()
		parts := strings.Split(host, ":")
		addr := parts[0]
		port := 0
		fmt.Sscanf(parts[1], "%d", &port)

		proxy.UpdateBackends([]config.GraphQLBackend{
			{
				Name:  "test-backend",
				Hosts: []config.BackendHost{{Address: addr, Port: port}},
			},
		})
	}

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGraphQLRouter(router),
		WithGraphQLProxy(proxy),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	gw.engine = engine
	gw.setupRoutes()

	return gw, engine
}

func TestHandleGraphQL_ValidRequest_200(t *testing.T) {
	t.Parallel()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"user":{"name":"test"}}}`))
	}))
	defer backendServer.Close()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	_, engine := setupGraphQLGateway(t, cfg, backendServer)

	body := `{"query":"{ user { name } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "user")
}

func TestHandleGraphQL_OversizedBody_413(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQL: &config.GraphQLConfig{
				MaxBodySize: 50, // Very small limit
			},
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	_, engine := setupGraphQLGateway(t, cfg, nil)

	// Create a body larger than 50 bytes
	largeBody := `{"query":"` + strings.Repeat("a", 100) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Contains(t, w.Body.String(), "request body too large")
}

func TestHandleGraphQL_InvalidJSON_400(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	_, engine := setupGraphQLGateway(t, cfg, nil)

	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader("not valid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid GraphQL request")
}

func TestHandleGraphQL_EmptyQuery_400(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	_, engine := setupGraphQLGateway(t, cfg, nil)

	body := `{"query":""}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "GraphQL query is empty")
}

func TestHandleGraphQL_NoMatchingRoute_404(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "mutation-only",
					Match: []config.GraphQLRouteMatch{
						{OperationType: "mutation"},
					},
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	_, engine := setupGraphQLGateway(t, cfg, nil)

	// Send a query (not a mutation) - should not match
	body := `{"query":"{ user { name } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "no matching GraphQL route")
}

func TestHandleGraphQL_BackendError_502(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "nonexistent-backend"}},
					},
				},
			},
		},
	}

	// Setup with no backend server - the proxy has no backends registered for "nonexistent-backend"
	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	err := router.LoadRoutes(cfg.Spec.GraphQLRoutes)
	require.NoError(t, err)

	proxy := graphqlproxy.New(graphqlproxy.WithLogger(observability.NopLogger()))
	// Don't register any backends - Forward will fail

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGraphQLRouter(router),
		WithGraphQLProxy(proxy),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	gw.engine = engine
	gw.setupRoutes()

	body := `{"query":"{ user { name } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code)
	assert.Contains(t, w.Body.String(), "backend error")
}

func TestHandleGraphQL_ResponseHeaderMultiValue(t *testing.T) {
	t.Parallel()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Set multiple values for Set-Cookie header
		w.Header().Add("Set-Cookie", "session=abc; Path=/")
		w.Header().Add("Set-Cookie", "token=xyz; Path=/")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer backendServer.Close()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	_, engine := setupGraphQLGateway(t, cfg, backendServer)

	body := `{"query":"{ user { name } }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Verify multi-value headers are preserved (Add vs Set)
	cookies := w.Result().Header["Set-Cookie"]
	assert.Len(t, cookies, 2, "expected 2 Set-Cookie headers to be preserved")
}

func TestHandleGraphQL_GET_Method(t *testing.T) {
	t.Parallel()

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer backendServer.Close()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	_, engine := setupGraphQLGateway(t, cfg, backendServer)

	body := `{"query":"{ user { name } }"}`
	req := httptest.NewRequest(http.MethodGet, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleGraphQL_IoCopyErrorPath(t *testing.T) {
	t.Parallel()

	// Create a backend that returns a response with a body that will be read
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer backendServer.Close()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	_, engine := setupGraphQLGateway(t, cfg, backendServer)

	body := `{"query":"{ ok }"}`
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// The io.Copy should succeed normally; this test ensures the path is exercised
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// getGraphQLPath Tests
// ============================================================================

func TestGetGraphQLPath_Default(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, "/graphql", gw.getGraphQLPath())
}

func TestGetGraphQLPath_CustomPath(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQL: &config.GraphQLConfig{
				Path: "/api/graphql",
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, "/api/graphql", gw.getGraphQLPath())
}

func TestGetGraphQLPath_EmptyPath(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQL: &config.GraphQLConfig{
				Path: "",
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, "/graphql", gw.getGraphQLPath())
}

func TestGetGraphQLPath_NilGraphQLConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQL: nil,
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, "/graphql", gw.getGraphQLPath())
}

// ============================================================================
// getGraphQLMaxBodySize Tests
// ============================================================================

func TestGetGraphQLMaxBodySize_Default(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, int64(10*1024*1024), gw.getGraphQLMaxBodySize())
}

func TestGetGraphQLMaxBodySize_CustomSize(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQL: &config.GraphQLConfig{
				MaxBodySize: 5 * 1024 * 1024,
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, int64(5*1024*1024), gw.getGraphQLMaxBodySize())
}

func TestGetGraphQLMaxBodySize_ZeroSize(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQL: &config.GraphQLConfig{
				MaxBodySize: 0,
			},
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	// Zero should fall back to default
	assert.Equal(t, int64(10*1024*1024), gw.getGraphQLMaxBodySize())
}

func TestGetGraphQLMaxBodySize_NilGraphQLConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQL: nil,
		},
	}

	gw, err := New(cfg)
	require.NoError(t, err)

	assert.Equal(t, int64(10*1024*1024), gw.getGraphQLMaxBodySize())
}

// ============================================================================
// WithGraphQLRouter and WithGraphQLProxy Options Tests
// ============================================================================

func TestWithGraphQLRouter(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
	}

	router := graphqlrouter.New()

	gw, err := New(cfg, WithGraphQLRouter(router))
	require.NoError(t, err)

	assert.Same(t, router, gw.graphqlRouter)
}

func TestWithGraphQLProxy(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
	}

	proxy := graphqlproxy.New()

	gw, err := New(cfg, WithGraphQLProxy(proxy))
	require.NoError(t, err)

	assert.Same(t, proxy, gw.graphqlProxy)
}

// ============================================================================
// setupRoutes GraphQL registration branch Tests
// ============================================================================

func TestSetupRoutes_WithGraphQLComponents(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
	}

	router := graphqlrouter.New()
	proxy := graphqlproxy.New()

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGraphQLRouter(router),
		WithGraphQLProxy(proxy),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	gw.engine = gin.New()
	gw.setupRoutes()

	// Verify the engine has routes registered
	routes := gw.engine.Routes()
	foundPost := false
	foundGet := false
	for _, r := range routes {
		if r.Path == "/graphql" && r.Method == "POST" {
			foundPost = true
		}
		if r.Path == "/graphql" && r.Method == "GET" {
			foundGet = true
		}
	}
	assert.True(t, foundPost, "POST /graphql should be registered")
	assert.True(t, foundGet, "GET /graphql should be registered")
}

func TestSetupRoutes_WithCustomGraphQLPath(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQL: &config.GraphQLConfig{
				Path: "/api/v1/graphql",
			},
		},
	}

	router := graphqlrouter.New()
	proxy := graphqlproxy.New()

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGraphQLRouter(router),
		WithGraphQLProxy(proxy),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	gw.engine = gin.New()
	gw.setupRoutes()

	routes := gw.engine.Routes()
	foundCustomPath := false
	for _, r := range routes {
		if r.Path == "/api/v1/graphql" {
			foundCustomPath = true
			break
		}
	}
	assert.True(t, foundCustomPath, "/api/v1/graphql should be registered")
}

func TestSetupRoutes_WithoutGraphQLComponents(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
	}

	gw, err := New(cfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	gw.engine = gin.New()
	gw.setupRoutes()

	// No GraphQL routes should be registered
	routes := gw.engine.Routes()
	for _, r := range routes {
		assert.NotEqual(t, "/graphql", r.Path, "GraphQL route should not be registered without components")
	}
}

func TestSetupRoutes_OnlyRouterNoProxy(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
	}

	router := graphqlrouter.New()

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGraphQLRouter(router),
		// No proxy
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	gw.engine = gin.New()
	gw.setupRoutes()

	// GraphQL routes should NOT be registered without both router and proxy
	routes := gw.engine.Routes()
	for _, r := range routes {
		assert.NotEqual(t, "/graphql", r.Path, "GraphQL route should not be registered without proxy")
	}
}

// ============================================================================
// handleGraphQL - Table-driven comprehensive test
// ============================================================================

func TestHandleGraphQL_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		body           string
		needsBackend   bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "invalid JSON",
			body:           `{invalid`,
			needsBackend:   false,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid GraphQL request",
		},
		{
			name:           "empty query",
			body:           `{"query":""}`,
			needsBackend:   false,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "GraphQL query is empty",
		},
		{
			name:           "missing query field",
			body:           `{"operationName":"Test"}`,
			needsBackend:   false,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "GraphQL query is empty",
		},
	}

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	_, engine := setupGraphQLGateway(t, cfg, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			engine.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			}
		})
	}
}

// ============================================================================
// handleGraphQL - Read body error path
// ============================================================================

func TestHandleGraphQL_ReadBodyError(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	err := router.LoadRoutes(cfg.Spec.GraphQLRoutes)
	require.NoError(t, err)

	proxy := graphqlproxy.New(graphqlproxy.WithLogger(observability.NopLogger()))

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGraphQLRouter(router),
		WithGraphQLProxy(proxy),
	)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	gw.engine = engine
	gw.setupRoutes()

	// Create a request with a body that errors on read
	req := httptest.NewRequest(http.MethodPost, "/graphql", &errorReader{})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "failed to read request body")
}

// errorReader is an io.Reader that always returns an error.
type errorReader struct{}

func (e *errorReader) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("simulated read error")
}

// ============================================================================
// Start with GraphQL components
// ============================================================================

func TestGateway_Start_WithGraphQLComponents(t *testing.T) {
	t.Parallel()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
			},
			GraphQLRoutes: []config.GraphQLRoute{
				{
					Name: "catch-all",
					Route: []config.RouteDestination{
						{Destination: config.Destination{Host: "test-backend"}},
					},
				},
			},
		},
	}

	router := graphqlrouter.New(graphqlrouter.WithRouterLogger(observability.NopLogger()))
	err := router.LoadRoutes(cfg.Spec.GraphQLRoutes)
	require.NoError(t, err)

	proxy := graphqlproxy.New(graphqlproxy.WithLogger(observability.NopLogger()))

	gw, err := New(cfg,
		WithLogger(observability.NopLogger()),
		WithGraphQLRouter(router),
		WithGraphQLProxy(proxy),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = gw.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = gw.Stop(ctx) }()

	assert.True(t, gw.IsRunning())
}
