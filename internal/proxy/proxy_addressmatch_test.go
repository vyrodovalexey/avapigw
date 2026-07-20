package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// newAddressMatchBackend registers a single-host backend in the registry.
func newAddressMatchBackend(
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

// TestReverseProxy_ResolveServiceBackend_Matrix mirrors the gRPC director's
// address-match matrix for the HTTP proxy: destinations referencing a
// backend by literal host:port attach that backend's features exactly like
// name-based destinations do.
func TestReverseProxy_ResolveServiceBackend_Matrix(t *testing.T) {
	t.Parallel()

	t.Run("name match keeps existing behavior", func(t *testing.T) {
		t.Parallel()
		registry := backend.NewRegistry(observability.NopLogger())
		newAddressMatchBackend(t, registry, "items-backend", "10.0.0.1", 8080)
		proxy := NewReverseProxy(router.New(), registry)

		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "items-backend", Port: 9999},
		}
		sb := proxy.resolveServiceBackend("items-route", dest)
		require.NotNil(t, sb)
		assert.Equal(t, "items-backend", sb.Name())
	})

	t.Run("address match attaches backend", func(t *testing.T) {
		t.Parallel()
		registry := backend.NewRegistry(observability.NopLogger())
		newAddressMatchBackend(t, registry, "items-backend", "host.docker.internal", 8080)
		proxy := NewReverseProxy(router.New(), registry)

		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "host.docker.internal", Port: 8080},
		}
		sb := proxy.resolveServiceBackend("items-route", dest)
		require.NotNil(t, sb, "literal-host destination must attach the backend declaring the endpoint")
		assert.Equal(t, "items-backend", sb.Name())
	})

	t.Run("no match returns nil (plain proxy)", func(t *testing.T) {
		t.Parallel()
		registry := backend.NewRegistry(observability.NopLogger())
		newAddressMatchBackend(t, registry, "items-backend", "host.docker.internal", 8080)
		proxy := NewReverseProxy(router.New(), registry)

		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "host.docker.internal", Port: 8081},
		}
		assert.Nil(t, proxy.resolveServiceBackend("items-route", dest))
	})

	t.Run("nil registry returns nil", func(t *testing.T) {
		t.Parallel()
		proxy := NewReverseProxy(router.New(), nil)
		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "host.docker.internal", Port: 8080},
		}
		assert.Nil(t, proxy.resolveServiceBackend("items-route", dest))
	})

	t.Run("ambiguous endpoints resolve deterministically", func(t *testing.T) {
		t.Parallel()
		registry := backend.NewRegistry(observability.NopLogger())
		newAddressMatchBackend(t, registry, "zeta-backend", "10.0.0.9", 8080)
		newAddressMatchBackend(t, registry, "alpha-backend", "10.0.0.9", 8080)
		proxy := NewReverseProxy(router.New(), registry)

		dest := &config.RouteDestination{
			Destination: config.Destination{Host: "10.0.0.9", Port: 8080},
		}
		for i := 0; i < 2; i++ {
			sb := proxy.resolveServiceBackend("ambiguous-route", dest)
			require.NotNil(t, sb)
			assert.Equal(t, "alpha-backend", sb.Name())
		}
	})
}

// TestReverseProxy_AddressMatch_DataPath proves the end-to-end consequence:
// a request routed to a literal host:port destination that matches a
// registered backend flows through that backend (load-balancer host
// selection and release included) and reaches the upstream.
func TestReverseProxy_AddressMatch_DataPath(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"via":"backend"}`))
		}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)

	registry := backend.NewRegistry(observability.NopLogger())
	sb := newAddressMatchBackend(t, registry, "upstream-backend", u.Hostname(), port)
	require.NoError(t, sb.Start(t.Context()))
	defer func() { _ = sb.Stop(t.Context()) }()

	r := router.New()
	require.NoError(t, r.AddRoute(config.Route{
		Name: "literal-dest-route",
		Match: []config.RouteMatch{
			{URI: &config.URIMatch{Prefix: "/items"}},
		},
		Route: []config.RouteDestination{
			{
				// Literal address:port of the backend host — not the name.
				Destination: config.Destination{Host: u.Hostname(), Port: port},
			},
		},
	}))

	proxy := NewReverseProxy(r, registry)

	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"via":"backend"`)
}
