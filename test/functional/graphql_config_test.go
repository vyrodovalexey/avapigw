//go:build functional
// +build functional

package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestFunctional_GraphQLConfig_LoadAndValidate(t *testing.T) {
	t.Parallel()

	t.Run("load valid GraphQL config", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("graphql-gateway-test.yaml")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Verify basic structure
		assert.Equal(t, "gateway.avapigw.io/v1", cfg.APIVersion)
		assert.Equal(t, "Gateway", cfg.Kind)
		assert.Equal(t, "graphql-test-gateway", cfg.Metadata.Name)

		// Verify HTTP listener
		require.NotEmpty(t, cfg.Spec.Listeners)
		listener := cfg.Spec.Listeners[0]
		assert.Equal(t, "http", listener.Name)
		assert.Equal(t, 18080, listener.Port)
		assert.Equal(t, "HTTP", listener.Protocol)

		// Verify GraphQL routes exist
		assert.NotEmpty(t, cfg.Spec.GraphQLRoutes)
	})

	t.Run("load GraphQL routes", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("graphql-gateway-test.yaml")
		require.NoError(t, err)

		// Find test-graphql route
		var testRoute *config.GraphQLRoute
		for i := range cfg.Spec.GraphQLRoutes {
			if cfg.Spec.GraphQLRoutes[i].Name == "test-graphql" {
				testRoute = &cfg.Spec.GraphQLRoutes[i]
				break
			}
		}
		require.NotNil(t, testRoute, "test-graphql route should exist")

		// Verify route match
		require.NotEmpty(t, testRoute.Match)
		require.NotNil(t, testRoute.Match[0].Path)
		assert.Equal(t, "/graphql", testRoute.Match[0].Path.Exact)

		// Verify route destinations
		require.Len(t, testRoute.Route, 1)
		assert.Equal(t, "127.0.0.1", testRoute.Route[0].Destination.Host)
		assert.Equal(t, 8821, testRoute.Route[0].Destination.Port)
		assert.Equal(t, 100, testRoute.Route[0].Weight)

		// Verify timeout
		assert.Equal(t, 30*time.Second, testRoute.Timeout.Duration())

		// Verify GraphQL-specific fields
		assert.Equal(t, 10, testRoute.DepthLimit)
		assert.Equal(t, 100, testRoute.ComplexityLimit)
		require.NotNil(t, testRoute.IntrospectionEnabled)
		assert.True(t, *testRoute.IntrospectionEnabled)

		// Verify allowed operations
		assert.Contains(t, testRoute.AllowedOperations, "query")
		assert.Contains(t, testRoute.AllowedOperations, "mutation")
	})

	t.Run("load restricted GraphQL route", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("graphql-gateway-test.yaml")
		require.NoError(t, err)

		// Find test-graphql-restricted route
		var restrictedRoute *config.GraphQLRoute
		for i := range cfg.Spec.GraphQLRoutes {
			if cfg.Spec.GraphQLRoutes[i].Name == "test-graphql-restricted" {
				restrictedRoute = &cfg.Spec.GraphQLRoutes[i]
				break
			}
		}
		require.NotNil(t, restrictedRoute, "test-graphql-restricted route should exist")

		// Verify restricted settings
		assert.Equal(t, 5, restrictedRoute.DepthLimit)
		assert.Equal(t, 50, restrictedRoute.ComplexityLimit)
		require.NotNil(t, restrictedRoute.IntrospectionEnabled)
		assert.False(t, *restrictedRoute.IntrospectionEnabled)

		// Verify only query is allowed
		require.Len(t, restrictedRoute.AllowedOperations, 1)
		assert.Equal(t, "query", restrictedRoute.AllowedOperations[0])
	})

	t.Run("load GraphQL backends", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("graphql-gateway-test.yaml")
		require.NoError(t, err)

		// Verify GraphQL backends
		require.Len(t, cfg.Spec.GraphQLBackends, 2)

		backend1 := cfg.Spec.GraphQLBackends[0]
		assert.Equal(t, "graphql-backend-1", backend1.Name)
		require.Len(t, backend1.Hosts, 1)
		assert.Equal(t, "127.0.0.1", backend1.Hosts[0].Address)
		assert.Equal(t, 8821, backend1.Hosts[0].Port)

		// Verify health check config
		require.NotNil(t, backend1.HealthCheck)
		assert.Equal(t, "/health", backend1.HealthCheck.Path)
		assert.Equal(t, 5*time.Second, backend1.HealthCheck.Interval.Duration())
		assert.Equal(t, 3*time.Second, backend1.HealthCheck.Timeout.Duration())
		assert.Equal(t, 2, backend1.HealthCheck.HealthyThreshold)
		assert.Equal(t, 3, backend1.HealthCheck.UnhealthyThreshold)

		// Verify load balancer config
		require.NotNil(t, backend1.LoadBalancer)
		assert.Equal(t, "roundRobin", backend1.LoadBalancer.Algorithm)
	})

	t.Run("load mutation-specific route", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("graphql-gateway-test.yaml")
		require.NoError(t, err)

		// Find test-graphql-mutation route
		var mutationRoute *config.GraphQLRoute
		for i := range cfg.Spec.GraphQLRoutes {
			if cfg.Spec.GraphQLRoutes[i].Name == "test-graphql-mutation" {
				mutationRoute = &cfg.Spec.GraphQLRoutes[i]
				break
			}
		}
		require.NotNil(t, mutationRoute, "test-graphql-mutation route should exist")

		// Verify operation type match
		require.NotEmpty(t, mutationRoute.Match)
		assert.Equal(t, "mutation", mutationRoute.Match[0].OperationType)
		assert.Equal(t, 60*time.Second, mutationRoute.Timeout.Duration())
	})

	t.Run("load header-match route", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("graphql-gateway-test.yaml")
		require.NoError(t, err)

		// Find test-graphql-header-match route
		var headerRoute *config.GraphQLRoute
		for i := range cfg.Spec.GraphQLRoutes {
			if cfg.Spec.GraphQLRoutes[i].Name == "test-graphql-header-match" {
				headerRoute = &cfg.Spec.GraphQLRoutes[i]
				break
			}
		}
		require.NotNil(t, headerRoute, "test-graphql-header-match route should exist")

		// Verify header match
		require.NotEmpty(t, headerRoute.Match)
		require.NotEmpty(t, headerRoute.Match[0].Headers)
		assert.Equal(t, "X-API-Version", headerRoute.Match[0].Headers[0].Name)
		assert.Equal(t, "v2", headerRoute.Match[0].Headers[0].Exact)
	})
}

func TestFunctional_GraphQLConfig_Defaults(t *testing.T) {
	t.Parallel()

	t.Run("default GraphQL route has zero values", func(t *testing.T) {
		t.Parallel()

		route := config.GraphQLRoute{}
		assert.Empty(t, route.Name)
		assert.Empty(t, route.Match)
		assert.Empty(t, route.Route)
		assert.Equal(t, 0, route.DepthLimit)
		assert.Equal(t, 0, route.ComplexityLimit)
		assert.Nil(t, route.IntrospectionEnabled)
		assert.Empty(t, route.AllowedOperations)
	})

	t.Run("default GraphQL backend has zero values", func(t *testing.T) {
		t.Parallel()

		backend := config.GraphQLBackend{}
		assert.Empty(t, backend.Name)
		assert.Empty(t, backend.Hosts)
		assert.Nil(t, backend.HealthCheck)
		assert.Nil(t, backend.LoadBalancer)
		assert.Nil(t, backend.TLS)
		assert.Nil(t, backend.CircuitBreaker)
		assert.Nil(t, backend.Authentication)
	})

	t.Run("GraphQLRouteMatch IsEmpty", func(t *testing.T) {
		t.Parallel()

		// Empty match
		match := config.GraphQLRouteMatch{}
		assert.True(t, match.IsEmpty())

		// Match with path
		match.Path = &config.StringMatch{Exact: "/graphql"}
		assert.False(t, match.IsEmpty())

		// Match with operation type only
		match2 := config.GraphQLRouteMatch{OperationType: "query"}
		assert.False(t, match2.IsEmpty())

		// Match with operation name only
		match3 := config.GraphQLRouteMatch{
			OperationName: &config.StringMatch{Exact: "GetUsers"},
		}
		assert.False(t, match3.IsEmpty())

		// Match with headers only
		match4 := config.GraphQLRouteMatch{
			Headers: []config.HeaderMatchConfig{
				{Name: "X-API-Version", Exact: "v1"},
			},
		}
		assert.False(t, match4.IsEmpty())
	})

	t.Run("GraphQLRoute HasTLSOverride", func(t *testing.T) {
		t.Parallel()

		// No TLS
		route := config.GraphQLRoute{}
		assert.False(t, route.HasTLSOverride())

		// TLS with cert files
		route.TLS = &config.RouteTLSConfig{
			CertFile: "/certs/tls.crt",
			KeyFile:  "/certs/tls.key",
		}
		assert.True(t, route.HasTLSOverride())

		// TLS with Vault
		route2 := config.GraphQLRoute{
			TLS: &config.RouteTLSConfig{
				Vault: &config.VaultTLSConfig{
					Enabled: true,
				},
			},
		}
		assert.True(t, route2.HasTLSOverride())

		// TLS with disabled Vault
		route3 := config.GraphQLRoute{
			TLS: &config.RouteTLSConfig{
				Vault: &config.VaultTLSConfig{
					Enabled: false,
				},
			},
		}
		assert.False(t, route3.HasTLSOverride())
	})

	t.Run("GraphQLRoute GetEffectiveSNIHosts", func(t *testing.T) {
		t.Parallel()

		// No TLS
		route := config.GraphQLRoute{}
		assert.Nil(t, route.GetEffectiveSNIHosts())

		// TLS with SNI hosts
		route.TLS = &config.RouteTLSConfig{
			SNIHosts: []string{"graphql.example.com"},
		}
		assert.Equal(t, []string{"graphql.example.com"}, route.GetEffectiveSNIHosts())

		// TLS with empty SNI hosts
		route2 := config.GraphQLRoute{
			TLS: &config.RouteTLSConfig{
				SNIHosts: []string{},
			},
		}
		assert.Nil(t, route2.GetEffectiveSNIHosts())
	})
}

func TestFunctional_GraphQLConfig_BackendConversion(t *testing.T) {
	t.Parallel()

	t.Run("GraphQLBackendToBackend preserves all fields", func(t *testing.T) {
		t.Parallel()

		gb := config.GraphQLBackend{
			Name: "full-graphql-backend",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8821, Weight: 60},
				{Address: "10.0.0.2", Port: 8822, Weight: 40},
			},
			HealthCheck: &config.HealthCheck{
				Path:               "/health",
				Interval:           config.Duration(10 * time.Second),
				Timeout:            config.Duration(5 * time.Second),
				HealthyThreshold:   2,
				UnhealthyThreshold: 3,
			},
			LoadBalancer: &config.LoadBalancer{
				Algorithm: "roundRobin",
			},
			TLS: &config.BackendTLSConfig{
				Enabled:    true,
				Mode:       "MUTUAL",
				CertFile:   "/certs/tls.crt",
				KeyFile:    "/certs/tls.key",
				CAFile:     "/certs/ca.crt",
				MinVersion: "TLS12",
				MaxVersion: "TLS13",
			},
			CircuitBreaker: &config.CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          config.Duration(30 * time.Second),
				HalfOpenRequests: 3,
			},
			Authentication: &config.BackendAuthConfig{
				Type: "jwt",
				JWT: &config.BackendJWTAuthConfig{
					Enabled:      true,
					TokenSource:  "static",
					StaticToken:  "test-token",
					HeaderName:   "authorization",
					HeaderPrefix: "Bearer",
				},
			},
		}

		b := config.GraphQLBackendToBackend(gb)

		// Verify name and hosts
		assert.Equal(t, "full-graphql-backend", b.Name)
		assert.Len(t, b.Hosts, 2)
		assert.Equal(t, "10.0.0.1", b.Hosts[0].Address)
		assert.Equal(t, 8821, b.Hosts[0].Port)
		assert.Equal(t, 60, b.Hosts[0].Weight)
		assert.Equal(t, "10.0.0.2", b.Hosts[1].Address)
		assert.Equal(t, 8822, b.Hosts[1].Port)
		assert.Equal(t, 40, b.Hosts[1].Weight)

		// Verify health check
		require.NotNil(t, b.HealthCheck)
		assert.Equal(t, "/health", b.HealthCheck.Path)
		assert.Equal(t, config.Duration(10*time.Second), b.HealthCheck.Interval)
		assert.Equal(t, config.Duration(5*time.Second), b.HealthCheck.Timeout)
		assert.Equal(t, 2, b.HealthCheck.HealthyThreshold)
		assert.Equal(t, 3, b.HealthCheck.UnhealthyThreshold)

		// Verify load balancer
		require.NotNil(t, b.LoadBalancer)
		assert.Equal(t, "roundRobin", b.LoadBalancer.Algorithm)

		// Verify TLS
		require.NotNil(t, b.TLS)
		assert.True(t, b.TLS.Enabled)
		assert.Equal(t, "MUTUAL", b.TLS.Mode)
		assert.Equal(t, "/certs/tls.crt", b.TLS.CertFile)
		assert.Equal(t, "/certs/tls.key", b.TLS.KeyFile)
		assert.Equal(t, "/certs/ca.crt", b.TLS.CAFile)
		assert.Equal(t, "TLS12", b.TLS.MinVersion)
		assert.Equal(t, "TLS13", b.TLS.MaxVersion)

		// Verify circuit breaker
		require.NotNil(t, b.CircuitBreaker)
		assert.True(t, b.CircuitBreaker.Enabled)
		assert.Equal(t, 5, b.CircuitBreaker.Threshold)

		// Verify authentication
		require.NotNil(t, b.Authentication)
		assert.Equal(t, "jwt", b.Authentication.Type)
	})

	t.Run("GraphQLBackendsToBackends batch conversion", func(t *testing.T) {
		t.Parallel()

		gbs := []config.GraphQLBackend{
			{
				Name: "backend-a",
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 8821, Weight: 1},
				},
			},
			{
				Name: "backend-b",
				Hosts: []config.BackendHost{
					{Address: "10.0.0.2", Port: 8822, Weight: 1},
				},
				HealthCheck: &config.HealthCheck{
					Path:     "/health",
					Interval: config.Duration(5 * time.Second),
					Timeout:  config.Duration(2 * time.Second),
				},
			},
		}

		result := config.GraphQLBackendsToBackends(gbs)

		require.Len(t, result, 2)
		assert.Equal(t, "backend-a", result[0].Name)
		assert.Nil(t, result[0].HealthCheck)
		assert.Equal(t, "backend-b", result[1].Name)
		assert.NotNil(t, result[1].HealthCheck)
	})

	t.Run("GraphQLBackendsToBackends empty and nil", func(t *testing.T) {
		t.Parallel()

		// Empty slice
		result := config.GraphQLBackendsToBackends([]config.GraphQLBackend{})
		assert.NotNil(t, result)
		assert.Empty(t, result)

		// Nil slice
		result = config.GraphQLBackendsToBackends(nil)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("conversion with nil optional fields", func(t *testing.T) {
		t.Parallel()

		gb := config.GraphQLBackend{
			Name: "minimal-backend",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8821, Weight: 1},
			},
		}

		b := config.GraphQLBackendToBackend(gb)

		assert.Equal(t, "minimal-backend", b.Name)
		assert.Len(t, b.Hosts, 1)
		assert.Nil(t, b.HealthCheck)
		assert.Nil(t, b.LoadBalancer)
		assert.Nil(t, b.TLS)
		assert.Nil(t, b.CircuitBreaker)
		assert.Nil(t, b.Authentication)
	})

	t.Run("conversion preserves TLS with Vault config", func(t *testing.T) {
		t.Parallel()

		gb := config.GraphQLBackend{
			Name: "graphql-vault-tls",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8821, Weight: 1},
			},
			TLS: &config.BackendTLSConfig{
				Enabled:    true,
				Mode:       "MUTUAL",
				MinVersion: "TLS12",
				Vault: &config.VaultBackendTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "graphql-client",
					CommonName: "gateway-graphql-client",
					AltNames:   []string{"gateway.local"},
				},
			},
		}

		b := config.GraphQLBackendToBackend(gb)

		require.NotNil(t, b.TLS)
		assert.True(t, b.TLS.Enabled)
		assert.Equal(t, "MUTUAL", b.TLS.Mode)
		require.NotNil(t, b.TLS.Vault)
		assert.True(t, b.TLS.Vault.Enabled)
		assert.Equal(t, "pki", b.TLS.Vault.PKIMount)
		assert.Equal(t, "graphql-client", b.TLS.Vault.Role)
		assert.Equal(t, "gateway-graphql-client", b.TLS.Vault.CommonName)
		assert.Equal(t, []string{"gateway.local"}, b.TLS.Vault.AltNames)
	})

	t.Run("conversion preserves cipher suites and insecure skip verify", func(t *testing.T) {
		t.Parallel()

		gb := config.GraphQLBackend{
			Name: "graphql-tls-ciphers",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 8821, Weight: 1},
			},
			TLS: &config.BackendTLSConfig{
				Enabled:            true,
				Mode:               "SIMPLE",
				CipherSuites:       []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				InsecureSkipVerify: true,
			},
		}

		b := config.GraphQLBackendToBackend(gb)
		require.NotNil(t, b.TLS)
		assert.True(t, b.TLS.InsecureSkipVerify)
		assert.Equal(t, []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}, b.TLS.CipherSuites)
	})
}

// TestFunctional_GraphQLConfig_RouteIntersectionValidation tests that config
// validation detects overlapping REST and GraphQL routes (TC-CROSS-005).
func TestFunctional_GraphQLConfig_RouteIntersectionValidation(t *testing.T) {
	t.Parallel()

	t.Run("overlapping prefix REST route and exact GraphQL route", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test-gateway"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "rest-route",
						Match: []config.RouteMatch{
							{
								URI: &config.URIMatch{Prefix: "/api"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "rest-backend", Port: 8080},
								Weight:      100,
							},
						},
					},
				},
				GraphQLRoutes: []config.GraphQLRoute{
					{
						Name: "graphql-route",
						Match: []config.GraphQLRouteMatch{
							{
								Path: &config.StringMatch{Exact: "/api/graphql"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "graphql-backend", Port: 8821},
								Weight:      100,
							},
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overlapping")
	})

	t.Run("exact REST route matches exact GraphQL route", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test-gateway"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "rest-route",
						Match: []config.RouteMatch{
							{
								URI: &config.URIMatch{Exact: "/graphql"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "rest-backend", Port: 8080},
								Weight:      100,
							},
						},
					},
				},
				GraphQLRoutes: []config.GraphQLRoute{
					{
						Name: "graphql-route",
						Match: []config.GraphQLRouteMatch{
							{
								Path: &config.StringMatch{Exact: "/graphql"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "graphql-backend", Port: 8821},
								Weight:      100,
							},
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overlapping")
	})

	t.Run("non-overlapping REST and GraphQL routes pass validation", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test-gateway"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "rest-route",
						Match: []config.RouteMatch{
							{
								URI: &config.URIMatch{Prefix: "/api/v1"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "rest-backend", Port: 8080},
								Weight:      100,
							},
						},
					},
				},
				GraphQLRoutes: []config.GraphQLRoute{
					{
						Name: "graphql-route",
						Match: []config.GraphQLRouteMatch{
							{
								Path: &config.StringMatch{Exact: "/graphql"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "graphql-backend", Port: 8821},
								Weight:      100,
							},
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		assert.NoError(t, err)
	})

	t.Run("catch-all REST route conflicts with any GraphQL route", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test-gateway"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name:  "catch-all-route",
						Match: []config.RouteMatch{}, // empty match = catch-all
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "rest-backend", Port: 8080},
								Weight:      100,
							},
						},
					},
				},
				GraphQLRoutes: []config.GraphQLRoute{
					{
						Name: "graphql-route",
						Match: []config.GraphQLRouteMatch{
							{
								Path: &config.StringMatch{Exact: "/graphql"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "graphql-backend", Port: 8821},
								Weight:      100,
							},
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overlapping")
	})

	t.Run("catch-all GraphQL route conflicts with any REST route", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test-gateway"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "rest-route",
						Match: []config.RouteMatch{
							{
								URI: &config.URIMatch{Prefix: "/api/v1"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "rest-backend", Port: 8080},
								Weight:      100,
							},
						},
					},
				},
				GraphQLRoutes: []config.GraphQLRoute{
					{
						Name:  "graphql-catch-all",
						Match: []config.GraphQLRouteMatch{}, // empty match = catch-all
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "graphql-backend", Port: 8821},
								Weight:      100,
							},
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overlapping")
	})

	t.Run("prefix-prefix overlap between REST and GraphQL routes", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test-gateway"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "rest-route",
						Match: []config.RouteMatch{
							{
								URI: &config.URIMatch{Prefix: "/shared"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "rest-backend", Port: 8080},
								Weight:      100,
							},
						},
					},
				},
				GraphQLRoutes: []config.GraphQLRoute{
					{
						Name: "graphql-route",
						Match: []config.GraphQLRouteMatch{
							{
								Path: &config.StringMatch{Prefix: "/shared/graphql"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "graphql-backend", Port: 8821},
								Weight:      100,
							},
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overlapping")
	})

	t.Run("no GraphQL routes means no intersection errors", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test-gateway"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				Routes: []config.Route{
					{
						Name: "rest-route",
						Match: []config.RouteMatch{
							{
								URI: &config.URIMatch{Prefix: "/api"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "rest-backend", Port: 8080},
								Weight:      100,
							},
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		assert.NoError(t, err)
	})

	t.Run("no REST routes means no intersection errors", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   config.Metadata{Name: "test-gateway"},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
				GraphQLRoutes: []config.GraphQLRoute{
					{
						Name: "graphql-route",
						Match: []config.GraphQLRouteMatch{
							{
								Path: &config.StringMatch{Exact: "/graphql"},
							},
						},
						Route: []config.RouteDestination{
							{
								Destination: config.Destination{Host: "graphql-backend", Port: 8821},
								Weight:      100,
							},
						},
					},
				},
			},
		}

		err := config.ValidateConfig(cfg)
		assert.NoError(t, err)
	})
}

func TestFunctional_GraphQLConfig_RouteValidation(t *testing.T) {
	t.Parallel()

	t.Run("path match types", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			name     string
			match    *config.StringMatch
			isEmpty  bool
			matchTyp string
		}{
			{
				name:     "exact path match",
				match:    &config.StringMatch{Exact: "/graphql"},
				isEmpty:  false,
				matchTyp: "exact",
			},
			{
				name:     "prefix path match",
				match:    &config.StringMatch{Prefix: "/graphql"},
				isEmpty:  false,
				matchTyp: "prefix",
			},
			{
				name:     "regex path match",
				match:    &config.StringMatch{Regex: `^/graphql(-v[0-9]+)?$`},
				isEmpty:  false,
				matchTyp: "regex",
			},
			{
				name:     "empty match",
				match:    &config.StringMatch{},
				isEmpty:  true,
				matchTyp: "",
			},
			{
				name:     "nil match",
				match:    nil,
				isEmpty:  true,
				matchTyp: "",
			},
		}

		for _, tc := range testCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				if tc.match == nil {
					assert.True(t, tc.isEmpty)
					return
				}

				assert.Equal(t, tc.isEmpty, tc.match.IsEmpty())
				assert.Equal(t, tc.matchTyp, tc.match.MatchType())
			})
		}
	})

	t.Run("operation type validation", func(t *testing.T) {
		t.Parallel()

		validOps := []string{"query", "mutation", "subscription"}
		for _, op := range validOps {
			match := config.GraphQLRouteMatch{OperationType: op}
			assert.False(t, match.IsEmpty(), "match with operation type %q should not be empty", op)
		}
	})

	t.Run("header match config", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			name   string
			header config.HeaderMatchConfig
		}{
			{
				name:   "exact header match",
				header: config.HeaderMatchConfig{Name: "X-API-Version", Exact: "v1"},
			},
			{
				name:   "prefix header match",
				header: config.HeaderMatchConfig{Name: "Authorization", Prefix: "Bearer "},
			},
			{
				name:   "regex header match",
				header: config.HeaderMatchConfig{Name: "X-Request-ID", Regex: `^[a-f0-9-]+$`},
			},
		}

		for _, tc := range testCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				assert.NotEmpty(t, tc.header.Name)
			})
		}
	})
}
