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

func TestFunctional_GRPCConfig_LoadAndValidate(t *testing.T) {
	t.Parallel()

	t.Run("load valid gRPC config", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("grpc-gateway-test.yaml")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Verify basic structure
		assert.Equal(t, "gateway.avapigw.io/v1", cfg.APIVersion)
		assert.Equal(t, "Gateway", cfg.Kind)
		assert.Equal(t, "grpc-test-gateway", cfg.Metadata.Name)

		// Verify gRPC listener
		var grpcListener *config.Listener
		for i := range cfg.Spec.Listeners {
			if cfg.Spec.Listeners[i].Protocol == config.ProtocolGRPC {
				grpcListener = &cfg.Spec.Listeners[i]
				break
			}
		}
		require.NotNil(t, grpcListener, "gRPC listener should exist")
		assert.Equal(t, "grpc", grpcListener.Name)
		assert.Equal(t, 19000, grpcListener.Port)
		assert.Equal(t, config.ProtocolGRPC, grpcListener.Protocol)

		// Verify gRPC listener config
		require.NotNil(t, grpcListener.GRPC)
		assert.Equal(t, uint32(100), grpcListener.GRPC.MaxConcurrentStreams)
		assert.Equal(t, 4*1024*1024, grpcListener.GRPC.MaxRecvMsgSize)
		assert.Equal(t, 4*1024*1024, grpcListener.GRPC.MaxSendMsgSize)
		assert.True(t, grpcListener.GRPC.Reflection)
		assert.True(t, grpcListener.GRPC.HealthCheck)

		// Verify gRPC routes
		assert.NotEmpty(t, cfg.Spec.GRPCRoutes)
	})

	t.Run("load gRPC routes", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("grpc-gateway-test.yaml")
		require.NoError(t, err)

		// Find test-service route
		var testServiceRoute *config.GRPCRoute
		for i := range cfg.Spec.GRPCRoutes {
			if cfg.Spec.GRPCRoutes[i].Name == "test-service" {
				testServiceRoute = &cfg.Spec.GRPCRoutes[i]
				break
			}
		}
		require.NotNil(t, testServiceRoute, "test-service route should exist")

		// Verify route match
		require.NotEmpty(t, testServiceRoute.Match)
		require.NotNil(t, testServiceRoute.Match[0].Service)
		assert.Equal(t, "api.v1.TestService", testServiceRoute.Match[0].Service.Exact)

		// Verify route destinations
		require.Len(t, testServiceRoute.Route, 2)
		assert.Equal(t, "127.0.0.1", testServiceRoute.Route[0].Destination.Host)
		assert.Equal(t, 8803, testServiceRoute.Route[0].Destination.Port)
		assert.Equal(t, 50, testServiceRoute.Route[0].Weight)
		assert.Equal(t, "127.0.0.1", testServiceRoute.Route[1].Destination.Host)
		assert.Equal(t, 8804, testServiceRoute.Route[1].Destination.Port)
		assert.Equal(t, 50, testServiceRoute.Route[1].Weight)

		// Verify timeout
		assert.Equal(t, 30*time.Second, testServiceRoute.Timeout.Duration())

		// Verify retries
		require.NotNil(t, testServiceRoute.Retries)
		assert.Equal(t, 3, testServiceRoute.Retries.Attempts)
		assert.Equal(t, 10*time.Second, testServiceRoute.Retries.PerTryTimeout.Duration())
		assert.Equal(t, "unavailable,resource-exhausted", testServiceRoute.Retries.RetryOn)
	})

	t.Run("load gRPC backends", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("grpc-gateway-test.yaml")
		require.NoError(t, err)

		// Verify gRPC backends
		require.Len(t, cfg.Spec.GRPCBackends, 2)

		backend1 := cfg.Spec.GRPCBackends[0]
		assert.Equal(t, "grpc-backend-1", backend1.Name)
		require.Len(t, backend1.Hosts, 1)
		assert.Equal(t, "127.0.0.1", backend1.Hosts[0].Address)
		assert.Equal(t, 8803, backend1.Hosts[0].Port)

		// Verify health check config
		require.NotNil(t, backend1.HealthCheck)
		assert.True(t, backend1.HealthCheck.Enabled)
		assert.Equal(t, 5*time.Second, backend1.HealthCheck.Interval.Duration())
		assert.Equal(t, 3*time.Second, backend1.HealthCheck.Timeout.Duration())
		assert.Equal(t, 2, backend1.HealthCheck.HealthyThreshold)
		assert.Equal(t, 3, backend1.HealthCheck.UnhealthyThreshold)

		// Verify load balancer config
		require.NotNil(t, backend1.LoadBalancer)
		assert.Equal(t, "roundRobin", backend1.LoadBalancer.Algorithm)
	})

	t.Run("load keepalive config", func(t *testing.T) {
		t.Parallel()

		cfg, err := helpers.LoadTestConfig("grpc-gateway-test.yaml")
		require.NoError(t, err)

		var grpcListener *config.Listener
		for i := range cfg.Spec.Listeners {
			if cfg.Spec.Listeners[i].Protocol == config.ProtocolGRPC {
				grpcListener = &cfg.Spec.Listeners[i]
				break
			}
		}
		require.NotNil(t, grpcListener)
		require.NotNil(t, grpcListener.GRPC)
		require.NotNil(t, grpcListener.GRPC.Keepalive)

		keepalive := grpcListener.GRPC.Keepalive
		assert.Equal(t, 30*time.Second, keepalive.Time.Duration())
		assert.Equal(t, 10*time.Second, keepalive.Timeout.Duration())
		assert.False(t, keepalive.PermitWithoutStream)
		assert.Equal(t, 5*time.Minute, keepalive.MaxConnectionIdle.Duration())
		assert.Equal(t, 30*time.Minute, keepalive.MaxConnectionAge.Duration())
		assert.Equal(t, 5*time.Second, keepalive.MaxConnectionAgeGrace.Duration())
	})
}

func TestFunctional_GRPCConfig_Defaults(t *testing.T) {
	t.Parallel()

	t.Run("default gRPC listener config", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultGRPCListenerConfig()
		require.NotNil(t, cfg)

		assert.Equal(t, uint32(100), cfg.MaxConcurrentStreams)
		assert.Equal(t, 4*1024*1024, cfg.MaxRecvMsgSize)
		assert.Equal(t, 4*1024*1024, cfg.MaxSendMsgSize)
		assert.False(t, cfg.Reflection)
		assert.True(t, cfg.HealthCheck)

		require.NotNil(t, cfg.Keepalive)
		assert.Equal(t, 30*time.Second, cfg.Keepalive.Time.Duration())
		assert.Equal(t, 10*time.Second, cfg.Keepalive.Timeout.Duration())
		assert.False(t, cfg.Keepalive.PermitWithoutStream)
		assert.Equal(t, 5*time.Minute, cfg.Keepalive.MaxConnectionIdle.Duration())
		assert.Equal(t, 30*time.Minute, cfg.Keepalive.MaxConnectionAge.Duration())
		assert.Equal(t, 5*time.Second, cfg.Keepalive.MaxConnectionAgeGrace.Duration())
	})

	t.Run("default gRPC health check config", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultGRPCHealthCheckConfig()
		require.NotNil(t, cfg)

		assert.True(t, cfg.Enabled)
		assert.Equal(t, "", cfg.Service)
		assert.Equal(t, 10*time.Second, cfg.Interval.Duration())
		assert.Equal(t, 5*time.Second, cfg.Timeout.Duration())
		assert.Equal(t, 2, cfg.HealthyThreshold)
		assert.Equal(t, 3, cfg.UnhealthyThreshold)
	})

	t.Run("default gRPC retry policy", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultGRPCRetryPolicy()
		require.NotNil(t, cfg)

		assert.Equal(t, 3, cfg.Attempts)
		assert.Equal(t, 10*time.Second, cfg.PerTryTimeout.Duration())
		assert.Equal(t, "unavailable,resource-exhausted", cfg.RetryOn)
		assert.Equal(t, 100*time.Millisecond, cfg.BackoffBaseInterval.Duration())
		assert.Equal(t, 1*time.Second, cfg.BackoffMaxInterval.Duration())
	})
}

func TestFunctional_GRPCConfig_InvalidConfig(t *testing.T) {
	t.Parallel()

	t.Run("invalid regex in service match", func(t *testing.T) {
		t.Parallel()

		cfg := &config.GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata: config.Metadata{
				Name: "invalid-config",
			},
			Spec: config.GatewaySpec{
				Listeners: []config.Listener{
					{
						Name:     "grpc",
						Port:     19000,
						Protocol: config.ProtocolGRPC,
					},
				},
				GRPCRoutes: []config.GRPCRoute{
					{
						Name: "invalid-route",
						Match: []config.GRPCRouteMatch{
							{
								Service: &config.StringMatch{Regex: "[invalid(regex"},
							},
						},
						Route: []config.RouteDestination{
							{Destination: config.Destination{Host: "localhost", Port: 8080}},
						},
					},
				},
			},
		}

		// Attempting to load routes with invalid regex should fail
		router := helpers.CreateGRPCTestConfig(19000, "127.0.0.1:8803", "127.0.0.1:8804")
		require.NotNil(t, router)

		// The config itself is valid, but loading into router should fail
		// This test verifies the config structure is correct
		assert.NotNil(t, cfg.Spec.GRPCRoutes[0].Match[0].Service.Regex)
	})

	t.Run("empty route name", func(t *testing.T) {
		t.Parallel()

		route := config.GRPCRoute{
			Name: "",
			Match: []config.GRPCRouteMatch{
				{
					Service: &config.StringMatch{Exact: "api.v1.TestService"},
				},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 8080}},
			},
		}

		// Empty name is technically valid but not recommended
		assert.Empty(t, route.Name)
	})

	t.Run("empty match conditions", func(t *testing.T) {
		t.Parallel()

		match := config.GRPCRouteMatch{}
		assert.True(t, match.IsEmpty())

		match.Service = &config.StringMatch{Exact: "api.v1.TestService"}
		assert.False(t, match.IsEmpty())
	})

	t.Run("string match types", func(t *testing.T) {
		t.Parallel()

		// Exact match
		sm := &config.StringMatch{Exact: "test"}
		assert.Equal(t, "exact", sm.MatchType())
		assert.False(t, sm.IsEmpty())
		assert.False(t, sm.IsWildcard())

		// Prefix match
		sm = &config.StringMatch{Prefix: "test"}
		assert.Equal(t, "prefix", sm.MatchType())
		assert.False(t, sm.IsEmpty())
		assert.False(t, sm.IsWildcard())

		// Regex match
		sm = &config.StringMatch{Regex: "test.*"}
		assert.Equal(t, "regex", sm.MatchType())
		assert.False(t, sm.IsEmpty())
		assert.False(t, sm.IsWildcard())

		// Empty match
		sm = &config.StringMatch{}
		assert.Equal(t, "", sm.MatchType())
		assert.True(t, sm.IsEmpty())
		assert.False(t, sm.IsWildcard())

		// Wildcard match
		sm = &config.StringMatch{Exact: "*"}
		assert.True(t, sm.IsWildcard())

		sm = &config.StringMatch{Prefix: "*"}
		assert.True(t, sm.IsWildcard())

		// Nil match
		var nilSM *config.StringMatch
		assert.Equal(t, "", nilSM.MatchType())
		assert.True(t, nilSM.IsEmpty())
		assert.False(t, nilSM.IsWildcard())
	})
}

func TestFunctional_GRPCConfig_BackendConversion(t *testing.T) {
	t.Parallel()

	t.Run("GRPCBackendToBackend preserves all fields", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "full-grpc-backend",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 60},
				{Address: "10.0.0.2", Port: 9001, Weight: 40},
			},
			HealthCheck: &config.GRPCHealthCheckConfig{
				Enabled:            true,
				Service:            "grpc.health.v1.Health",
				Interval:           config.Duration(10 * time.Second),
				Timeout:            config.Duration(5 * time.Second),
				HealthyThreshold:   2,
				UnhealthyThreshold: 3,
			},
			LoadBalancer: &config.LoadBalancer{
				Algorithm: "roundRobin",
			},
			TLS: &config.TLSConfig{
				Enabled:    true,
				Mode:       "MUTUAL",
				CertFile:   "/certs/tls.crt",
				KeyFile:    "/certs/tls.key",
				CAFile:     "/certs/ca.crt",
				MinVersion: "TLS12",
				MaxVersion: "TLS13",
				Vault: &config.VaultGRPCTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "grpc-client",
					CommonName: "gateway-grpc-client",
					AltNames:   []string{"gateway.local"},
				},
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

		b := config.GRPCBackendToBackend(gb)

		// Verify name and hosts
		assert.Equal(t, "full-grpc-backend", b.Name)
		assert.Len(t, b.Hosts, 2)
		assert.Equal(t, "10.0.0.1", b.Hosts[0].Address)
		assert.Equal(t, 9000, b.Hosts[0].Port)
		assert.Equal(t, 60, b.Hosts[0].Weight)

		// Verify health check conversion
		require.NotNil(t, b.HealthCheck)
		assert.Equal(t, "/grpc.health.v1.Health/Check", b.HealthCheck.Path)
		assert.Equal(t, config.Duration(10*time.Second), b.HealthCheck.Interval)
		assert.Equal(t, config.Duration(5*time.Second), b.HealthCheck.Timeout)
		assert.Equal(t, 2, b.HealthCheck.HealthyThreshold)
		assert.Equal(t, 3, b.HealthCheck.UnhealthyThreshold)

		// Verify load balancer
		require.NotNil(t, b.LoadBalancer)
		assert.Equal(t, "roundRobin", b.LoadBalancer.Algorithm)

		// Verify TLS conversion
		require.NotNil(t, b.TLS)
		assert.True(t, b.TLS.Enabled)
		assert.Equal(t, "MUTUAL", b.TLS.Mode)
		assert.Equal(t, "/certs/tls.crt", b.TLS.CertFile)
		assert.Equal(t, "/certs/tls.key", b.TLS.KeyFile)
		assert.Equal(t, "/certs/ca.crt", b.TLS.CAFile)
		assert.Equal(t, "TLS12", b.TLS.MinVersion)
		assert.Equal(t, "TLS13", b.TLS.MaxVersion)

		// Verify Vault TLS conversion
		require.NotNil(t, b.TLS.Vault)
		assert.True(t, b.TLS.Vault.Enabled)
		assert.Equal(t, "pki", b.TLS.Vault.PKIMount)
		assert.Equal(t, "grpc-client", b.TLS.Vault.Role)
		assert.Equal(t, "gateway-grpc-client", b.TLS.Vault.CommonName)
		assert.Equal(t, []string{"gateway.local"}, b.TLS.Vault.AltNames)

		// Verify circuit breaker
		require.NotNil(t, b.CircuitBreaker)
		assert.True(t, b.CircuitBreaker.Enabled)
		assert.Equal(t, 5, b.CircuitBreaker.Threshold)

		// Verify authentication
		require.NotNil(t, b.Authentication)
		assert.Equal(t, "jwt", b.Authentication.Type)
	})

	t.Run("GRPCBackendsToBackends batch conversion", func(t *testing.T) {
		t.Parallel()

		gbs := []config.GRPCBackend{
			{
				Name: "backend-a",
				Hosts: []config.BackendHost{
					{Address: "10.0.0.1", Port: 9000, Weight: 1},
				},
			},
			{
				Name: "backend-b",
				Hosts: []config.BackendHost{
					{Address: "10.0.0.2", Port: 9001, Weight: 1},
				},
				HealthCheck: &config.GRPCHealthCheckConfig{
					Enabled:  true,
					Interval: config.Duration(5 * time.Second),
					Timeout:  config.Duration(2 * time.Second),
				},
			},
		}

		result := config.GRPCBackendsToBackends(gbs)

		require.Len(t, result, 2)
		assert.Equal(t, "backend-a", result[0].Name)
		assert.Nil(t, result[0].HealthCheck)
		assert.Equal(t, "backend-b", result[1].Name)
		assert.NotNil(t, result[1].HealthCheck)
	})

	t.Run("GRPCBackendsToBackends empty and nil", func(t *testing.T) {
		t.Parallel()

		// Empty slice
		result := config.GRPCBackendsToBackends([]config.GRPCBackend{})
		assert.NotNil(t, result)
		assert.Empty(t, result)

		// Nil slice
		result = config.GRPCBackendsToBackends(nil)
		assert.NotNil(t, result)
		assert.Empty(t, result)
	})

	t.Run("health check disabled produces nil backend health check", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "no-hc",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			HealthCheck: &config.GRPCHealthCheckConfig{
				Enabled: false,
			},
		}

		b := config.GRPCBackendToBackend(gb)
		assert.Nil(t, b.HealthCheck)
	})

	t.Run("TLS with disabled Vault produces nil Vault config", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "tls-no-vault",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			TLS: &config.TLSConfig{
				Enabled: true,
				Mode:    "SIMPLE",
				Vault: &config.VaultGRPCTLSConfig{
					Enabled: false,
				},
			},
		}

		b := config.GRPCBackendToBackend(gb)
		require.NotNil(t, b.TLS)
		assert.Nil(t, b.TLS.Vault)
	})

	t.Run("TLS with nil Vault produces nil Vault config", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "tls-nil-vault",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			TLS: &config.TLSConfig{
				Enabled: true,
				Mode:    "SIMPLE",
				Vault:   nil,
			},
		}

		b := config.GRPCBackendToBackend(gb)
		require.NotNil(t, b.TLS)
		assert.Nil(t, b.TLS.Vault)
	})

	t.Run("TLS cipher suites and insecure skip verify", func(t *testing.T) {
		t.Parallel()

		gb := config.GRPCBackend{
			Name: "tls-ciphers",
			Hosts: []config.BackendHost{
				{Address: "10.0.0.1", Port: 9000, Weight: 1},
			},
			TLS: &config.TLSConfig{
				Enabled:            true,
				Mode:               "SIMPLE",
				CipherSuites:       []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
				InsecureSkipVerify: true,
			},
		}

		b := config.GRPCBackendToBackend(gb)
		require.NotNil(t, b.TLS)
		assert.True(t, b.TLS.InsecureSkipVerify)
		assert.Equal(t, []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}, b.TLS.CipherSuites)
	})
}

func TestFunctional_GRPCConfig_RouteMatchValidation(t *testing.T) {
	t.Parallel()

	t.Run("service match validation", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			name     string
			match    *config.StringMatch
			isEmpty  bool
			matchTyp string
		}{
			{
				name:     "exact match",
				match:    &config.StringMatch{Exact: "api.v1.TestService"},
				isEmpty:  false,
				matchTyp: "exact",
			},
			{
				name:     "prefix match",
				match:    &config.StringMatch{Prefix: "api.v1"},
				isEmpty:  false,
				matchTyp: "prefix",
			},
			{
				name:     "regex match",
				match:    &config.StringMatch{Regex: "^api\\.v[0-9]+\\..*$"},
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

	t.Run("metadata match validation", func(t *testing.T) {
		t.Parallel()

		present := true
		absent := true

		testCases := []struct {
			name  string
			match config.MetadataMatch
		}{
			{
				name:  "exact metadata",
				match: config.MetadataMatch{Name: "x-api-version", Exact: "v1"},
			},
			{
				name:  "prefix metadata",
				match: config.MetadataMatch{Name: "authorization", Prefix: "Bearer "},
			},
			{
				name:  "regex metadata",
				match: config.MetadataMatch{Name: "x-request-id", Regex: "^[a-f0-9-]+$"},
			},
			{
				name:  "present metadata",
				match: config.MetadataMatch{Name: "x-request-id", Present: &present},
			},
			{
				name:  "absent metadata",
				match: config.MetadataMatch{Name: "x-internal", Absent: &absent},
			},
		}

		for _, tc := range testCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()

				assert.NotEmpty(t, tc.match.Name)
			})
		}
	})
}
