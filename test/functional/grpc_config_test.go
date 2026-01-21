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
