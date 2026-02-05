//go:build functional

// Package operator_test contains functional tests for the ingress controller.
package operator_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/operator/controller"
)

// ============================================================================
// Helper Functions
// ============================================================================

func ptrPathType(pt networkingv1.PathType) *networkingv1.PathType {
	return &pt
}

func ptrString(s string) *string {
	return &s
}

func newBasicIngress(name, namespace string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "backend-svc",
											Port: networkingv1.ServiceBackendPort{
												Number: 8080,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func unmarshalRoute(t *testing.T, routeJSON []byte) config.Route {
	t.Helper()
	var route config.Route
	err := json.Unmarshal(routeJSON, &route)
	require.NoError(t, err, "failed to unmarshal route JSON")
	return route
}

func unmarshalBackend(t *testing.T, backendJSON []byte) config.Backend {
	t.Helper()
	var backend config.Backend
	err := json.Unmarshal(backendJSON, &backend)
	require.NoError(t, err, "failed to unmarshal backend JSON")
	return backend
}

// ============================================================================
// Functional Tests
// ============================================================================

// TestFunctional_IngressConverter_BasicIngress tests converting a basic Ingress
// with a single rule/path to config.Route/Backend.
func TestFunctional_IngressConverter_BasicIngress(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newBasicIngress("basic-ingress", "avapigw-test")

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should produce exactly 1 route and 1 backend
	assert.Len(t, result.Routes, 1, "expected 1 route")
	assert.Len(t, result.Backends, 1, "expected 1 backend")

	// Verify route key format
	expectedRouteKey := "ingress-avapigw-test-basic-ingress-r0-p0"
	routeJSON, ok := result.Routes[expectedRouteKey]
	require.True(t, ok, "expected route key %q", expectedRouteKey)

	route := unmarshalRoute(t, routeJSON)
	assert.Equal(t, expectedRouteKey, route.Name)
	require.Len(t, route.Match, 1)
	require.NotNil(t, route.Match[0].URI)
	assert.Equal(t, "/api", route.Match[0].URI.Prefix)

	// Verify route destination
	require.Len(t, route.Route, 1)
	assert.Equal(t, "backend-svc", route.Route[0].Destination.Host)
	assert.Equal(t, 8080, route.Route[0].Destination.Port)
	assert.Equal(t, 100, route.Route[0].Weight)

	// Verify backend
	expectedBackendKey := "ingress-avapigw-test-basic-ingress-backend-svc-8080"
	backendJSON, ok := result.Backends[expectedBackendKey]
	require.True(t, ok, "expected backend key %q", expectedBackendKey)

	backend := unmarshalBackend(t, backendJSON)
	assert.Equal(t, expectedBackendKey, backend.Name)
	require.Len(t, backend.Hosts, 1)
	assert.Equal(t, "backend-svc", backend.Hosts[0].Address)
	assert.Equal(t, 8080, backend.Hosts[0].Port)

	// No annotations → no extra config
	assert.Nil(t, route.Retries)
	assert.Nil(t, route.RateLimit)
	assert.Nil(t, route.CORS)
	assert.Nil(t, route.TLS)
}

// TestFunctional_IngressConverter_MultipleRules tests converting an Ingress
// with multiple host rules.
func TestFunctional_IngressConverter_MultipleRules(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-rule",
			Namespace: "avapigw-test",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "api.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/v1",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "api-v1",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
								{
									Path:     "/v2",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "api-v2",
											Port: networkingv1.ServiceBackendPort{Number: 8081},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "web.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "web-svc",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.NotNil(t, result)

	// 2 paths in rule 0 + 1 path in rule 1 = 3 routes
	assert.Len(t, result.Routes, 3, "expected 3 routes")
	// 3 distinct backends
	assert.Len(t, result.Backends, 3, "expected 3 backends")

	// Verify route keys
	assert.Contains(t, result.Routes, "ingress-avapigw-test-multi-rule-r0-p0")
	assert.Contains(t, result.Routes, "ingress-avapigw-test-multi-rule-r0-p1")
	assert.Contains(t, result.Routes, "ingress-avapigw-test-multi-rule-r1-p0")

	// Verify first route
	route0 := unmarshalRoute(t, result.Routes["ingress-avapigw-test-multi-rule-r0-p0"])
	require.Len(t, route0.Match, 1)
	assert.Equal(t, "/v1", route0.Match[0].URI.Prefix)

	// Verify second route
	route1 := unmarshalRoute(t, result.Routes["ingress-avapigw-test-multi-rule-r0-p1"])
	require.Len(t, route1.Match, 1)
	assert.Equal(t, "/v2", route1.Match[0].URI.Prefix)

	// Verify third route
	route2 := unmarshalRoute(t, result.Routes["ingress-avapigw-test-multi-rule-r1-p0"])
	require.Len(t, route2.Match, 1)
	assert.Equal(t, "/", route2.Match[0].URI.Prefix)
}

// TestFunctional_IngressConverter_PathTypes tests Exact, Prefix, and
// ImplementationSpecific path types.
func TestFunctional_IngressConverter_PathTypes(t *testing.T) {
	converter := controller.NewIngressConverter()

	tests := []struct {
		name       string
		pathType   networkingv1.PathType
		path       string
		wantPrefix string
		wantExact  string
	}{
		{
			name:       "Prefix path type",
			pathType:   networkingv1.PathTypePrefix,
			path:       "/api/v1",
			wantPrefix: "/api/v1",
		},
		{
			name:      "Exact path type",
			pathType:  networkingv1.PathTypeExact,
			path:      "/api/v1/users",
			wantExact: "/api/v1/users",
		},
		{
			name:       "ImplementationSpecific path type treated as prefix",
			pathType:   networkingv1.PathTypeImplementationSpecific,
			path:       "/custom",
			wantPrefix: "/custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingress := &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "path-type-test",
					Namespace: "avapigw-test",
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     tt.path,
											PathType: ptrPathType(tt.pathType),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc",
													Port: networkingv1.ServiceBackendPort{Number: 80},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			}

			result, err := converter.ConvertIngress(ingress)
			require.NoError(t, err)
			require.Len(t, result.Routes, 1)

			routeJSON := result.Routes["ingress-avapigw-test-path-type-test-r0-p0"]
			route := unmarshalRoute(t, routeJSON)
			require.Len(t, route.Match, 1)
			require.NotNil(t, route.Match[0].URI)

			if tt.wantPrefix != "" {
				assert.Equal(t, tt.wantPrefix, route.Match[0].URI.Prefix)
				assert.Empty(t, route.Match[0].URI.Exact)
			}
			if tt.wantExact != "" {
				assert.Equal(t, tt.wantExact, route.Match[0].URI.Exact)
				assert.Empty(t, route.Match[0].URI.Prefix)
			}
		})
	}
}

// TestFunctional_IngressConverter_DefaultBackend tests converting an Ingress
// with only a defaultBackend (no rules).
func TestFunctional_IngressConverter_DefaultBackend(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-backend",
			Namespace: "avapigw-test",
		},
		Spec: networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "fallback-svc",
					Port: networkingv1.ServiceBackendPort{Number: 80},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should produce 1 default route and 1 default backend
	assert.Len(t, result.Routes, 1)
	assert.Len(t, result.Backends, 1)

	// Verify default route key
	expectedRouteKey := "ingress-avapigw-test-default-backend-default"
	routeJSON, ok := result.Routes[expectedRouteKey]
	require.True(t, ok, "expected default route key %q", expectedRouteKey)

	route := unmarshalRoute(t, routeJSON)
	assert.Equal(t, expectedRouteKey, route.Name)

	// Default route should have catch-all prefix "/"
	require.Len(t, route.Match, 1)
	require.NotNil(t, route.Match[0].URI)
	assert.Equal(t, "/", route.Match[0].URI.Prefix)

	// Verify default backend
	expectedBackendKey := "ingress-avapigw-test-default-backend-default-backend"
	backendJSON, ok := result.Backends[expectedBackendKey]
	require.True(t, ok, "expected default backend key %q", expectedBackendKey)

	backend := unmarshalBackend(t, backendJSON)
	require.Len(t, backend.Hosts, 1)
	assert.Equal(t, "fallback-svc", backend.Hosts[0].Address)
	assert.Equal(t, 80, backend.Hosts[0].Port)
}

// TestFunctional_IngressConverter_TLSAnnotations tests converting an Ingress
// with TLS section and TLS annotations.
func TestFunctional_IngressConverter_TLSAnnotations(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-ingress",
			Namespace: "avapigw-test",
			Annotations: map[string]string{
				controller.AnnotationTLSMinVersion: "TLS12",
				controller.AnnotationTLSMaxVersion: "TLS13",
			},
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"secure.example.com"},
					SecretName: "tls-secret",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "secure.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "secure-svc",
											Port: networkingv1.ServiceBackendPort{Number: 443},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "insecure.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "insecure-svc",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.Routes, 2)

	// Verify TLS route (secure.example.com)
	secureRoute := unmarshalRoute(t, result.Routes["ingress-avapigw-test-tls-ingress-r0-p0"])
	require.NotNil(t, secureRoute.TLS, "TLS host should have TLS config")
	assert.Equal(t, []string{"secure.example.com"}, secureRoute.TLS.SNIHosts)
	assert.Equal(t, "TLS12", secureRoute.TLS.MinVersion)
	assert.Equal(t, "TLS13", secureRoute.TLS.MaxVersion)

	// Verify non-TLS route (insecure.example.com)
	insecureRoute := unmarshalRoute(t, result.Routes["ingress-avapigw-test-tls-ingress-r1-p0"])
	assert.Nil(t, insecureRoute.TLS, "non-TLS host should not have TLS config")
}

// TestFunctional_IngressConverter_TimeoutRetryAnnotations tests timeout,
// retries, and retry-on annotations.
func TestFunctional_IngressConverter_TimeoutRetryAnnotations(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newBasicIngress("timeout-retry", "avapigw-test")
	ingress.Annotations = map[string]string{
		controller.AnnotationTimeout:            "60s",
		controller.AnnotationRetryAttempts:      "5",
		controller.AnnotationRetryPerTryTimeout: "10s",
		controller.AnnotationRetryOn:            "5xx,reset,connect-failure",
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.Routes, 1)

	for _, routeJSON := range result.Routes {
		route := unmarshalRoute(t, routeJSON)

		// Verify timeout
		assert.Equal(t, config.Duration(60*time.Second), route.Timeout)

		// Verify retries
		require.NotNil(t, route.Retries)
		assert.Equal(t, 5, route.Retries.Attempts)
		assert.Equal(t, config.Duration(10*time.Second), route.Retries.PerTryTimeout)
		assert.Equal(t, "5xx,reset,connect-failure", route.Retries.RetryOn)
	}
}

// TestFunctional_IngressConverter_RateLimitAnnotations tests rate-limit-rps
// and rate-limit-burst annotations.
func TestFunctional_IngressConverter_RateLimitAnnotations(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newBasicIngress("rate-limit", "avapigw-test")
	ingress.Annotations = map[string]string{
		controller.AnnotationRateLimitEnabled:   "true",
		controller.AnnotationRateLimitRPS:       "200",
		controller.AnnotationRateLimitBurst:     "50",
		controller.AnnotationRateLimitPerClient: "true",
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.Routes, 1)

	for _, routeJSON := range result.Routes {
		route := unmarshalRoute(t, routeJSON)

		require.NotNil(t, route.RateLimit)
		assert.True(t, route.RateLimit.Enabled)
		assert.Equal(t, 200, route.RateLimit.RequestsPerSecond)
		assert.Equal(t, 50, route.RateLimit.Burst)
		assert.True(t, route.RateLimit.PerClient)
	}

	// Test that rate limit is nil when annotation is not present
	t.Run("no rate limit annotations", func(t *testing.T) {
		ingressNoRL := newBasicIngress("no-rate-limit", "avapigw-test")
		resultNoRL, err := converter.ConvertIngress(ingressNoRL)
		require.NoError(t, err)
		for _, routeJSON := range resultNoRL.Routes {
			route := unmarshalRoute(t, routeJSON)
			assert.Nil(t, route.RateLimit)
		}
	})
}

// TestFunctional_IngressConverter_CORSAnnotations tests CORS annotations.
func TestFunctional_IngressConverter_CORSAnnotations(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newBasicIngress("cors-test", "avapigw-test")
	ingress.Annotations = map[string]string{
		controller.AnnotationCORSAllowOrigins:     "https://example.com, https://app.example.com",
		controller.AnnotationCORSAllowMethods:     "GET, POST, PUT, DELETE",
		controller.AnnotationCORSAllowHeaders:     "Content-Type, Authorization, X-Request-ID",
		controller.AnnotationCORSExposeHeaders:    "X-Request-ID, X-Response-Time",
		controller.AnnotationCORSMaxAge:           "86400",
		controller.AnnotationCORSAllowCredentials: "true",
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.Routes, 1)

	for _, routeJSON := range result.Routes {
		route := unmarshalRoute(t, routeJSON)

		require.NotNil(t, route.CORS)
		assert.Equal(t, []string{"https://example.com", "https://app.example.com"}, route.CORS.AllowOrigins)
		assert.Equal(t, []string{"GET", "POST", "PUT", "DELETE"}, route.CORS.AllowMethods)
		assert.Equal(t, []string{"Content-Type", "Authorization", "X-Request-ID"}, route.CORS.AllowHeaders)
		assert.Equal(t, []string{"X-Request-ID", "X-Response-Time"}, route.CORS.ExposeHeaders)
		assert.Equal(t, 86400, route.CORS.MaxAge)
		assert.True(t, route.CORS.AllowCredentials)
	}

	// Test that CORS is nil when no origins annotation
	t.Run("no CORS annotations", func(t *testing.T) {
		ingressNoCORS := newBasicIngress("no-cors", "avapigw-test")
		resultNoCORS, err := converter.ConvertIngress(ingressNoCORS)
		require.NoError(t, err)
		for _, routeJSON := range resultNoCORS.Routes {
			route := unmarshalRoute(t, routeJSON)
			assert.Nil(t, route.CORS)
		}
	})
}

// TestFunctional_IngressConverter_CircuitBreakerAnnotations tests circuit
// breaker annotations on the backend.
func TestFunctional_IngressConverter_CircuitBreakerAnnotations(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newBasicIngress("cb-test", "avapigw-test")
	ingress.Annotations = map[string]string{
		controller.AnnotationCircuitBreakerEnabled:   "true",
		controller.AnnotationCircuitBreakerThreshold: "10",
		controller.AnnotationCircuitBreakerTimeout:   "30s",
		controller.AnnotationCircuitBreakerHalfOpen:  "5",
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.Backends, 1)

	for _, backendJSON := range result.Backends {
		backend := unmarshalBackend(t, backendJSON)

		require.NotNil(t, backend.CircuitBreaker)
		assert.True(t, backend.CircuitBreaker.Enabled)
		assert.Equal(t, 10, backend.CircuitBreaker.Threshold)
		assert.Equal(t, config.Duration(30*time.Second), backend.CircuitBreaker.Timeout)
		assert.Equal(t, 5, backend.CircuitBreaker.HalfOpenRequests)
	}

	// Also verify health check and load balancer annotations on backend
	t.Run("health check and load balancer annotations", func(t *testing.T) {
		ingressHC := newBasicIngress("hc-lb-test", "avapigw-test")
		ingressHC.Annotations = map[string]string{
			controller.AnnotationHealthCheckPath:               "/healthz",
			controller.AnnotationHealthCheckInterval:           "15s",
			controller.AnnotationHealthCheckTimeout:            "3s",
			controller.AnnotationHealthCheckHealthyThreshold:   "2",
			controller.AnnotationHealthCheckUnhealthyThreshold: "3",
			controller.AnnotationLoadBalancerAlgorithm:         "leastConn",
		}

		resultHC, err := converter.ConvertIngress(ingressHC)
		require.NoError(t, err)

		for _, backendJSON := range resultHC.Backends {
			backend := unmarshalBackend(t, backendJSON)

			require.NotNil(t, backend.HealthCheck)
			assert.Equal(t, "/healthz", backend.HealthCheck.Path)
			assert.Equal(t, config.Duration(15*time.Second), backend.HealthCheck.Interval)
			assert.Equal(t, config.Duration(3*time.Second), backend.HealthCheck.Timeout)
			assert.Equal(t, 2, backend.HealthCheck.HealthyThreshold)
			assert.Equal(t, 3, backend.HealthCheck.UnhealthyThreshold)

			require.NotNil(t, backend.LoadBalancer)
			assert.Equal(t, "leastConn", backend.LoadBalancer.Algorithm)
		}
	})
}

// ============================================================================
// gRPC Ingress Helper Functions
// ============================================================================

func newGRPCIngress(name, namespace string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				controller.AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrString(controller.DefaultIngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/myservice.MyService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "grpc-backend",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func unmarshalGRPCRoute(t *testing.T, routeJSON []byte) config.GRPCRoute {
	t.Helper()
	var route config.GRPCRoute
	err := json.Unmarshal(routeJSON, &route)
	require.NoError(t, err, "failed to unmarshal gRPC route JSON")
	return route
}

func unmarshalGRPCBackend(t *testing.T, backendJSON []byte) config.GRPCBackend {
	t.Helper()
	var backend config.GRPCBackend
	err := json.Unmarshal(backendJSON, &backend)
	require.NoError(t, err, "failed to unmarshal gRPC backend JSON")
	return backend
}

// ============================================================================
// gRPC Ingress Functional Tests
// ============================================================================

// TestFunctional_IngressConverter_GRPCBasicIngress tests converting a basic gRPC Ingress
// with a single rule/path to config.GRPCRoute/GRPCBackend.
func TestFunctional_IngressConverter_GRPCBasicIngress(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newGRPCIngress("basic-grpc-ingress", "avapigw-test")

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should produce exactly 1 gRPC route and 1 gRPC backend (not HTTP)
	assert.Len(t, result.GRPCRoutes, 1, "expected 1 gRPC route")
	assert.Len(t, result.GRPCBackends, 1, "expected 1 gRPC backend")
	assert.Len(t, result.Routes, 0, "expected 0 HTTP routes")
	assert.Len(t, result.Backends, 0, "expected 0 HTTP backends")

	// Verify gRPC route key format
	expectedRouteKey := "ingress-grpc-avapigw-test-basic-grpc-ingress-r0-p0"
	routeJSON, ok := result.GRPCRoutes[expectedRouteKey]
	require.True(t, ok, "expected gRPC route key %q", expectedRouteKey)

	route := unmarshalGRPCRoute(t, routeJSON)
	assert.Equal(t, expectedRouteKey, route.Name)
	require.Len(t, route.Match, 1)

	// Verify authority match from host
	require.NotNil(t, route.Match[0].Authority)
	assert.Equal(t, "grpc.example.com", route.Match[0].Authority.Exact)

	// Verify service match from path
	require.NotNil(t, route.Match[0].Service)
	assert.Equal(t, "myservice.MyService", route.Match[0].Service.Prefix)

	// Verify route destination
	require.Len(t, route.Route, 1)
	assert.Equal(t, "grpc-backend", route.Route[0].Destination.Host)
	assert.Equal(t, 50051, route.Route[0].Destination.Port)
	assert.Equal(t, 100, route.Route[0].Weight)

	// Verify gRPC backend
	expectedBackendKey := "ingress-grpc-avapigw-test-basic-grpc-ingress-grpc-backend-50051"
	backendJSON, ok := result.GRPCBackends[expectedBackendKey]
	require.True(t, ok, "expected gRPC backend key %q", expectedBackendKey)

	backend := unmarshalGRPCBackend(t, backendJSON)
	assert.Equal(t, expectedBackendKey, backend.Name)
	require.Len(t, backend.Hosts, 1)
	assert.Equal(t, "grpc-backend", backend.Hosts[0].Address)
	assert.Equal(t, 50051, backend.Hosts[0].Port)

	// No annotations → no extra config
	assert.Nil(t, route.Retries)
	assert.Nil(t, route.RateLimit)
	assert.Nil(t, route.CORS)
	assert.Nil(t, route.TLS)
}

// TestFunctional_IngressConverter_GRPCWithServiceMethod tests gRPC Ingress
// with explicit service and method annotations.
func TestFunctional_IngressConverter_GRPCWithServiceMethod(t *testing.T) {
	converter := controller.NewIngressConverter()

	tests := []struct {
		name              string
		annotations       map[string]string
		wantServiceExact  string
		wantServicePrefix string
		wantServiceRegex  string
		wantMethodExact   string
		wantMethodPrefix  string
		wantMethodRegex   string
	}{
		{
			name: "exact service and method match",
			annotations: map[string]string{
				controller.AnnotationProtocol:             "grpc",
				controller.AnnotationGRPCService:          "api.v1.UserService",
				controller.AnnotationGRPCServiceMatchType: "exact",
				controller.AnnotationGRPCMethod:           "GetUser",
				controller.AnnotationGRPCMethodMatchType:  "exact",
			},
			wantServiceExact: "api.v1.UserService",
			wantMethodExact:  "GetUser",
		},
		{
			name: "prefix service and method match",
			annotations: map[string]string{
				controller.AnnotationProtocol:             "grpc",
				controller.AnnotationGRPCService:          "api.v1",
				controller.AnnotationGRPCServiceMatchType: "prefix",
				controller.AnnotationGRPCMethod:           "Get",
				controller.AnnotationGRPCMethodMatchType:  "prefix",
			},
			wantServicePrefix: "api.v1",
			wantMethodPrefix:  "Get",
		},
		{
			name: "regex service and method match",
			annotations: map[string]string{
				controller.AnnotationProtocol:             "grpc",
				controller.AnnotationGRPCService:          "api\\.v[0-9]+\\..*",
				controller.AnnotationGRPCServiceMatchType: "regex",
				controller.AnnotationGRPCMethod:           "Get.*",
				controller.AnnotationGRPCMethodMatchType:  "regex",
			},
			wantServiceRegex: "api\\.v[0-9]+\\..*",
			wantMethodRegex:  "Get.*",
		},
		{
			name: "service only (no method)",
			annotations: map[string]string{
				controller.AnnotationProtocol:             "grpc",
				controller.AnnotationGRPCService:          "api.v1.UserService",
				controller.AnnotationGRPCServiceMatchType: "exact",
			},
			wantServiceExact: "api.v1.UserService",
		},
		{
			name: "default match type is prefix",
			annotations: map[string]string{
				controller.AnnotationProtocol:    "grpc",
				controller.AnnotationGRPCService: "api.v1",
				controller.AnnotationGRPCMethod:  "Get",
			},
			wantServicePrefix: "api.v1",
			wantMethodPrefix:  "Get",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ingress := newGRPCIngress("grpc-service-method", "avapigw-test")
			ingress.Annotations = tt.annotations

			result, err := converter.ConvertIngress(ingress)
			require.NoError(t, err)
			require.Len(t, result.GRPCRoutes, 1)

			var route config.GRPCRoute
			for _, routeJSON := range result.GRPCRoutes {
				route = unmarshalGRPCRoute(t, routeJSON)
				break
			}

			require.Len(t, route.Match, 1)
			match := route.Match[0]

			// Verify service match
			if tt.wantServiceExact != "" {
				require.NotNil(t, match.Service)
				assert.Equal(t, tt.wantServiceExact, match.Service.Exact)
			}
			if tt.wantServicePrefix != "" {
				require.NotNil(t, match.Service)
				assert.Equal(t, tt.wantServicePrefix, match.Service.Prefix)
			}
			if tt.wantServiceRegex != "" {
				require.NotNil(t, match.Service)
				assert.Equal(t, tt.wantServiceRegex, match.Service.Regex)
			}

			// Verify method match
			if tt.wantMethodExact != "" {
				require.NotNil(t, match.Method)
				assert.Equal(t, tt.wantMethodExact, match.Method.Exact)
			}
			if tt.wantMethodPrefix != "" {
				require.NotNil(t, match.Method)
				assert.Equal(t, tt.wantMethodPrefix, match.Method.Prefix)
			}
			if tt.wantMethodRegex != "" {
				require.NotNil(t, match.Method)
				assert.Equal(t, tt.wantMethodRegex, match.Method.Regex)
			}
		})
	}
}

// TestFunctional_IngressConverter_GRPCWithRetryAnnotations tests gRPC retry annotations.
func TestFunctional_IngressConverter_GRPCWithRetryAnnotations(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newGRPCIngress("grpc-retry", "avapigw-test")
	ingress.Annotations[controller.AnnotationRetryAttempts] = "5"
	ingress.Annotations[controller.AnnotationRetryPerTryTimeout] = "10s"
	ingress.Annotations[controller.AnnotationGRPCRetryOn] = "unavailable,resource-exhausted"
	ingress.Annotations[controller.AnnotationGRPCBackoffBaseInterval] = "100ms"
	ingress.Annotations[controller.AnnotationGRPCBackoffMaxInterval] = "1s"

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.GRPCRoutes, 1)

	for _, routeJSON := range result.GRPCRoutes {
		route := unmarshalGRPCRoute(t, routeJSON)

		require.NotNil(t, route.Retries)
		assert.Equal(t, 5, route.Retries.Attempts)
		assert.Equal(t, config.Duration(10*time.Second), route.Retries.PerTryTimeout)
		assert.Equal(t, "unavailable,resource-exhausted", route.Retries.RetryOn)
		assert.Equal(t, config.Duration(100*time.Millisecond), route.Retries.BackoffBaseInterval)
		assert.Equal(t, config.Duration(1*time.Second), route.Retries.BackoffMaxInterval)
	}

	// Test fallback to standard retry-on annotation
	t.Run("fallback to standard retry-on", func(t *testing.T) {
		ingressFallback := newGRPCIngress("grpc-retry-fallback", "avapigw-test")
		ingressFallback.Annotations[controller.AnnotationRetryAttempts] = "3"
		ingressFallback.Annotations[controller.AnnotationRetryOn] = "5xx,reset"

		resultFallback, err := converter.ConvertIngress(ingressFallback)
		require.NoError(t, err)

		for _, routeJSON := range resultFallback.GRPCRoutes {
			route := unmarshalGRPCRoute(t, routeJSON)
			require.NotNil(t, route.Retries)
			assert.Equal(t, "5xx,reset", route.Retries.RetryOn)
		}
	})
}

// TestFunctional_IngressConverter_GRPCWithHealthCheck tests gRPC health check annotations.
func TestFunctional_IngressConverter_GRPCWithHealthCheck(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newGRPCIngress("grpc-health", "avapigw-test")
	ingress.Annotations[controller.AnnotationGRPCHealthCheckEnabled] = "true"
	ingress.Annotations[controller.AnnotationGRPCHealthCheckService] = "grpc.health.v1.Health"
	ingress.Annotations[controller.AnnotationGRPCHealthCheckInterval] = "15s"
	ingress.Annotations[controller.AnnotationGRPCHealthCheckTimeout] = "5s"
	ingress.Annotations[controller.AnnotationGRPCHealthCheckHealthyThreshold] = "2"
	ingress.Annotations[controller.AnnotationGRPCHealthCheckUnhealthyThreshold] = "3"

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.GRPCBackends, 1)

	for _, backendJSON := range result.GRPCBackends {
		backend := unmarshalGRPCBackend(t, backendJSON)

		require.NotNil(t, backend.HealthCheck)
		assert.True(t, backend.HealthCheck.Enabled)
		assert.Equal(t, "grpc.health.v1.Health", backend.HealthCheck.Service)
		assert.Equal(t, config.Duration(15*time.Second), backend.HealthCheck.Interval)
		assert.Equal(t, config.Duration(5*time.Second), backend.HealthCheck.Timeout)
		assert.Equal(t, 2, backend.HealthCheck.HealthyThreshold)
		assert.Equal(t, 3, backend.HealthCheck.UnhealthyThreshold)
	}

	// Test disabled health check
	t.Run("disabled health check", func(t *testing.T) {
		ingressDisabled := newGRPCIngress("grpc-health-disabled", "avapigw-test")
		ingressDisabled.Annotations[controller.AnnotationGRPCHealthCheckEnabled] = "false"

		resultDisabled, err := converter.ConvertIngress(ingressDisabled)
		require.NoError(t, err)

		for _, backendJSON := range resultDisabled.GRPCBackends {
			backend := unmarshalGRPCBackend(t, backendJSON)
			require.NotNil(t, backend.HealthCheck)
			assert.False(t, backend.HealthCheck.Enabled)
		}
	})
}

// TestFunctional_IngressConverter_GRPCWithConnectionPool tests gRPC connection pool annotations.
func TestFunctional_IngressConverter_GRPCWithConnectionPool(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newGRPCIngress("grpc-connpool", "avapigw-test")
	ingress.Annotations[controller.AnnotationGRPCMaxIdleConns] = "50"
	ingress.Annotations[controller.AnnotationGRPCMaxConnsPerHost] = "100"
	ingress.Annotations[controller.AnnotationGRPCIdleConnTimeout] = "5m"

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.GRPCBackends, 1)

	for _, backendJSON := range result.GRPCBackends {
		backend := unmarshalGRPCBackend(t, backendJSON)

		require.NotNil(t, backend.ConnectionPool)
		assert.Equal(t, 50, backend.ConnectionPool.MaxIdleConns)
		assert.Equal(t, 100, backend.ConnectionPool.MaxConnsPerHost)
		assert.Equal(t, config.Duration(5*time.Minute), backend.ConnectionPool.IdleConnTimeout)
	}

	// Test partial connection pool config
	t.Run("partial connection pool config", func(t *testing.T) {
		ingressPartial := newGRPCIngress("grpc-connpool-partial", "avapigw-test")
		ingressPartial.Annotations[controller.AnnotationGRPCMaxIdleConns] = "25"

		resultPartial, err := converter.ConvertIngress(ingressPartial)
		require.NoError(t, err)

		for _, backendJSON := range resultPartial.GRPCBackends {
			backend := unmarshalGRPCBackend(t, backendJSON)
			require.NotNil(t, backend.ConnectionPool)
			assert.Equal(t, 25, backend.ConnectionPool.MaxIdleConns)
			assert.Equal(t, 0, backend.ConnectionPool.MaxConnsPerHost)
		}
	})
}

// TestFunctional_IngressConverter_GRPCDefaultBackend tests gRPC Ingress with default backend.
func TestFunctional_IngressConverter_GRPCDefaultBackend(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-default-backend",
			Namespace: "avapigw-test",
			Annotations: map[string]string{
				controller.AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "grpc-fallback-svc",
					Port: networkingv1.ServiceBackendPort{Number: 50051},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should produce 1 default gRPC route and 1 default gRPC backend
	assert.Len(t, result.GRPCRoutes, 1)
	assert.Len(t, result.GRPCBackends, 1)
	assert.Len(t, result.Routes, 0)
	assert.Len(t, result.Backends, 0)

	// Verify default gRPC route key
	expectedRouteKey := "ingress-grpc-avapigw-test-grpc-default-backend-default"
	routeJSON, ok := result.GRPCRoutes[expectedRouteKey]
	require.True(t, ok, "expected default gRPC route key %q", expectedRouteKey)

	route := unmarshalGRPCRoute(t, routeJSON)
	assert.Equal(t, expectedRouteKey, route.Name)

	// Default gRPC route should have catch-all service match
	require.Len(t, route.Match, 1)
	require.NotNil(t, route.Match[0].Service)
	assert.Equal(t, "", route.Match[0].Service.Prefix) // Empty prefix matches all

	// Verify default gRPC backend
	expectedBackendKey := "ingress-grpc-avapigw-test-grpc-default-backend-default-backend"
	backendJSON, ok := result.GRPCBackends[expectedBackendKey]
	require.True(t, ok, "expected default gRPC backend key %q", expectedBackendKey)

	backend := unmarshalGRPCBackend(t, backendJSON)
	require.Len(t, backend.Hosts, 1)
	assert.Equal(t, "grpc-fallback-svc", backend.Hosts[0].Address)
	assert.Equal(t, 50051, backend.Hosts[0].Port)
}

// TestFunctional_IngressConverter_GRPCWithTLS tests gRPC Ingress with TLS configuration.
func TestFunctional_IngressConverter_GRPCWithTLS(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-tls-ingress",
			Namespace: "avapigw-test",
			Annotations: map[string]string{
				controller.AnnotationProtocol:      "grpc",
				controller.AnnotationTLSMinVersion: "TLS12",
				controller.AnnotationTLSMaxVersion: "TLS13",
				controller.AnnotationGRPCService:   "api.v1.SecureService",
				controller.AnnotationGRPCMethod:    "SecureMethod",
				controller.AnnotationRetryAttempts: "3",
				controller.AnnotationGRPCRetryOn:   "unavailable",
			},
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"secure-grpc.example.com"},
					SecretName: "grpc-tls-secret",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "secure-grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "secure-grpc-svc",
											Port: networkingv1.ServiceBackendPort{Number: 443},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "insecure-grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "insecure-grpc-svc",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.GRPCRoutes, 2)

	// Find and verify TLS route (secure-grpc.example.com)
	var secureRoute, insecureRoute config.GRPCRoute
	for key, routeJSON := range result.GRPCRoutes {
		route := unmarshalGRPCRoute(t, routeJSON)
		if route.Match[0].Authority != nil && route.Match[0].Authority.Exact == "secure-grpc.example.com" {
			secureRoute = route
		} else if route.Match[0].Authority != nil && route.Match[0].Authority.Exact == "insecure-grpc.example.com" {
			insecureRoute = route
		}
		_ = key
	}

	// Verify TLS route
	require.NotNil(t, secureRoute.TLS, "TLS host should have TLS config")
	assert.Equal(t, []string{"secure-grpc.example.com"}, secureRoute.TLS.SNIHosts)
	assert.Equal(t, "TLS12", secureRoute.TLS.MinVersion)
	assert.Equal(t, "TLS13", secureRoute.TLS.MaxVersion)

	// Verify non-TLS route
	assert.Nil(t, insecureRoute.TLS, "non-TLS host should not have TLS config")

	// Verify retry config is applied to both
	require.NotNil(t, secureRoute.Retries)
	assert.Equal(t, 3, secureRoute.Retries.Attempts)
	assert.Equal(t, "unavailable", secureRoute.Retries.RetryOn)
}

// TestFunctional_IngressConverter_GRPCWithAllAnnotations tests gRPC Ingress with all supported annotations.
func TestFunctional_IngressConverter_GRPCWithAllAnnotations(t *testing.T) {
	converter := controller.NewIngressConverter()

	ingress := newGRPCIngress("grpc-all-annotations", "avapigw-test")
	ingress.Annotations = map[string]string{
		// Protocol
		controller.AnnotationProtocol: "grpc",

		// Service/Method matching
		controller.AnnotationGRPCService:          "api.v1.UserService",
		controller.AnnotationGRPCServiceMatchType: "exact",
		controller.AnnotationGRPCMethod:           "GetUser",
		controller.AnnotationGRPCMethodMatchType:  "exact",

		// Timeout
		controller.AnnotationTimeout: "60s",

		// Retry
		controller.AnnotationRetryAttempts:           "5",
		controller.AnnotationRetryPerTryTimeout:      "10s",
		controller.AnnotationGRPCRetryOn:             "unavailable,resource-exhausted",
		controller.AnnotationGRPCBackoffBaseInterval: "100ms",
		controller.AnnotationGRPCBackoffMaxInterval:  "1s",

		// Rate limit
		controller.AnnotationRateLimitEnabled:   "true",
		controller.AnnotationRateLimitRPS:       "200",
		controller.AnnotationRateLimitBurst:     "50",
		controller.AnnotationRateLimitPerClient: "true",

		// CORS
		controller.AnnotationCORSAllowOrigins:     "https://example.com",
		controller.AnnotationCORSAllowMethods:     "POST",
		controller.AnnotationCORSAllowHeaders:     "Content-Type,Authorization",
		controller.AnnotationCORSExposeHeaders:    "X-Request-ID",
		controller.AnnotationCORSMaxAge:           "3600",
		controller.AnnotationCORSAllowCredentials: "true",

		// Security
		controller.AnnotationSecurityEnabled:        "true",
		controller.AnnotationSecurityXFrameOptions:  "DENY",
		controller.AnnotationSecurityXContentType:   "nosniff",
		controller.AnnotationSecurityXXSSProtection: "1; mode=block",

		// Encoding
		controller.AnnotationEncodingRequestContentType:  "application/grpc",
		controller.AnnotationEncodingResponseContentType: "application/grpc",

		// Cache
		controller.AnnotationCacheEnabled: "true",
		controller.AnnotationCacheTTL:     "5m",

		// Health check
		controller.AnnotationGRPCHealthCheckEnabled:            "true",
		controller.AnnotationGRPCHealthCheckService:            "grpc.health.v1.Health",
		controller.AnnotationGRPCHealthCheckInterval:           "10s",
		controller.AnnotationGRPCHealthCheckTimeout:            "5s",
		controller.AnnotationGRPCHealthCheckHealthyThreshold:   "2",
		controller.AnnotationGRPCHealthCheckUnhealthyThreshold: "3",

		// Connection pool
		controller.AnnotationGRPCMaxIdleConns:    "50",
		controller.AnnotationGRPCMaxConnsPerHost: "100",
		controller.AnnotationGRPCIdleConnTimeout: "5m",

		// Load balancer
		controller.AnnotationLoadBalancerAlgorithm: "roundRobin",

		// Circuit breaker
		controller.AnnotationCircuitBreakerEnabled:   "true",
		controller.AnnotationCircuitBreakerThreshold: "10",
		controller.AnnotationCircuitBreakerTimeout:   "30s",
		controller.AnnotationCircuitBreakerHalfOpen:  "5",
	}

	result, err := converter.ConvertIngress(ingress)
	require.NoError(t, err)
	require.Len(t, result.GRPCRoutes, 1)
	require.Len(t, result.GRPCBackends, 1)

	// Verify route
	for _, routeJSON := range result.GRPCRoutes {
		route := unmarshalGRPCRoute(t, routeJSON)

		// Match
		require.Len(t, route.Match, 1)
		require.NotNil(t, route.Match[0].Service)
		assert.Equal(t, "api.v1.UserService", route.Match[0].Service.Exact)
		require.NotNil(t, route.Match[0].Method)
		assert.Equal(t, "GetUser", route.Match[0].Method.Exact)

		// Timeout
		assert.Equal(t, config.Duration(60*time.Second), route.Timeout)

		// Retries
		require.NotNil(t, route.Retries)
		assert.Equal(t, 5, route.Retries.Attempts)
		assert.Equal(t, config.Duration(10*time.Second), route.Retries.PerTryTimeout)
		assert.Equal(t, "unavailable,resource-exhausted", route.Retries.RetryOn)
		assert.Equal(t, config.Duration(100*time.Millisecond), route.Retries.BackoffBaseInterval)
		assert.Equal(t, config.Duration(1*time.Second), route.Retries.BackoffMaxInterval)

		// Rate limit
		require.NotNil(t, route.RateLimit)
		assert.True(t, route.RateLimit.Enabled)
		assert.Equal(t, 200, route.RateLimit.RequestsPerSecond)
		assert.Equal(t, 50, route.RateLimit.Burst)
		assert.True(t, route.RateLimit.PerClient)

		// CORS
		require.NotNil(t, route.CORS)
		assert.Equal(t, []string{"https://example.com"}, route.CORS.AllowOrigins)
		assert.Equal(t, []string{"POST"}, route.CORS.AllowMethods)
		assert.Equal(t, []string{"Content-Type", "Authorization"}, route.CORS.AllowHeaders)
		assert.Equal(t, []string{"X-Request-ID"}, route.CORS.ExposeHeaders)
		assert.Equal(t, 3600, route.CORS.MaxAge)
		assert.True(t, route.CORS.AllowCredentials)

		// Security
		require.NotNil(t, route.Security)
		assert.True(t, route.Security.Enabled)
		require.NotNil(t, route.Security.Headers)
		assert.Equal(t, "DENY", route.Security.Headers.XFrameOptions)
		assert.Equal(t, "nosniff", route.Security.Headers.XContentTypeOptions)
		assert.Equal(t, "1; mode=block", route.Security.Headers.XXSSProtection)

		// Encoding
		require.NotNil(t, route.Encoding)
		assert.Equal(t, "application/grpc", route.Encoding.RequestEncoding)
		assert.Equal(t, "application/grpc", route.Encoding.ResponseEncoding)

		// Cache
		require.NotNil(t, route.Cache)
		assert.True(t, route.Cache.Enabled)
		assert.Equal(t, config.Duration(5*time.Minute), route.Cache.TTL)
	}

	// Verify backend
	for _, backendJSON := range result.GRPCBackends {
		backend := unmarshalGRPCBackend(t, backendJSON)

		// Health check
		require.NotNil(t, backend.HealthCheck)
		assert.True(t, backend.HealthCheck.Enabled)
		assert.Equal(t, "grpc.health.v1.Health", backend.HealthCheck.Service)
		assert.Equal(t, config.Duration(10*time.Second), backend.HealthCheck.Interval)
		assert.Equal(t, config.Duration(5*time.Second), backend.HealthCheck.Timeout)
		assert.Equal(t, 2, backend.HealthCheck.HealthyThreshold)
		assert.Equal(t, 3, backend.HealthCheck.UnhealthyThreshold)

		// Connection pool
		require.NotNil(t, backend.ConnectionPool)
		assert.Equal(t, 50, backend.ConnectionPool.MaxIdleConns)
		assert.Equal(t, 100, backend.ConnectionPool.MaxConnsPerHost)
		assert.Equal(t, config.Duration(5*time.Minute), backend.ConnectionPool.IdleConnTimeout)

		// Load balancer
		require.NotNil(t, backend.LoadBalancer)
		assert.Equal(t, "roundRobin", backend.LoadBalancer.Algorithm)

		// Circuit breaker
		require.NotNil(t, backend.CircuitBreaker)
		assert.True(t, backend.CircuitBreaker.Enabled)
		assert.Equal(t, 10, backend.CircuitBreaker.Threshold)
		assert.Equal(t, config.Duration(30*time.Second), backend.CircuitBreaker.Timeout)
		assert.Equal(t, 5, backend.CircuitBreaker.HalfOpenRequests)
	}
}

// ============================================================================
// HTTP Ingress Functional Tests (continued)
// ============================================================================

// TestFunctional_IngressConverter_HeaderManipulation tests request/response
// header add/remove annotations via rewrite, redirect, security, encoding,
// cache, and max sessions annotations.
func TestFunctional_IngressConverter_HeaderManipulation(t *testing.T) {
	converter := controller.NewIngressConverter()

	t.Run("rewrite annotations", func(t *testing.T) {
		ingress := newBasicIngress("rewrite-test", "avapigw-test")
		ingress.Annotations = map[string]string{
			controller.AnnotationRewriteURI:       "/new-path",
			controller.AnnotationRewriteAuthority: "new-host.example.com",
		}

		result, err := converter.ConvertIngress(ingress)
		require.NoError(t, err)

		for _, routeJSON := range result.Routes {
			route := unmarshalRoute(t, routeJSON)
			require.NotNil(t, route.Rewrite)
			assert.Equal(t, "/new-path", route.Rewrite.URI)
			assert.Equal(t, "new-host.example.com", route.Rewrite.Authority)
		}
	})

	t.Run("redirect annotations", func(t *testing.T) {
		ingress := newBasicIngress("redirect-test", "avapigw-test")
		ingress.Annotations = map[string]string{
			controller.AnnotationRedirectURI:    "/new-location",
			controller.AnnotationRedirectCode:   "301",
			controller.AnnotationRedirectScheme: "https",
		}

		result, err := converter.ConvertIngress(ingress)
		require.NoError(t, err)

		for _, routeJSON := range result.Routes {
			route := unmarshalRoute(t, routeJSON)
			require.NotNil(t, route.Redirect)
			assert.Equal(t, "/new-location", route.Redirect.URI)
			assert.Equal(t, 301, route.Redirect.Code)
			assert.Equal(t, "https", route.Redirect.Scheme)
		}
	})

	t.Run("security annotations", func(t *testing.T) {
		ingress := newBasicIngress("security-test", "avapigw-test")
		ingress.Annotations = map[string]string{
			controller.AnnotationSecurityEnabled:        "true",
			controller.AnnotationSecurityXFrameOptions:  "DENY",
			controller.AnnotationSecurityXContentType:   "nosniff",
			controller.AnnotationSecurityXXSSProtection: "1; mode=block",
		}

		result, err := converter.ConvertIngress(ingress)
		require.NoError(t, err)

		for _, routeJSON := range result.Routes {
			route := unmarshalRoute(t, routeJSON)
			require.NotNil(t, route.Security)
			assert.True(t, route.Security.Enabled)
			require.NotNil(t, route.Security.Headers)
			assert.True(t, route.Security.Headers.Enabled)
			assert.Equal(t, "DENY", route.Security.Headers.XFrameOptions)
			assert.Equal(t, "nosniff", route.Security.Headers.XContentTypeOptions)
			assert.Equal(t, "1; mode=block", route.Security.Headers.XXSSProtection)
		}
	})

	t.Run("encoding annotations", func(t *testing.T) {
		ingress := newBasicIngress("encoding-test", "avapigw-test")
		ingress.Annotations = map[string]string{
			controller.AnnotationEncodingRequestContentType:  "application/json",
			controller.AnnotationEncodingResponseContentType: "application/xml",
		}

		result, err := converter.ConvertIngress(ingress)
		require.NoError(t, err)

		for _, routeJSON := range result.Routes {
			route := unmarshalRoute(t, routeJSON)
			require.NotNil(t, route.Encoding)
			assert.Equal(t, "application/json", route.Encoding.RequestEncoding)
			assert.Equal(t, "application/xml", route.Encoding.ResponseEncoding)
		}
	})

	t.Run("cache annotations", func(t *testing.T) {
		ingress := newBasicIngress("cache-test", "avapigw-test")
		ingress.Annotations = map[string]string{
			controller.AnnotationCacheEnabled: "true",
			controller.AnnotationCacheTTL:     "10m",
		}

		result, err := converter.ConvertIngress(ingress)
		require.NoError(t, err)

		for _, routeJSON := range result.Routes {
			route := unmarshalRoute(t, routeJSON)
			require.NotNil(t, route.Cache)
			assert.True(t, route.Cache.Enabled)
			assert.Equal(t, config.Duration(10*time.Minute), route.Cache.TTL)
		}
	})

	t.Run("max sessions annotations", func(t *testing.T) {
		ingress := newBasicIngress("maxsessions-test", "avapigw-test")
		ingress.Annotations = map[string]string{
			controller.AnnotationMaxSessionsEnabled:       "true",
			controller.AnnotationMaxSessionsMaxConcurrent: "500",
			controller.AnnotationMaxSessionsQueueSize:     "100",
			controller.AnnotationMaxSessionsQueueTimeout:  "5s",
		}

		result, err := converter.ConvertIngress(ingress)
		require.NoError(t, err)

		for _, routeJSON := range result.Routes {
			route := unmarshalRoute(t, routeJSON)
			require.NotNil(t, route.MaxSessions)
			assert.True(t, route.MaxSessions.Enabled)
			assert.Equal(t, 500, route.MaxSessions.MaxConcurrent)
			assert.Equal(t, 100, route.MaxSessions.QueueSize)
			assert.Equal(t, config.Duration(5*time.Second), route.MaxSessions.QueueTimeout)
		}
	})

	t.Run("max body size annotation", func(t *testing.T) {
		ingress := newBasicIngress("maxbody-test", "avapigw-test")
		ingress.Annotations = map[string]string{
			controller.AnnotationMaxBodySize: "2097152",
		}

		result, err := converter.ConvertIngress(ingress)
		require.NoError(t, err)

		for _, routeJSON := range result.Routes {
			route := unmarshalRoute(t, routeJSON)
			require.NotNil(t, route.RequestLimits)
			assert.Equal(t, int64(2097152), route.RequestLimits.MaxBodySize)
		}
	})
}
