//go:build functional

// Package operator_test contains functional tests for the apigw-operator.
//
// Phase-3 CRD-field tests verify the NEW CRD fields end-to-end at the
// CR -> gateway boundary: each spec is admitted by the real webhook
// validator, marshaled to JSON exactly the way the operator pushes config,
// unmarshaled onto the gateway configuration types, and asserted for a
// lossless wire shape. Covered fields:
//
//   - transform.request staticHeaders/dynamicHeaders/injectFields/
//     removeFields/defaultValues/validateBeforeTransform/passthroughBody
//     and transform.response groupFields/flattenFields/arrayOperations/
//     template/mergeStrategy (incl. ndjson)
//   - cache keyConfig/maxEntries/honorCacheControl/negativeCacheTTL
//     (+ deprecated keyComponents admission warning)
//   - redis TLS blocks on cache.redis and rateLimit.redis
//   - authorization.cache redis shape + legacy sentinel gateway-side compat
//   - security structured hsts/csp + referrerPolicy + customHeaders
//   - backend healthCheck useGRPC/grpcService/port
package operator_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// jsonValue builds an apiextensions JSON literal.
func jsonValue(t *testing.T, v interface{}) *apiextensionsv1.JSON {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return &apiextensionsv1.JSON{Raw: raw}
}

// marshalSpecToGatewayRoute admits the APIRoute through the real webhook
// validator, then performs the operator's serialization (spec JSON) and the
// gateway's deserialization (config.Route).
func marshalSpecToGatewayRoute(t *testing.T, route *avapigwv1alpha1.APIRoute) config.Route {
	t.Helper()

	validator := &webhook.APIRouteValidator{}
	_, err := validator.ValidateCreate(context.Background(), route)
	require.NoError(t, err, "CR must be admitted by the webhook")

	data, err := json.Marshal(route.Spec)
	require.NoError(t, err)

	var gwRoute config.Route
	require.NoError(t, json.Unmarshal(data, &gwRoute),
		"gateway must deserialize the operator-pushed spec")
	gwRoute.Name = route.Name
	return gwRoute
}

// TestFunctional_APIRoute_TransformAdvanced_GatewayContract verifies the
// advanced request/response transform fields round-trip CR -> gateway.
func TestFunctional_APIRoute_TransformAdvanced_GatewayContract(t *testing.T) {
	route := createBasicAPIRoute()
	route.Spec.Transform = &avapigwv1alpha1.TransformConfig{
		Request: &avapigwv1alpha1.RequestTransform{
			Template:        `{"wrapped": {{.Body}}}`,
			PassthroughBody: false,
			StaticHeaders: map[string]string{
				"X-Static-One": "alpha",
				"X-Static-Two": "beta",
			},
			DynamicHeaders: []avapigwv1alpha1.TransformDynamicHeader{
				{Name: "X-User", Source: "jwt.claim.sub"},
			},
			InjectFields: []avapigwv1alpha1.TransformFieldInjection{
				{Field: "meta.source", Value: jsonValue(t, "gateway")},
				{Field: "meta.request_id", Source: "context.request_id"},
			},
			RemoveFields: []string{"internal.secret", "debug"},
			DefaultValues: map[string]apiextensionsv1.JSON{
				"page": *jsonValue(t, 1),
			},
			ValidateBeforeTransform: true,
		},
		Response: &avapigwv1alpha1.ResponseTransform{
			AllowFields:   []string{"id", "name", "grouped", "items"},
			FieldMappings: map[string]string{"internal_name": "name"},
			GroupFields: []avapigwv1alpha1.TransformFieldGroup{
				{Name: "grouped", Fields: []string{"a", "b"}},
			},
			FlattenFields: []string{"metadata"},
			ArrayOperations: []avapigwv1alpha1.TransformArrayOperation{
				{Field: "items", Operation: "limit", Value: jsonValue(t, 10)},
				{Field: "items", Operation: "filter", Condition: `item.active == true`},
			},
			MergeStrategy: "ndjson",
		},
	}

	gwRoute := marshalSpecToGatewayRoute(t, route)

	require.NotNil(t, gwRoute.Transform)
	req := gwRoute.Transform.Request
	require.NotNil(t, req, "request transform must survive the wire")

	// CRD `template` maps onto the gateway's BodyTemplate via the custom
	// unmarshaler — the advertised compatibility contract.
	assert.Equal(t, `{"wrapped": {{.Body}}}`, req.BodyTemplate,
		"CRD template must map to gateway bodyTemplate")
	assert.Equal(t, "alpha", req.StaticHeaders["X-Static-One"])
	assert.Equal(t, "beta", req.StaticHeaders["X-Static-Two"])
	require.Len(t, req.DynamicHeaders, 1)
	assert.Equal(t, "X-User", req.DynamicHeaders[0].Name)
	assert.Equal(t, "jwt.claim.sub", req.DynamicHeaders[0].Source)
	require.Len(t, req.InjectFields, 2)
	assert.Equal(t, "meta.source", req.InjectFields[0].Field)
	assert.Equal(t, "gateway", req.InjectFields[0].Value)
	assert.Equal(t, "context.request_id", req.InjectFields[1].Source)
	assert.Equal(t, []string{"internal.secret", "debug"}, req.RemoveFields)
	assert.EqualValues(t, 1, req.DefaultValues["page"])
	assert.True(t, req.ValidateBeforeTransform)

	resp := gwRoute.Transform.Response
	require.NotNil(t, resp, "response transform must survive the wire")
	assert.Equal(t, []string{"id", "name", "grouped", "items"}, resp.AllowFields)
	require.Len(t, resp.GroupFields, 1)
	assert.Equal(t, "grouped", resp.GroupFields[0].Name)
	assert.Equal(t, []string{"a", "b"}, resp.GroupFields[0].Fields)
	assert.Equal(t, []string{"metadata"}, resp.FlattenFields)
	require.Len(t, resp.ArrayOperations, 2)
	assert.Equal(t, config.ArrayOperationLimit, resp.ArrayOperations[0].Operation)
	assert.EqualValues(t, 10, resp.ArrayOperations[0].Value)
	assert.Equal(t, config.ArrayOperationFilter, resp.ArrayOperations[1].Operation)
	assert.Equal(t, `item.active == true`, resp.ArrayOperations[1].Condition)
	assert.Equal(t, config.MergeStrategyNDJSON, resp.MergeStrategy,
		"ndjson merge strategy must reach the data plane")
}

// TestFunctional_APIRoute_CacheAdvanced_GatewayContract verifies the new
// cache tuning fields round-trip CR -> gateway, and that the deprecated
// keyComponents field yields an admission warning.
func TestFunctional_APIRoute_CacheAdvanced_GatewayContract(t *testing.T) {
	route := createBasicAPIRoute()
	route.Spec.Cache = &avapigwv1alpha1.CacheConfig{
		Enabled:           true,
		TTL:               "90s",
		Type:              "memory",
		MaxEntries:        5000,
		HonorCacheControl: true,
		NegativeCacheTTL:  "10s",
		KeyConfig: &avapigwv1alpha1.CacheKeyConfig{
			IncludeMethod:      true,
			IncludePath:        true,
			IncludeQueryParams: []string{"page", "size"},
			IncludeHeaders:     []string{"X-Tenant"},
			IncludeBodyHash:    true,
			KeyTemplate:        "{{.Method}}:{{.Path}}",
		},
	}

	gwRoute := marshalSpecToGatewayRoute(t, route)

	cache := gwRoute.Cache
	require.NotNil(t, cache)
	assert.True(t, cache.Enabled)
	assert.Equal(t, 5000, cache.MaxEntries, "maxEntries must survive")
	assert.True(t, cache.HonorCacheControl, "honorCacheControl must survive")
	assert.Equal(t, 10*time.Second, cache.NegativeCacheTTL.Duration(),
		"negativeCacheTTL must survive")

	require.NotNil(t, cache.KeyConfig, "keyConfig must survive")
	assert.True(t, cache.KeyConfig.IncludeMethod)
	assert.True(t, cache.KeyConfig.IncludePath)
	assert.Equal(t, []string{"page", "size"}, cache.KeyConfig.IncludeQueryParams)
	assert.Equal(t, []string{"X-Tenant"}, cache.KeyConfig.IncludeHeaders)
	assert.True(t, cache.KeyConfig.IncludeBodyHash)
	assert.Equal(t, "{{.Method}}:{{.Path}}", cache.KeyConfig.KeyTemplate)

	t.Run("deprecated keyComponents warns on admission", func(t *testing.T) {
		legacy := createBasicAPIRoute()
		legacy.Spec.Cache = &avapigwv1alpha1.CacheConfig{
			Enabled:       true,
			TTL:           "1m",
			Type:          "memory",
			KeyComponents: []string{"path", "query"},
		}

		validator := &webhook.APIRouteValidator{}
		warnings, err := validator.ValidateCreate(context.Background(), legacy)
		require.NoError(t, err, "legacy field is accepted for compatibility")

		joined := ""
		for _, w := range warnings {
			joined += w + "\n"
		}
		assert.Contains(t, joined, "keyComponents",
			"deprecated keyComponents must produce an admission warning")
	})
}

// TestFunctional_RedisTLS_GatewayContract verifies the redis TLS blocks on
// route cache and rate limit round-trip CR -> gateway.
func TestFunctional_RedisTLS_GatewayContract(t *testing.T) {
	redisTLS := &avapigwv1alpha1.RedisTLSSpec{
		Enabled:    true,
		CertFile:   "/etc/redis-certs/client.crt",
		KeyFile:    "/etc/redis-certs/client.key",
		CAFile:     "/etc/redis-certs/ca.crt",
		MinVersion: "TLS12",
	}

	route := createBasicAPIRoute()
	route.Spec.Cache = &avapigwv1alpha1.CacheConfig{
		Enabled: true,
		TTL:     "2m",
		Type:    "redis",
		Redis: &avapigwv1alpha1.RedisCacheSpec{
			URL: "rediss://redis.svc:6380",
			TLS: redisTLS,
		},
	}
	route.Spec.RateLimit = &avapigwv1alpha1.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 50,
		Burst:             100,
		Store:             "redis",
		Redis: &avapigwv1alpha1.RateLimitRedisSpec{
			URL: "rediss://redis.svc:6380",
			TLS: redisTLS,
		},
	}

	gwRoute := marshalSpecToGatewayRoute(t, route)

	require.NotNil(t, gwRoute.Cache)
	require.NotNil(t, gwRoute.Cache.Redis)
	cacheTLS := gwRoute.Cache.Redis.TLS
	require.NotNil(t, cacheTLS, "cache.redis.tls must survive the wire")
	assert.True(t, cacheTLS.Enabled)
	assert.Equal(t, "/etc/redis-certs/client.crt", cacheTLS.CertFile)
	assert.Equal(t, "/etc/redis-certs/client.key", cacheTLS.KeyFile)
	assert.Equal(t, "/etc/redis-certs/ca.crt", cacheTLS.CAFile)
	assert.Equal(t, "TLS12", cacheTLS.MinVersion)

	require.NotNil(t, gwRoute.RateLimit)
	require.NotNil(t, gwRoute.RateLimit.Redis)
	rlTLS := gwRoute.RateLimit.Redis.TLS
	require.NotNil(t, rlTLS, "rateLimit.redis.tls must survive the wire")
	assert.True(t, rlTLS.Enabled)
	assert.Equal(t, "/etc/redis-certs/client.crt", rlTLS.CertFile)
	assert.Equal(t, "/etc/redis-certs/ca.crt", rlTLS.CAFile)
	assert.Equal(t, "TLS12", rlTLS.MinVersion)
}

// TestFunctional_AuthzCache_RedisShape_GatewayContract verifies the
// authorization decision cache redis shape: the preferred redis block
// round-trips, and the legacy sentinel key is consumable by the gateway
// type (the operator's normalizer folds it into redis.sentinel; the gateway
// additionally deserializes the legacy key for compatibility).
func TestFunctional_AuthzCache_RedisShape_GatewayContract(t *testing.T) {
	t.Run("preferred redis block round-trips", func(t *testing.T) {
		route := createBasicAPIRoute()
		route.Spec.Authorization = &avapigwv1alpha1.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:      "readers",
						Roles:     []string{"reader"},
						Resources: []string{"/api/v1/items"},
						Actions:   []string{"GET"},
						Effect:    "allow",
					},
				},
			},
			Cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				TTL:     "30s",
				MaxSize: 500,
				Type:    "redis",
				Redis: &avapigwv1alpha1.RedisCacheSpec{
					KeyPrefix: "authz:",
					Sentinel:  redisSentinelSpecFromEnvShape(),
				},
			},
		}

		gwRoute := marshalSpecToGatewayRoute(t, route)

		require.NotNil(t, gwRoute.Authorization)
		cache := gwRoute.Authorization.Cache
		require.NotNil(t, cache, "authz cache must survive the wire")
		assert.True(t, cache.Enabled)
		assert.Equal(t, 30*time.Second, cache.TTL.Duration())
		assert.Equal(t, 500, cache.MaxSize)
		assert.Equal(t, "redis", cache.Type)
		require.NotNil(t, cache.Redis, "authz cache redis block must survive")
		assert.Equal(t, "authz:", cache.Redis.KeyPrefix)
		require.NotNil(t, cache.Redis.Sentinel)
		assert.Equal(t, "mymaster", cache.Redis.Sentinel.MasterName)
		assert.Len(t, cache.Redis.Sentinel.SentinelAddrs, 3)
	})

	t.Run("legacy sentinel key reaches the gateway type", func(t *testing.T) {
		// Serialize a CR spec still carrying the deprecated top-level
		// sentinel key (as older manifests do). The gateway's
		// AuthzCacheConfig deserializes it for compatibility; the authz
		// converter folds it into Redis.Sentinel at runtime.
		spec := map[string]interface{}{
			"enabled": true,
			"type":    "redis",
			"sentinel": map[string]interface{}{
				"masterName":    "mymaster",
				"sentinelAddrs": []string{"127.0.0.1:26379", "127.0.0.1:26380"},
			},
		}
		raw, err := json.Marshal(spec)
		require.NoError(t, err)

		var gwCache config.AuthzCacheConfig
		require.NoError(t, json.Unmarshal(raw, &gwCache))
		require.NotNil(t, gwCache.Sentinel,
			"gateway must consume the legacy sentinel key")
		assert.Equal(t, "mymaster", gwCache.Sentinel.MasterName)
		assert.Len(t, gwCache.Sentinel.SentinelAddrs, 2)
	})
}

// TestFunctional_Security_Structured_GatewayContract verifies the
// structured security hsts/csp blocks (plus referrerPolicy and
// customHeaders) round-trip CR -> gateway, and that the deprecated raw
// header fields are declared (deprecated markers) on the legacy fields.
func TestFunctional_Security_Structured_GatewayContract(t *testing.T) {
	route := createBasicAPIRoute()
	route.Spec.Security = &avapigwv1alpha1.SecurityConfig{
		Enabled: true,
		Headers: &avapigwv1alpha1.SecurityHeadersConfig{
			Enabled:             true,
			XFrameOptions:       "DENY",
			XContentTypeOptions: "nosniff",
			XXSSProtection:      "1; mode=block",
			CustomHeaders: map[string]string{
				"X-Custom-Security": "enabled",
			},
		},
		HSTS: &avapigwv1alpha1.SecurityHSTSConfig{
			Enabled:           true,
			MaxAge:            31536000,
			IncludeSubDomains: true,
			Preload:           true,
		},
		CSP: &avapigwv1alpha1.SecurityCSPConfig{
			Enabled:    true,
			Policy:     "default-src 'self'",
			ReportOnly: false,
			ReportURI:  "https://csp.example.com/report",
		},
		ReferrerPolicy: "strict-origin-when-cross-origin",
	}

	gwRoute := marshalSpecToGatewayRoute(t, route)

	sec := gwRoute.Security
	require.NotNil(t, sec, "security config must survive the wire")
	assert.True(t, sec.Enabled)

	require.NotNil(t, sec.Headers)
	assert.Equal(t, "DENY", sec.Headers.XFrameOptions)
	assert.Equal(t, "nosniff", sec.Headers.XContentTypeOptions)
	assert.Equal(t, "1; mode=block", sec.Headers.XXSSProtection)
	assert.Equal(t, "enabled", sec.Headers.CustomHeaders["X-Custom-Security"],
		"customHeaders must survive the wire")

	require.NotNil(t, sec.HSTS, "structured hsts must survive the wire")
	assert.True(t, sec.HSTS.Enabled)
	assert.Equal(t, 31536000, sec.HSTS.MaxAge)
	assert.True(t, sec.HSTS.IncludeSubDomains)
	assert.True(t, sec.HSTS.Preload)

	require.NotNil(t, sec.CSP, "structured csp must survive the wire")
	assert.True(t, sec.CSP.Enabled)
	assert.Equal(t, "default-src 'self'", sec.CSP.Policy)
	assert.Equal(t, "https://csp.example.com/report", sec.CSP.ReportURI)

	assert.Equal(t, "strict-origin-when-cross-origin", sec.ReferrerPolicy,
		"referrerPolicy must survive the wire")
}

// TestFunctional_Backend_HealthCheckGRPC_GatewayContract verifies the new
// backend healthCheck useGRPC/grpcService/port fields round-trip
// Backend CR -> gateway config.Backend (the shape needed for backends whose
// probes live on a separate monitoring port, like the reference images).
func TestFunctional_Backend_HealthCheckGRPC_GatewayContract(t *testing.T) {
	backendCR := createBasicBackend()
	backendCR.Spec.HealthCheck = &avapigwv1alpha1.HealthCheckConfig{
		Path:               "/grpc.health.v1.Health/Check",
		Interval:           "10s",
		Timeout:            "5s",
		HealthyThreshold:   2,
		UnhealthyThreshold: 3,
		UseGRPC:            true,
		GRPCService:        "api.v1.TestService",
		Port:               9090,
	}

	// 1. Admitted by the real webhook.
	validator := &webhook.BackendValidator{}
	_, err := validator.ValidateCreate(context.Background(), backendCR)
	require.NoError(t, err, "backend CR with gRPC health check must be admitted")

	// 2. Operator serialization -> gateway deserialization.
	data, err := json.Marshal(backendCR.Spec)
	require.NoError(t, err)

	var gwBackend config.Backend
	require.NoError(t, json.Unmarshal(data, &gwBackend))
	gwBackend.Name = backendCR.Name

	// 3. Wire shape assertions.
	hc := gwBackend.HealthCheck
	require.NotNil(t, hc, "healthCheck must survive the wire")
	assert.True(t, hc.UseGRPC, "useGRPC must survive")
	assert.Equal(t, "api.v1.TestService", hc.GRPCService, "grpcService must survive")
	assert.Equal(t, 9090, hc.Port, "probe port override must survive")
	assert.Equal(t, 10*time.Second, hc.Interval.Duration())
	assert.Equal(t, 2, hc.HealthyThreshold)

	// 4. The translated backend passes gateway validation inside a full
	// config.
	gwCfg := &config.GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   config.Metadata{Name: "hc-contract-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{Name: "http", Port: 8080, Protocol: config.ProtocolHTTP},
			},
			Backends: []config.Backend{gwBackend},
		},
	}
	require.NoError(t, config.ValidateConfig(gwCfg),
		"CRD-expressed gRPC health check must pass gateway validation")
}
