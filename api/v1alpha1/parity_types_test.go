package v1alpha1

import (
	"encoding/json"
	"reflect"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// This file covers the CRD/data-plane parity additions: advanced transform
// options, cache key configuration, Redis TLS, structured security CSP/HSTS,
// the authorization cache redis block, and gRPC health check fields —
// deep-copy semantics plus the JSON wire shape consumed by the gateway.

// newFullRequestTransform returns a RequestTransform with every advanced
// field populated.
func newFullRequestTransform() *RequestTransform {
	return &RequestTransform{
		Template:        "{{ .body }}",
		PassthroughBody: true,
		StaticHeaders:   map[string]string{"X-Static": "v1"},
		DynamicHeaders: []TransformDynamicHeader{
			{Name: "X-User", Source: "jwt.claim.sub"},
		},
		InjectFields: []TransformFieldInjection{
			{Field: "meta.user", Source: "jwt.claim.sub"},
			{Field: "meta.flag", Value: &apiextensionsv1.JSON{Raw: []byte(`true`)}},
		},
		RemoveFields: []string{"internal.secret"},
		DefaultValues: map[string]apiextensionsv1.JSON{
			"page": {Raw: []byte(`1`)},
		},
		ValidateBeforeTransform: true,
	}
}

// newFullResponseTransform returns a ResponseTransform with every advanced
// field populated.
func newFullResponseTransform() *ResponseTransform {
	return &ResponseTransform{
		AllowFields:   []string{"id", "name"},
		FieldMappings: map[string]string{"internal_id": "id"},
		GroupFields: []TransformFieldGroup{
			{Name: "meta", Fields: []string{"created", "updated"}},
		},
		FlattenFields: []string{"nested"},
		ArrayOperations: []TransformArrayOperation{
			{Field: "items", Operation: "limit", Value: &apiextensionsv1.JSON{Raw: []byte(`5`)}},
			{Field: "items", Operation: "filter", Condition: "item.active == true"},
		},
		Template:      "{{ . }}",
		MergeStrategy: "ndjson",
	}
}

func TestRequestTransform_DeepCopy_AdvancedFields(t *testing.T) {
	src := newFullRequestTransform()
	got := src.DeepCopy()

	if got == src {
		t.Fatal("DeepCopy must return a new object")
	}
	if !reflect.DeepEqual(got, src) {
		t.Fatalf("DeepCopy mismatch: got %+v want %+v", got, src)
	}

	got.StaticHeaders["X-Static"] = "changed"
	got.DynamicHeaders[0].Name = "changed"
	got.InjectFields[1].Value.Raw[0] = 'X'
	got.DefaultValues["page"] = apiextensionsv1.JSON{Raw: []byte(`2`)}
	if src.StaticHeaders["X-Static"] != "v1" ||
		src.DynamicHeaders[0].Name != "X-User" ||
		string(src.InjectFields[1].Value.Raw) != "true" ||
		string(src.DefaultValues["page"].Raw) != "1" {
		t.Error("mutating the copy must not affect the source")
	}
}

func TestResponseTransform_DeepCopy_AdvancedFields(t *testing.T) {
	src := newFullResponseTransform()
	got := src.DeepCopy()

	if got == src {
		t.Fatal("DeepCopy must return a new object")
	}
	if !reflect.DeepEqual(got, src) {
		t.Fatalf("DeepCopy mismatch: got %+v want %+v", got, src)
	}

	got.GroupFields[0].Fields[0] = "changed"
	got.ArrayOperations[0].Value.Raw[0] = 'X'
	if src.GroupFields[0].Fields[0] != "created" || string(src.ArrayOperations[0].Value.Raw) != "5" {
		t.Error("mutating the copy must not affect the source")
	}
}

func TestTransformHelperTypes_DeepCopy(t *testing.T) {
	dynamicHeader := &TransformDynamicHeader{Name: "X-A", Source: "context.request_id"}
	if got := dynamicHeader.DeepCopy(); got == dynamicHeader || *got != *dynamicHeader {
		t.Error("TransformDynamicHeader deep copy failed")
	}

	group := &TransformFieldGroup{Name: "g", Fields: []string{"a", "b"}}
	gotGroup := group.DeepCopy()
	if gotGroup == group || !reflect.DeepEqual(gotGroup, group) {
		t.Error("TransformFieldGroup deep copy failed")
	}
	gotGroup.Fields[0] = "changed"
	if group.Fields[0] != "a" {
		t.Error("TransformFieldGroup fields slice must not be shared")
	}

	injection := &TransformFieldInjection{Field: "f", Value: &apiextensionsv1.JSON{Raw: []byte(`"x"`)}}
	gotInjection := injection.DeepCopy()
	if gotInjection == injection || !reflect.DeepEqual(gotInjection, injection) {
		t.Error("TransformFieldInjection deep copy failed")
	}

	op := &TransformArrayOperation{Field: "f", Operation: "sort", Value: &apiextensionsv1.JSON{Raw: []byte(`"asc"`)}}
	gotOp := op.DeepCopy()
	if gotOp == op || !reflect.DeepEqual(gotOp, op) {
		t.Error("TransformArrayOperation deep copy failed")
	}
}

func TestCacheConfig_DeepCopy_KeyConfigAndNewFields(t *testing.T) {
	src := &CacheConfig{
		Enabled:           true,
		TTL:               "30s",
		MaxEntries:        1000,
		HonorCacheControl: true,
		NegativeCacheTTL:  "5s",
		KeyConfig: &CacheKeyConfig{
			IncludeMethod:      true,
			IncludePath:        true,
			IncludeQueryParams: []string{"page"},
			IncludeHeaders:     []string{"Accept"},
			IncludeBodyHash:    true,
			KeyTemplate:        "{{.Method}}:{{.Path}}",
		},
	}

	got := src.DeepCopy()
	if got == src || !reflect.DeepEqual(got, src) {
		t.Fatal("CacheConfig deep copy failed")
	}
	if got.KeyConfig == src.KeyConfig {
		t.Error("keyConfig must be deep-copied")
	}
	got.KeyConfig.IncludeQueryParams[0] = "changed"
	if src.KeyConfig.IncludeQueryParams[0] != "page" {
		t.Error("keyConfig slices must not be shared")
	}

	standalone := src.KeyConfig.DeepCopy()
	if standalone == src.KeyConfig || !reflect.DeepEqual(standalone, src.KeyConfig) {
		t.Error("CacheKeyConfig deep copy failed")
	}
}

func TestRedisTLSSpec_DeepCopy(t *testing.T) {
	src := &RedisTLSSpec{
		Enabled:            true,
		CertFile:           "/tls/cert.pem",
		KeyFile:            "/tls/key.pem",
		CAFile:             "/tls/ca.pem",
		MinVersion:         "TLS12",
		MaxVersion:         "TLS13",
		InsecureSkipVerify: false,
	}
	got := src.DeepCopy()
	if got == src || *got != *src {
		t.Fatal("RedisTLSSpec deep copy failed")
	}
}

func TestRedisSpecs_DeepCopy_TLSField(t *testing.T) {
	cacheSpec := &RedisCacheSpec{
		URL: "redis://cache:6379/0",
		TLS: &RedisTLSSpec{Enabled: true, CAFile: "/tls/ca.pem"},
	}
	gotCache := cacheSpec.DeepCopy()
	if gotCache.TLS == cacheSpec.TLS || gotCache.TLS.CAFile != "/tls/ca.pem" {
		t.Error("RedisCacheSpec.TLS must be deep-copied")
	}

	rlSpec := &RateLimitRedisSpec{
		URL: "redis://rl:6379/1",
		TLS: &RedisTLSSpec{Enabled: true, CertFile: "/c.pem", KeyFile: "/k.pem"},
	}
	gotRL := rlSpec.DeepCopy()
	if gotRL.TLS == rlSpec.TLS || gotRL.TLS.CertFile != "/c.pem" {
		t.Error("RateLimitRedisSpec.TLS must be deep-copied")
	}
}

func TestSecurityConfig_DeepCopy_StructuredBlocks(t *testing.T) {
	src := &SecurityConfig{
		Enabled: true,
		Headers: &SecurityHeadersConfig{
			Enabled:       true,
			XFrameOptions: "DENY",
			CustomHeaders: map[string]string{"X-Custom": "v"},
		},
		HSTS: &SecurityHSTSConfig{
			Enabled: true, MaxAge: 31536000, IncludeSubDomains: true, Preload: true,
		},
		CSP: &SecurityCSPConfig{
			Enabled: true, Policy: "default-src 'self'", ReportOnly: true, ReportURI: "/csp-report",
		},
		ReferrerPolicy: "no-referrer",
	}

	got := src.DeepCopy()
	if got == src || !reflect.DeepEqual(got, src) {
		t.Fatal("SecurityConfig deep copy failed")
	}
	if got.HSTS == src.HSTS || got.CSP == src.CSP || got.Headers == src.Headers {
		t.Error("nested security blocks must be deep-copied")
	}
	got.Headers.CustomHeaders["X-Custom"] = "changed"
	if src.Headers.CustomHeaders["X-Custom"] != "v" {
		t.Error("customHeaders map must not be shared")
	}

	if h := src.HSTS.DeepCopy(); h == src.HSTS || *h != *src.HSTS {
		t.Error("SecurityHSTSConfig deep copy failed")
	}
	if c := src.CSP.DeepCopy(); c == src.CSP || *c != *src.CSP {
		t.Error("SecurityCSPConfig deep copy failed")
	}
}

func TestAuthzCacheConfig_DeepCopy_RedisBlock(t *testing.T) {
	src := &AuthzCacheConfig{
		Enabled: true,
		TTL:     "60s",
		MaxSize: 500,
		Type:    "redis",
		Redis: &RedisCacheSpec{
			Sentinel: &RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"s1:26379"},
			},
		},
	}

	got := src.DeepCopy()
	if got == src || !reflect.DeepEqual(got, src) {
		t.Fatal("AuthzCacheConfig deep copy failed")
	}
	if got.Redis == src.Redis || got.Redis.Sentinel == src.Redis.Sentinel {
		t.Error("redis block must be deep-copied")
	}
}

func TestHealthCheckConfig_GRPCFields(t *testing.T) {
	src := &HealthCheckConfig{
		Path:        "/healthz",
		UseGRPC:     true,
		GRPCService: "api.v1.TestService",
		Port:        9090,
	}
	got := src.DeepCopy()
	if got == src || !reflect.DeepEqual(got, src) {
		t.Fatal("HealthCheckConfig deep copy failed")
	}

	// The JSON keys must match the gateway's HealthCheck configuration.
	data, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"path", "useGRPC", "grpcService", "port"} {
		if _, ok := wire[key]; !ok {
			t.Errorf("expected JSON key %q in serialized health check, got %s", key, data)
		}
	}
}

// TestTransformConfig_WireShape verifies the serialized transform JSON uses
// exactly the keys the gateway's transform configuration deserializes.
func TestTransformConfig_WireShape(t *testing.T) {
	cfg := &TransformConfig{
		Request:  newFullRequestTransform(),
		Response: newFullResponseTransform(),
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var wire struct {
		Request  map[string]json.RawMessage `json:"request"`
		Response map[string]json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	requestKeys := []string{
		"template", "passthroughBody", "staticHeaders", "dynamicHeaders",
		"injectFields", "removeFields", "defaultValues", "validateBeforeTransform",
	}
	for _, key := range requestKeys {
		if _, ok := wire.Request[key]; !ok {
			t.Errorf("request transform must serialize key %q", key)
		}
	}

	responseKeys := []string{
		"allowFields", "fieldMappings", "groupFields", "flattenFields",
		"arrayOperations", "template", "mergeStrategy",
	}
	for _, key := range responseKeys {
		if _, ok := wire.Response[key]; !ok {
			t.Errorf("response transform must serialize key %q", key)
		}
	}
}

// TestCacheConfig_WireShape verifies the serialized cache JSON uses exactly
// the keys the gateway's cache configuration deserializes.
func TestCacheConfig_WireShape(t *testing.T) {
	cfg := &CacheConfig{
		Enabled:           true,
		TTL:               "30s",
		MaxEntries:        100,
		HonorCacheControl: true,
		NegativeCacheTTL:  "5s",
		KeyConfig:         &CacheKeyConfig{IncludeMethod: true, IncludePath: true},
		Type:              "redis",
		Redis: &RedisCacheSpec{
			URL: "redis://cache:6379/0",
			TLS: &RedisTLSSpec{Enabled: true, CAFile: "/tls/ca.pem"},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{
		"enabled", "ttl", "maxEntries", "honorCacheControl",
		"negativeCacheTTL", "keyConfig", "type", "redis",
	} {
		if _, ok := wire[key]; !ok {
			t.Errorf("cache config must serialize key %q", key)
		}
	}

	var redisWire map[string]json.RawMessage
	if err := json.Unmarshal(wire["redis"], &redisWire); err != nil {
		t.Fatalf("unmarshal redis: %v", err)
	}
	if _, ok := redisWire["tls"]; !ok {
		t.Error("redis cache spec must serialize the tls key")
	}
}

// TestAuthzCacheConfig_WireShape verifies the authorization cache serializes
// the redis key (the shape the gateway's AuthzCacheConfig deserializes) and
// keeps the deprecated sentinel key only when explicitly set.
func TestAuthzCacheConfig_WireShape(t *testing.T) {
	cfg := &AuthzCacheConfig{
		Enabled: true,
		Type:    "redis",
		Redis:   &RedisCacheSpec{URL: "redis://cache:6379/0"},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := wire["redis"]; !ok {
		t.Error("authorization cache must serialize the redis key for the gateway")
	}
	if _, ok := wire["sentinel"]; ok {
		t.Error("sentinel key must be omitted when unset")
	}
}

// TestDeprecatedFields_WireShapeRoundTrip pins the negative wire-shape
// guarantee for deprecated CRD fields: when explicitly set, they survive a
// JSON round-trip byte-identically. The reconcile-time normalizer converts
// them for the gateway, but the CRD shape itself must keep carrying the
// legacy keys so stored objects deserialize losslessly.
func TestDeprecatedFields_WireShapeRoundTrip(t *testing.T) {
	t.Run("cache keyComponents", func(t *testing.T) {
		src := &CacheConfig{
			Enabled:       true,
			TTL:           "30s",
			KeyComponents: []string{"method", "path"},
		}

		data, err := json.Marshal(src)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(data, &wire); err != nil {
			t.Fatalf("unmarshal wire: %v", err)
		}
		if _, ok := wire["keyComponents"]; !ok {
			t.Errorf("deprecated keyComponents key must survive serialization, got %s", data)
		}

		var back CacheConfig
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("unmarshal round-trip: %v", err)
		}
		if !reflect.DeepEqual(&back, src) {
			t.Errorf("round-trip mismatch: got %+v want %+v", &back, src)
		}
	})

	t.Run("authz cache sentinel", func(t *testing.T) {
		src := &AuthzCacheConfig{
			Enabled: true,
			Type:    "redis",
			Sentinel: &RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"s1:26379", "s2:26379"},
			},
		}

		data, err := json.Marshal(src)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(data, &wire); err != nil {
			t.Fatalf("unmarshal wire: %v", err)
		}
		if _, ok := wire["sentinel"]; !ok {
			t.Errorf("deprecated sentinel key must survive serialization when set, got %s", data)
		}
		if _, ok := wire["redis"]; ok {
			t.Error("redis key must stay absent when only the legacy sentinel field is set")
		}

		var back AuthzCacheConfig
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("unmarshal round-trip: %v", err)
		}
		if !reflect.DeepEqual(&back, src) {
			t.Errorf("round-trip mismatch: got %+v want %+v", &back, src)
		}
	})

	t.Run("legacy CSP and HSTS header strings", func(t *testing.T) {
		src := &SecurityHeadersConfig{
			Enabled:                 true,
			ContentSecurityPolicy:   "default-src 'self'",
			StrictTransportSecurity: "max-age=31536000; includeSubDomains",
		}

		data, err := json.Marshal(src)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(data, &wire); err != nil {
			t.Fatalf("unmarshal wire: %v", err)
		}
		for _, key := range []string{"contentSecurityPolicy", "strictTransportSecurity"} {
			if _, ok := wire[key]; !ok {
				t.Errorf("deprecated header-string key %q must survive serialization, got %s", key, data)
			}
		}

		var back SecurityHeadersConfig
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("unmarshal round-trip: %v", err)
		}
		if !reflect.DeepEqual(&back, src) {
			t.Errorf("round-trip mismatch: got %+v want %+v", &back, src)
		}
	})
}

// TestSecurityConfig_WireShape verifies the structured security blocks
// serialize under the keys the gateway's SecurityConfig deserializes.
func TestSecurityConfig_WireShape(t *testing.T) {
	cfg := &SecurityConfig{
		Enabled:        true,
		Headers:        &SecurityHeadersConfig{Enabled: true, CustomHeaders: map[string]string{"X-C": "v"}},
		HSTS:           &SecurityHSTSConfig{Enabled: true, MaxAge: 300},
		CSP:            &SecurityCSPConfig{Enabled: true, Policy: "default-src 'self'", ReportURI: "/r"},
		ReferrerPolicy: "no-referrer",
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"enabled", "headers", "hsts", "csp", "referrerPolicy"} {
		if _, ok := wire[key]; !ok {
			t.Errorf("security config must serialize key %q", key)
		}
	}

	var cspWire map[string]json.RawMessage
	if err := json.Unmarshal(wire["csp"], &cspWire); err != nil {
		t.Fatalf("unmarshal csp: %v", err)
	}
	if _, ok := cspWire["reportUri"]; !ok {
		t.Error("csp must serialize reportUri (gateway JSON key)")
	}
}
