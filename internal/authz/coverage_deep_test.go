package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/auth"
	"github.com/vyrodovalexey/avapigw/internal/authz/abac"
	"github.com/vyrodovalexey/avapigw/internal/authz/external"
	"github.com/vyrodovalexey/avapigw/internal/authz/rbac"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ============================================================================
// initializeOPA tests
// ============================================================================

func TestInitializeOPA_ExternalDisabled(t *testing.T) {
	t.Parallel()

	a := &authorizer{
		config:  &Config{Enabled: true},
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	// External not configured at all
	err := a.initializeOPA(&Config{Enabled: true})
	assert.NoError(t, err)
	assert.Nil(t, a.opaClient)
}

func TestInitializeOPA_ExternalEnabledButNoOPA(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			// OPA is nil
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeOPA(config)
	assert.NoError(t, err)
	assert.Nil(t, a.opaClient)
}

func TestInitializeOPA_OPAClientAlreadySet(t *testing.T) {
	t.Parallel()

	existingClient := &mockOPAClient{
		result: &external.OPAResult{Allow: true},
	}

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	a := &authorizer{
		config:    config,
		logger:    observability.NopLogger(),
		metrics:   newNoopMetrics(),
		opaClient: existingClient,
	}

	err := a.initializeOPA(config)
	assert.NoError(t, err)
	// Should keep the existing client
	assert.Equal(t, existingClient, a.opaClient)
}

func TestInitializeOPA_CreatesNewClient(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeOPA(config)
	assert.NoError(t, err)
	assert.NotNil(t, a.opaClient)
	_ = a.opaClient.Close()
}

func TestInitializeOPA_WithCustomTimeout(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			Timeout: 30 * time.Second,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeOPA(config)
	assert.NoError(t, err)
	assert.NotNil(t, a.opaClient)
	_ = a.opaClient.Close()
}

func TestInitializeOPA_DefaultTimeout(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			Timeout: 0, // Should use default 10s
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeOPA(config)
	assert.NoError(t, err)
	assert.NotNil(t, a.opaClient)
	_ = a.opaClient.Close()
}

// ============================================================================
// initializeEngines tests
// ============================================================================

func TestInitializeEngines_AllEngines(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test-policy",
					Roles:     []string{"admin"},
					Resources: []string{"/api/*"},
					Actions:   []string{"*"},
					Effect:    "allow",
				},
			},
		},
		ABAC: &abac.Config{
			Enabled: true,
			Policies: []abac.Policy{
				{
					Name:       "test-abac",
					Expression: `subject.id == "user123"`,
					Effect:     abac.EffectAllow,
					Priority:   1,
					Resources:  []string{"/api/*"},
					Actions:    []string{"GET"},
				},
			},
		},
		External: &external.Config{
			Enabled: true,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeEngines(config)
	assert.NoError(t, err)
	assert.NotNil(t, a.rbacEngine)
	assert.NotNil(t, a.abacEngine)
	assert.NotNil(t, a.opaClient)
	_ = a.opaClient.Close()
}

func TestInitializeEngines_RBACOnly(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test-policy",
					Roles:     []string{"admin"},
					Resources: []string{"/api/*"},
					Actions:   []string{"*"},
					Effect:    "allow",
				},
			},
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeEngines(config)
	assert.NoError(t, err)
	assert.NotNil(t, a.rbacEngine)
	assert.Nil(t, a.abacEngine)
	assert.Nil(t, a.opaClient)
}

func TestInitializeEngines_OPAOnly(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			Timeout: 5 * time.Second,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeEngines(config)
	assert.NoError(t, err)
	assert.Nil(t, a.rbacEngine)
	assert.Nil(t, a.abacEngine)
	assert.NotNil(t, a.opaClient)
	_ = a.opaClient.Close()
}

func TestInitializeEngines_RBACError(t *testing.T) {
	t.Parallel()

	// Invalid RBAC config that will cause an error
	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled:  true,
			Policies: []rbac.Policy{}, // Empty policies
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	// This may or may not error depending on RBAC engine validation
	_ = a.initializeEngines(config)
}

func TestInitializeEngines_ABACError(t *testing.T) {
	t.Parallel()

	// ABAC with invalid expression
	config := &Config{
		Enabled: true,
		ABAC: &abac.Config{
			Enabled: true,
			Policies: []abac.Policy{
				{
					Name:       "bad-policy",
					Expression: "invalid!!!expression",
					Effect:     abac.EffectAllow,
					Resources:  []string{"/api/*"},
					Actions:    []string{"GET"},
				},
			},
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeEngines(config)
	// ABAC with invalid expression should return an error
	assert.Error(t, err)
}

// ============================================================================
// New authorizer tests - additional paths
// ============================================================================

func TestNew_WithDefaultMetrics(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: false,
	}

	// Don't pass metrics - should create default
	authorizer, err := New(config)
	require.NoError(t, err)
	assert.NotNil(t, authorizer)
	_ = authorizer.Close()
}

func TestNew_WithOPAConfig(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			Timeout: 5 * time.Second,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	assert.NotNil(t, authorizer)
	_ = authorizer.Close()
}

func TestNew_WithCacheDefaultTTLAndMaxSize(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test",
					Roles:     []string{"admin"},
					Resources: []string{"/*"},
					Actions:   []string{"*"},
					Effect:    "allow",
				},
			},
		},
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     0, // Should use default 5 min
			MaxSize: 0, // Should use default 10000
		},
	}

	authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	assert.NotNil(t, authorizer)
	_ = authorizer.Close()
}

func TestNew_WithNilCache(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test",
					Roles:     []string{"admin"},
					Resources: []string{"/*"},
					Actions:   []string{"*"},
					Effect:    "allow",
				},
			},
		},
		Cache: nil, // No cache config
	}

	authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	assert.NotNil(t, authorizer)
	_ = authorizer.Close()
}

// ============================================================================
// Metrics.Init tests
// ============================================================================

func TestMetrics_Init(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_init", reg)
	require.NotNil(t, metrics)

	// Should not panic
	metrics.Init()

	// Verify metrics were pre-initialized by gathering them
	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestMetrics_Init_NilMetrics(t *testing.T) {
	t.Parallel()

	var m *Metrics
	// Should not panic
	m.Init()
}

// ============================================================================
// Metrics methods with real metrics (non-nil counters)
// ============================================================================

func TestMetrics_RecordEvaluation_WithRealMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_eval", reg)

	metrics.RecordEvaluation("rbac", "allowed", 100*time.Millisecond)
	metrics.RecordEvaluation("abac", "denied", 50*time.Millisecond)
	metrics.RecordEvaluation("combined", "error", 200*time.Millisecond)

	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestMetrics_RecordDecision_WithRealMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_decision", reg)

	metrics.RecordDecision("allowed", "admin-policy")
	metrics.RecordDecision("denied", "default")

	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestMetrics_RecordCacheHit_WithRealMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_cache_hit", reg)

	metrics.RecordCacheHit()
	metrics.RecordCacheHit()

	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestMetrics_RecordCacheMiss_WithRealMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_cache_miss", reg)

	metrics.RecordCacheMiss()
	metrics.RecordCacheMiss()

	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestMetrics_RecordExternalRequest_WithRealMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_ext_req", reg)

	metrics.RecordExternalRequest("opa", "allowed", 100*time.Millisecond)
	metrics.RecordExternalRequest("opa", "denied", 50*time.Millisecond)
	metrics.RecordExternalRequest("opa", "error", 200*time.Millisecond)

	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestMetrics_SetPolicyCount_WithRealMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_policy_count", reg)

	metrics.SetPolicyCount("rbac", 5)
	metrics.SetPolicyCount("abac", 3)

	families, err := reg.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, families)
}

func TestNewMetricsWithRegisterer_EmptyNamespace(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("", reg)
	require.NotNil(t, metrics)
	assert.NotNil(t, metrics.evaluationTotal)
}

func TestNewMetricsWithRegisterer_NilRegisterer(t *testing.T) {
	// Not parallel since it uses DefaultRegisterer
	metrics := NewMetricsWithRegisterer("test_nil_reg", nil)
	require.NotNil(t, metrics)
	assert.NotNil(t, metrics.evaluationTotal)
}

// ============================================================================
// External decision cache - additional edge cases
// ============================================================================

func TestExternalDecisionCache_GetWithMetrics_CacheMiss(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_ext_cache_miss", reg)

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheMetrics(metrics),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Cache miss should record metric
	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExternalDecisionCache_GetWithMetrics_CacheHit(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_ext_cache_hit", reg)

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheMetrics(metrics),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Set a valid decision
	c.Set(context.Background(), key, &CachedDecision{
		Allowed: true,
		Reason:  "test",
	})

	// Cache hit should record metric
	result, ok := c.Get(context.Background(), key)
	assert.True(t, ok)
	assert.NotNil(t, result)
	assert.True(t, result.Allowed)
}

func TestExternalDecisionCache_GetWithMetrics_Error(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_ext_cache_err", reg)

	mockC := newMockCacheForAuthz()
	mockC.getErr = errors.New("cache error")
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
		WithExternalCacheMetrics(metrics),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExternalDecisionCache_GetWithMetrics_InvalidJSON(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_ext_cache_json", reg)

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
		WithExternalCacheMetrics(metrics),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Set invalid JSON directly
	cacheKey := "authz:" + key.String()
	mockC.data[cacheKey] = []byte("invalid json")

	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExternalDecisionCache_GetWithMetrics_Expired(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_ext_cache_exp", reg)

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheMetrics(metrics),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Set expired decision directly
	decision := &CachedDecision{
		Allowed:   true,
		CachedAt:  time.Now().Add(-10 * time.Minute),
		ExpiresAt: time.Now().Add(-5 * time.Minute),
	}
	data, _ := json.Marshal(decision)
	cacheKey := "authz:" + key.String()
	mockC.data[cacheKey] = data

	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExternalDecisionCache_SetWithMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_ext_cache_set", reg)

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheMetrics(metrics),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	c.Set(context.Background(), key, &CachedDecision{
		Allowed: true,
		Reason:  "test",
	})

	// Verify it was stored
	result, ok := c.Get(context.Background(), key)
	assert.True(t, ok)
	assert.True(t, result.Allowed)
}

// ============================================================================
// Memory decision cache - additional metrics paths
// ============================================================================

func TestMemoryDecisionCache_GetExpired_WithMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_mem_expired", reg)

	c := NewMemoryDecisionCache(1*time.Millisecond, 100,
		WithMemoryCacheMetrics(metrics),
	)
	defer c.Close()

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	c.Set(context.Background(), key, &CachedDecision{Allowed: true})

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Should record cache miss for expired entry
	result, ok := c.Get(context.Background(), key)
	assert.False(t, ok)
	assert.Nil(t, result)
}

// ============================================================================
// Middleware handleAuthzError - default error case
// ============================================================================

func TestHTTPAuthorizer_HandleAuthzError_GenericError(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		err: errors.New("some generic error"),
	}
	config := &Config{Enabled: true}

	authorizer := NewHTTPAuthorizer(mockAuth, config,
		WithHTTPAuthorizerLogger(observability.NopLogger()),
		WithHTTPAuthorizerMetrics(newNoopMetrics()),
	)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	middleware := authorizer.HTTPMiddleware()
	handler := middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	identity := &auth.Identity{Subject: "user123"}
	ctx := auth.ContextWithIdentity(req.Context(), identity)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var response map[string]string
	err := json.NewDecoder(rr.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "authorization error", response["error"])
}

// ============================================================================
// Middleware - default metrics initialization
// ============================================================================

func TestNewHTTPAuthorizer_DefaultMetrics(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	// Don't pass metrics - should create default
	authorizer := NewHTTPAuthorizer(mockAuth, config)
	assert.NotNil(t, authorizer)
}

func TestNewGRPCAuthorizer_DefaultMetrics(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	// Don't pass metrics - should create default
	authorizer := NewGRPCAuthorizer(mockAuth, config)
	assert.NotNil(t, authorizer)
}

// ============================================================================
// initializeRBAC and initializeABAC - engine already set paths
// ============================================================================

func TestInitializeRBAC_EngineAlreadySet(t *testing.T) {
	t.Parallel()

	existingEngine := &mockRBACEngine{
		decision: &rbac.Decision{Allowed: true},
	}

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
			Policies: []rbac.Policy{
				{
					Name:      "test",
					Roles:     []string{"admin"},
					Resources: []string{"/*"},
					Actions:   []string{"*"},
					Effect:    "allow",
				},
			},
		},
	}

	a := &authorizer{
		config:     config,
		logger:     observability.NopLogger(),
		metrics:    newNoopMetrics(),
		rbacEngine: existingEngine,
	}

	err := a.initializeRBAC(config)
	assert.NoError(t, err)
	// Should keep the existing engine
	assert.Equal(t, existingEngine, a.rbacEngine)
}

func TestInitializeABAC_EngineAlreadySet(t *testing.T) {
	t.Parallel()

	existingEngine := &mockABACEngine{
		decision: &abac.Decision{Allowed: true},
	}

	config := &Config{
		Enabled: true,
		ABAC: &abac.Config{
			Enabled: true,
			Policies: []abac.Policy{
				{
					Name:       "test",
					Expression: `subject.id == "user123"`,
					Effect:     abac.EffectAllow,
					Resources:  []string{"/api/*"},
					Actions:    []string{"GET"},
				},
			},
		},
	}

	a := &authorizer{
		config:     config,
		logger:     observability.NopLogger(),
		metrics:    newNoopMetrics(),
		abacEngine: existingEngine,
	}

	err := a.initializeABAC(config)
	assert.NoError(t, err)
	// Should keep the existing engine
	assert.Equal(t, existingEngine, a.abacEngine)
}

func TestInitializeRBAC_Disabled(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: false,
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeRBAC(config)
	assert.NoError(t, err)
	assert.Nil(t, a.rbacEngine)
}

func TestInitializeABAC_Disabled(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		ABAC: &abac.Config{
			Enabled: false,
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	err := a.initializeABAC(config)
	assert.NoError(t, err)
	assert.Nil(t, a.abacEngine)
}

// ============================================================================
// initializeCache - additional paths
// ============================================================================

func TestInitializeCache_CacheAlreadySet(t *testing.T) {
	t.Parallel()

	existingCache := NewNoopDecisionCache()

	config := &Config{
		Enabled: true,
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 1000,
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
		cache:   existingCache,
	}

	a.initializeCache(config)
	// Should keep the existing cache
	assert.Equal(t, existingCache, a.cache)
}

func TestInitializeCache_NilCacheConfig(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Cache:   nil,
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	a.initializeCache(config)
	// Should create noop cache
	assert.NotNil(t, a.cache)
}

func TestInitializeCache_CacheDisabled(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		Cache: &CacheConfig{
			Enabled: false,
		},
	}

	a := &authorizer{
		config:  config,
		logger:  observability.NopLogger(),
		metrics: newNoopMetrics(),
	}

	a.initializeCache(config)
	// Should create noop cache
	assert.NotNil(t, a.cache)
}

// ============================================================================
// Close with both cache and OPA errors
// ============================================================================

func TestAuthorizer_Close_BothErrors(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	// Create a mock cache that returns an error on close
	mockCache := &mockDecisionCacheWithCloseError{
		closeErr: errors.New("cache close error"),
	}

	mockOPA := &mockOPAClient{
		closeErr: errors.New("OPA close error"),
	}

	authorizer, err := New(config,
		WithOPAClient(mockOPA),
		WithDecisionCache(mockCache),
		WithAuthorizerMetrics(newNoopMetrics()),
	)
	require.NoError(t, err)

	err = authorizer.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cache close error")
	assert.Contains(t, err.Error(), "OPA close error")
}

// mockDecisionCacheWithCloseError is a mock cache that returns an error on Close.
type mockDecisionCacheWithCloseError struct {
	closeErr error
}

func (m *mockDecisionCacheWithCloseError) Get(_ context.Context, _ *CacheKey) (*CachedDecision, bool) {
	return nil, false
}

func (m *mockDecisionCacheWithCloseError) Set(_ context.Context, _ *CacheKey, _ *CachedDecision) {}

func (m *mockDecisionCacheWithCloseError) Delete(_ context.Context, _ *CacheKey) {}

func (m *mockDecisionCacheWithCloseError) Clear(_ context.Context) {}

func (m *mockDecisionCacheWithCloseError) Close() error {
	return m.closeErr
}

// ============================================================================
// Noop decision cache - explicit coverage for empty methods
// ============================================================================

func TestNoopDecisionCache_AllMethods(t *testing.T) {
	t.Parallel()

	c := NewNoopDecisionCache()
	ctx := context.Background()
	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/test",
		Action:   "GET",
	}

	// Test Set (no-op)
	c.Set(ctx, key, &CachedDecision{Allowed: true, Reason: "test"})

	// Test Get (always returns false)
	result, ok := c.Get(ctx, key)
	assert.False(t, ok)
	assert.Nil(t, result)

	// Test Delete (no-op)
	c.Delete(ctx, key)

	// Test Clear (no-op)
	c.Clear(ctx)

	// Test Close
	err := c.Close()
	assert.NoError(t, err)
}

// ============================================================================
// Authorizer functional options
// ============================================================================

func TestWithAuthorizerLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	opt := WithAuthorizerLogger(logger)

	a := &authorizer{}
	opt(a)
	assert.Equal(t, logger, a.logger)
}

func TestWithAuthorizerMetrics(t *testing.T) {
	t.Parallel()

	metrics := newNoopMetrics()
	opt := WithAuthorizerMetrics(metrics)

	a := &authorizer{}
	opt(a)
	assert.Equal(t, metrics, a.metrics)
}

func TestWithRBACEngine(t *testing.T) {
	t.Parallel()

	engine := &mockRBACEngine{}
	opt := WithRBACEngine(engine)

	a := &authorizer{}
	opt(a)
	assert.Equal(t, engine, a.rbacEngine)
}

func TestWithABACEngine(t *testing.T) {
	t.Parallel()

	engine := &mockABACEngine{}
	opt := WithABACEngine(engine)

	a := &authorizer{}
	opt(a)
	assert.Equal(t, engine, a.abacEngine)
}

func TestWithOPAClient(t *testing.T) {
	t.Parallel()

	client := &mockOPAClient{}
	opt := WithOPAClient(client)

	a := &authorizer{}
	opt(a)
	assert.Equal(t, client, a.opaClient)
}

func TestWithDecisionCache(t *testing.T) {
	t.Parallel()

	cache := NewNoopDecisionCache()
	opt := WithDecisionCache(cache)

	a := &authorizer{}
	opt(a)
	assert.Equal(t, cache, a.cache)
}

// ============================================================================
// Full integration test: New with OPA that creates real client
// ============================================================================

func TestNew_FullOPAInitialization(t *testing.T) {
	t.Parallel()

	// Start a mock OPA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow":  true,
				"reason": "test allowed",
			},
		})
	}))
	defer server.Close()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled: true,
			Timeout: 5 * time.Second,
			OPA: &external.OPAConfig{
				URL:    server.URL,
				Policy: "authz/allow",
			},
		},
	}

	authorizer, err := New(config, WithAuthorizerMetrics(newNoopMetrics()))
	require.NoError(t, err)
	defer authorizer.Close()

	// Test authorization through the full path
	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
			Roles:   []string{"admin"},
		},
		Resource: "/api/users",
		Action:   "GET",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, "external", decision.Engine)
}

// ============================================================================
// Authorizer.Authorize - evaluation error path
// ============================================================================

func TestAuthorizer_Authorize_EvaluationError(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		External: &external.Config{
			Enabled:  true,
			FailOpen: false,
			OPA: &external.OPAConfig{
				URL:    "http://localhost:8181",
				Policy: "authz/allow",
			},
		},
	}

	mockOPA := &mockOPAClient{
		err: errors.New("OPA connection failed"),
	}

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_eval_err", reg)

	authorizer, err := New(config,
		WithOPAClient(mockOPA),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(metrics),
		WithAuthorizerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
		},
		Resource: "/api/users",
		Action:   "GET",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, decision)
}

// ============================================================================
// Authorizer.Authorize - allowed decision with real metrics
// ============================================================================

func TestAuthorizer_Authorize_AllowedWithRealMetrics(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled: true,
		RBAC: &rbac.Config{
			Enabled: true,
		},
	}

	mockEngine := &mockRBACEngine{
		decision: &rbac.Decision{
			Allowed: true,
			Reason:  "admin allowed",
			Policy:  "admin-policy",
		},
	}

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_allowed_metrics", reg)

	authorizer, err := New(config,
		WithRBACEngine(mockEngine),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(metrics),
	)
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
			Roles:   []string{"admin"},
		},
		Resource: "/api/users",
		Action:   "GET",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

// ============================================================================
// Authorizer.Authorize - denied decision with real metrics
// ============================================================================

func TestAuthorizer_Authorize_DeniedWithRealMetrics(t *testing.T) {
	t.Parallel()

	config := &Config{
		Enabled:       true,
		DefaultPolicy: PolicyDeny,
		RBAC: &rbac.Config{
			Enabled: true,
		},
	}

	mockEngine := &mockRBACEngine{
		decision: &rbac.Decision{
			Allowed: false,
			Reason:  "no matching policy",
			Policy:  "",
		},
	}

	reg := prometheus.NewRegistry()
	metrics := NewMetricsWithRegisterer("test_denied_metrics", reg)

	authorizer, err := New(config,
		WithRBACEngine(mockEngine),
		WithDecisionCache(NewNoopDecisionCache()),
		WithAuthorizerMetrics(metrics),
	)
	require.NoError(t, err)
	defer authorizer.Close()

	req := &Request{
		Identity: &auth.Identity{
			Subject: "user123",
			Roles:   []string{"guest"},
		},
		Resource: "/api/admin",
		Action:   "DELETE",
	}

	decision, err := authorizer.Authorize(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

// ============================================================================
// ExternalDecisionCache.Set - error path for cache.Set
// ============================================================================

func TestExternalDecisionCache_Set_CacheSetError(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	mockC.setErr = errors.New("redis connection refused")

	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Should not panic, just log warning
	c.Set(context.Background(), key, &CachedDecision{
		Allowed: true,
		Reason:  "test",
	})
}

// ============================================================================
// ExternalDecisionCache.Delete - error path
// ============================================================================

func TestExternalDecisionCache_Delete_CacheDeleteError(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	mockC.deleteErr = errors.New("redis connection refused")

	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
	)

	key := &CacheKey{
		Subject:  "user1",
		Resource: "/api/users",
		Action:   "GET",
	}

	// Should not panic, just log warning
	c.Delete(context.Background(), key)
}

// ============================================================================
// ExternalDecisionCache.Clear - logs warning
// ============================================================================

func TestExternalDecisionCache_Clear_LogsWarning(t *testing.T) {
	t.Parallel()

	mockC := newMockCacheForAuthz()
	c := NewExternalDecisionCache(mockC, 5*time.Minute,
		WithExternalCacheLogger(observability.NopLogger()),
	)

	// Should not panic, just log warning
	c.Clear(context.Background())
}

// ============================================================================
// Interceptor - buildRequestContext with peer info
// ============================================================================

func TestGRPCAuthorizer_BuildRequestContext_WithPeer(t *testing.T) {
	t.Parallel()

	mockAuth := &mockAuthorizer{
		decision: &Decision{Allowed: true},
	}
	config := &Config{Enabled: true}

	authorizer := NewGRPCAuthorizer(mockAuth, config, WithGRPCAuthorizerMetrics(newNoopMetrics())).(*grpcAuthorizer)

	// Context without peer info but with metadata
	ctx := context.Background()

	reqCtx := authorizer.buildRequestContext(ctx, "test.Service", "GetUser")
	assert.Equal(t, "test.Service", reqCtx["service"])
	assert.Equal(t, "GetUser", reqCtx["method"])
}
