package config

// Tests for the development-phase fixes:
//   - T3.A1 (H1): RequiresVaultTLS covers backend/grpcBackend/graphqlBackend
//     tls.vault and mTLS-auth vault blocks + route-level overrides, and the
//     validator disabled-conflict rule fires for backend-only PKI usage;
//   - T3.A4 (M8): TracingConfig OTLP TLS fields and transport resolution;
//   - T3.E1 (M4): validator warning for mixed zero/non-zero weights;
//   - T3.H2 (H2-op): AuthzCacheConfig sentinel shape validation;
//   - RedisCacheConfig/RedisSentinelConfig Clone (copy-on-resolve support).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vaultTLSBoolPtr returns a pointer to b (test helper).
func vaultTLSBoolPtr(b bool) *bool { return &b }

func TestRequiresVaultTLS_BackendBlindSpotFixed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		spec     GatewaySpec
		expected bool
	}{
		{
			name:     "empty spec",
			spec:     GatewaySpec{},
			expected: false,
		},
		{
			name: "backend tls.vault enabled",
			spec: GatewaySpec{
				Backends: []Backend{{
					Name: "b",
					TLS:  &BackendTLSConfig{Enabled: true, Vault: &VaultBackendTLSConfig{Enabled: true}},
				}},
			},
			expected: true,
		},
		{
			name: "backend tls.vault disabled",
			spec: GatewaySpec{
				Backends: []Backend{{
					Name: "b",
					TLS:  &BackendTLSConfig{Enabled: true, Vault: &VaultBackendTLSConfig{Enabled: false}},
				}},
			},
			expected: false,
		},
		{
			name: "grpc backend tls.vault enabled",
			spec: GatewaySpec{
				GRPCBackends: []GRPCBackend{{
					Name: "gb",
					TLS:  &TLSConfig{Enabled: true, Vault: &VaultGRPCTLSConfig{Enabled: true}},
				}},
			},
			expected: true,
		},
		{
			name: "graphql backend tls.vault enabled",
			spec: GatewaySpec{
				GraphQLBackends: []GraphQLBackend{{
					Name: "qb",
					TLS:  &BackendTLSConfig{Enabled: true, Vault: &VaultBackendTLSConfig{Enabled: true}},
				}},
			},
			expected: true,
		},
		{
			name: "backend mtls auth vault enabled",
			spec: GatewaySpec{
				Backends: []Backend{{
					Name: "b",
					Authentication: &BackendAuthConfig{
						Type: "mtls",
						MTLS: &BackendMTLSAuthConfig{
							Enabled: true,
							Vault:   &VaultBackendTLSConfig{Enabled: true},
						},
					},
				}},
			},
			expected: true,
		},
		{
			name: "backend mtls auth disabled",
			spec: GatewaySpec{
				Backends: []Backend{{
					Name: "b",
					Authentication: &BackendAuthConfig{
						Type: "mtls",
						MTLS: &BackendMTLSAuthConfig{
							Enabled: false,
							Vault:   &VaultBackendTLSConfig{Enabled: true},
						},
					},
				}},
			},
			expected: false,
		},
		{
			name: "grpc backend mtls auth vault enabled",
			spec: GatewaySpec{
				GRPCBackends: []GRPCBackend{{
					Name: "gb",
					Authentication: &BackendAuthConfig{
						Type: "mtls",
						MTLS: &BackendMTLSAuthConfig{
							Enabled: true,
							Vault:   &VaultBackendTLSConfig{Enabled: true},
						},
					},
				}},
			},
			expected: true,
		},
		{
			name: "grpc route tls.vault enabled",
			spec: GatewaySpec{
				GRPCRoutes: []GRPCRoute{{
					Name: "gr",
					TLS:  &RouteTLSConfig{Vault: &VaultTLSConfig{Enabled: true}},
				}},
			},
			expected: true,
		},
		{
			name: "graphql route tls.vault enabled",
			spec: GatewaySpec{
				GraphQLRoutes: []GraphQLRoute{{
					Name: "qr",
					TLS:  &RouteTLSConfig{Vault: &VaultTLSConfig{Enabled: true}},
				}},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.spec.RequiresVaultTLS())
		})
	}
}

// TestValidateVaultSpec_DisabledConflict_BackendOnlyPKI is the H1
// acceptance criterion: an explicitly disabled spec.vault combined with
// backend-only tls.vault usage must fail validation with a clear message
// (previously only an opaque runtime error at TLS-build time).
func TestValidateVaultSpec_DisabledConflict_BackendOnlyPKI(t *testing.T) {
	t.Parallel()

	cfg := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "g"},
		Spec: GatewaySpec{
			Listeners: []Listener{{Name: "http", Port: 8080, Protocol: ProtocolHTTP}},
			Backends: []Backend{{
				Name:  "b",
				Hosts: []BackendHost{{Address: "127.0.0.1", Port: 9000}},
				TLS: &BackendTLSConfig{
					Enabled: true,
					Vault: &VaultBackendTLSConfig{
						Enabled:    true,
						PKIMount:   "pki",
						Role:       "role",
						CommonName: "b.local",
					},
				},
			}},
			Vault: &VaultConfig{Enabled: false},
		},
	}

	err := ValidateConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.vault.enabled")
	assert.Contains(t, err.Error(), "tls.vault")
}

func TestTracingConfig_EffectiveOTLPInsecure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *TracingConfig
		expected bool
	}{
		{name: "nil config defaults insecure", cfg: nil, expected: true},
		{
			name:     "explicit insecure true wins over TLS material",
			cfg:      &TracingConfig{OTLPInsecure: vaultTLSBoolPtr(true), OTLPTLS: &OTLPTLSConfig{CAFile: "/ca.crt"}},
			expected: true,
		},
		{
			name:     "explicit insecure false",
			cfg:      &TracingConfig{OTLPInsecure: vaultTLSBoolPtr(false), OTLPEndpoint: "localhost:4317"},
			expected: false,
		},
		{
			name:     "TLS material forces TLS",
			cfg:      &TracingConfig{OTLPEndpoint: "localhost:4317", OTLPTLS: &OTLPTLSConfig{CAFile: "/ca.crt"}},
			expected: false,
		},
		{
			name:     "unset endpoint stays plaintext",
			cfg:      &TracingConfig{},
			expected: true,
		},
		{
			name:     "localhost endpoint stays plaintext",
			cfg:      &TracingConfig{OTLPEndpoint: "localhost:4317"},
			expected: true,
		},
		{
			name:     "127.0.0.1 endpoint stays plaintext",
			cfg:      &TracingConfig{OTLPEndpoint: "127.0.0.1:4317"},
			expected: true,
		},
		{
			name:     "ipv6 loopback stays plaintext",
			cfg:      &TracingConfig{OTLPEndpoint: "[::1]:4317"},
			expected: true,
		},
		{
			name:     "scheme-prefixed localhost stays plaintext",
			cfg:      &TracingConfig{OTLPEndpoint: "http://localhost:4317"},
			expected: true,
		},
		{
			name:     "remote endpoint defaults to TLS",
			cfg:      &TracingConfig{OTLPEndpoint: "otel-collector.observability:4317"},
			expected: false,
		},
		{
			name:     "remote IP defaults to TLS",
			cfg:      &TracingConfig{OTLPEndpoint: "10.0.0.5:4317"},
			expected: false,
		},
		{
			name:     "bare remote host without port defaults to TLS",
			cfg:      &TracingConfig{OTLPEndpoint: "otel-collector"},
			expected: false,
		},
		{
			name:     "bare localhost without port stays plaintext",
			cfg:      &TracingConfig{OTLPEndpoint: "localhost"},
			expected: true,
		},
		{
			name:     "https URL with path defaults to TLS",
			cfg:      &TracingConfig{OTLPEndpoint: "https://collector:4318/v1/traces"},
			expected: false,
		},
		{
			name:     "http URL with path on loopback stays plaintext",
			cfg:      &TracingConfig{OTLPEndpoint: "http://127.0.0.1:4318/v1/traces"},
			expected: true,
		},
		{
			name:     "bracketed ipv6 loopback without port stays plaintext",
			cfg:      &TracingConfig{OTLPEndpoint: "[::1]"},
			expected: true,
		},
		{
			name:     "whitespace-padded endpoint is trimmed",
			cfg:      &TracingConfig{OTLPEndpoint: "  localhost:4317  "},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.EffectiveOTLPInsecure())
		})
	}
}

func TestValidateTracing_OTLPTLS(t *testing.T) {
	t.Parallel()

	base := func(tracing *TracingConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "g"},
			Spec: GatewaySpec{
				Listeners:     []Listener{{Name: "http", Port: 8080, Protocol: ProtocolHTTP}},
				Observability: &ObservabilityConfig{Tracing: tracing},
			},
		}
	}

	t.Run("cert without key rejected", func(t *testing.T) {
		t.Parallel()
		err := ValidateConfig(base(&TracingConfig{
			OTLPTLS: &OTLPTLSConfig{CertFile: "/tls.crt"},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "keyFile is required")
	})

	t.Run("key without cert rejected", func(t *testing.T) {
		t.Parallel()
		err := ValidateConfig(base(&TracingConfig{
			OTLPTLS: &OTLPTLSConfig{KeyFile: "/tls.key"},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certFile is required")
	})

	t.Run("full material accepted", func(t *testing.T) {
		t.Parallel()
		err := ValidateConfig(base(&TracingConfig{
			OTLPTLS: &OTLPTLSConfig{CertFile: "/tls.crt", KeyFile: "/tls.key", CAFile: "/ca.crt"},
		}))
		assert.NoError(t, err)
	})

	t.Run("insecure with TLS material warns", func(t *testing.T) {
		t.Parallel()
		warnings, err := ValidateConfigWithWarnings(base(&TracingConfig{
			OTLPInsecure: vaultTLSBoolPtr(true),
			OTLPTLS:      &OTLPTLSConfig{CAFile: "/ca.crt"},
		}))
		require.NoError(t, err)
		found := false
		for _, w := range warnings {
			if w.Path == "spec.observability.tracing.otlpTLS" {
				found = true
			}
		}
		assert.True(t, found, "expected otlpTLS-ignored warning, got %v", warnings)
	})
}

// TestValidateRouteDestinations_MixedZeroWeightWarns covers the T3.E1
// validator side: mixed zero/non-zero weights produce a warning.
func TestValidateRouteDestinations_MixedZeroWeightWarns(t *testing.T) {
	t.Parallel()

	cfg := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "g"},
		Spec: GatewaySpec{
			Listeners: []Listener{{Name: "http", Port: 8080, Protocol: ProtocolHTTP}},
			Routes: []Route{{
				Name:  "canary",
				Match: []RouteMatch{{URI: &URIMatch{Prefix: "/"}}},
				Route: []RouteDestination{
					{Destination: Destination{Host: "a", Port: 8081}, Weight: 100},
					{Destination: Destination{Host: "b", Port: 8082}, Weight: 0},
				},
			}},
		},
	}

	warnings, err := ValidateConfigWithWarnings(cfg)
	require.NoError(t, err)

	found := false
	for _, w := range warnings {
		if w.Path == "spec.routes[0].route" {
			found = true
			assert.Contains(t, w.Message, "weight 0")
		}
	}
	assert.True(t, found, "expected mixed-weight warning, got %v", warnings)
}

func TestValidateAuthzCacheConfig_SentinelShapes(t *testing.T) {
	t.Parallel()

	base := func(cache *AuthzCacheConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "g"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: ProtocolHTTP}},
				Authorization: &AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					RBAC: &RBACConfig{
						Enabled: true,
						Policies: []RBACPolicyConfig{{
							Name: "p", Roles: []string{"admin"},
							Resources: []string{"/*"}, Actions: []string{"*"},
						}},
					},
					Cache: cache,
				},
			},
		}
	}

	t.Run("CRD sentinel shape accepted", func(t *testing.T) {
		t.Parallel()
		err := ValidateConfig(base(&AuthzCacheConfig{
			Enabled: true,
			Type:    CacheTypeRedis,
			Sentinel: &RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"s1:26379"},
			},
		}))
		assert.NoError(t, err)
	})

	t.Run("sentinel plus redis url rejected", func(t *testing.T) {
		t.Parallel()
		err := ValidateConfig(base(&AuthzCacheConfig{
			Enabled:  true,
			Type:     CacheTypeRedis,
			Redis:    &RedisCacheConfig{URL: "redis://localhost:6379"},
			Sentinel: &RedisSentinelConfig{MasterName: "m", SentinelAddrs: []string{"s1:26379"}},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("redis type without connection warns", func(t *testing.T) {
		t.Parallel()
		warnings, err := ValidateConfigWithWarnings(base(&AuthzCacheConfig{
			Enabled: true,
			Type:    CacheTypeRedis,
		}))
		require.NoError(t, err)
		found := false
		for _, w := range warnings {
			if w.Path == "spec.authorization.cache.type" {
				found = true
			}
		}
		assert.True(t, found, "expected fallback warning, got %v", warnings)
	})
}

func TestRedisCacheConfig_Clone(t *testing.T) {
	t.Parallel()

	t.Run("nil safe", func(t *testing.T) {
		t.Parallel()
		var rcc *RedisCacheConfig
		assert.Nil(t, rcc.Clone())
		var rsc *RedisSentinelConfig
		assert.Nil(t, rsc.Clone())
	})

	t.Run("deep copy", func(t *testing.T) {
		t.Parallel()
		original := &RedisCacheConfig{
			URL: "redis://localhost:6379",
			Sentinel: &RedisSentinelConfig{
				MasterName:    "m",
				SentinelAddrs: []string{"s1:26379"},
				Password:      "raw",
			},
		}

		clone := original.Clone()
		require.NotNil(t, clone)
		require.NotSame(t, original, clone)
		require.NotSame(t, original.Sentinel, clone.Sentinel)

		// Mutating the clone (copy-on-resolve target) must not leak back.
		clone.URL = "redis://:secret@localhost:6379"
		clone.Sentinel.Password = "resolved-secret"
		clone.Sentinel.SentinelAddrs[0] = "changed:26379"

		assert.Equal(t, "redis://localhost:6379", original.URL)
		assert.Equal(t, "raw", original.Sentinel.Password)
		assert.Equal(t, "s1:26379", original.Sentinel.SentinelAddrs[0])
	})
}
