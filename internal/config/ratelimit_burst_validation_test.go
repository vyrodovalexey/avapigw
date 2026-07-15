// Burst validation alignment tests: the config validator must require
// Burst >= 1 when rate limiting is enabled, matching the operator webhook.
// A zero burst means the token bucket can never hold a whole token — with
// the redis store the Lua bucket starts empty and silently denies every
// request.
package config

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// burstTestConfig builds a minimal valid gateway config with the given
// spec-level rate limit.
func burstTestConfig(rl *RateLimitConfig) *GatewayConfig {
	return &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: "test"},
		Spec: GatewaySpec{
			Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
			RateLimit: rl,
		},
	}
}

func TestValidateRateLimit_BurstAlignment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rl      *RateLimitConfig
		wantErr bool
	}{
		{
			name:    "zero burst rejected when enabled",
			rl:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 0},
			wantErr: true,
		},
		{
			name:    "negative burst rejected when enabled",
			rl:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: -5},
			wantErr: true,
		},
		{
			name:    "burst of one accepted",
			rl:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 1},
			wantErr: false,
		},
		{
			name:    "zero burst allowed when disabled",
			rl:      &RateLimitConfig{Enabled: false, RequestsPerSecond: 0, Burst: 0},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateConfig(burstTestConfig(tt.rl))
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "burst must be at least 1 when enabled")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateRateLimit_RouteAndBackendBurst verifies the burst rule is
// enforced on route-level and backend-level rate limits as well.
func TestValidateRateLimit_RouteAndBackendBurst(t *testing.T) {
	t.Parallel()

	zeroBurst := &RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 0}

	t.Run("route level", func(t *testing.T) {
		t.Parallel()

		cfg := burstTestConfig(nil)
		cfg.Spec.Routes = []Route{
			{
				Name:      "rl-route",
				Match:     []RouteMatch{{URI: &URIMatch{Prefix: "/api"}}},
				Route:     []RouteDestination{{Destination: Destination{Host: "backend", Port: 8080}}},
				RateLimit: zeroBurst,
			},
		}

		err := ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("%s.burst", "spec.routes[0].rateLimit"))
	})

	t.Run("backend level", func(t *testing.T) {
		t.Parallel()

		cfg := burstTestConfig(nil)
		cfg.Spec.Backends = []Backend{
			{
				Name:      "rl-backend",
				Hosts:     []BackendHost{{Address: "10.0.0.1", Port: 8080}},
				RateLimit: zeroBurst,
			},
		}

		err := ValidateConfig(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "burst must be at least 1 when enabled")
	})
}

// TestValidateRateLimit_WebhookParity documents the alignment contract: the
// same boundary values accepted or rejected by the operator webhook
// (internal/operator/webhook validateRateLimit) are accepted or rejected by
// the config validator.
func TestValidateRateLimit_WebhookParity(t *testing.T) {
	t.Parallel()

	boundaries := []struct {
		rps, burst int
		valid      bool
	}{
		{rps: 1, burst: 1, valid: true},
		{rps: 100, burst: 200, valid: true},
		{rps: 0, burst: 100, valid: false},
		{rps: 100, burst: 0, valid: false},
	}

	for _, b := range boundaries {
		name := fmt.Sprintf("rps=%d burst=%d", b.rps, b.burst)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := ValidateConfig(burstTestConfig(&RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: b.rps,
				Burst:             b.burst,
			}))
			if b.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestValidateRateLimit_RedisStoreZeroBurst pins the original failure mode:
// redis-store rate limits with zero burst must fail validation instead of
// creating a bucket that permanently denies all traffic.
func TestValidateRateLimit_RedisStoreZeroBurst(t *testing.T) {
	t.Parallel()

	cfg := burstTestConfig(&RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 50,
		Burst:             0,
		Store:             RateLimitStoreRedis,
		Redis: &RateLimitRedisConfig{
			URL:         "redis://localhost:6379",
			ReadTimeout: Duration(50 * time.Millisecond),
		},
	})

	err := ValidateConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "burst must be at least 1 when enabled")
}
