package authz

// Tests for the Vault-resolved Redis password path of the authorization
// decision cache: WithAuthorizerVaultClient supplies the client, and
// buildRedisDecisionCache forwards it to the backing cache so
// redis.passwordVaultPath is resolved. Mirrors
// internal/cache/copy_on_resolve_test.go, including the no-write-back
// assertion on the shared configuration.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// authzMockKVClient implements vault.KVClient serving fixed secrets.
type authzMockKVClient struct {
	readData map[string]map[string]interface{}
}

func (m *authzMockKVClient) Read(
	_ context.Context, mount, path string,
) (map[string]interface{}, error) {
	key := mount + "/" + path
	if data, ok := m.readData[key]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("secret not found at %s", key)
}

func (m *authzMockKVClient) Write(
	_ context.Context, _, _ string, _ map[string]interface{},
) error {
	return nil
}

func (m *authzMockKVClient) Delete(_ context.Context, _, _ string) error { return nil }

func (m *authzMockKVClient) List(_ context.Context, _, _ string) ([]string, error) {
	return nil, nil
}

// authzMockVaultClient implements vault.Client backed by authzMockKVClient.
type authzMockVaultClient struct {
	enabled bool
	kv      vault.KVClient
}

func (m *authzMockVaultClient) IsEnabled() bool                    { return m.enabled }
func (m *authzMockVaultClient) Authenticate(context.Context) error { return nil }
func (m *authzMockVaultClient) RenewToken(context.Context) error   { return nil }
func (m *authzMockVaultClient) Health(context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (m *authzMockVaultClient) PKI() vault.PKIClient         { return nil }
func (m *authzMockVaultClient) KV() vault.KVClient           { return m.kv }
func (m *authzMockVaultClient) Transit() vault.TransitClient { return nil }
func (m *authzMockVaultClient) Close() error                 { return nil }

// newAuthzMockVaultClient returns an enabled vault client serving the given
// password at secret/redis.
func newAuthzMockVaultClient(password string) *authzMockVaultClient {
	return &authzMockVaultClient{
		enabled: true,
		kv: &authzMockKVClient{readData: map[string]map[string]interface{}{
			"secret/redis": {"password": password},
		}},
	}
}

// TestWithAuthorizerVaultClient_OptionApplied verifies the functional
// option stores the client on the authorizer.
func TestWithAuthorizerVaultClient_OptionApplied(t *testing.T) {
	t.Parallel()

	vaultClient := newAuthzMockVaultClient("unused")

	a, err := New(newRedisCacheAuthzConfig(nil), WithAuthorizerVaultClient(vaultClient))
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })

	concrete, ok := a.(*authorizer)
	require.True(t, ok)
	assert.Same(t, vaultClient, concrete.vaultClient,
		"WithAuthorizerVaultClient must store the supplied client")
}

// TestAuthorizer_RedisDecisionCache_VaultPassword covers the
// PasswordVaultPath resolution branch: an auth-protected Redis is only
// reachable with the Vault-resolved password, so the external decision
// cache coming up proves the vault client was forwarded to the backing
// cache builder.
func TestAuthorizer_RedisDecisionCache_VaultPassword(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	mr.RequireAuth("vault-password")

	cacheCfg := &CacheConfig{
		Enabled: true,
		Type:    "redis",
		TTL:     time.Minute,
		Redis: &config.RedisCacheConfig{
			URL:               "redis://" + mr.Addr(),
			PasswordVaultPath: "secret/redis",
		},
	}
	before, err := json.Marshal(cacheCfg.Redis)
	require.NoError(t, err)

	a, err := New(newRedisCacheAuthzConfig(cacheCfg),
		WithAuthorizerVaultClient(newAuthzMockVaultClient("vault-password")))
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })

	concrete, ok := a.(*authorizer)
	require.True(t, ok)
	_, isExternal := concrete.cache.(*externalDecisionCache)
	require.True(t, isExternal,
		"vault-resolved password must bring up the redis-backed external decision cache")

	// A decision round-trips through the auth-protected Redis.
	key := &CacheKey{Subject: "alice", Resource: "/api", Action: "GET"}
	concrete.cache.Set(context.Background(), key, &CachedDecision{Allowed: true, Policy: "allow-admin"})
	cached, cacheHit := concrete.cache.Get(context.Background(), key)
	require.True(t, cacheHit, "decision must be readable back from redis")
	assert.True(t, cached.Allowed)

	// Copy-on-resolve parity with internal/cache: the resolved password must
	// never be written back into the caller's shared configuration.
	after, err := json.Marshal(cacheCfg.Redis)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after),
		"caller's redis cache config must be byte-unchanged after vault resolution")
	assert.NotContains(t, string(after), "vault-password",
		"resolved password must never appear in the shared config")
}

// TestAuthorizer_RedisDecisionCache_VaultPassword_WrongSecretFallsBack
// covers the error path: a wrong Vault password cannot authenticate, so the
// authorizer falls back to the in-memory decision cache.
func TestAuthorizer_RedisDecisionCache_VaultPassword_WrongSecretFallsBack(t *testing.T) {
	t.Parallel()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	mr.RequireAuth("real-password")

	cacheCfg := &CacheConfig{
		Enabled: true,
		Type:    "redis",
		TTL:     time.Minute,
		Redis: &config.RedisCacheConfig{
			URL:               "redis://" + mr.Addr(),
			PasswordVaultPath: "secret/redis",
			Retry: &config.RedisRetryConfig{
				MaxRetries:     1,
				InitialBackoff: config.Duration(time.Millisecond),
				MaxBackoff:     config.Duration(2 * time.Millisecond),
			},
		},
	}

	a, err := New(newRedisCacheAuthzConfig(cacheCfg),
		WithAuthorizerVaultClient(newAuthzMockVaultClient("wrong-password")))
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })

	concrete, ok := a.(*authorizer)
	require.True(t, ok)
	_, isMemory := concrete.cache.(*memoryDecisionCache)
	assert.True(t, isMemory,
		"unusable vault-resolved credentials must fall back to the in-memory decision cache")
}
