// Package config provides configuration types and loading for the API Gateway.
package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCacheConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *CacheConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &CacheConfig{},
			expected: true,
		},
		{
			name: "disabled config",
			config: &CacheConfig{
				Enabled: false,
				Type:    CacheTypeMemory,
				TTL:     Duration(5 * time.Minute),
			},
			expected: true,
		},
		{
			name: "enabled config",
			config: &CacheConfig{
				Enabled: true,
				Type:    CacheTypeMemory,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedisCacheConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *RedisCacheConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &RedisCacheConfig{},
			expected: true,
		},
		{
			name: "config without URL",
			config: &RedisCacheConfig{
				PoolSize: 10,
			},
			expected: true,
		},
		{
			name: "config with URL",
			config: &RedisCacheConfig{
				URL: "redis://localhost:6379",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCacheKeyConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   *CacheKeyConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &CacheKeyConfig{},
			expected: true,
		},
		{
			name: "config with include method",
			config: &CacheKeyConfig{
				IncludeMethod: true,
			},
			expected: false,
		},
		{
			name: "config with include path",
			config: &CacheKeyConfig{
				IncludePath: true,
			},
			expected: false,
		},
		{
			name: "config with include query params",
			config: &CacheKeyConfig{
				IncludeQueryParams: []string{"page", "limit"},
			},
			expected: false,
		},
		{
			name: "config with include headers",
			config: &CacheKeyConfig{
				IncludeHeaders: []string{"Accept", "Accept-Language"},
			},
			expected: false,
		},
		{
			name: "config with include body hash",
			config: &CacheKeyConfig{
				IncludeBodyHash: true,
			},
			expected: false,
		},
		{
			name: "config with key template",
			config: &CacheKeyConfig{
				KeyTemplate: "{{.Method}}:{{.Path}}",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()

	assert.NotNil(t, config)
	assert.False(t, config.Enabled)
	assert.Equal(t, CacheTypeMemory, config.Type)
	assert.Equal(t, Duration(300000000000), config.TTL) // 5 minutes
	assert.Equal(t, 10000, config.MaxEntries)
	assert.NotNil(t, config.KeyConfig)
	assert.True(t, config.KeyConfig.IncludeMethod)
	assert.True(t, config.KeyConfig.IncludePath)
}

func TestDefaultRedisCacheConfig(t *testing.T) {
	config := DefaultRedisCacheConfig()

	assert.NotNil(t, config)
	assert.Equal(t, 10, config.PoolSize)
	assert.Equal(t, Duration(5000000000), config.ConnectTimeout) // 5 seconds
	assert.Equal(t, Duration(3000000000), config.ReadTimeout)    // 3 seconds
	assert.Equal(t, Duration(3000000000), config.WriteTimeout)   // 3 seconds
	assert.Equal(t, "avapigw:", config.KeyPrefix)
}

func TestCacheTypeConstants(t *testing.T) {
	assert.Equal(t, "memory", CacheTypeMemory)
	assert.Equal(t, "redis", CacheTypeRedis)
}

func TestCacheConfig_YAMLMarshalUnmarshal(t *testing.T) {
	original := &CacheConfig{
		Enabled:    true,
		Type:       CacheTypeMemory,
		TTL:        Duration(5 * time.Minute),
		MaxEntries: 10000,
		Redis: &RedisCacheConfig{
			URL:            "redis://localhost:6379",
			PoolSize:       10,
			ConnectTimeout: Duration(5 * time.Second),
			ReadTimeout:    Duration(3 * time.Second),
			WriteTimeout:   Duration(3 * time.Second),
			KeyPrefix:      "myapp:",
		},
		KeyConfig: &CacheKeyConfig{
			IncludeMethod:      true,
			IncludePath:        true,
			IncludeQueryParams: []string{"page", "limit"},
			IncludeHeaders:     []string{"Accept"},
			IncludeBodyHash:    false,
		},
		HonorCacheControl:    true,
		StaleWhileRevalidate: Duration(30 * time.Second),
		NegativeCacheTTL:     Duration(1 * time.Minute),
	}

	// Marshal to YAML
	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result CacheConfig
	err = yaml.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Enabled, result.Enabled)
	assert.Equal(t, original.Type, result.Type)
	assert.Equal(t, original.TTL, result.TTL)
	assert.Equal(t, original.MaxEntries, result.MaxEntries)
	assert.Equal(t, original.HonorCacheControl, result.HonorCacheControl)
	assert.Equal(t, original.StaleWhileRevalidate, result.StaleWhileRevalidate)
	assert.Equal(t, original.NegativeCacheTTL, result.NegativeCacheTTL)

	// Verify Redis config
	assert.NotNil(t, result.Redis)
	assert.Equal(t, original.Redis.URL, result.Redis.URL)
	assert.Equal(t, original.Redis.PoolSize, result.Redis.PoolSize)
	assert.Equal(t, original.Redis.KeyPrefix, result.Redis.KeyPrefix)

	// Verify KeyConfig
	assert.NotNil(t, result.KeyConfig)
	assert.Equal(t, original.KeyConfig.IncludeMethod, result.KeyConfig.IncludeMethod)
	assert.Equal(t, original.KeyConfig.IncludePath, result.KeyConfig.IncludePath)
	assert.Equal(t, original.KeyConfig.IncludeQueryParams, result.KeyConfig.IncludeQueryParams)
	assert.Equal(t, original.KeyConfig.IncludeHeaders, result.KeyConfig.IncludeHeaders)
}

func TestCacheConfig_JSONMarshalUnmarshal(t *testing.T) {
	original := &CacheConfig{
		Enabled:    true,
		Type:       CacheTypeRedis,
		TTL:        Duration(10 * time.Minute),
		MaxEntries: 5000,
		Redis: &RedisCacheConfig{
			URL:      "redis://localhost:6379/0",
			PoolSize: 20,
		},
		KeyConfig: &CacheKeyConfig{
			IncludeMethod: true,
			IncludePath:   true,
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result CacheConfig
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Enabled, result.Enabled)
	assert.Equal(t, original.Type, result.Type)
	assert.Equal(t, original.MaxEntries, result.MaxEntries)
	assert.NotNil(t, result.Redis)
	assert.Equal(t, original.Redis.URL, result.Redis.URL)
	assert.Equal(t, original.Redis.PoolSize, result.Redis.PoolSize)
}

func TestRedisCacheConfig_Struct(t *testing.T) {
	config := RedisCacheConfig{
		URL:            "redis://user:password@localhost:6379/0",
		PoolSize:       20,
		ConnectTimeout: Duration(5 * time.Second),
		ReadTimeout:    Duration(3 * time.Second),
		WriteTimeout:   Duration(3 * time.Second),
		KeyPrefix:      "myapp:",
		TLS: &TLSConfig{
			Enabled: true,
		},
	}

	assert.Equal(t, "redis://user:password@localhost:6379/0", config.URL)
	assert.Equal(t, 20, config.PoolSize)
	assert.Equal(t, Duration(5*time.Second), config.ConnectTimeout)
	assert.Equal(t, Duration(3*time.Second), config.ReadTimeout)
	assert.Equal(t, Duration(3*time.Second), config.WriteTimeout)
	assert.Equal(t, "myapp:", config.KeyPrefix)
	assert.NotNil(t, config.TLS)
	assert.True(t, config.TLS.Enabled)
}

func TestCacheKeyConfig_Struct(t *testing.T) {
	config := CacheKeyConfig{
		IncludeMethod:      true,
		IncludePath:        true,
		IncludeQueryParams: []string{"page", "limit", "sort"},
		IncludeHeaders:     []string{"Accept", "Accept-Language"},
		IncludeBodyHash:    true,
		KeyTemplate:        "{{.Method}}:{{.Path}}:{{.Query.page}}",
	}

	assert.True(t, config.IncludeMethod)
	assert.True(t, config.IncludePath)
	assert.Len(t, config.IncludeQueryParams, 3)
	assert.Contains(t, config.IncludeQueryParams, "page")
	assert.Len(t, config.IncludeHeaders, 2)
	assert.Contains(t, config.IncludeHeaders, "Accept")
	assert.True(t, config.IncludeBodyHash)
	assert.NotEmpty(t, config.KeyTemplate)
}

func TestCacheConfig_FullConfiguration(t *testing.T) {
	config := &CacheConfig{
		Enabled:    true,
		Type:       CacheTypeRedis,
		TTL:        Duration(10 * time.Minute),
		MaxEntries: 50000,
		Redis: &RedisCacheConfig{
			URL:            "redis://localhost:6379/0",
			PoolSize:       50,
			ConnectTimeout: Duration(10 * time.Second),
			ReadTimeout:    Duration(5 * time.Second),
			WriteTimeout:   Duration(5 * time.Second),
			KeyPrefix:      "api-gateway:",
			TLS: &TLSConfig{
				Enabled: true,
			},
		},
		KeyConfig: &CacheKeyConfig{
			IncludeMethod:      true,
			IncludePath:        true,
			IncludeQueryParams: []string{"page", "limit", "sort", "filter"},
			IncludeHeaders:     []string{"Accept", "Accept-Language", "Authorization"},
			IncludeBodyHash:    true,
			KeyTemplate:        "",
		},
		HonorCacheControl:    true,
		StaleWhileRevalidate: Duration(1 * time.Minute),
		NegativeCacheTTL:     Duration(30 * time.Second),
	}

	assert.False(t, config.IsEmpty())
	assert.False(t, config.Redis.IsEmpty())
	assert.False(t, config.KeyConfig.IsEmpty())
}

// --- Redis Sentinel Config Tests ---

func TestRedisSentinelConfig_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *RedisSentinelConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "empty config",
			config:   &RedisSentinelConfig{},
			expected: true,
		},
		{
			name: "empty master name",
			config: &RedisSentinelConfig{
				MasterName:    "",
				SentinelAddrs: []string{"localhost:26379"},
			},
			expected: true,
		},
		{
			name: "valid config with master name",
			config: &RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"localhost:26379"},
			},
			expected: false,
		},
		{
			name: "master name only without addrs",
			config: &RedisSentinelConfig{
				MasterName: "mymaster",
			},
			expected: false,
		},
		{
			name: "full config",
			config: &RedisSentinelConfig{
				MasterName:       "mymaster",
				SentinelAddrs:    []string{"sentinel1:26379", "sentinel2:26379", "sentinel3:26379"},
				SentinelPassword: "sentinelpass",
				Password:         "masterpass",
				DB:               2,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedisCacheConfig_IsEmpty_WithSentinel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *RedisCacheConfig
		expected bool
	}{
		{
			name: "sentinel with master name makes config non-empty",
			config: &RedisCacheConfig{
				Sentinel: &RedisSentinelConfig{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"localhost:26379"},
				},
			},
			expected: false,
		},
		{
			name: "sentinel without master name is empty",
			config: &RedisCacheConfig{
				Sentinel: &RedisSentinelConfig{
					SentinelAddrs: []string{"localhost:26379"},
				},
			},
			expected: true,
		},
		{
			name: "nil sentinel is empty",
			config: &RedisCacheConfig{
				Sentinel: nil,
			},
			expected: true,
		},
		{
			name: "both URL and sentinel - non-empty",
			config: &RedisCacheConfig{
				URL: "redis://localhost:6379",
				Sentinel: &RedisSentinelConfig{
					MasterName: "mymaster",
				},
			},
			expected: false,
		},
		{
			name: "URL only - non-empty",
			config: &RedisCacheConfig{
				URL: "redis://localhost:6379",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.config.IsEmpty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultRedisSentinelConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultRedisSentinelConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, DefaultRedisSentinelDB, cfg.DB)
	assert.Equal(t, 0, cfg.DB)
	assert.Empty(t, cfg.MasterName)
	assert.Nil(t, cfg.SentinelAddrs)
	assert.Empty(t, cfg.SentinelPassword)
	assert.Empty(t, cfg.Password)
}

func TestDefaultRedisSentinelDB_Constant(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 0, DefaultRedisSentinelDB)
}

func TestRedisSentinelConfig_YAMLMarshalUnmarshal(t *testing.T) {
	t.Parallel()

	original := &RedisCacheConfig{
		Sentinel: &RedisSentinelConfig{
			MasterName:       "mymaster",
			SentinelAddrs:    []string{"sentinel1:26379", "sentinel2:26379", "sentinel3:26379"},
			SentinelPassword: "sentinelpass",
			Password:         "masterpass",
			DB:               3,
		},
		PoolSize:       20,
		ConnectTimeout: Duration(5 * time.Second),
		ReadTimeout:    Duration(3 * time.Second),
		WriteTimeout:   Duration(3 * time.Second),
		KeyPrefix:      "myapp:",
	}

	// Marshal to YAML
	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result RedisCacheConfig
	err = yaml.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify sentinel config
	require.NotNil(t, result.Sentinel)
	assert.Equal(t, original.Sentinel.MasterName, result.Sentinel.MasterName)
	assert.Equal(t, original.Sentinel.SentinelAddrs, result.Sentinel.SentinelAddrs)
	assert.Equal(t, original.Sentinel.SentinelPassword, result.Sentinel.SentinelPassword)
	assert.Equal(t, original.Sentinel.Password, result.Sentinel.Password)
	assert.Equal(t, original.Sentinel.DB, result.Sentinel.DB)

	// Verify shared config
	assert.Equal(t, original.PoolSize, result.PoolSize)
	assert.Equal(t, original.ConnectTimeout, result.ConnectTimeout)
	assert.Equal(t, original.ReadTimeout, result.ReadTimeout)
	assert.Equal(t, original.WriteTimeout, result.WriteTimeout)
	assert.Equal(t, original.KeyPrefix, result.KeyPrefix)
}

func TestRedisSentinelConfig_JSONMarshalUnmarshal(t *testing.T) {
	t.Parallel()

	original := &RedisCacheConfig{
		Sentinel: &RedisSentinelConfig{
			MasterName:       "mymaster",
			SentinelAddrs:    []string{"sentinel1:26379", "sentinel2:26379"},
			SentinelPassword: "sentinelpass",
			Password:         "masterpass",
			DB:               5,
		},
		PoolSize:  15,
		KeyPrefix: "test:",
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var result RedisCacheConfig
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify sentinel config
	require.NotNil(t, result.Sentinel)
	assert.Equal(t, original.Sentinel.MasterName, result.Sentinel.MasterName)
	assert.Equal(t, original.Sentinel.SentinelAddrs, result.Sentinel.SentinelAddrs)
	assert.Equal(t, original.Sentinel.SentinelPassword, result.Sentinel.SentinelPassword)
	assert.Equal(t, original.Sentinel.Password, result.Sentinel.Password)
	assert.Equal(t, original.Sentinel.DB, result.Sentinel.DB)
	assert.Equal(t, original.PoolSize, result.PoolSize)
	assert.Equal(t, original.KeyPrefix, result.KeyPrefix)
}

func TestCacheConfig_WithSentinel_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := &CacheConfig{
		Enabled:    true,
		Type:       CacheTypeRedis,
		TTL:        Duration(5 * time.Minute),
		MaxEntries: 10000,
		Redis: &RedisCacheConfig{
			Sentinel: &RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel1:26379", "sentinel2:26379"},
				DB:            1,
			},
			PoolSize:  20,
			KeyPrefix: "gw:",
		},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var result CacheConfig
	err = yaml.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, original.Enabled, result.Enabled)
	assert.Equal(t, original.Type, result.Type)
	require.NotNil(t, result.Redis)
	require.NotNil(t, result.Redis.Sentinel)
	assert.Equal(t, "mymaster", result.Redis.Sentinel.MasterName)
	assert.Equal(t, []string{"sentinel1:26379", "sentinel2:26379"}, result.Redis.Sentinel.SentinelAddrs)
	assert.Equal(t, 1, result.Redis.Sentinel.DB)
}

func TestAuthzCacheConfig_RedisField(t *testing.T) {
	t.Parallel()

	cfg := &AuthzCacheConfig{
		Enabled: true,
		TTL:     Duration(5 * time.Minute),
		MaxSize: 1000,
		Type:    CacheTypeRedis,
		Redis: &RedisCacheConfig{
			Sentinel: &RedisSentinelConfig{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel1:26379"},
			},
			KeyPrefix: "authz:",
		},
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, CacheTypeRedis, cfg.Type)
	require.NotNil(t, cfg.Redis)
	require.NotNil(t, cfg.Redis.Sentinel)
	assert.Equal(t, "mymaster", cfg.Redis.Sentinel.MasterName)
	assert.False(t, cfg.Redis.IsEmpty())
}
