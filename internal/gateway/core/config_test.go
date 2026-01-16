package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestBaseConfig_InitSkipPaths(t *testing.T) {
	t.Parallel()

	t.Run("initializes empty map for empty slice", func(t *testing.T) {
		config := BaseConfig{}
		config.InitSkipPaths()

		assert.NotNil(t, config.skipPathMap)
		assert.Len(t, config.skipPathMap, 0)
	})

	t.Run("initializes map from slice", func(t *testing.T) {
		config := BaseConfig{
			SkipPaths: []string{"/health", "/ready", "/metrics"},
		}
		config.InitSkipPaths()

		assert.Len(t, config.skipPathMap, 3)
		assert.True(t, config.skipPathMap["/health"])
		assert.True(t, config.skipPathMap["/ready"])
		assert.True(t, config.skipPathMap["/metrics"])
	})
}

func TestBaseConfig_ShouldSkip(t *testing.T) {
	t.Parallel()

	t.Run("returns false when map is nil", func(t *testing.T) {
		config := BaseConfig{}

		assert.False(t, config.ShouldSkip("/any/path"))
	})

	t.Run("returns false for non-skip paths", func(t *testing.T) {
		config := BaseConfig{
			SkipPaths: []string{"/health"},
		}
		config.InitSkipPaths()

		assert.False(t, config.ShouldSkip("/api/v1/users"))
	})

	t.Run("returns true for skip paths", func(t *testing.T) {
		config := BaseConfig{
			SkipPaths: []string{"/health", "/ready"},
		}
		config.InitSkipPaths()

		assert.True(t, config.ShouldSkip("/health"))
		assert.True(t, config.ShouldSkip("/ready"))
	})
}

func TestBaseConfig_GetLogger(t *testing.T) {
	t.Parallel()

	t.Run("returns noop logger when nil", func(t *testing.T) {
		config := BaseConfig{}

		logger := config.GetLogger()

		assert.NotNil(t, logger)
	})

	t.Run("returns configured logger", func(t *testing.T) {
		expectedLogger := zap.NewNop()
		config := BaseConfig{
			Logger: expectedLogger,
		}

		logger := config.GetLogger()

		assert.Equal(t, expectedLogger, logger)
	})
}

func TestDefaultRateLimitCoreConfig(t *testing.T) {
	t.Parallel()

	config := DefaultRateLimitCoreConfig()

	assert.True(t, config.IncludeHeaders)
	assert.Nil(t, config.Limiter)
	assert.Nil(t, config.KeyFunc)
}

func TestDefaultCircuitBreakerCoreConfig(t *testing.T) {
	t.Parallel()

	config := DefaultCircuitBreakerCoreConfig()

	assert.Nil(t, config.Registry)
	assert.Nil(t, config.NameFunc)
}

func TestDefaultAuthCoreConfig(t *testing.T) {
	t.Parallel()

	config := DefaultAuthCoreConfig()

	assert.True(t, config.RequireAuth)
	assert.False(t, config.AllowAnonymous)
	assert.False(t, config.JWTEnabled)
	assert.False(t, config.APIKeyEnabled)
	assert.False(t, config.BasicEnabled)
}

func TestAuthCoreConfig_InitAnonymousPaths(t *testing.T) {
	t.Parallel()

	t.Run("initializes empty map for empty slice", func(t *testing.T) {
		config := AuthCoreConfig{}
		config.InitAnonymousPaths()

		assert.NotNil(t, config.anonymousPathMap)
		assert.Len(t, config.anonymousPathMap, 0)
	})

	t.Run("initializes map from slice", func(t *testing.T) {
		config := AuthCoreConfig{
			AnonymousPaths: []string{"/public", "/docs"},
		}
		config.InitAnonymousPaths()

		assert.Len(t, config.anonymousPathMap, 2)
		assert.True(t, config.anonymousPathMap["/public"])
		assert.True(t, config.anonymousPathMap["/docs"])
	})
}

func TestAuthCoreConfig_IsAnonymousPath(t *testing.T) {
	t.Parallel()

	t.Run("returns false when map is nil", func(t *testing.T) {
		config := AuthCoreConfig{}

		assert.False(t, config.IsAnonymousPath("/any/path"))
	})

	t.Run("returns false for non-anonymous paths", func(t *testing.T) {
		config := AuthCoreConfig{
			AnonymousPaths: []string{"/public"},
		}
		config.InitAnonymousPaths()

		assert.False(t, config.IsAnonymousPath("/private"))
	})

	t.Run("returns true for anonymous paths", func(t *testing.T) {
		config := AuthCoreConfig{
			AnonymousPaths: []string{"/public", "/docs"},
		}
		config.InitAnonymousPaths()

		assert.True(t, config.IsAnonymousPath("/public"))
		assert.True(t, config.IsAnonymousPath("/docs"))
	})
}
