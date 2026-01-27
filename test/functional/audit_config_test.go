//go:build functional
// +build functional

package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
)

func TestFunctional_AuditConfig_Validation(t *testing.T) {
	t.Parallel()

	t.Run("valid config with defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid config with file output", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "file",
			Format:  "json",
			File: &audit.FileConfig{
				Path:       "/var/log/audit.log",
				MaxSize:    100,
				MaxBackups: 5,
				MaxAge:     30,
				Compress:   true,
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("valid config with events", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Events: &audit.EventsConfig{
				Authentication: true,
				Authorization:  true,
				Request:        false,
				Response:       false,
				Configuration:  true,
				Administrative: true,
				Security:       true,
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("disabled config is always valid", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: false,
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("nil config is valid", func(t *testing.T) {
		t.Parallel()

		var cfg *audit.Config
		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid level", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   "invalid",
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "level")
	})

	t.Run("invalid format", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Format:  "invalid",
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "format")
	})

	t.Run("negative max body size", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled:     true,
			MaxBodySize: -1,
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maxBodySize")
	})
}

func TestFunctional_AuditConfig_FileValidation(t *testing.T) {
	t.Parallel()

	t.Run("valid file config", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.FileConfig{
			Path:       "/var/log/audit.log",
			MaxSize:    100,
			MaxBackups: 5,
			MaxAge:     30,
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})

	t.Run("missing path", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.FileConfig{
			MaxSize: 100,
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path")
	})

	t.Run("negative max size", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.FileConfig{
			Path:    "/var/log/audit.log",
			MaxSize: -1,
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maxSize")
	})

	t.Run("negative max backups", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.FileConfig{
			Path:       "/var/log/audit.log",
			MaxBackups: -1,
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maxBackups")
	})

	t.Run("negative max age", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.FileConfig{
			Path:   "/var/log/audit.log",
			MaxAge: -1,
		}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maxAge")
	})

	t.Run("nil config is valid", func(t *testing.T) {
		t.Parallel()

		var cfg *audit.FileConfig
		err := cfg.Validate()
		require.NoError(t, err)
	})
}

func TestFunctional_AuditConfig_DefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := audit.DefaultConfig()
	require.NotNil(t, cfg)

	assert.True(t, cfg.Enabled)
	assert.Equal(t, audit.LevelInfo, cfg.Level)
	assert.Equal(t, "stdout", cfg.Output)
	assert.Equal(t, "json", cfg.Format)
	assert.Equal(t, 4096, cfg.MaxBodySize)

	// Check events config
	require.NotNil(t, cfg.Events)
	assert.True(t, cfg.Events.Authentication)
	assert.True(t, cfg.Events.Authorization)
	assert.False(t, cfg.Events.Request)
	assert.False(t, cfg.Events.Response)
	assert.True(t, cfg.Events.Configuration)
	assert.True(t, cfg.Events.Administrative)
	assert.True(t, cfg.Events.Security)

	// Check redact fields
	assert.Contains(t, cfg.RedactFields, "password")
	assert.Contains(t, cfg.RedactFields, "secret")
	assert.Contains(t, cfg.RedactFields, "token")
}

func TestFunctional_AuditConfig_HelperMethods(t *testing.T) {
	t.Parallel()

	t.Run("GetEffectiveLevel", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{Level: audit.LevelDebug}
		assert.Equal(t, audit.LevelDebug, cfg.GetEffectiveLevel())

		cfg.Level = ""
		assert.Equal(t, audit.LevelInfo, cfg.GetEffectiveLevel())
	})

	t.Run("GetEffectiveFormat", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{Format: "text"}
		assert.Equal(t, "text", cfg.GetEffectiveFormat())

		cfg.Format = ""
		assert.Equal(t, "json", cfg.GetEffectiveFormat())
	})

	t.Run("GetEffectiveOutput", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{Output: "stderr"}
		assert.Equal(t, "stderr", cfg.GetEffectiveOutput())

		cfg.Output = ""
		assert.Equal(t, "stdout", cfg.GetEffectiveOutput())
	})

	t.Run("ShouldAuditAuthentication", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events:  &audit.EventsConfig{Authentication: true},
		}
		assert.True(t, cfg.ShouldAuditAuthentication())

		cfg.Events.Authentication = false
		assert.False(t, cfg.ShouldAuditAuthentication())

		cfg.Enabled = false
		assert.False(t, cfg.ShouldAuditAuthentication())
	})

	t.Run("ShouldAuditAuthorization", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events:  &audit.EventsConfig{Authorization: true},
		}
		assert.True(t, cfg.ShouldAuditAuthorization())

		cfg.Events.Authorization = false
		assert.False(t, cfg.ShouldAuditAuthorization())
	})

	t.Run("ShouldAuditRequest", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events:  &audit.EventsConfig{Request: true},
		}
		assert.True(t, cfg.ShouldAuditRequest())

		cfg.Events.Request = false
		assert.False(t, cfg.ShouldAuditRequest())
	})

	t.Run("ShouldAuditResponse", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events:  &audit.EventsConfig{Response: true},
		}
		assert.True(t, cfg.ShouldAuditResponse())

		cfg.Events.Response = false
		assert.False(t, cfg.ShouldAuditResponse())
	})

	t.Run("ShouldAuditConfiguration", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events:  &audit.EventsConfig{Configuration: true},
		}
		assert.True(t, cfg.ShouldAuditConfiguration())

		cfg.Events.Configuration = false
		assert.False(t, cfg.ShouldAuditConfiguration())
	})

	t.Run("ShouldAuditAdministrative", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events:  &audit.EventsConfig{Administrative: true},
		}
		assert.True(t, cfg.ShouldAuditAdministrative())

		cfg.Events.Administrative = false
		assert.False(t, cfg.ShouldAuditAdministrative())
	})

	t.Run("ShouldAuditSecurity", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events:  &audit.EventsConfig{Security: true},
		}
		assert.True(t, cfg.ShouldAuditSecurity())

		cfg.Events.Security = false
		assert.False(t, cfg.ShouldAuditSecurity())
	})

	t.Run("ShouldSkipPath", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			SkipPaths: []string{
				"/health",
				"/metrics",
				"/api/internal/*",
			},
		}

		assert.True(t, cfg.ShouldSkipPath("/health"))
		assert.True(t, cfg.ShouldSkipPath("/metrics"))
		assert.True(t, cfg.ShouldSkipPath("/api/internal/status"))
		assert.False(t, cfg.ShouldSkipPath("/api/users"))
		assert.False(t, cfg.ShouldSkipPath("/healthcheck"))
	})
}

func TestFunctional_AuditConfig_Levels(t *testing.T) {
	t.Parallel()

	validLevels := []audit.Level{
		audit.LevelDebug,
		audit.LevelInfo,
		audit.LevelWarn,
		audit.LevelError,
	}

	for _, level := range validLevels {
		level := level
		t.Run(string(level), func(t *testing.T) {
			t.Parallel()

			cfg := &audit.Config{
				Enabled: true,
				Level:   level,
			}

			err := cfg.Validate()
			require.NoError(t, err)
		})
	}
}

func TestFunctional_AuditConfig_Retention(t *testing.T) {
	t.Parallel()

	t.Run("valid retention config", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Retention: &audit.RetentionConfig{
				MaxAge:   30 * 24 * time.Hour,
				MaxSize:  1024 * 1024 * 1024, // 1GB
				MaxCount: 100,
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})
}

func TestFunctional_AuditConfig_RedactFields(t *testing.T) {
	t.Parallel()

	cfg := &audit.Config{
		Enabled: true,
		RedactFields: []string{
			"password",
			"secret",
			"token",
			"api_key",
			"authorization",
		},
	}

	err := cfg.Validate()
	require.NoError(t, err)

	assert.Len(t, cfg.RedactFields, 5)
	assert.Contains(t, cfg.RedactFields, "password")
	assert.Contains(t, cfg.RedactFields, "secret")
}

func TestFunctional_AuditConfig_BodyInclusion(t *testing.T) {
	t.Parallel()

	t.Run("include request body", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled:            true,
			IncludeRequestBody: true,
			MaxBodySize:        8192,
		}

		err := cfg.Validate()
		require.NoError(t, err)
		assert.True(t, cfg.IncludeRequestBody)
	})

	t.Run("include response body", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled:             true,
			IncludeResponseBody: true,
			MaxBodySize:         8192,
		}

		err := cfg.Validate()
		require.NoError(t, err)
		assert.True(t, cfg.IncludeResponseBody)
	})

	t.Run("include both bodies", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled:             true,
			IncludeRequestBody:  true,
			IncludeResponseBody: true,
			MaxBodySize:         4096,
		}

		err := cfg.Validate()
		require.NoError(t, err)
	})
}

func TestFunctional_AuditConfig_StdoutOutput(t *testing.T) {
	t.Parallel()

	t.Run("stdout output is valid", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
		}

		err := cfg.Validate()
		require.NoError(t, err)
		assert.Equal(t, "stdout", cfg.Output)
		assert.Equal(t, "stdout", cfg.GetEffectiveOutput())
	})

	t.Run("empty output defaults to stdout", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "",
			Format:  "json",
		}

		err := cfg.Validate()
		require.NoError(t, err)
		assert.Equal(t, "stdout", cfg.GetEffectiveOutput())
	})

	t.Run("stderr output is valid", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stderr",
			Format:  "json",
		}

		err := cfg.Validate()
		require.NoError(t, err)
		assert.Equal(t, "stderr", cfg.GetEffectiveOutput())
	})

	t.Run("default config uses stdout output", func(t *testing.T) {
		t.Parallel()

		cfg := audit.DefaultConfig()
		require.NotNil(t, cfg)
		assert.Equal(t, "stdout", cfg.Output)
		assert.Equal(t, "stdout", cfg.GetEffectiveOutput())
	})
}

func TestFunctional_AuditConfig_EventsMapping(t *testing.T) {
	t.Parallel()

	t.Run("all events enabled", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events: &audit.EventsConfig{
				Authentication: true,
				Authorization:  true,
				Request:        true,
				Response:       true,
				Configuration:  true,
				Administrative: true,
				Security:       true,
			},
		}

		assert.True(t, cfg.ShouldAuditAuthentication())
		assert.True(t, cfg.ShouldAuditAuthorization())
		assert.True(t, cfg.ShouldAuditRequest())
		assert.True(t, cfg.ShouldAuditResponse())
		assert.True(t, cfg.ShouldAuditConfiguration())
		assert.True(t, cfg.ShouldAuditAdministrative())
		assert.True(t, cfg.ShouldAuditSecurity())
	})

	t.Run("all events disabled", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events: &audit.EventsConfig{
				Authentication: false,
				Authorization:  false,
				Request:        false,
				Response:       false,
				Configuration:  false,
				Administrative: false,
				Security:       false,
			},
		}

		assert.False(t, cfg.ShouldAuditAuthentication())
		assert.False(t, cfg.ShouldAuditAuthorization())
		assert.False(t, cfg.ShouldAuditRequest())
		assert.False(t, cfg.ShouldAuditResponse())
		assert.False(t, cfg.ShouldAuditConfiguration())
		assert.False(t, cfg.ShouldAuditAdministrative())
		assert.False(t, cfg.ShouldAuditSecurity())
	})

	t.Run("nil events config uses defaults", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Events:  nil,
		}

		// With nil events, authentication/authorization/configuration/administrative/security default to true
		assert.True(t, cfg.ShouldAuditAuthentication())
		assert.True(t, cfg.ShouldAuditAuthorization())
		assert.True(t, cfg.ShouldAuditConfiguration())
		assert.True(t, cfg.ShouldAuditAdministrative())
		assert.True(t, cfg.ShouldAuditSecurity())

		// Request and Response require explicit Events config
		assert.False(t, cfg.ShouldAuditRequest())
		assert.False(t, cfg.ShouldAuditResponse())
	})

	t.Run("disabled config disables all events", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: false,
			Events: &audit.EventsConfig{
				Authentication: true,
				Authorization:  true,
				Request:        true,
				Response:       true,
				Configuration:  true,
				Administrative: true,
				Security:       true,
			},
		}

		assert.False(t, cfg.ShouldAuditAuthentication())
		assert.False(t, cfg.ShouldAuditAuthorization())
		assert.False(t, cfg.ShouldAuditRequest())
		assert.False(t, cfg.ShouldAuditResponse())
		assert.False(t, cfg.ShouldAuditConfiguration())
		assert.False(t, cfg.ShouldAuditAdministrative())
		assert.False(t, cfg.ShouldAuditSecurity())
	})
}

func TestFunctional_AuditConfig_MiddlewareIntegration(t *testing.T) {
	t.Parallel()

	t.Run("config with stdout output creates valid logger", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "json",
			Events: &audit.EventsConfig{
				Request:  true,
				Response: true,
			},
			SkipPaths: []string{"/health", "/metrics"},
			RedactFields: []string{
				"password",
				"secret",
				"token",
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)

		// Verify the config is suitable for middleware use
		assert.True(t, cfg.Enabled)
		assert.Equal(t, "stdout", cfg.GetEffectiveOutput())
		assert.Equal(t, "json", cfg.GetEffectiveFormat())
		assert.Equal(t, audit.LevelInfo, cfg.GetEffectiveLevel())
		assert.True(t, cfg.ShouldAuditRequest())
		assert.True(t, cfg.ShouldAuditResponse())
		assert.True(t, cfg.ShouldSkipPath("/health"))
		assert.True(t, cfg.ShouldSkipPath("/metrics"))
		assert.False(t, cfg.ShouldSkipPath("/api/v1/items"))
	})

	t.Run("config with all defaults creates valid logger", func(t *testing.T) {
		t.Parallel()

		cfg := audit.DefaultConfig()
		require.NotNil(t, cfg)

		err := cfg.Validate()
		require.NoError(t, err)

		assert.True(t, cfg.Enabled)
		assert.Equal(t, "stdout", cfg.GetEffectiveOutput())
		assert.Equal(t, "json", cfg.GetEffectiveFormat())
		assert.Equal(t, audit.LevelInfo, cfg.GetEffectiveLevel())
	})

	t.Run("config with text format is valid", func(t *testing.T) {
		t.Parallel()

		cfg := &audit.Config{
			Enabled: true,
			Level:   audit.LevelInfo,
			Output:  "stdout",
			Format:  "text",
		}

		err := cfg.Validate()
		require.NoError(t, err)
		assert.Equal(t, "text", cfg.GetEffectiveFormat())
	})
}
