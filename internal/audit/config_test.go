package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config is valid",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config is valid",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid enabled config",
			config: &Config{
				Enabled: true,
				Level:   LevelInfo,
				Output:  "stdout",
				Format:  "json",
			},
			wantErr: false,
		},
		{
			name: "valid config with text format",
			config: &Config{
				Enabled: true,
				Format:  "text",
			},
			wantErr: false,
		},
		{
			name: "invalid level",
			config: &Config{
				Enabled: true,
				Level:   "invalid",
			},
			wantErr: true,
			errMsg:  "invalid audit level",
		},
		{
			name: "invalid format",
			config: &Config{
				Enabled: true,
				Format:  "xml",
			},
			wantErr: true,
			errMsg:  "invalid audit format",
		},
		{
			name: "negative max body size",
			config: &Config{
				Enabled:     true,
				MaxBodySize: -1,
			},
			wantErr: true,
			errMsg:  "maxBodySize must be non-negative",
		},
		{
			name: "valid file config",
			config: &Config{
				Enabled: true,
				File: &FileConfig{
					Path:       "/var/log/audit.log",
					MaxSize:    100,
					MaxBackups: 5,
					MaxAge:     30,
					Compress:   true,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid file config - empty path",
			config: &Config{
				Enabled: true,
				File: &FileConfig{
					Path: "",
				},
			},
			wantErr: true,
			errMsg:  "path is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFileConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *FileConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config is valid",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid config",
			config: &FileConfig{
				Path:       "/var/log/audit.log",
				MaxSize:    100,
				MaxBackups: 5,
				MaxAge:     30,
				Compress:   true,
			},
			wantErr: false,
		},
		{
			name: "empty path",
			config: &FileConfig{
				Path: "",
			},
			wantErr: true,
			errMsg:  "path is required",
		},
		{
			name: "negative max size",
			config: &FileConfig{
				Path:    "/var/log/audit.log",
				MaxSize: -1,
			},
			wantErr: true,
			errMsg:  "maxSize must be non-negative",
		},
		{
			name: "negative max backups",
			config: &FileConfig{
				Path:       "/var/log/audit.log",
				MaxBackups: -1,
			},
			wantErr: true,
			errMsg:  "maxBackups must be non-negative",
		},
		{
			name: "negative max age",
			config: &FileConfig{
				Path:   "/var/log/audit.log",
				MaxAge: -1,
			},
			wantErr: true,
			errMsg:  "maxAge must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()

	assert.True(t, config.Enabled)
	assert.Equal(t, LevelInfo, config.Level)
	assert.Equal(t, "stdout", config.Output)
	assert.Equal(t, "json", config.Format)
	assert.Equal(t, 4096, config.MaxBodySize)

	// Check events config
	require.NotNil(t, config.Events)
	assert.True(t, config.Events.Authentication)
	assert.True(t, config.Events.Authorization)
	assert.False(t, config.Events.Request)
	assert.False(t, config.Events.Response)
	assert.True(t, config.Events.Configuration)
	assert.True(t, config.Events.Administrative)
	assert.True(t, config.Events.Security)

	// Check redact fields
	assert.Contains(t, config.RedactFields, "password")
	assert.Contains(t, config.RedactFields, "secret")
	assert.Contains(t, config.RedactFields, "token")
	assert.Contains(t, config.RedactFields, "authorization")
}

func TestConfig_GetEffectiveLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected Level
	}{
		{
			name:     "default level when empty",
			config:   &Config{},
			expected: LevelInfo,
		},
		{
			name:     "debug level",
			config:   &Config{Level: LevelDebug},
			expected: LevelDebug,
		},
		{
			name:     "warn level",
			config:   &Config{Level: LevelWarn},
			expected: LevelWarn,
		},
		{
			name:     "error level",
			config:   &Config{Level: LevelError},
			expected: LevelError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.GetEffectiveLevel())
		})
	}
}

func TestConfig_GetEffectiveFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "default format when empty",
			config:   &Config{},
			expected: "json",
		},
		{
			name:     "json format",
			config:   &Config{Format: "json"},
			expected: "json",
		},
		{
			name:     "text format",
			config:   &Config{Format: "text"},
			expected: "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.GetEffectiveFormat())
		})
	}
}

func TestConfig_GetEffectiveOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name:     "default output when empty",
			config:   &Config{},
			expected: "stdout",
		},
		{
			name:     "stdout output",
			config:   &Config{Output: "stdout"},
			expected: "stdout",
		},
		{
			name:     "stderr output",
			config:   &Config{Output: "stderr"},
			expected: "stderr",
		},
		{
			name:     "file output",
			config:   &Config{Output: "/var/log/audit.log"},
			expected: "/var/log/audit.log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.GetEffectiveOutput())
		})
	}
}

func TestConfig_ShouldAuditAuthentication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "disabled config",
			config:   &Config{Enabled: false},
			expected: false,
		},
		{
			name:     "enabled with nil events",
			config:   &Config{Enabled: true, Events: nil},
			expected: true,
		},
		{
			name:     "enabled with authentication true",
			config:   &Config{Enabled: true, Events: &EventsConfig{Authentication: true}},
			expected: true,
		},
		{
			name:     "enabled with authentication false",
			config:   &Config{Enabled: true, Events: &EventsConfig{Authentication: false}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.ShouldAuditAuthentication())
		})
	}
}

func TestConfig_ShouldAuditAuthorization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "disabled config",
			config:   &Config{Enabled: false},
			expected: false,
		},
		{
			name:     "enabled with nil events",
			config:   &Config{Enabled: true, Events: nil},
			expected: true,
		},
		{
			name:     "enabled with authorization true",
			config:   &Config{Enabled: true, Events: &EventsConfig{Authorization: true}},
			expected: true,
		},
		{
			name:     "enabled with authorization false",
			config:   &Config{Enabled: true, Events: &EventsConfig{Authorization: false}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.ShouldAuditAuthorization())
		})
	}
}

func TestConfig_ShouldAuditRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "disabled config",
			config:   &Config{Enabled: false},
			expected: false,
		},
		{
			name:     "enabled with nil events",
			config:   &Config{Enabled: true, Events: nil},
			expected: false,
		},
		{
			name:     "enabled with request true",
			config:   &Config{Enabled: true, Events: &EventsConfig{Request: true}},
			expected: true,
		},
		{
			name:     "enabled with request false",
			config:   &Config{Enabled: true, Events: &EventsConfig{Request: false}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.ShouldAuditRequest())
		})
	}
}

func TestConfig_ShouldAuditResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "enabled with nil events",
			config:   &Config{Enabled: true, Events: nil},
			expected: false,
		},
		{
			name:     "enabled with response true",
			config:   &Config{Enabled: true, Events: &EventsConfig{Response: true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.ShouldAuditResponse())
		})
	}
}

func TestConfig_ShouldAuditConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "enabled with nil events",
			config:   &Config{Enabled: true, Events: nil},
			expected: true,
		},
		{
			name:     "enabled with configuration true",
			config:   &Config{Enabled: true, Events: &EventsConfig{Configuration: true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.ShouldAuditConfiguration())
		})
	}
}

func TestConfig_ShouldAuditAdministrative(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "enabled with nil events",
			config:   &Config{Enabled: true, Events: nil},
			expected: true,
		},
		{
			name:     "enabled with administrative true",
			config:   &Config{Enabled: true, Events: &EventsConfig{Administrative: true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.ShouldAuditAdministrative())
		})
	}
}

func TestConfig_ShouldAuditSecurity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "enabled with nil events",
			config:   &Config{Enabled: true, Events: nil},
			expected: true,
		},
		{
			name:     "enabled with security true",
			config:   &Config{Enabled: true, Events: &EventsConfig{Security: true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.ShouldAuditSecurity())
		})
	}
}

func TestConfig_ShouldSkipPath(t *testing.T) {
	t.Parallel()

	config := &Config{
		SkipPaths: []string{
			"/health",
			"/metrics",
			"/api/internal/*",
		},
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/metrics", true},
		{"/api/internal/status", true},
		{"/api/internal/config", true},
		{"/api/users", false},
		{"/api/v1/users", false},
		{"/healthcheck", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, config.ShouldSkipPath(tt.path))
		})
	}
}

func TestMatchPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "/health",
			path:     "/health",
			expected: true,
		},
		{
			name:     "no match",
			pattern:  "/health",
			path:     "/metrics",
			expected: false,
		},
		{
			name:     "wildcard match",
			pattern:  "/api/*",
			path:     "/api/users",
			expected: true,
		},
		{
			name:     "wildcard match nested",
			pattern:  "/api/*",
			path:     "/api/users/123",
			expected: true,
		},
		{
			name:     "wildcard no match",
			pattern:  "/api/*",
			path:     "/health",
			expected: false,
		},
		{
			name:     "empty pattern",
			pattern:  "",
			path:     "/health",
			expected: false,
		},
		{
			name:     "empty path",
			pattern:  "/health",
			path:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, matchPath(tt.pattern, tt.path))
		})
	}
}

func TestLevelConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, Level("debug"), LevelDebug)
	assert.Equal(t, Level("info"), LevelInfo)
	assert.Equal(t, Level("warn"), LevelWarn)
	assert.Equal(t, Level("error"), LevelError)
}

func TestRetentionConfig(t *testing.T) {
	t.Parallel()

	config := &RetentionConfig{
		MaxAge:   24 * time.Hour,
		MaxSize:  1024 * 1024 * 100, // 100MB
		MaxCount: 10,
	}

	assert.Equal(t, 24*time.Hour, config.MaxAge)
	assert.Equal(t, int64(1024*1024*100), config.MaxSize)
	assert.Equal(t, 10, config.MaxCount)
}

func TestEventsConfig(t *testing.T) {
	t.Parallel()

	config := &EventsConfig{
		Authentication: true,
		Authorization:  true,
		Request:        false,
		Response:       false,
		Configuration:  true,
		Administrative: true,
		Security:       true,
	}

	assert.True(t, config.Authentication)
	assert.True(t, config.Authorization)
	assert.False(t, config.Request)
	assert.False(t, config.Response)
	assert.True(t, config.Configuration)
	assert.True(t, config.Administrative)
	assert.True(t, config.Security)
}
