package audit

import (
	"errors"
	"fmt"
	"time"
)

// Level represents the audit log level.
type Level string

// Audit log levels.
const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Config represents the audit logging configuration.
type Config struct {
	// Enabled enables audit logging.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Level is the minimum audit level to log.
	Level Level `yaml:"level,omitempty" json:"level,omitempty"`

	// Output specifies the output destination (stdout, stderr, file path).
	Output string `yaml:"output,omitempty" json:"output,omitempty"`

	// Format specifies the output format (json, text).
	Format string `yaml:"format,omitempty" json:"format,omitempty"`

	// File configures file output.
	File *FileConfig `yaml:"file,omitempty" json:"file,omitempty"`

	// Events configures which events to audit.
	Events *EventsConfig `yaml:"events,omitempty" json:"events,omitempty"`

	// Retention configures log retention.
	Retention *RetentionConfig `yaml:"retention,omitempty" json:"retention,omitempty"`

	// IncludeRequestBody includes request body in audit logs.
	IncludeRequestBody bool `yaml:"includeRequestBody,omitempty" json:"includeRequestBody,omitempty"`

	// IncludeResponseBody includes response body in audit logs.
	IncludeResponseBody bool `yaml:"includeResponseBody,omitempty" json:"includeResponseBody,omitempty"`

	// MaxBodySize is the maximum body size to include in logs.
	MaxBodySize int `yaml:"maxBodySize,omitempty" json:"maxBodySize,omitempty"`

	// RedactFields specifies fields to redact from logs.
	RedactFields []string `yaml:"redactFields,omitempty" json:"redactFields,omitempty"`

	// SkipPaths specifies paths to skip auditing.
	SkipPaths []string `yaml:"skipPaths,omitempty" json:"skipPaths,omitempty"`
}

// FileConfig configures file output for audit logs.
type FileConfig struct {
	// Path is the file path.
	Path string `yaml:"path" json:"path"`

	// MaxSize is the maximum size in megabytes before rotation.
	MaxSize int `yaml:"maxSize,omitempty" json:"maxSize,omitempty"`

	// MaxBackups is the maximum number of old log files to retain.
	MaxBackups int `yaml:"maxBackups,omitempty" json:"maxBackups,omitempty"`

	// MaxAge is the maximum number of days to retain old log files.
	MaxAge int `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`

	// Compress determines if rotated files should be compressed.
	Compress bool `yaml:"compress,omitempty" json:"compress,omitempty"`
}

// EventsConfig configures which events to audit.
type EventsConfig struct {
	// Authentication enables authentication event auditing.
	Authentication bool `yaml:"authentication,omitempty" json:"authentication,omitempty"`

	// Authorization enables authorization event auditing.
	Authorization bool `yaml:"authorization,omitempty" json:"authorization,omitempty"`

	// Request enables request event auditing.
	Request bool `yaml:"request,omitempty" json:"request,omitempty"`

	// Response enables response event auditing.
	Response bool `yaml:"response,omitempty" json:"response,omitempty"`

	// Configuration enables configuration change auditing.
	Configuration bool `yaml:"configuration,omitempty" json:"configuration,omitempty"`

	// Administrative enables administrative action auditing.
	Administrative bool `yaml:"administrative,omitempty" json:"administrative,omitempty"`

	// Security enables security event auditing.
	Security bool `yaml:"security,omitempty" json:"security,omitempty"`
}

// RetentionConfig configures audit log retention.
type RetentionConfig struct {
	// MaxAge is the maximum age of audit logs to retain.
	MaxAge time.Duration `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`

	// MaxSize is the maximum total size of audit logs to retain.
	MaxSize int64 `yaml:"maxSize,omitempty" json:"maxSize,omitempty"`

	// MaxCount is the maximum number of audit log files to retain.
	MaxCount int `yaml:"maxCount,omitempty" json:"maxCount,omitempty"`
}

// Validate validates the audit configuration.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}

	if !c.Enabled {
		return nil
	}

	// Validate level
	if c.Level != "" {
		validLevels := map[Level]bool{
			LevelDebug: true,
			LevelInfo:  true,
			LevelWarn:  true,
			LevelError: true,
		}
		if !validLevels[c.Level] {
			return fmt.Errorf("invalid audit level: %s", c.Level)
		}
	}

	// Validate format
	if c.Format != "" && c.Format != "json" && c.Format != "text" {
		return fmt.Errorf("invalid audit format: %s (must be 'json' or 'text')", c.Format)
	}

	// Validate file config
	if c.File != nil {
		if err := c.File.Validate(); err != nil {
			return fmt.Errorf("file config: %w", err)
		}
	}

	// Validate max body size
	if c.MaxBodySize < 0 {
		return errors.New("maxBodySize must be non-negative")
	}

	return nil
}

// Validate validates the file configuration.
func (c *FileConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.Path == "" {
		return errors.New("path is required")
	}

	if c.MaxSize < 0 {
		return errors.New("maxSize must be non-negative")
	}

	if c.MaxBackups < 0 {
		return errors.New("maxBackups must be non-negative")
	}

	if c.MaxAge < 0 {
		return errors.New("maxAge must be non-negative")
	}

	return nil
}

// DefaultConfig returns a default audit configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:     true,
		Level:       LevelInfo,
		Output:      "stdout",
		Format:      "json",
		MaxBodySize: 4096,
		Events: &EventsConfig{
			Authentication: true,
			Authorization:  true,
			Request:        false,
			Response:       false,
			Configuration:  true,
			Administrative: true,
			Security:       true,
		},
		RedactFields: []string{
			"password",
			"secret",
			"token",
			"api_key",
			"apiKey",
			"authorization",
			"cookie",
		},
	}
}

// GetEffectiveLevel returns the effective audit level.
func (c *Config) GetEffectiveLevel() Level {
	if c.Level != "" {
		return c.Level
	}
	return LevelInfo
}

// GetEffectiveFormat returns the effective output format.
func (c *Config) GetEffectiveFormat() string {
	if c.Format != "" {
		return c.Format
	}
	return "json"
}

// GetEffectiveOutput returns the effective output destination.
func (c *Config) GetEffectiveOutput() string {
	if c.Output != "" {
		return c.Output
	}
	return "stdout"
}

// ShouldAuditAuthentication returns true if authentication events should be audited.
func (c *Config) ShouldAuditAuthentication() bool {
	return c != nil && c.Enabled && (c.Events == nil || c.Events.Authentication)
}

// ShouldAuditAuthorization returns true if authorization events should be audited.
func (c *Config) ShouldAuditAuthorization() bool {
	return c != nil && c.Enabled && (c.Events == nil || c.Events.Authorization)
}

// ShouldAuditRequest returns true if request events should be audited.
func (c *Config) ShouldAuditRequest() bool {
	return c != nil && c.Enabled && c.Events != nil && c.Events.Request
}

// ShouldAuditResponse returns true if response events should be audited.
func (c *Config) ShouldAuditResponse() bool {
	return c != nil && c.Enabled && c.Events != nil && c.Events.Response
}

// ShouldAuditConfiguration returns true if configuration events should be audited.
func (c *Config) ShouldAuditConfiguration() bool {
	return c != nil && c.Enabled && (c.Events == nil || c.Events.Configuration)
}

// ShouldAuditAdministrative returns true if administrative events should be audited.
func (c *Config) ShouldAuditAdministrative() bool {
	return c != nil && c.Enabled && (c.Events == nil || c.Events.Administrative)
}

// ShouldAuditSecurity returns true if security events should be audited.
func (c *Config) ShouldAuditSecurity() bool {
	return c != nil && c.Enabled && (c.Events == nil || c.Events.Security)
}

// ShouldSkipPath returns true if the path should be skipped from auditing.
func (c *Config) ShouldSkipPath(path string) bool {
	for _, skipPath := range c.SkipPaths {
		if matchPath(skipPath, path) {
			return true
		}
	}
	return false
}

// matchPath checks if a path matches a pattern.
func matchPath(pattern, path string) bool {
	if pattern == path {
		return true
	}
	// Check for wildcard suffix
	if pattern != "" && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return false
}
