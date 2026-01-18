// Package validator provides validation logic for CRD webhooks.
package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration string
		wantErr  bool
	}{
		{
			name:     "empty string is valid",
			duration: "",
			wantErr:  false,
		},
		{
			name:     "valid seconds",
			duration: "30s",
			wantErr:  false,
		},
		{
			name:     "valid minutes",
			duration: "5m",
			wantErr:  false,
		},
		{
			name:     "valid hours",
			duration: "1h",
			wantErr:  false,
		},
		{
			name:     "valid milliseconds",
			duration: "100ms",
			wantErr:  false,
		},
		{
			name:     "large number",
			duration: "3600s",
			wantErr:  false,
		},
		{
			name:     "invalid format - no unit",
			duration: "30",
			wantErr:  true,
		},
		{
			name:     "invalid format - wrong unit",
			duration: "30d",
			wantErr:  true,
		},
		{
			name:     "invalid format - negative",
			duration: "-30s",
			wantErr:  true,
		},
		{
			name:     "invalid format - decimal",
			duration: "1.5s",
			wantErr:  true,
		},
		{
			name:     "invalid format - spaces",
			duration: "30 s",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDuration(tt.duration)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{
			name:     "empty string is valid",
			hostname: "",
			wantErr:  false,
		},
		{
			name:     "simple hostname",
			hostname: "example",
			wantErr:  false,
		},
		{
			name:     "domain name",
			hostname: "example.com",
			wantErr:  false,
		},
		{
			name:     "subdomain",
			hostname: "api.example.com",
			wantErr:  false,
		},
		{
			name:     "wildcard hostname",
			hostname: "*.example.com",
			wantErr:  false,
		},
		{
			name:     "hostname with numbers",
			hostname: "api1.example.com",
			wantErr:  false,
		},
		{
			name:     "hostname with hyphens",
			hostname: "my-api.example.com",
			wantErr:  false,
		},
		{
			name:     "uppercase hostname (converted to lowercase)",
			hostname: "EXAMPLE.COM",
			wantErr:  false,
		},
		{
			name:     "invalid - starts with hyphen",
			hostname: "-example.com",
			wantErr:  true,
		},
		{
			name:     "invalid - ends with hyphen",
			hostname: "example-.com",
			wantErr:  true,
		},
		{
			name:     "invalid - underscore",
			hostname: "my_api.example.com",
			wantErr:  true,
		},
		{
			name:     "invalid - wildcard only",
			hostname: "*",
			wantErr:  true,
		},
		{
			name:     "invalid - wildcard in middle",
			hostname: "api.*.example.com",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostname(tt.hostname)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "empty string is valid",
			path:    "",
			wantErr: false,
		},
		{
			name:    "root path",
			path:    "/",
			wantErr: false,
		},
		{
			name:    "simple path",
			path:    "/api",
			wantErr: false,
		},
		{
			name:    "nested path",
			path:    "/api/v1/users",
			wantErr: false,
		},
		{
			name:    "path with hyphens",
			path:    "/api/v1/user-profiles",
			wantErr: false,
		},
		{
			name:    "path with underscores",
			path:    "/api/v1/user_profiles",
			wantErr: false,
		},
		{
			name:    "path with numbers",
			path:    "/api/v1/users/123",
			wantErr: false,
		},
		{
			name:    "invalid - no leading slash",
			path:    "api/v1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsDurationRegexMatch(t *testing.T) {
	assert.True(t, IsDurationRegexMatch("30s"))
	assert.True(t, IsDurationRegexMatch("5m"))
	assert.True(t, IsDurationRegexMatch("1h"))
	assert.True(t, IsDurationRegexMatch("100ms"))
	assert.False(t, IsDurationRegexMatch("30"))
	assert.False(t, IsDurationRegexMatch("30d"))
	assert.False(t, IsDurationRegexMatch(""))
}

func TestIsHostnameRegexMatch(t *testing.T) {
	assert.True(t, IsHostnameRegexMatch("example.com"))
	assert.True(t, IsHostnameRegexMatch("*.example.com"))
	assert.True(t, IsHostnameRegexMatch("api.example.com"))
	assert.False(t, IsHostnameRegexMatch("-example.com"))
	assert.False(t, IsHostnameRegexMatch(""))
}

func TestIsPathRegexMatch(t *testing.T) {
	assert.True(t, IsPathRegexMatch("/"))
	assert.True(t, IsPathRegexMatch("/api"))
	assert.True(t, IsPathRegexMatch("/api/v1/users"))
	assert.False(t, IsPathRegexMatch("api"))
	assert.False(t, IsPathRegexMatch(""))
}
