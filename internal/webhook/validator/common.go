// Package validator provides validation logic for CRD webhooks.
package validator

import (
	"fmt"
	"regexp"
	"strings"
)

// Pre-compiled regular expressions for validation.
// These are compiled once at package initialization to avoid repeated compilation.
var (
	// durationRegex validates duration strings like "30s", "5m", "1h", "100ms".
	durationRegex = regexp.MustCompile(`^(\d+)(ms|s|m|h)$`)

	// hostnameRegex validates hostname strings according to RFC 1123.
	// Supports wildcards like "*.example.com".
	hostnameRegex = regexp.MustCompile(`^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

	// pathRegex validates URL path patterns.
	pathRegex = regexp.MustCompile(`^/[a-zA-Z0-9\-._~!$&'()*+,;=:@%/]*$`)
)

// ValidateDuration validates a duration string format.
// Valid formats: "30s", "5m", "1h", "100ms"
// Returns nil if the duration is valid or empty.
func ValidateDuration(duration string) error {
	if duration == "" {
		return nil
	}

	if !durationRegex.MatchString(duration) {
		return fmt.Errorf("invalid duration format: %s (expected format like '30s', '5m', '1h', '100ms')", duration)
	}

	return nil
}

// ValidateHostname validates a hostname string.
// Supports wildcards like "*.example.com".
// Returns nil if the hostname is valid or empty.
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return nil
	}

	// Convert to lowercase for validation
	lower := strings.ToLower(hostname)

	if !hostnameRegex.MatchString(lower) {
		return fmt.Errorf("invalid hostname: %s", hostname)
	}

	// Additional validation for wildcard hostnames
	if strings.HasPrefix(lower, "*.") {
		// Wildcard must be followed by at least one domain segment
		parts := strings.Split(lower, ".")
		if len(parts) < 2 {
			return fmt.Errorf("invalid wildcard hostname: %s (must have at least one domain segment)", hostname)
		}
	}

	return nil
}

// ValidatePath validates a URL path pattern.
// Returns nil if the path is valid or empty.
func ValidatePath(path string) error {
	if path == "" {
		return nil
	}

	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path must start with '/': %s", path)
	}

	if !pathRegex.MatchString(path) {
		return fmt.Errorf("invalid path: %s", path)
	}

	return nil
}

// IsDurationRegexMatch checks if a string matches the duration regex.
// This is a lower-level function for cases where custom error handling is needed.
func IsDurationRegexMatch(s string) bool {
	return durationRegex.MatchString(s)
}

// IsHostnameRegexMatch checks if a string matches the hostname regex.
// This is a lower-level function for cases where custom error handling is needed.
func IsHostnameRegexMatch(s string) bool {
	return hostnameRegex.MatchString(strings.ToLower(s))
}

// IsPathRegexMatch checks if a string matches the path regex.
// This is a lower-level function for cases where custom error handling is needed.
func IsPathRegexMatch(s string) bool {
	return pathRegex.MatchString(s)
}
